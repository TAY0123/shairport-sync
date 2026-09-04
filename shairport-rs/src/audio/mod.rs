use anyhow::Context;
use cpal::{
    I24, SampleFormat, Stream, StreamError, U24,
    traits::{DeviceTrait, HostTrait, StreamTrait},
};
use parking_lot::Mutex;
use ringbuf::{
    HeapRb,
    traits::{Consumer, Split},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread::JoinHandle,
    time::Duration,
};

pub mod drift;

use crate::codec;
use crate::config::{AudioConfig, AudioHostName, MAX_PCM_FIFO_MS};

/// Maximum ring-buffer size in f32 samples (~32 MiB for 8_388_608 samples).
/// Caps allocations regardless of sample rate, channel count, or duration.
const MAX_CAPACITY_SAMPLES: usize = 8_388_608;

#[derive(Clone)]
pub struct AudioManager {
    config: AudioConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AudioDevice {
    pub id: String,
    pub name: String,
    pub host: String,
    pub is_default: bool,
    pub supported_output_configs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SelectAudioDeviceRequest {
    pub device_id: Option<String>,
}

/// Result of a frame-oriented enqueue operation.
///
/// Most fields are expressed in **frames** (one frame = `channels` samples).
/// `trailing_samples` captures any incomplete frame at the end of the input
/// that cannot be enqueued — it is always < `channels`.
/// Use the sample-count helpers when a flat sample count is needed:
/// they include `trailing_samples` in `requested_samples` and
/// `rejected_samples` for a faithful total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnqueueResult {
    /// Number of complete frames presented for enqueue.
    pub requested_frames: usize,
    /// Number of complete frames actually enqueued.
    pub accepted_frames: usize,
    /// Number of complete frames rejected (full buffer).
    pub rejected_frames: usize,
    /// Incomplete trailing samples (0 ≤ trailing_samples < channels) that
    /// were presented but could not form a complete frame.
    pub trailing_samples: usize,
    /// Output channel count used for the operation.
    pub channels: u16,
}

impl EnqueueResult {
    /// Total samples presented (`requested_frames * channels + trailing_samples`).
    pub fn requested_samples(&self) -> usize {
        self.requested_frames * self.channels as usize + self.trailing_samples
    }

    /// Samples successfully enqueued (`accepted_frames * channels`).
    /// Trailing samples are never accepted.
    pub fn accepted_samples(&self) -> usize {
        self.accepted_frames * self.channels as usize
    }

    /// Samples rejected (`rejected_frames * channels + trailing_samples`).
    pub fn rejected_samples(&self) -> usize {
        self.rejected_frames * self.channels as usize + self.trailing_samples
    }
}

/// Producer/control side of the audio pipeline.
///
/// Cloneable and shared across the application. Owns the ring-buffer
/// producer half (behind a mutex for the non-real-time enqueue path) and
/// all atomic diagnostic/configuration fields.
#[derive(Clone)]
pub struct AudioEngine {
    producer: Arc<Mutex<ringbuf::HeapProd<f32>>>,
    capacity: usize,
    output_format: Arc<Mutex<AudioOutputFormat>>,
    resampler_cache: Arc<Mutex<codec::ResamplerCache>>,
    volume_gain_bits: Arc<AtomicU32>,
    playback_enabled: Arc<AtomicBool>,
    /// Cumulative samples written as silence in the output callback due to ring-buffer underrun.
    callback_underrun_samples: Arc<AtomicUsize>,
    /// Cumulative samples the producer could not push because the ring buffer was full.
    producer_overflow_samples: Arc<AtomicUsize>,
    /// Cumulative samples rejected solely because playback was disabled.
    /// Tracked independently of [`producer_overflow_samples`] so callers can
    /// distinguish "we chose not to play" from a genuine FIFO overflow.
    playback_disabled_rejected_samples: Arc<AtomicUsize>,
    /// Number of times a flush was requested (clear-output/flush events).
    flush_count: Arc<AtomicU64>,
    /// Monotonically incrementing flush epoch. Each clear_output_samples / request_flush
    /// call bumps this; the consumer drains on the next callback when it detects the change.
    flush_epoch: Arc<AtomicU64>,
    /// Latest flush epoch applied by the real-time consumer.
    applied_flush_epoch: Arc<AtomicU64>,
    /// Write-index boundary captured at the moment of the latest flush request.
    /// The consumer pops samples only up to (but not past) this index, preserving
    /// samples enqueued after the flush request was issued.
    flush_target_write_index: Arc<AtomicUsize>,
    /// Maximum observed ring-buffer occupancy (peak occupancy in samples).
    max_observed_occupancy: Arc<AtomicUsize>,
}

/// Real-time-safe consumer side of the audio pipeline.
///
/// Not Clone — exactly one instance is moved into the CPAL output callback.
/// Owns the `HeapCons<f32>` directly (no Mutex), so the callback methods
/// are lock-free and allocation-free.  All shared state is read via atomics.
pub struct AudioConsumer {
    consumer: ringbuf::HeapCons<f32>,
    volume_gain_bits: Arc<AtomicU32>,
    current_volume_gain: f32,
    playback_enabled: Arc<AtomicBool>,
    callback_underrun_samples: Arc<AtomicUsize>,
    flush_epoch: Arc<AtomicU64>,
    applied_flush_epoch: Arc<AtomicU64>,
    /// The last flush epoch observed by this consumer. On mismatch the
    /// consumer drains the ring buffer up to `flush_target_write_index`
    /// before producing output.
    last_seen_flush_epoch: u64,
    /// Write-index boundary captured at the moment of the latest flush request.
    /// The consumer pops samples only up to (but not past) this index.
    flush_target_write_index: Arc<AtomicUsize>,
}

pub struct AudioOutput {
    stream: Option<Stream>,
    consumer_return_rx: Option<Receiver<AudioConsumer>>,
    pub sample_rate: u32,
    pub channels: u16,
    pub sample_format: SampleFormat,
}

impl AudioOutput {
    /// Stop this CPAL stream and recover its sole ring-buffer consumer.
    ///
    /// The callback owns `AudioConsumer` directly while active. When CPAL
    /// drops the callback closure, `ReturningConsumer::drop` hands it back
    /// over this control-thread channel. No lock is taken in the callback.
    fn reclaim_consumer(mut self) -> anyhow::Result<AudioConsumer> {
        let receiver = self
            .consumer_return_rx
            .take()
            .context("audio output is missing its consumer return channel")?;
        drop(self.stream.take());
        receiver
            .recv_timeout(Duration::from_secs(2))
            .context("CPAL callback did not return its audio consumer after stream shutdown")
    }
}

const OUTPUT_POLL_INTERVAL: Duration = Duration::from_secs(1);

type OutputRecoveryHook = Arc<dyn Fn() + Send + Sync + 'static>;

enum OutputSupervisorMessage {
    StreamError { generation: u64, error: StreamError },
    SetDevice(Option<String>),
    Shutdown,
}

/// Cloneable control handle for runtime output-device changes.
#[derive(Clone)]
pub struct AudioOutputController {
    command_tx: Sender<OutputSupervisorMessage>,
    recovery_hook: Arc<Mutex<Option<OutputRecoveryHook>>>,
}

impl AudioOutputController {
    fn new(
        command_tx: Sender<OutputSupervisorMessage>,
        recovery_hook: Arc<Mutex<Option<OutputRecoveryHook>>>,
    ) -> Self {
        Self {
            command_tx,
            recovery_hook,
        }
    }

    /// Set the explicitly preferred output device. `None` resumes following
    /// the current system default device.
    pub fn set_device(&self, device: Option<String>) {
        let _ = self
            .command_tx
            .send(OutputSupervisorMessage::SetDevice(device));
    }

    /// Register a control-thread hook invoked before output recovery.
    pub fn set_recovery_hook<F>(&self, hook: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        *self.recovery_hook.lock() = Some(Arc::new(hook));
    }
}

impl Default for AudioOutputController {
    fn default() -> Self {
        let (command_tx, _command_rx) = mpsc::channel();
        Self {
            command_tx,
            recovery_hook: Arc::new(Mutex::new(None)),
        }
    }
}

/// Owns the live CPAL output stream on a dedicated control thread and
/// rebuilds it after device loss or runtime device changes.
///
/// Audio callbacks remain lock-free: each live callback exclusively owns the
/// same `AudioConsumer`, which is returned to this supervisor when the stream
/// is dropped and then moved into the replacement callback.
pub struct AudioOutputSupervisor {
    command_tx: Option<Sender<OutputSupervisorMessage>>,
    join: Option<JoinHandle<()>>,
}

impl AudioOutputSupervisor {
    fn spawn(
        manager: AudioManager,
        engine: AudioEngine,
        consumer: AudioConsumer,
        initial_device: Option<SelectedOutput>,
    ) -> (Self, AudioOutputController, anyhow::Result<()>) {
        let (command_tx, command_rx) = mpsc::channel();
        let recovery_hook = Arc::new(Mutex::new(None));
        let controller = AudioOutputController::new(command_tx.clone(), recovery_hook.clone());
        let (initial_tx, initial_rx) = mpsc::channel();
        let thread_command_tx = command_tx.clone();

        let join = std::thread::Builder::new()
            .name("cpal-output-supervisor".to_string())
            .spawn(move || {
                let mut current: Option<AudioOutput> = None;
                let mut available_consumer = Some(consumer);
                let mut current_device_id: Option<cpal::DeviceId> = None;
                let mut current_using_fallback = false;
                let mut preferred_device = manager.config.device.clone();
                let mut generation = 0u64;

                let initial = match initial_device {
                    Some(selected) => activate_selected_output(
                        &manager,
                        &engine,
                        &thread_command_tx,
                        &mut generation,
                        &mut current,
                        &mut available_consumer,
                        &mut current_device_id,
                        &mut current_using_fallback,
                        selected,
                    ),
                    None => try_activate_output(
                        &manager,
                        &engine,
                        &thread_command_tx,
                        &mut generation,
                        &mut current,
                        &mut available_consumer,
                        &mut current_device_id,
                        &mut current_using_fallback,
                        preferred_device.as_deref(),
                        false,
                        &recovery_hook,
                    ),
                };

                if let Err(err) = &initial {
                    tracing::warn!(%err, "CPAL output stream not started; supervisor will keep retrying");
                }
                let _ = initial_tx.send(initial);

                supervisor_loop(
                    &manager,
                    &engine,
                    &thread_command_tx,
                    &command_rx,
                    &recovery_hook,
                    &mut generation,
                    &mut current,
                    &mut available_consumer,
                    &mut current_device_id,
                    &mut current_using_fallback,
                    &mut preferred_device,
                );
            })
            .expect("failed to spawn CPAL output supervisor thread");

        let initial = initial_rx.recv().unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "CPAL output supervisor thread exited during startup"
            ))
        });

        (
            Self {
                command_tx: Some(command_tx),
                join: Some(join),
            },
            controller,
            initial,
        )
    }

    pub fn shutdown(mut self) {
        if let Some(tx) = self.command_tx.take() {
            let _ = tx.send(OutputSupervisorMessage::Shutdown);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for AudioOutputSupervisor {
    fn drop(&mut self) {
        if let Some(tx) = self.command_tx.take() {
            let _ = tx.send(OutputSupervisorMessage::Shutdown);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct ReturningConsumer {
    consumer: Option<AudioConsumer>,
    return_tx: Sender<AudioConsumer>,
}

impl ReturningConsumer {
    fn new(consumer: AudioConsumer, return_tx: Sender<AudioConsumer>) -> Self {
        Self {
            consumer: Some(consumer),
            return_tx,
        }
    }

    fn consumer_mut(&mut self) -> &mut AudioConsumer {
        self.consumer
            .as_mut()
            .expect("audio callback consumer already returned")
    }
}

impl Drop for ReturningConsumer {
    fn drop(&mut self) {
        if let Some(consumer) = self.consumer.take() {
            let _ = self.return_tx.send(consumer);
        }
    }
}

struct OutputBuildFailure {
    error: anyhow::Error,
    consumer: AudioConsumer,
}

struct SelectedOutput {
    device: cpal::Device,
    stream_config: cpal::StreamConfig,
    sample_format: SampleFormat,
    device_id: cpal::DeviceId,
    using_fallback: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AudioEngineStatus {
    // ---- existing fields (preserved for API compatibility) ----
    pub queued_samples: usize,
    pub capacity_samples: usize,
    pub output_sample_rate: u32,
    pub output_channels: u16,

    // ---- derived convenience fields ----
    /// queued_samples / output_channels (0 when channels is 0)
    pub queued_frames: usize,
    /// queued_samples duration in milliseconds at the output rate
    pub queued_ms: u64,
    /// capacity_samples / output_channels (0 when channels is 0)
    pub capacity_frames: usize,
    /// capacity_samples duration in milliseconds at the output rate
    pub capacity_ms: u64,

    // ---- diagnostic counters ----
    pub callback_underrun_samples: usize,
    pub callback_underrun_frames: usize,
    pub producer_overflow_samples: usize,
    pub producer_overflow_frames: usize,
    /// Samples rejected solely because playback was disabled.
    #[serde(default)]
    pub playback_disabled_rejected_samples: usize,
    /// playback_disabled_rejected_samples / output_channels (0 when channels is 0)
    #[serde(default)]
    pub playback_disabled_rejected_frames: usize,
    pub flush_count: u64,
    pub max_observed_occupancy: usize,
}

#[derive(Clone, Copy, Debug)]
struct AudioOutputFormat {
    sample_rate: u32,
    channels: u16,
}

impl AudioManager {
    pub fn new(config: AudioConfig) -> Self {
        Self { config }
    }

    #[allow(deprecated)]
    pub fn list_devices(&self) -> Vec<AudioDevice> {
        let hosts = match self.config.host {
            AudioHostName::Default => cpal::available_hosts(),
            host => vec![host_to_cpal(host)].into_iter().flatten().collect(),
        };

        hosts
            .into_iter()
            .filter_map(|host_id| cpal::host_from_id(host_id).ok().map(|host| (host_id, host)))
            .flat_map(|(host_id, host)| {
                let default_name = host.default_output_device().and_then(|d| d.name().ok());
                host.output_devices()
                    .map(|devices| {
                        devices
                            .filter_map(move |device| {
                                let name = device.name().ok()?;
                                let configs = device
                                    .supported_output_configs()
                                    .map(|supported| {
                                        supported
                                            .map(|config| {
                                                format!(
                                                    "{:?}/{:?}/{:?}-{:?}",
                                                    config.sample_format(),
                                                    config.channels(),
                                                    config.min_sample_rate(),
                                                    config.max_sample_rate()
                                                )
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                Some(AudioDevice {
                                    id: format!("{host_id:?}:{name}"),
                                    name: name.clone(),
                                    host: format!("{host_id:?}").to_lowercase(),
                                    is_default: default_name.as_ref() == Some(&name),
                                    supported_output_configs: configs,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Create the traditional single CPAL output. New application code uses
    /// [`create_engine_and_supervised_output`] so output can recover at runtime.
    pub fn create_engine_and_output(&self) -> (AudioEngine, anyhow::Result<AudioOutput>) {
        let mut config = self.config.clone();
        config.normalize();

        let selected = match self.open_selected_output(self.config.device.as_deref()) {
            Ok(selected) => selected,
            Err(err) => {
                let (engine, _consumer) =
                    AudioEngine::new_for_output(44_100, 2, config.pcm_fifo_ms);
                return (engine, Err(err));
            }
        };

        let (engine, consumer) = AudioEngine::new_for_output(
            selected.stream_config.sample_rate,
            selected.stream_config.channels,
            config.pcm_fifo_ms,
        );
        tracing::info!(
            sample_rate = selected.stream_config.sample_rate,
            channels = selected.stream_config.channels,
            sample_format = ?selected.sample_format,
            pcm_fifo_ms = config.pcm_fifo_ms,
            "CPAL output stream format"
        );

        match self.build_stream(selected, consumer, None, 0) {
            Ok(output) => (engine, Ok(output)),
            Err(failure) => (engine, Err(failure.error)),
        }
    }

    /// Create an [`AudioEngine`] plus a dedicated output supervisor.
    ///
    /// If no output device exists at startup, a fallback-shaped engine is
    /// returned immediately and the supervisor keeps retrying once per second.
    /// Runtime device changes preserve the same ring-buffer consumer by moving
    /// it from the old CPAL callback into the replacement callback.
    pub fn create_engine_and_supervised_output(
        &self,
    ) -> (
        AudioEngine,
        AudioOutputSupervisor,
        AudioOutputController,
        anyhow::Result<()>,
    ) {
        let mut config = self.config.clone();
        config.normalize();

        match self.open_selected_output(self.config.device.as_deref()) {
            Ok(selected) => {
                let (engine, consumer) = AudioEngine::new_for_output(
                    selected.stream_config.sample_rate,
                    selected.stream_config.channels,
                    config.pcm_fifo_ms,
                );
                // The output callback starts before an AirPlay stream exists.
                // Keep the gate closed until the scheduler reaches Playing so
                // idle silence is not counted as a callback underrun.
                engine.set_output_gate(false);
                let (supervisor, controller, initial) = AudioOutputSupervisor::spawn(
                    self.clone(),
                    engine.clone(),
                    consumer,
                    Some(selected),
                );
                (engine, supervisor, controller, initial)
            }
            Err(_) => {
                let (engine, consumer) = AudioEngine::new_for_output(44_100, 2, config.pcm_fifo_ms);
                // As above, the fallback output callback is live before any
                // AirPlay transport starts; leave it gated until Playing.
                engine.set_output_gate(false);
                let (supervisor, controller, initial) =
                    AudioOutputSupervisor::spawn(self.clone(), engine.clone(), consumer, None);
                (engine, supervisor, controller, initial)
            }
        }
    }

    fn host(&self) -> anyhow::Result<cpal::Host> {
        let host_id = match self.config.host {
            AudioHostName::Default => cpal::default_host().id(),
            host => host_to_cpal(host)
                .context("requested CPAL host is not available on this platform")?,
        };
        cpal::host_from_id(host_id).context("failed to initialise CPAL host")
    }

    /// Select an explicit device when available; otherwise temporarily fall
    /// back to the system default. `using_fallback` lets the supervisor keep
    /// polling so it can return to the preferred device when it reappears.
    #[allow(deprecated)]
    fn select_device_with_policy(
        &self,
        selected_device: Option<&str>,
    ) -> anyhow::Result<(cpal::Device, cpal::DeviceId, bool)> {
        let host = self.host()?;
        let host_id = host.id();
        let (device, using_fallback) = if let Some(selected) = selected_device {
            match host.output_devices()?.find(|device| {
                let name = device.name().unwrap_or_default();
                format!("{host_id:?}:{name}") == selected
            }) {
                Some(device) => (device, false),
                None => (
                    host.default_output_device()
                        .context("no CPAL output device available")?,
                    true,
                ),
            }
        } else {
            (
                host.default_output_device()
                    .context("no CPAL output device available")?,
                false,
            )
        };
        let device_id = device
            .id()
            .map_err(|err| anyhow::anyhow!("failed to get CPAL output device id: {err}"))?;
        Ok((device, device_id, using_fallback))
    }

    fn open_selected_output(
        &self,
        selected_device: Option<&str>,
    ) -> anyhow::Result<SelectedOutput> {
        let (device, device_id, using_fallback) =
            self.select_device_with_policy(selected_device)?;
        let (stream_config, sample_format) = choose_stream_config(&device)?;
        Ok(SelectedOutput {
            device,
            stream_config,
            sample_format,
            device_id,
            using_fallback,
        })
    }

    fn build_stream(
        &self,
        selected: SelectedOutput,
        consumer: AudioConsumer,
        supervisor_tx: Option<Sender<OutputSupervisorMessage>>,
        generation: u64,
    ) -> Result<AudioOutput, OutputBuildFailure> {
        let SelectedOutput {
            device,
            stream_config,
            sample_format,
            ..
        } = selected;
        let (return_tx, return_rx) = mpsc::channel();
        let mut consumer = ReturningConsumer::new(consumer, return_tx);
        let error_tx = supervisor_tx;
        let err_fn = move |error: StreamError| {
            if should_rebuild(&error) {
                tracing::warn!(%error, generation, "CPAL output device lost");
                if let Some(tx) = &error_tx {
                    let _ = tx.send(OutputSupervisorMessage::StreamError { generation, error });
                }
            } else {
                tracing::warn!(%error, generation, "CPAL output stream error");
            }
        };

        let stream_result = match sample_format {
            SampleFormat::F32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [f32], _| {
                    consumer.consumer_mut().fill_output(data);
                },
                err_fn,
                None,
            ),
            SampleFormat::F64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [f64], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::I8 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i8], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::I16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i16], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::I24 => device.build_output_stream(
                &stream_config,
                move |data: &mut [I24], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::I32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i32], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::I64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i64], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::U8 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u8], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::U16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u16], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::U24 => device.build_output_stream(
                &stream_config,
                move |data: &mut [U24], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::U32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u32], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            SampleFormat::U64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u64], _| fill_converted(data, consumer.consumer_mut()),
                err_fn,
                None,
            ),
            sample_format => {
                drop(consumer);
                let consumer = return_rx
                    .recv()
                    .expect("unsupported-format callback consumer was not returned");
                return Err(OutputBuildFailure {
                    error: anyhow::anyhow!("unsupported CPAL sample format {sample_format:?}"),
                    consumer,
                });
            }
        };

        let stream = match stream_result {
            Ok(stream) => stream,
            Err(error) => {
                let consumer = return_rx
                    .recv()
                    .expect("failed CPAL stream build did not return its audio consumer");
                return Err(OutputBuildFailure {
                    error: error.into(),
                    consumer,
                });
            }
        };

        if let Err(error) = stream.play() {
            drop(stream);
            let consumer = return_rx
                .recv()
                .expect("failed CPAL stream start did not return its audio consumer");
            return Err(OutputBuildFailure {
                error: error.into(),
                consumer,
            });
        }

        Ok(AudioOutput {
            stream: Some(stream),
            consumer_return_rx: Some(return_rx),
            sample_rate: stream_config.sample_rate,
            channels: stream_config.channels,
            sample_format,
        })
    }

    /// Legacy API — create an output stream from a pre-existing engine and consumer.
    pub fn start_output(
        &self,
        engine: &AudioEngine,
        consumer: AudioConsumer,
    ) -> anyhow::Result<AudioOutput> {
        let selected = self.open_selected_output(self.config.device.as_deref())?;
        engine.set_output_format(
            selected.stream_config.sample_rate,
            selected.stream_config.channels,
        );
        tracing::info!(
            sample_rate = selected.stream_config.sample_rate,
            channels = selected.stream_config.channels,
            sample_format = ?selected.sample_format,
            "CPAL output stream format"
        );
        self.build_stream(selected, consumer, None, 0)
            .map_err(|failure| failure.error)
    }
}

fn fill_converted<T>(output: &mut [T], consumer: &mut AudioConsumer)
where
    T: cpal::Sample + cpal::FromSample<f32>,
{
    consumer.fill_output_converted(output);
}

fn should_rebuild(error: &StreamError) -> bool {
    matches!(
        error,
        StreamError::DeviceNotAvailable | StreamError::StreamInvalidated
    )
}

fn should_recheck_device(preferred_device: Option<&str>, using_fallback: bool) -> bool {
    preferred_device.is_none() || using_fallback
}

fn prepare_output_recovery(
    engine: &AudioEngine,
    recovery_hook: &Arc<Mutex<Option<OutputRecoveryHook>>>,
) {
    let hook = recovery_hook.lock().clone();

    // A scheduler hook is installed shortly after the supervisor starts. Once
    // it exists we can close the output gate and rely on the scheduler's flush
    // transition to re-prime and reopen it. Before that hook exists (the tiny
    // startup window), still discard stale PCM/reset drift but do not close a
    // gate that nobody can yet reopen.
    if hook.is_some() {
        engine.set_output_gate(false);
    }
    engine.request_flush();
    engine.set_drift_correction_ppm(0.0);
    if let Some(hook) = hook {
        hook();
    }
}

#[allow(clippy::too_many_arguments)]
fn activate_selected_output(
    manager: &AudioManager,
    engine: &AudioEngine,
    command_tx: &Sender<OutputSupervisorMessage>,
    generation: &mut u64,
    current: &mut Option<AudioOutput>,
    available_consumer: &mut Option<AudioConsumer>,
    current_device_id: &mut Option<cpal::DeviceId>,
    current_using_fallback: &mut bool,
    selected: SelectedOutput,
) -> anyhow::Result<()> {
    let device_id = selected.device_id.clone();
    let using_fallback = selected.using_fallback;
    let sample_rate = selected.stream_config.sample_rate;
    let channels = selected.stream_config.channels;
    let sample_format = selected.sample_format;
    let consumer = available_consumer
        .take()
        .context("audio consumer unavailable while activating output")?;

    engine.set_output_format(sample_rate, channels);
    *generation = generation.wrapping_add(1);
    let stream_generation = *generation;
    match manager.build_stream(
        selected,
        consumer,
        Some(command_tx.clone()),
        stream_generation,
    ) {
        Ok(output) => {
            tracing::info!(
                device = %device_id,
                sample_rate,
                channels,
                sample_format = ?sample_format,
                using_fallback,
                generation = stream_generation,
                "CPAL output stream started"
            );
            *current = Some(output);
            *current_device_id = Some(device_id);
            *current_using_fallback = using_fallback;
            Ok(())
        }
        Err(failure) => {
            *available_consumer = Some(failure.consumer);
            *current_device_id = None;
            *current_using_fallback = false;
            Err(failure.error)
        }
    }
}

fn reclaim_current_output(
    current: &mut Option<AudioOutput>,
    available_consumer: &mut Option<AudioConsumer>,
    current_device_id: &mut Option<cpal::DeviceId>,
    current_using_fallback: &mut bool,
) -> anyhow::Result<()> {
    if let Some(output) = current.take() {
        let consumer = output.reclaim_consumer()?;
        *available_consumer = Some(consumer);
    }
    *current_device_id = None;
    *current_using_fallback = false;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_activate_output(
    manager: &AudioManager,
    engine: &AudioEngine,
    command_tx: &Sender<OutputSupervisorMessage>,
    generation: &mut u64,
    current: &mut Option<AudioOutput>,
    available_consumer: &mut Option<AudioConsumer>,
    current_device_id: &mut Option<cpal::DeviceId>,
    current_using_fallback: &mut bool,
    preferred_device: Option<&str>,
    recovering: bool,
    recovery_hook: &Arc<Mutex<Option<OutputRecoveryHook>>>,
) -> anyhow::Result<()> {
    let selected = manager.open_selected_output(preferred_device)?;
    if recovering {
        prepare_output_recovery(engine, recovery_hook);
    }
    activate_selected_output(
        manager,
        engine,
        command_tx,
        generation,
        current,
        available_consumer,
        current_device_id,
        current_using_fallback,
        selected,
    )
}

#[allow(clippy::too_many_arguments)]
fn rebuild_output(
    manager: &AudioManager,
    engine: &AudioEngine,
    command_tx: &Sender<OutputSupervisorMessage>,
    recovery_hook: &Arc<Mutex<Option<OutputRecoveryHook>>>,
    generation: &mut u64,
    current: &mut Option<AudioOutput>,
    available_consumer: &mut Option<AudioConsumer>,
    current_device_id: &mut Option<cpal::DeviceId>,
    current_using_fallback: &mut bool,
    preferred_device: Option<&str>,
) -> anyhow::Result<()> {
    prepare_output_recovery(engine, recovery_hook);
    reclaim_current_output(
        current,
        available_consumer,
        current_device_id,
        current_using_fallback,
    )?;
    try_activate_output(
        manager,
        engine,
        command_tx,
        generation,
        current,
        available_consumer,
        current_device_id,
        current_using_fallback,
        preferred_device,
        false,
        recovery_hook,
    )
}

#[allow(clippy::too_many_arguments)]
fn supervisor_loop(
    manager: &AudioManager,
    engine: &AudioEngine,
    command_tx: &Sender<OutputSupervisorMessage>,
    command_rx: &Receiver<OutputSupervisorMessage>,
    recovery_hook: &Arc<Mutex<Option<OutputRecoveryHook>>>,
    generation: &mut u64,
    current: &mut Option<AudioOutput>,
    available_consumer: &mut Option<AudioConsumer>,
    current_device_id: &mut Option<cpal::DeviceId>,
    current_using_fallback: &mut bool,
    preferred_device: &mut Option<String>,
) {
    loop {
        match command_rx.recv_timeout(OUTPUT_POLL_INTERVAL) {
            Ok(OutputSupervisorMessage::Shutdown) => break,
            Ok(OutputSupervisorMessage::SetDevice(device)) => {
                tracing::info!(device = ?device, "output device preference updated");
                *preferred_device = device;
                if let Err(error) = rebuild_output(
                    manager,
                    engine,
                    command_tx,
                    recovery_hook,
                    generation,
                    current,
                    available_consumer,
                    current_device_id,
                    current_using_fallback,
                    preferred_device.as_deref(),
                ) {
                    tracing::warn!(%error, "CPAL device selection failed; will retry");
                }
            }
            Ok(OutputSupervisorMessage::StreamError {
                generation: failed_generation,
                error,
            }) => {
                if failed_generation != *generation || current.is_none() {
                    tracing::debug!(
                        failed_generation,
                        active_generation = *generation,
                        "ignoring stale CPAL stream error"
                    );
                    continue;
                }
                tracing::warn!(%error, generation = failed_generation, "rebuilding failed CPAL output");
                if let Err(rebuild_error) = rebuild_output(
                    manager,
                    engine,
                    command_tx,
                    recovery_hook,
                    generation,
                    current,
                    available_consumer,
                    current_device_id,
                    current_using_fallback,
                    preferred_device.as_deref(),
                ) {
                    tracing::warn!(%rebuild_error, "CPAL recovery build failed; will retry");
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if current.is_none() {
                    if let Err(error) = try_activate_output(
                        manager,
                        engine,
                        command_tx,
                        generation,
                        current,
                        available_consumer,
                        current_device_id,
                        current_using_fallback,
                        preferred_device.as_deref(),
                        true,
                        recovery_hook,
                    ) {
                        tracing::debug!(%error, "CPAL output retry failed");
                    }
                    continue;
                }

                if !should_recheck_device(preferred_device.as_deref(), *current_using_fallback) {
                    continue;
                }

                match manager.select_device_with_policy(preferred_device.as_deref()) {
                    Ok((_device, desired_id, desired_fallback)) => {
                        let changed = current_device_id.as_ref() != Some(&desired_id)
                            || *current_using_fallback != desired_fallback;
                        if changed {
                            tracing::info!(
                                device = %desired_id,
                                using_fallback = desired_fallback,
                                "preferred/default output device changed"
                            );
                            if let Err(error) = rebuild_output(
                                manager,
                                engine,
                                command_tx,
                                recovery_hook,
                                generation,
                                current,
                                available_consumer,
                                current_device_id,
                                current_using_fallback,
                                preferred_device.as_deref(),
                            ) {
                                tracing::warn!(%error, "CPAL output switch failed; will retry");
                            }
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "no output device available while polling");
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

impl AudioEngine {
    /// Create a new audio pipeline, returning the producer/control side and
    /// the real-time-safe consumer side.
    pub fn new(capacity_samples: usize) -> (Self, AudioConsumer) {
        let rb = HeapRb::<f32>::new(capacity_samples);
        let (producer, consumer) = rb.split();
        let volume_gain_bits = Arc::new(AtomicU32::new(1.0f32.to_bits()));
        let playback_enabled = Arc::new(AtomicBool::new(true));
        let callback_underrun_samples = Arc::new(AtomicUsize::new(0));
        let flush_epoch = Arc::new(AtomicU64::new(0));
        let applied_flush_epoch = Arc::new(AtomicU64::new(0));
        let flush_target_write_index = Arc::new(AtomicUsize::new(0));
        let engine = Self {
            producer: Arc::new(Mutex::new(producer)),
            capacity: capacity_samples,
            output_format: Arc::new(Mutex::new(AudioOutputFormat {
                sample_rate: 48_000,
                channels: 2,
            })),
            resampler_cache: Arc::new(Mutex::new(codec::ResamplerCache::new())),
            volume_gain_bits: Arc::clone(&volume_gain_bits),
            playback_enabled: Arc::clone(&playback_enabled),
            callback_underrun_samples: Arc::clone(&callback_underrun_samples),
            producer_overflow_samples: Arc::new(AtomicUsize::new(0)),
            playback_disabled_rejected_samples: Arc::new(AtomicUsize::new(0)),
            flush_count: Arc::new(AtomicU64::new(0)),
            flush_epoch: Arc::clone(&flush_epoch),
            applied_flush_epoch: Arc::clone(&applied_flush_epoch),
            flush_target_write_index: Arc::clone(&flush_target_write_index),
            max_observed_occupancy: Arc::new(AtomicUsize::new(0)),
        };
        let audio_consumer = AudioConsumer {
            consumer,
            volume_gain_bits,
            current_volume_gain: 1.0,
            playback_enabled,
            callback_underrun_samples,
            flush_epoch,
            applied_flush_epoch,
            flush_target_write_index,
            last_seen_flush_epoch: 0,
        };
        (engine, audio_consumer)
    }

    /// Create a new audio pipeline with capacity derived from a duration.
    ///
    /// `capacity_samples = ceil(sample_rate * fifo_ms / 1000) * channels`,
    /// computed with overflow-safe u128 arithmetic.  The output format is
    /// automatically set to `(sample_rate, channels)`.
    ///
    /// Capacity is clamped to [`MAX_CAPACITY_SAMPLES`] to prevent
    /// unreasonable allocations from extreme inputs.  When clamping,
    /// channel alignment is preserved and at least one frame is
    /// guaranteed.
    pub fn new_for_output(sample_rate: u32, channels: u16, fifo_ms: u32) -> (Self, AudioConsumer) {
        let rate = sample_rate.max(1) as u128;
        let ch = channels.max(1) as u128;
        let ms = (fifo_ms.max(1) as u128).min(MAX_PCM_FIFO_MS as u128);

        // Ceil division with u128 — safe for any realistic (rate, ms) pair.
        let frames = (rate * ms).div_ceil(1000);
        let samples = frames * ch;

        // Clamp to the documented absolute maximum, preserving channel
        // alignment and guaranteeing at least one frame.
        let capacity_samples = if samples > MAX_CAPACITY_SAMPLES as u128 {
            let max_aligned = (MAX_CAPACITY_SAMPLES as u128 / ch) * ch;
            if max_aligned < ch {
                ch as usize
            } else {
                max_aligned as usize
            }
        } else {
            samples as usize
        };

        let (engine, consumer) = Self::new(capacity_samples);
        engine.set_output_format(sample_rate, channels);
        (engine, consumer)
    }

    /// Return the current ring-buffer occupancy by observing the producer.
    fn occupied_len(&self) -> usize {
        use ringbuf::traits::Observer;
        self.producer.lock().occupied_len()
    }

    pub fn set_output_format(&self, sample_rate: u32, channels: u16) {
        *self.output_format.lock() = AudioOutputFormat {
            sample_rate: sample_rate.max(1),
            channels: channels.max(1),
        };
    }

    /// Set drift correction ratio in parts per million, forwarded to the
    /// resampler cache.  A positive value speeds up output (compensates
    /// for a fast DAC).  Only meaningful for AP2 buffered playback with
    /// PTP clock lock.
    pub fn set_drift_correction_ppm(&self, ppm: f64) {
        self.resampler_cache.lock().set_correction_ppm(ppm);
    }

    /// Return the output channel count (≥ 1).
    fn output_channels(&self) -> u16 {
        self.output_format.lock().channels.max(1)
    }

    /// Update the software volume target.
    ///
    /// Non-finite control values are ignored. Passing NaN through to the
    /// real-time callback would produce NaN PCM samples, which some platform
    /// audio stacks and enhancement drivers do not handle safely.
    pub fn set_volume_db(&self, db: f64) {
        if !db.is_finite() {
            tracing::warn!(volume_db = db, "ignoring non-finite volume");
            return;
        }
        let db = db.clamp(-144.0, 0.0);
        let gain = if db <= -144.0 {
            0.0
        } else {
            10.0f64.powf(db / 20.0) as f32
        };
        self.volume_gain_bits
            .store(gain.to_bits(), Ordering::Release);
    }

    /// Enable or disable the output gate without flushing the ring buffer.
    ///
    /// When disabled the output callback outputs silence but queued samples
    /// are preserved.  Callers that need to discard the current FIFO should
    /// use [`set_playback_enabled`] (which flushes on disable) or call
    /// [`request_flush`] explicitly.
    pub fn set_output_gate(&self, enabled: bool) {
        self.playback_enabled.store(enabled, Ordering::Release);
    }

    /// Enable or disable playback, requesting a flush of the ring buffer
    /// when disabling.
    ///
    /// Delegates to [`set_output_gate`] and additionally calls
    /// [`request_flush`] on the enabled→disabled transition so that stale
    /// audio is discarded.
    pub fn set_playback_enabled(&self, enabled: bool) {
        self.set_output_gate(enabled);
        if !enabled {
            self.request_flush();
        }
    }

    pub fn is_playback_enabled(&self) -> bool {
        self.playback_enabled.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    pub fn enqueue_interleaved(&self, samples: &[f32]) -> usize {
        let format = *self.output_format.lock();
        self.enqueue_interleaved_for_output(samples, format.sample_rate, format.channels)
            .0
    }

    pub fn enqueue_interleaved_for_output(
        &self,
        samples: &[f32],
        input_sample_rate: u32,
        input_channels: u16,
    ) -> (usize, usize) {
        let converted =
            self.convert_interleaved_for_output(samples, input_sample_rate, input_channels);
        let total = converted.len();
        let result = self.enqueue_output_frames(&converted);
        (result.accepted_samples(), total)
    }

    pub fn convert_interleaved_for_output(
        &self,
        samples: &[f32],
        input_sample_rate: u32,
        input_channels: u16,
    ) -> Vec<f32> {
        let output_format = *self.output_format.lock();
        let converted_channels = convert_channels(samples, input_channels, output_format.channels);
        // Always pass through the cache: its zero-correction/equal-rate path
        // is cheap, while AP2 drift correction must also work when source and
        // DAC nominal rates are identical.
        self.resampler_cache.lock().resample(
            &converted_channels,
            input_sample_rate,
            output_format.sample_rate,
            output_format.channels,
        )
    }

    // -----------------------------------------------------------------------
    // Frame-safe enqueue (core, new public API)
    // -----------------------------------------------------------------------

    /// Enqueue complete audio frames, respecting `playback_enabled`.
    ///
    /// Returns an [`EnqueueResult`] with frame-level accounting.
    /// Incomplete trailing samples (< `channels`) are never pushed;
    /// they are counted as rejected.
    pub fn enqueue_output_frames(&self, samples: &[f32]) -> EnqueueResult {
        if !self.playback_enabled.load(Ordering::Acquire) {
            let channels = self.output_channels() as usize;
            let total_frames = samples.len() / channels.max(1);
            let trailing = samples.len() % channels.max(1);
            // All samples are rejected when playback is disabled;
            // count both complete frames and trailing samples exactly once
            // on a dedicated counter — not as a producer overflow.
            let total_rejected = trailing + total_frames * channels.max(1);
            if total_rejected > 0 {
                self.playback_disabled_rejected_samples
                    .fetch_add(total_rejected, Ordering::Release);
            }
            return EnqueueResult {
                requested_frames: total_frames,
                accepted_frames: 0,
                rejected_frames: total_frames,
                trailing_samples: trailing,
                channels: channels as u16,
            };
        }
        self.enqueue_output_frames_unchecked(samples)
    }

    /// Enqueue complete audio frames without checking `playback_enabled`.
    ///
    /// Same frame-safe semantics as [`enqueue_output_frames`] but skips
    /// the playback-enabled guard.
    pub fn enqueue_output_frames_unchecked(&self, samples: &[f32]) -> EnqueueResult {
        let channels = self.output_channels() as usize;
        let total_frames = samples.len() / channels; // floor-div → complete frames only
        let trailing_samples = samples.len() % channels;

        let mut producer = self.producer.lock();

        use ringbuf::traits::{Observer, Producer};
        let occupied = producer.occupied_len();
        let available_samples = self.capacity.saturating_sub(occupied);
        let available_frames = available_samples / channels;

        let frames_to_push = total_frames.min(available_frames);
        let samples_to_push = frames_to_push * channels;

        // Bulk write — push_slice returns the number of elements actually
        // written, which must equal samples_to_push because we pre-computed
        // the available space while holding the producer lock.
        let pushed = producer.push_slice(&samples[..samples_to_push]);
        debug_assert_eq!(
            pushed, samples_to_push,
            "push_slice wrote {pushed} of {samples_to_push} pre-computed samples"
        );

        let accepted_frames = pushed / channels;
        let rejected_frames = total_frames - accepted_frames;

        // Count all rejected samples: trailing incomplete frame + buffer-full.
        let total_rejected_samples = trailing_samples + rejected_frames * channels;
        if total_rejected_samples > 0 {
            self.producer_overflow_samples
                .fetch_add(total_rejected_samples, Ordering::Release);
        }

        // Track max observed occupancy.
        let current_occupancy = producer.occupied_len();
        let mut prev = self.max_observed_occupancy.load(Ordering::Acquire);
        while current_occupancy > prev {
            match self.max_observed_occupancy.compare_exchange_weak(
                prev,
                current_occupancy,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => prev = current,
            }
        }

        EnqueueResult {
            requested_frames: total_frames,
            accepted_frames,
            rejected_frames,
            trailing_samples,
            channels: channels as u16,
        }
    }

    /// Try to enqueue all complete frames atomically under a single
    /// producer-lock interval — either every complete frame is accepted
    /// or zero are.
    ///
    /// When `unchecked` is `false`: checks the playback gate first.
    /// If the gate is closed the call returns `(requested, 0)` without
    /// touching any overflow/loss counters.
    ///
    /// When `unchecked` is `true`: the playback gate is bypassed
    /// (used during Priming / Rebuffering so the output FIFO can fill).
    ///
    /// The producer lock is acquired once.  If the ring buffer has
    /// enough room for all complete frames the entire block is pushed.
    /// If not, **zero** frames are pushed and no overflow/loss counter
    /// is incremented — capacity rejection is scheduler backpressure,
    /// not a genuine overflow.
    ///
    /// Trailing samples that do not form a complete frame (`< channels`)
    /// are never accepted and cause the block to be fully rejected.
    ///
    /// Returns `(requested_frames, accepted_frames)` where
    /// `accepted_frames` is either `requested_frames` or `0`.
    pub fn try_enqueue_output_frames_all_or_nothing(
        &self,
        samples: &[f32],
        unchecked: bool,
    ) -> (usize, usize) {
        let channels = self.output_channels() as usize;
        if channels == 0 {
            return (0, 0);
        }
        let total_frames = samples.len() / channels;
        if total_frames == 0 {
            return (0, 0);
        }
        // Incomplete trailing samples → can never push.
        let has_trailing = !samples.len().is_multiple_of(channels);
        if has_trailing {
            // Trailing samples prevent an all-or-nothing push.
            return (total_frames, 0);
        }

        // Check the playback gate when not in unchecked mode.
        if !unchecked && !self.playback_enabled.load(Ordering::Acquire) {
            // Gate is closed — reject without touching overflow counters.
            // Count on the playback-disabled counter.
            self.playback_disabled_rejected_samples
                .fetch_add(samples.len(), Ordering::Release);
            return (total_frames, 0);
        }

        let mut producer = self.producer.lock();

        use ringbuf::traits::{Observer, Producer};
        let occupied = producer.occupied_len();
        let available_samples = self.capacity.saturating_sub(occupied);
        let available_frames = available_samples / channels;

        if total_frames > available_frames {
            // Insufficient capacity — reject entirely without counting
            // as overflow (this is scheduler backpressure).
            return (total_frames, 0);
        }

        let samples_to_push = total_frames * channels;
        let pushed = producer.push_slice(&samples[..samples_to_push]);
        debug_assert_eq!(
            pushed, samples_to_push,
            "try_enqueue_all_or_nothing: push_slice wrote {pushed} of {samples_to_push}"
        );

        // Track max observed occupancy (only on successful push).
        let current_occupancy = producer.occupied_len();
        let mut prev = self.max_observed_occupancy.load(Ordering::Acquire);
        while current_occupancy > prev {
            match self.max_observed_occupancy.compare_exchange_weak(
                prev,
                current_occupancy,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => prev = current,
            }
        }

        (total_frames, total_frames)
    }

    // -----------------------------------------------------------------------
    // Legacy sample-oriented enqueue (delegates to frame-safe internals)
    // -----------------------------------------------------------------------

    /// Enqueue samples (legacy). Delegates to the frame-safe API and
    /// returns the number of **samples** accepted.
    ///
    /// Incomplete trailing samples are rejected.  Prefer
    /// [`enqueue_output_frames`] for new code.
    pub fn enqueue_output_samples(&self, samples: &[f32]) -> usize {
        self.enqueue_output_frames(samples).accepted_samples()
    }

    /// Enqueue samples without playback-enabled check (legacy).
    /// Delegates to the frame-safe API.
    pub fn enqueue_output_samples_unchecked(&self, samples: &[f32]) -> usize {
        self.enqueue_output_frames_unchecked(samples)
            .accepted_samples()
    }

    /// Number of **complete frames** that can still be enqueued without overflow.
    pub fn available_frames(&self) -> usize {
        let channels = self.output_channels() as usize;
        self.capacity.saturating_sub(self.occupied_len()) / channels
    }

    /// Number of frame-aligned samples that can still be enqueued without overflow.
    ///
    /// The value is always a multiple of the output channel count.
    pub fn available_samples(&self) -> usize {
        self.available_frames() * self.output_channels() as usize
    }

    /// Request the consumer to drain the ring buffer up to the current
    /// write-index boundary.
    ///
    /// Snapsnots the producer write index under the producer mutex,
    /// publishes it via `flush_target_write_index` (Release), then bumps
    /// the flush epoch (Release).  The consumer pops only samples that
    /// were enqueued *before* this boundary; samples enqueued after the
    /// flush request are preserved.
    ///
    /// Also bumps the `flush_count` diagnostic counter.
    pub fn request_flush(&self) {
        // Snapshot the producer's current write index under the mutex
        // so the consumer knows precisely which samples to discard.
        // The mutex serialises against concurrent enqueue calls, which
        // advance write_index inside the lock, so the snapshot
        // reflects the exact point in the enqueue stream.
        {
            use ringbuf::traits::Observer;
            let producer = self.producer.lock();
            let target = producer.write_index();
            // Publish the target before publishing the epoch so that a
            // consumer that observes the new epoch is guaranteed to see
            // this target (the Release on flush_epoch below creates the
            // happens-before edge).
            self.flush_target_write_index
                .store(target, Ordering::Release);
        }
        self.flush_epoch.fetch_add(1, Ordering::Release);
        self.flush_count.fetch_add(1, Ordering::Release);
    }

    /// Request a flush (backward-compatible alias for `request_flush`).
    pub fn clear_output_samples(&self) {
        self.request_flush();
    }

    /// Whether the real-time callback has not yet applied the latest flush.
    pub fn is_flush_pending(&self) -> bool {
        self.applied_flush_epoch.load(Ordering::Acquire) != self.flush_epoch.load(Ordering::Acquire)
    }

    pub fn status(&self) -> AudioEngineStatus {
        let output_format = *self.output_format.lock();
        let channels = output_format.channels.max(1) as usize;
        let rate = output_format.sample_rate.max(1) as u64;
        let queued = self.occupied_len();
        let capacity = self.capacity;
        let und_run = self.callback_underrun_samples.load(Ordering::Acquire);
        let over = self.producer_overflow_samples.load(Ordering::Acquire);
        let disabled_rej = self
            .playback_disabled_rejected_samples
            .load(Ordering::Acquire);
        let flushes = self.flush_count.load(Ordering::Acquire);
        let max_occ = self.max_observed_occupancy.load(Ordering::Acquire);

        let ms_from_samples =
            |samples: usize| -> u64 { (samples as u64 * 1000) / (channels as u64 * rate) };

        AudioEngineStatus {
            queued_samples: queued,
            capacity_samples: capacity,
            output_sample_rate: output_format.sample_rate,
            output_channels: output_format.channels,
            queued_frames: queued / channels,
            queued_ms: ms_from_samples(queued),
            capacity_frames: capacity / channels,
            capacity_ms: ms_from_samples(capacity),
            callback_underrun_samples: und_run,
            callback_underrun_frames: und_run / channels,
            producer_overflow_samples: over,
            producer_overflow_frames: over / channels,
            playback_disabled_rejected_samples: disabled_rej,
            playback_disabled_rejected_frames: disabled_rej / channels,
            flush_count: flushes,
            max_observed_occupancy: max_occ,
        }
    }
}

// ---------------------------------------------------------------------------
// AudioConsumer — real-time safe callback methods (no alloc, no sleep,
// no log, no mutex).
// ---------------------------------------------------------------------------
impl AudioConsumer {
    /// Check and apply any pending flush request.
    ///
    /// When a new flush epoch is observed, the consumer discards samples
    /// up to the `flush_target_write_index` boundary that was captured
    /// at flush-request time.  Samples enqueued after that boundary are
    /// preserved and will be output normally.
    ///
    /// Ring-buffer indices wrap modulo `2 * capacity`, so the distance
    /// to the boundary is computed with modular arithmetic.  If the
    /// consumer has already advanced past the boundary (the forward
    /// distance exceeds the currently occupied region), nothing is
    /// discarded — the target belongs to an epoch whose samples were
    /// already consumed.
    ///
    /// Drain is O(1): we advance the consumer read index in a single
    /// operation instead of popping sample-by-sample.  This is safe
    /// because `f32` has no destructor — discarding the initialized
    /// slots without dropping them is a no-op.
    fn check_flush(&mut self) {
        use ringbuf::traits::Observer;
        let current_epoch = self.flush_epoch.load(Ordering::Acquire);
        if current_epoch != self.last_seen_flush_epoch {
            // Acquire pairs with the Release stores in request_flush,
            // ensuring we see the latest target write-index.
            let target = self.flush_target_write_index.load(Ordering::Acquire);
            let read = self.consumer.read_index();
            let occupied = self.consumer.occupied_len();
            let modulus = 2 * self.consumer.capacity().get();

            // Forward distance from read_index to target, modulo 2*capacity.
            let distance = (target + modulus - read) % modulus;

            if distance <= occupied {
                // The flush boundary lies within the currently occupied
                // region: discard exactly `distance` samples in O(1).
                //
                // SAFETY: f32 has no Drop impl.  The discarded slots
                // contain initialized f32 values, but skipping their
                // drop is a no-op — no resources are leaked and no
                // side effects are lost.
                unsafe {
                    self.consumer.advance_read_index(distance);
                }
            }
            // If distance > occupied, the consumer has already consumed
            // past the boundary (the producer wrapped past it multiple
            // times), so discard nothing.

            self.last_seen_flush_epoch = current_epoch;
            self.applied_flush_epoch
                .store(current_epoch, Ordering::Release);
        }
    }

    /// Fill `output` with samples popped from the ring buffer, applying
    /// volume gain. Write 0.0 for every underrun slot.
    ///
    /// Returns the number of valid (non-underrun) samples written.
    pub fn fill_output(&mut self, output: &mut [f32]) -> usize {
        // Apply any pending flush before consuming.
        self.check_flush();

        if !self.playback_enabled.load(Ordering::Acquire) {
            output.fill(0.0);
            self.current_volume_gain =
                f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
            return 0;
        }
        let target_gain = f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
        let mut filled = 0usize;
        let mut underrun = 0usize;
        for sample in output.iter_mut() {
            let gain = smooth_volume_gain(&mut self.current_volume_gain, target_gain);
            match self.consumer.try_pop() {
                Some(value) => {
                    *sample = value * gain;
                    filled += 1;
                }
                None => {
                    *sample = 0.0;
                    underrun += 1;
                }
            }
        }
        if underrun > 0 {
            self.callback_underrun_samples
                .fetch_add(underrun, Ordering::Release);
        }
        filled
    }

    /// Like `fill_output` but converts each sample to the CPAL output type `T`.
    pub fn fill_output_converted<T>(&mut self, output: &mut [T]) -> usize
    where
        T: cpal::Sample + cpal::FromSample<f32>,
    {
        self.check_flush();

        if !self.playback_enabled.load(Ordering::Acquire) {
            for sample in output.iter_mut() {
                *sample = T::from_sample(0.0);
            }
            self.current_volume_gain =
                f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
            return 0;
        }
        let target_gain = f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
        let mut filled = 0usize;
        let mut underrun = 0usize;
        for sample in output.iter_mut() {
            let gain = smooth_volume_gain(&mut self.current_volume_gain, target_gain);
            match self.consumer.try_pop() {
                Some(value) => {
                    *sample = T::from_sample(value * gain);
                    filled += 1;
                }
                None => {
                    *sample = T::from_sample(0.0);
                    underrun += 1;
                }
            }
        }
        if underrun > 0 {
            self.callback_underrun_samples
                .fetch_add(underrun, Ordering::Release);
        }
        filled
    }
}

/// Apply a short, lock-free gain ramp in the real-time callback.
///
/// An instantaneous gain step creates an audible click because it introduces
/// a discontinuity in the PCM waveform. At 48 kHz stereo this coefficient
/// settles a normal slider change in roughly 7 ms.
#[inline]
fn smooth_volume_gain(current: &mut f32, target: f32) -> f32 {
    const SMOOTHING_FACTOR: f32 = 0.01;
    const SNAP_THRESHOLD: f32 = 0.000_01;

    let delta = target - *current;
    if delta.abs() <= SNAP_THRESHOLD {
        *current = target;
    } else {
        *current += delta * SMOOTHING_FACTOR;
    }
    *current
}

fn convert_channels(samples: &[f32], input_channels: u16, output_channels: u16) -> Vec<f32> {
    let input_channels = input_channels.max(1) as usize;
    let output_channels = output_channels.max(1) as usize;
    if input_channels == output_channels {
        return samples.to_vec();
    }

    if input_channels > 2 && output_channels == 2 {
        return codec::mixdown_to_stereo(samples, input_channels as u16);
    }

    let frames = samples.len() / input_channels;
    let mut output = Vec::with_capacity(frames * output_channels);
    for frame in 0..frames {
        let input_offset = frame * input_channels;
        let left = samples.get(input_offset).copied().unwrap_or(0.0);
        let right = if input_channels > 1 {
            samples.get(input_offset + 1).copied().unwrap_or(left)
        } else {
            left
        };

        for ch in 0..output_channels {
            output.push(match ch {
                0 => left,
                1 => right,
                _ => 0.0,
            });
        }
    }
    output
}

fn choose_stream_config(
    device: &cpal::Device,
) -> anyhow::Result<(cpal::StreamConfig, SampleFormat)> {
    let default_config = device.default_output_config()?;
    let stream_config = default_config.config();
    tracing::info!(
        sample_rate = stream_config.sample_rate,
        channels = stream_config.channels,
        sample_format = ?default_config.sample_format(),
        "using device default output config"
    );
    Ok((default_config.config(), default_config.sample_format()))
}

fn host_to_cpal(host: AudioHostName) -> Option<cpal::HostId> {
    match host {
        AudioHostName::Default => None,
        #[cfg(target_os = "linux")]
        AudioHostName::Alsa => Some(cpal::HostId::Alsa),
        #[cfg(not(target_os = "linux"))]
        AudioHostName::Alsa => None,
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        AudioHostName::Coreaudio => Some(cpal::HostId::CoreAudio),
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        AudioHostName::Coreaudio => None,
        #[cfg(target_os = "windows")]
        AudioHostName::Wasapi => Some(cpal::HostId::Wasapi),
        #[cfg(not(target_os = "windows"))]
        AudioHostName::Wasapi => None,
        #[cfg(all(target_os = "windows", feature = "asio"))]
        AudioHostName::Asio => Some(cpal::HostId::Asio),
        #[cfg(not(all(target_os = "windows", feature = "asio")))]
        AudioHostName::Asio => None,
        #[cfg(feature = "jack")]
        AudioHostName::Jack => Some(cpal::HostId::Jack),
        #[cfg(not(feature = "jack"))]
        AudioHostName::Jack => None,
    }
}

// ---------------------------------------------------------------------------
// Test-only helpers exposed to the test module below.
// ---------------------------------------------------------------------------
#[cfg(test)]
impl AudioEngine {
    /// Return the actual ring-buffer occupancy via the ringbuf `Observer` trait.
    fn ring_occupied_len(&self) -> usize {
        self.occupied_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_error_classification_rebuilds_only_device_loss() {
        assert!(should_rebuild(&StreamError::DeviceNotAvailable));
        assert!(should_rebuild(&StreamError::StreamInvalidated));
        assert!(!should_rebuild(&StreamError::BufferUnderrun));
    }

    #[test]
    fn device_recheck_policy_tracks_default_and_temporary_fallback() {
        assert!(should_recheck_device(None, false));
        assert!(should_recheck_device(Some("preferred"), true));
        assert!(!should_recheck_device(Some("preferred"), false));
    }

    #[test]
    fn returning_consumer_hands_ownership_back_without_callback_mutex() {
        let (_engine, consumer) = AudioEngine::new(16);
        let (tx, rx) = mpsc::channel();
        drop(ReturningConsumer::new(consumer, tx));
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_ok());
    }

    #[test]
    fn recovery_before_scheduler_hook_does_not_leave_output_gate_closed() {
        let (engine, _consumer) = AudioEngine::new(16);
        let hook: Arc<Mutex<Option<OutputRecoveryHook>>> = Arc::new(Mutex::new(None));
        assert!(engine.is_playback_enabled());
        prepare_output_recovery(&engine, &hook);
        assert!(engine.is_playback_enabled());
    }

    #[test]
    fn recovery_with_scheduler_hook_closes_gate_and_invokes_hook() {
        let (engine, _consumer) = AudioEngine::new(16);
        let called = Arc::new(AtomicBool::new(false));
        let hook_called = called.clone();
        let hook: Arc<Mutex<Option<OutputRecoveryHook>>> =
            Arc::new(Mutex::new(Some(Arc::new(move || {
                hook_called.store(true, Ordering::Release)
            }))));

        prepare_output_recovery(&engine, &hook);
        assert!(!engine.is_playback_enabled());
        assert!(called.load(Ordering::Acquire));
    }

    // ---------------------------------------------------------------------------
    // Existing tests (preserved, adapted to new API)
    // ---------------------------------------------------------------------------

    #[test]
    fn audio_engine_preserves_sample_order_and_zeros_underrun() {
        let (engine, mut consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        assert_eq!(engine.enqueue_interleaved(&[0.1, 0.2, 0.3, 0.4]), 4);
        let mut out = [1.0; 6];
        assert_eq!(consumer.fill_output(&mut out), 4);
        assert_eq!(out, [0.1, 0.2, 0.3, 0.4, 0.0, 0.0]);
    }

    #[test]
    fn audio_engine_applies_volume_gain() {
        let (engine, mut consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        engine.set_volume_db(-6.0);
        assert_eq!(engine.enqueue_interleaved(&[1.0, 1.0]), 2);
        let mut out = [0.0; 2];
        consumer.fill_output(&mut out);
        assert!(out[0] < 1.0 && out[0] > 0.501_187_2);
        assert!(out[1] < out[0] && out[1] > 0.501_187_2);

        let mut silence = [0.0; 2_048];
        consumer.fill_output(&mut silence);
        assert_eq!(engine.enqueue_interleaved(&[1.0, 1.0]), 2);
        consumer.fill_output(&mut out);
        assert!((out[0] - 0.501_187_2).abs() < 0.000_01);
        assert!((out[1] - 0.501_187_2).abs() < 0.000_01);
    }

    #[test]
    fn audio_engine_ignores_non_finite_volume() {
        let (engine, mut consumer) = AudioEngine::new(4);
        engine.set_volume_db(-6.0);
        engine.set_volume_db(f64::NAN);
        engine.set_volume_db(f64::INFINITY);

        let mut silence = [0.0; 2_048];
        consumer.fill_output(&mut silence);
        assert_eq!(engine.enqueue_interleaved(&[1.0, 1.0]), 2);
        let mut out = [0.0; 2];
        consumer.fill_output(&mut out);
        assert!(out.iter().all(|sample| sample.is_finite()));
        assert!((out[0] - 0.501_187_2).abs() < 0.000_01);
    }

    #[test]
    fn audio_engine_drops_samples_when_playback_disabled() {
        let (engine, mut consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        engine.set_playback_enabled(false);
        assert_eq!(engine.enqueue_interleaved(&[0.1, 0.2]), 0);
        let mut out = [1.0; 2];
        assert_eq!(consumer.fill_output(&mut out), 0);
        assert_eq!(out, [0.0, 0.0]);

        // Disabled rejection is counted separately, not as overflow.
        let s = engine.status();
        assert_eq!(s.playback_disabled_rejected_samples, 2);
        assert_eq!(s.playback_disabled_rejected_frames, 1);
        assert_eq!(s.producer_overflow_samples, 0);
    }

    #[test]
    fn disabled_rejection_does_not_increase_producer_overflow() {
        let (engine, _consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        engine.set_playback_enabled(false);

        // Enqueue several frames while disabled — includes trailing sample.
        engine.enqueue_output_samples(&[0.5; 7]); // 3 frames + 1 trailing, all rejected
        let s = engine.status();
        assert_eq!(s.playback_disabled_rejected_samples, 7);
        assert_eq!(s.playback_disabled_rejected_frames, 3);
        // producer_overflow must stay 0 — the ring buffer wasn't full.
        assert_eq!(s.producer_overflow_samples, 0);
    }

    #[test]
    fn audio_engine_resamples_to_output_rate() {
        let (engine, _consumer) = AudioEngine::new(256);
        engine.set_output_format(44_100, 2);
        let input = vec![0.0; 96];
        let (enqueued, total) = engine.enqueue_interleaved_for_output(&input, 48_000, 2);
        assert_eq!(enqueued, total);
        assert!(total < input.len());
    }

    #[test]
    fn audio_engine_expands_stereo_to_multichannel_output() {
        let (engine, mut consumer) = AudioEngine::new(16);
        engine.set_output_format(48_000, 4);
        let (enqueued, total) =
            engine.enqueue_interleaved_for_output(&[1.0, -1.0, 0.5, -0.5], 48_000, 2);
        assert_eq!(enqueued, 8);
        assert_eq!(total, 8);
        let mut out = [9.0; 8];
        consumer.fill_output(&mut out);
        assert_eq!(out, [1.0, -1.0, 0.0, 0.0, 0.5, -0.5, 0.0, 0.0]);
    }

    // ---------------------------------------------------------------------------
    // New metric tests — non-failing, run with the normal test suite
    // ---------------------------------------------------------------------------

    #[test]
    fn status_derived_fields_match_output_format() {
        // 48000 Hz stereo → each frame = 2 samples, ~0.0208 ms per sample
        let (engine, _consumer) = AudioEngine::new(960); // 480 frames = 10 ms
        engine.set_output_format(48_000, 2);
        engine.enqueue_interleaved(&[1.0; 480]); // 480 samples = 240 frames = 5 ms

        let s = engine.status();
        assert_eq!(s.output_sample_rate, 48_000);
        assert_eq!(s.output_channels, 2);
        assert_eq!(s.queued_samples, 480);
        assert_eq!(s.queued_frames, 240);
        assert_eq!(s.queued_ms, 5); // 480 samples / 2 ch / 48000 * 1000 = 5
        assert_eq!(s.capacity_samples, 960);
        assert_eq!(s.capacity_frames, 480);
        assert_eq!(s.capacity_ms, 10); // 960 / 2 / 48000 * 1000 = 10
    }

    #[test]
    fn status_derived_fields_zero_when_empty() {
        let (engine, _consumer) = AudioEngine::new(512);
        engine.set_output_format(44_100, 2);
        let s = engine.status();
        assert_eq!(s.queued_samples, 0);
        assert_eq!(s.queued_frames, 0);
        assert_eq!(s.queued_ms, 0);
        assert_eq!(s.capacity_ms, 5); // 512/2/44100*1000 = trunc(5.80) = 5
    }

    #[test]
    fn status_derived_handles_mono_output() {
        let (engine, _consumer) = AudioEngine::new(441); // 10 ms at 44100 Hz mono
        engine.set_output_format(44_100, 1);
        engine.enqueue_interleaved(&[1.0; 441]);

        let s = engine.status();
        assert_eq!(s.queued_frames, 441);
        assert_eq!(s.queued_ms, 10); // 441/1/44100*1000 = 10
        assert_eq!(s.capacity_frames, 441);
        assert_eq!(s.capacity_ms, 10);
    }

    #[test]
    fn callback_underrun_counter_increments_on_empty_buffer() {
        let (engine, mut consumer) = AudioEngine::new(8);
        engine.set_output_format(48_000, 2);

        // Nothing enqueued — all output slots are underruns.
        let mut out = [0.0f32; 4];
        consumer.fill_output(&mut out);
        assert_eq!(engine.status().callback_underrun_samples, 4);
        assert_eq!(engine.status().callback_underrun_frames, 2);

        // Second call accumulates.
        let mut out2 = [0.0f32; 6];
        consumer.fill_output(&mut out2);
        assert_eq!(engine.status().callback_underrun_samples, 10);
    }

    #[test]
    fn callback_underrun_only_counts_playback_enabled() {
        let (engine, mut consumer) = AudioEngine::new(8);
        engine.set_playback_enabled(false);
        let mut out = [0.0f32; 4];
        consumer.fill_output(&mut out);
        // Zeros produced because playback was disabled, not because of underrun.
        assert_eq!(engine.status().callback_underrun_samples, 0);
    }

    #[test]
    fn producer_overflow_counter_increments_on_full_buffer() {
        let (engine, _consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        // Fill completely.
        assert_eq!(engine.enqueue_output_samples(&[0.5; 4]), 4);
        // Try to push more — everything overflows.
        assert_eq!(engine.enqueue_output_samples(&[0.5; 10]), 0);
        assert_eq!(engine.status().producer_overflow_samples, 10);
        assert_eq!(engine.status().producer_overflow_frames, 5);
    }

    #[test]
    fn producer_overflow_partial_push_counts_remainder() {
        let (engine, _consumer) = AudioEngine::new(5);
        engine.set_output_format(48_000, 2);
        // Capacity 5 samples = 2 complete stereo frames (4 samples).
        // Input 7 samples → 3 frames + 1 trailing → accepts 2 frames (4 samples).
        // Rejected: 1 trailing + 2 over-capacity = 3 samples.
        assert_eq!(engine.enqueue_output_samples(&[0.1; 7]), 4);
        assert_eq!(engine.status().producer_overflow_samples, 3);
    }

    #[test]
    fn flush_counter_increments_on_clear() {
        let (engine, _consumer) = AudioEngine::new(8);
        engine.set_output_format(48_000, 2);
        engine.enqueue_interleaved(&[1.0; 4]);
        engine.clear_output_samples();
        assert_eq!(engine.status().flush_count, 1);
        engine.clear_output_samples();
        assert_eq!(engine.status().flush_count, 2);
    }

    #[test]
    fn max_occupancy_tracks_peak() {
        let (engine, mut consumer) = AudioEngine::new(100);
        engine.set_output_format(48_000, 2);

        engine.enqueue_output_samples(&[0.1; 30]);
        assert_eq!(engine.status().max_observed_occupancy, 30);

        engine.enqueue_output_samples(&[0.1; 50]);
        assert_eq!(engine.status().max_observed_occupancy, 80);

        // Drain some, then push less — peak should stay at 80.
        let mut out = [0.0f32; 40];
        consumer.fill_output(&mut out);
        engine.enqueue_output_samples(&[0.1; 10]);
        assert_eq!(engine.status().max_observed_occupancy, 80);
    }

    #[test]
    fn status_serde_roundtrip_preserves_all_fields() {
        let (engine, mut consumer) = AudioEngine::new(1024);
        engine.set_output_format(96_000, 6);
        engine.enqueue_output_samples(&[0.5; 300]);
        let mut out = [0.0f32; 64];
        consumer.fill_output(&mut out); // drain some
        engine.clear_output_samples();

        let s = engine.status();
        let json = serde_json::to_string(&s).expect("serialize");
        let roundtripped: AudioEngineStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, roundtripped);
        // Spot-check a few derived fields.
        assert_eq!(roundtripped.queued_frames, s.queued_frames);
        assert_eq!(roundtripped.queued_ms, s.queued_ms);
        assert_eq!(roundtripped.flush_count, 1);
    }

    // ---------------------------------------------------------------------------
    // Phase 1 — occupancy/flush race is fixed.
    // ---------------------------------------------------------------------------

    #[test]
    fn occupancy_never_diverges_after_flush_and_enqueue() {
        // flush only increments an epoch and captures a write-index boundary;
        // the consumer drains up to the boundary on the next callback.
        // status() reads occupancy directly from the ring-buffer Observer.
        let (engine, mut consumer) = AudioEngine::new(1024);
        engine.set_output_format(48_000, 2);
        engine.enqueue_output_samples(&[1.0; 500]);

        // Flush: captures write_index at 500, bumps epoch.
        // The consumer hasn't seen it yet so the ring still has 500 samples.
        engine.clear_output_samples();
        let actual = engine.ring_occupied_len();
        assert_eq!(
            actual, 500,
            "flush does not drain the ring from the control side"
        );

        // Enqueue more — still succeeds because the ring has space.
        // write_index advances to 700, past the flush boundary at 500.
        let pushed = engine.enqueue_output_samples(&[2.0; 200]);
        assert!(pushed > 0, "enqueue after flush still works");

        // Now the consumer sees the flush epoch and drains up to write_idx=500
        // (discarding the 1.0 samples), then reads 64 slots of the 2.0 samples.
        let mut out = [0.0f32; 64];
        consumer.fill_output(&mut out);
        // After draining and consuming, occupancy should reflect reality.
        let actual_after = engine.ring_occupied_len();
        assert_eq!(
            engine.status().queued_samples,
            actual_after,
            "status queued_samples matches ring observer after callback"
        );
    }

    #[test]
    fn flush_epoch_drains_consumer() {
        let (engine, mut consumer) = AudioEngine::new(128);
        engine.set_output_format(48_000, 2);
        engine.enqueue_output_samples(&[1.0; 80]);

        // Before flush, consumer gets real samples.
        let mut out = [0.0f32; 30];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 30);
        assert!(out.iter().all(|&s| s > 0.0));

        // Now flush via the engine — captures write_index at 80.
        engine.clear_output_samples();
        assert!(engine.is_flush_pending());
        // The consumer sees the new epoch, reads flush_target_write_index=80,
        // and pops from its current read_index (30) up to 80, discarding
        // the 50 remaining pre-flush samples.
        let mut out2 = [0.0f32; 20];
        let filled2 = consumer.fill_output(&mut out2);
        // All 20 slots are underruns (no samples after the boundary).
        assert_eq!(
            filled2, 0,
            "flush drained remaining pre-boundary samples; all output is silence"
        );
        assert_eq!(
            engine.ring_occupied_len(),
            0,
            "ring is empty after flush+callback"
        );
        assert!(!engine.is_flush_pending());
    }

    // ---------------------------------------------------------------------------
    // Phase 1 — flush boundary tests: verify that samples enqueued after a
    // flush request are preserved through the consumer callback.
    // ---------------------------------------------------------------------------

    /// Samples enqueued *after* a flush request must survive the next callback.
    /// Old code drained the entire ring, discarding post-flush samples.
    #[test]
    fn flush_preserves_samples_enqueued_after_request() {
        let (engine, mut consumer) = AudioEngine::new(256);
        engine.set_output_format(48_000, 2);

        // Enqueue old samples, then flush.
        engine.enqueue_output_samples(&[0.1; 80]);
        engine.request_flush();

        // Now enqueue new samples — write index has advanced past the
        // flush boundary.  The consumer must discard only the old 80 and
        // output the new 40.
        engine.enqueue_output_samples(&[0.5; 40]);

        // First callback: check_flush discards up to the boundary (80),
        // then fill_output reads the 40 post-flush samples.
        let mut out = [0.0f32; 60];
        let filled = consumer.fill_output(&mut out);
        // We asked for 60 but only 40 remain → 40 filled, 20 underrun zeros.
        assert_eq!(filled, 40);
        assert!(
            out[..40].iter().all(|&s| (s - 0.5).abs() < 0.001),
            "first 40 samples must be the post-flush 0.5 values"
        );
        assert!(
            out[40..].iter().all(|&s| s.abs() < 0.001),
            "remaining 20 samples are underrun zeros"
        );
    }

    /// AP2 priming workflow: disable → unchecked-enqueue → enable → callback
    /// must output the priming samples.
    ///
    /// When `set_playback_enabled(false)` is called it requests a flush
    /// (incrementing the epoch).  The unchecked enqueue then writes priming
    /// samples past the flush boundary.  When playback is re-enabled and the
    /// callback sees the pending flush, it must preserve the priming samples.
    #[test]
    fn priming_preserved_when_playback_reenabled() {
        let (engine, mut consumer) = AudioEngine::new(256);
        engine.set_output_format(48_000, 2);

        // Simulate an active stream with some old samples.
        engine.enqueue_output_samples(&[0.9; 50]);

        // Disable: this requests a flush internally.
        engine.set_playback_enabled(false);
        // Flush was requested but not yet consumed; old samples still in ring.
        assert!(engine.ring_occupied_len() > 0);

        // Unchecked enqueue — the AP2 'waiting_for_title' path.
        let priming = vec![0.3; 60];
        let pushed = engine.enqueue_output_samples_unchecked(&priming);
        assert_eq!(pushed, 60, "priming samples were enqueued");

        // Enable playback after priming.
        engine.set_playback_enabled(true);

        // Consumer callback: the flush epoch from set_playback_enabled(false)
        // is now processed.  The old 50 samples (before the flush boundary)
        // are discarded; the 60 priming samples (after the boundary) survive.
        let mut out = [0.0f32; 70];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 60);
        assert!(
            out[..60].iter().all(|&s| (s - 0.3).abs() < 0.001),
            "all filled samples must be the priming 0.3 values"
        );
        assert!(
            out[60..].iter().all(|&s| s.abs() < 0.001),
            "remaining slots are underrun zeros"
        );
    }

    /// Multiple flush requests before a callback preserve only samples
    /// enqueued after the *latest* boundary.
    #[test]
    fn repeated_flush_preserves_only_after_latest_boundary() {
        let (engine, mut consumer) = AudioEngine::new(256);
        engine.set_output_format(48_000, 2);

        // Batch 1: enqueued before first flush → discarded.
        engine.enqueue_output_samples(&[1.0; 30]);
        engine.request_flush(); // target at write_idx ≈ 30

        // Batch 2: enqueued between first and second flush → also discarded.
        engine.enqueue_output_samples(&[2.0; 20]);
        engine.request_flush(); // target advances to ≈ 50

        // Batch 3: enqueued after both flushes → must survive.
        engine.enqueue_output_samples(&[3.0; 14]);

        let mut out = [0.0f32; 32];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 14, "only the 14 post-flush samples survive");
        assert!(
            out[..14].iter().all(|&s| (s - 3.0).abs() < 0.001),
            "surviving samples are from the last batch (value 3.0)"
        );
        assert!(
            out[14..].iter().all(|&s| s.abs() < 0.001),
            "remaining slots are underrun zeros"
        );
    }

    // ---------------------------------------------------------------------------
    // Phase 1 — flush wrap / already-passed boundary tests.
    // ---------------------------------------------------------------------------

    /// Flush boundary is correctly computed when the ring-buffer write index
    /// has wrapped past `2 * capacity` and the target is numerically less
    /// than the current read index.
    ///
    /// Without modular distance the old `while read_index() < target` loop
    /// would skip the drain (because target < read_index numerically),
    /// leaking stale pre-flush samples into the output.
    #[test]
    fn flush_drains_across_index_wrap() {
        use ringbuf::traits::Observer;

        const CAP: usize = 8;
        let (engine, mut consumer) = AudioEngine::new(CAP);
        engine.set_output_format(48_000, 2);

        engine.enqueue_output_samples(&[1.0; 8]);
        let mut first = [0.0f32; 8];
        assert_eq!(consumer.fill_output(&mut first), 8);

        engine.enqueue_output_samples(&[1.0; 4]);
        let mut second = [0.0f32; 4];
        assert_eq!(consumer.fill_output(&mut second), 4);
        let read = consumer.consumer.read_index();
        assert_eq!(read, 12);

        engine.enqueue_output_samples(&[0.2; 6]);
        engine.request_flush();
        let target = engine.flush_target_write_index.load(Ordering::Acquire);
        assert_eq!(target, 2);
        assert!(target < read, "test must cross the raw-index wrap");

        engine.enqueue_output_samples(&[0.9; 2]);
        let mut out = [0.0f32; 4];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 2);
        assert!(out[..2].iter().all(|&s| (s - 0.9).abs() < 0.001));
        assert!(out[2..].iter().all(|&s| s == 0.0));
    }

    /// When the consumer has already consumed past the flush boundary
    /// (via normal playback in previous callbacks), `check_flush` must
    /// detect this and discard nothing — the boundary belongs to an
    /// epoch whose samples are already gone.
    #[test]
    fn flush_boundary_already_passed_discards_nothing() {
        use ringbuf::traits::{Consumer, Observer};

        const CAP: usize = 16;
        let (engine, mut consumer) = AudioEngine::new(CAP);
        engine.set_output_format(48_000, 2);

        engine.enqueue_output_samples(&[0.2; 6]);
        engine.request_flush();
        engine.enqueue_output_samples(&[0.4; 4]);

        for _ in 0..10 {
            assert!(consumer.consumer.try_pop().is_some());
        }
        assert_eq!(consumer.consumer.occupied_len(), 0);

        engine.enqueue_output_samples(&[0.8; 4]);
        let read = consumer.consumer.read_index();
        let target = engine.flush_target_write_index.load(Ordering::Acquire);
        let occupied = consumer.consumer.occupied_len();
        let modulus = 2 * consumer.consumer.capacity().get();
        let distance = (target + modulus - read) % modulus;
        assert!(
            distance > occupied,
            "pending boundary must be behind the current occupied region"
        );

        let mut out = [0.0f32; 6];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 4);
        assert!(out[..4].iter().all(|&s| (s - 0.8).abs() < 0.001));
        assert!(out[4..].iter().all(|&s| s == 0.0));
    }

    // ---------------------------------------------------------------------------
    // Concurrent stress test with deterministic channel/barrier coordination.
    // Producer enqueues and requests flushes while the consumer callback runs
    // on another thread.  No sleep, no busy-spin — the consumer signals drain
    // completion via an mpsc channel.
    // ---------------------------------------------------------------------------

    #[test]
    fn concurrent_enqueue_flush_callback_occupancy_bounded_and_flush_semantics() {
        use std::{sync::mpsc, thread};

        enum Command {
            Callback,
            Stop,
        }

        const CAP: usize = 32;
        let (engine, consumer) = AudioEngine::new(CAP);
        engine.set_output_format(48_000, 2);

        let (command_tx, command_rx) = mpsc::channel::<Command>();
        let (result_tx, result_rx) = mpsc::channel::<(usize, [f32; 8])>();
        let consumer_handle = thread::spawn(move || {
            let mut consumer = consumer;
            while let Ok(command) = command_rx.recv() {
                match command {
                    Command::Callback => {
                        let mut output = [0.0f32; 8];
                        let filled = consumer.fill_output(&mut output);
                        result_tx.send((filled, output)).unwrap();
                    }
                    Command::Stop => break,
                }
            }
        });

        for round in 0..40 {
            engine.enqueue_output_samples(&[0.1; 6]);
            engine.request_flush();
            let post_value = 0.5 + round as f32 / 1000.0;
            engine.enqueue_output_samples(&[post_value; 2]);
            assert!(engine.ring_occupied_len() <= CAP);

            command_tx.send(Command::Callback).unwrap();
            let (filled, output) = result_rx.recv().unwrap();
            assert_eq!(filled, 2, "round {round}");
            assert!(
                output[..2]
                    .iter()
                    .all(|&sample| (sample - post_value).abs() < 0.000_01),
                "round {round}: post-boundary samples were not preserved"
            );
            assert!(output[2..].iter().all(|&sample| sample == 0.0));
            assert_eq!(engine.ring_occupied_len(), 0, "round {round}");
        }

        command_tx.send(Command::Stop).unwrap();
        consumer_handle.join().expect("consumer thread panicked");
    }

    // ---------------------------------------------------------------------------
    // Frame-safety and scheduler regression tests.
    // ---------------------------------------------------------------------------

    /// After Phase 2 frame-safe enqueue, odd-length input for stereo output
    /// is rejected: only complete frames are accepted, and the trailing
    /// sample is counted as overflow.
    #[test]
    fn enqueue_rejects_partial_stereo_frame() {
        let (engine, _consumer) = AudioEngine::new(16);
        engine.set_output_format(48_000, 2);
        // Push 3 samples (= 1.5 stereo frames). A frame-aware API would
        // reject the odd sample or pad to an even count.
        let pushed = engine.enqueue_output_samples(&[0.1, 0.2, 0.3]);
        // Desired invariant: for 2-channel output the enqueued count is even.
        assert_eq!(
            pushed % 2,
            0,
            "frame-safe invariant: sample count ({pushed}) must be even for stereo output"
        );
        let s = engine.status();
        assert_eq!(
            s.queued_samples % 2,
            0,
            "frame-safe invariant: queued_samples ({}) must be even for stereo; \
             odd count means a partial frame was accepted",
            s.queued_samples
        );
    }

    /// Regression: `Player` is now control-only — it has no audio-frame queue
    /// and cannot accumulate duplicate PCM via `push_frame`.
    ///
    /// In a prior architecture the RTP path fed decoded audio into *both*
    /// `Player::push_frame` (timing-aware frame buffer) and
    /// `AudioEngine::enqueue_interleaved_for_output` (the ring buffer that
    /// `fill_output` actually reads from), creating a duplicate queue that was
    /// never drained.
    ///
    /// Phase 3 removed the frame queue from Player entirely.  This test proves:
    ///  * `Player` no longer exposes a `push_frame` method (`SharedPlayer`
    ///    also lacks it).
    ///  * All queue-related `PlayerStatus` fields report zero/`None` even after
    ///    a start.
    ///  * The `AudioEngine` pipeline is completely independent of the Player.
    #[test]
    fn player_is_control_only_and_cannot_accumulate_audio_queue() {
        let player = crate::player::SharedPlayer::new();
        player.start(11025);
        let s = player.status();

        // --- Queue fields are always zero / None ---
        assert_eq!(s.buffered_frames, 0, "no frame buffer exists");
        assert_eq!(s.total_frames_played, 0);
        assert_eq!(s.underruns, 0);
        assert_eq!(s.late_frames_dropped, 0);
        assert!(s.timestamp_offset.is_none());

        // --- Transport-only state is observable ---
        assert!(s.playing);
        assert_eq!(s.latency_frames, 11025);
        assert_eq!(s.sample_rate, 44100);

        // --- AudioEngine is independent — fill_output reads its own ring buffer ---
        let (engine, mut consumer) = AudioEngine::new(2048);
        engine.set_output_format(48_000, 2);
        engine.enqueue_interleaved_for_output(&[0.5; 960], 48_000, 2);

        let mut out = [0.0f32; 480];
        let filled = consumer.fill_output(&mut out);
        assert!(filled > 0, "AudioEngine pipeline works independently");

        // Player queue counters are untouched by audio-engine activity.
        let s2 = player.status();
        assert_eq!(s2.buffered_frames, 0);
        assert_eq!(s2.total_frames_played, 0);
        assert_eq!(s2.underruns, 0);
        assert_eq!(s2.late_frames_dropped, 0);
    }

    struct Ap2PrimingTestDecoder;

    impl crate::playout::scheduler::PacketDecoder for Ap2PrimingTestDecoder {
        fn reset(&mut self) {}

        fn decode(
            &mut self,
            _packet: &crate::playout::packet::TimedPacket,
        ) -> anyhow::Result<crate::playout::scheduler::DecodedAudio> {
            Ok(crate::playout::scheduler::DecodedAudio {
                // 352 stereo frames at 48 kHz is about 7.3 ms.
                samples: vec![0.25; 352 * 2],
                sample_rate: 48_000,
                channels: 2,
            })
        }

        fn conceal_missing(
            &mut self,
            _expected_sequence: u64,
            _last_packet: Option<&crate::playout::packet::TimedPacket>,
        ) -> anyhow::Result<crate::playout::scheduler::DecodedAudio> {
            self.decode(&_last_packet.cloned().unwrap_or_else(|| {
                crate::playout::packet::TimedPacket::new(
                    crate::playout::packet::StreamProtocol::AirPlay2Buffered,
                    0,
                    0,
                    0,
                    0x1500_0000,
                    Some(crate::codec::AudioFormat::Alac48000S24Stereo),
                    bytes::Bytes::new(),
                    std::time::Instant::now(),
                    false,
                    0,
                )
            }))
        }
    }

    async fn wait_for_playout_status(
        handle: &crate::playout::scheduler::PlayoutHandle,
        predicate: impl Fn(&crate::playout::scheduler::SchedulerStatus) -> bool,
    ) -> crate::playout::scheduler::SchedulerStatus {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let status = handle.status();
                if predicate(&status) {
                    return status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("playout status did not reach expected state")
    }

    #[tokio::test]
    async fn ap2_playback_waits_for_start_watermark() {
        use crate::playout::{
            packet::{StreamProtocol, TimedPacket},
            scheduler::{PlayoutState, SchedulerConfig, spawn_playout_service},
        };

        let (engine, mut consumer) = AudioEngine::new_for_output(48_000, 2, 100);
        let config = SchedulerConfig {
            start_watermark_ms: 20,
            low_watermark_ms: 10,
            target_watermark_ms: 15,
            jitter_capacity_packets: 32,
            reorder_grace_ms: 20,
        };
        let (handle, task) = spawn_playout_service(config, Ap2PrimingTestDecoder, engine.clone());
        handle.start();
        wait_for_playout_status(&handle, |status| status.state == PlayoutState::Priming).await;
        let mut callback = [0.0f32; 128];
        consumer.fill_output(&mut callback);
        assert!(!engine.is_flush_pending());

        let packet = |seq: u64| {
            TimedPacket::new(
                StreamProtocol::AirPlay2Buffered,
                seq,
                seq as u32,
                seq as u32 * 352,
                0x1500_0000,
                Some(crate::codec::AudioFormat::Alac48000S24Stereo),
                bytes::Bytes::from_static(&[0; 16]),
                std::time::Instant::now(),
                false,
                0,
            )
        };

        assert_eq!(
            handle.send_ap2(packet(0)).await,
            crate::playout::ingress::IngressResult::Accepted
        );
        let after_one =
            wait_for_playout_status(&handle, |status| status.diag.decoded_blocks >= 1).await;
        assert_eq!(after_one.state, PlayoutState::Priming);
        assert!(after_one.queued_ms < 20);
        assert!(!engine.is_playback_enabled());

        for seq in 1..=2 {
            assert_eq!(
                handle.send_ap2(packet(seq)).await,
                crate::playout::ingress::IngressResult::Accepted
            );
        }
        let primed =
            wait_for_playout_status(&handle, |status| status.state == PlayoutState::Playing).await;
        assert!(primed.queued_ms >= 20);
        assert!(engine.is_playback_enabled());

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("playout service shutdown timed out")
            .expect("playout service panicked");
    }

    #[test]
    fn all_or_nothing_enqueue_is_atomic_between_concurrent_producers() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (engine, _consumer) = AudioEngine::new(40);
        engine.set_output_format(48_000, 2); // 20 frames total.

        // Leave room for exactly one of two eight-frame blocks.
        let initial = vec![0.1f32; 10 * 2];
        assert_eq!(
            engine.try_enqueue_output_frames_all_or_nothing(&initial, true),
            (10, 10)
        );

        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for value in [0.2f32, 0.3f32] {
            let engine = engine.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let block = vec![value; 8 * 2];
                barrier.wait();
                engine.try_enqueue_output_frames_all_or_nothing(&block, true)
            }));
        }
        barrier.wait();

        let results: Vec<(usize, usize)> = handles
            .into_iter()
            .map(|handle| handle.join().expect("producer thread panicked"))
            .collect();
        assert!(results.iter().all(|&(requested, _)| requested == 8));
        assert_eq!(
            results.iter().map(|&(_, accepted)| accepted).sum::<usize>(),
            8,
            "exactly one complete producer block must fit"
        );
        assert_eq!(engine.status().queued_frames, 18);
        assert_eq!(engine.status().producer_overflow_samples, 0);
    }

    // ---------------------------------------------------------------------------
    // Phase 6A1 — set_output_gate vs set_playback_enabled semantics.
    // ---------------------------------------------------------------------------

    /// `set_output_gate(false)` must not flush: queued samples must survive
    /// and be output once the gate is re-enabled.
    #[test]
    fn set_output_gate_off_preserves_queued_samples() {
        let (engine, mut consumer) = AudioEngine::new(128);
        engine.set_output_format(48_000, 2);

        // Enqueue audio with playback enabled.
        engine.enqueue_output_samples(&[0.42; 30]);
        assert_eq!(engine.ring_occupied_len(), 30);

        // Gate off — no flush.
        let flushes_before = engine.flush_count.load(Ordering::Acquire);
        engine.set_output_gate(false);
        assert_eq!(
            engine.flush_count.load(Ordering::Acquire),
            flushes_before,
            "set_output_gate(false) must not request a flush"
        );
        // Samples are still in the ring.
        assert_eq!(engine.ring_occupied_len(), 30);

        // A callback while gated off must output silence.
        let mut out = [0.0f32; 20];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 0, "gated-off callback must output silence");
        assert!(out.iter().all(|&s| s == 0.0));
        // Samples are still preserved.
        assert_eq!(engine.ring_occupied_len(), 30);

        // Gate back on — no flush.
        engine.set_output_gate(true);
        assert_eq!(engine.ring_occupied_len(), 30);

        // Now the callback must output the preserved samples.
        let mut out2 = [0.0f32; 40];
        let filled2 = consumer.fill_output(&mut out2);
        assert_eq!(filled2, 30, "all 30 preserved samples must be output");
        assert!(
            out2[..30].iter().all(|&s| (s - 0.42).abs() < 0.001),
            "preserved samples must be the original 0.42 values"
        );
        assert!(out2[30..].iter().all(|&s| s == 0.0));
    }

    /// `set_playback_enabled(false)` must request a flush so that stale
    /// audio is discarded.  This is the existing contract that callers
    /// depend on for stream-switch / stop semantics.
    #[test]
    fn set_playback_enabled_false_requests_flush() {
        let (engine, mut consumer) = AudioEngine::new(128);
        engine.set_output_format(48_000, 2);

        engine.enqueue_output_samples(&[0.99; 20]);
        let flushes_before = engine.flush_count.load(Ordering::Acquire);
        engine.set_playback_enabled(false);

        assert!(
            engine.flush_count.load(Ordering::Acquire) > flushes_before,
            "set_playback_enabled(false) must request a flush"
        );
        // Gate is off.
        assert!(!engine.is_playback_enabled());

        // The flush epoch is now pending.  The callback drains the old
        // samples when it processes the flush.
        let mut out = [0.0f32; 30];
        let filled = consumer.fill_output(&mut out);
        // Flush drained the 20 pre-disable samples; output is silence.
        assert_eq!(filled, 0, "flush drained stale samples; output is silence");
        assert!(out.iter().all(|&s| s == 0.0));
        assert_eq!(engine.ring_occupied_len(), 0);

        // Re-enable, enqueue new data — must play normally.
        engine.set_playback_enabled(true);
        engine.enqueue_output_samples(&[0.11; 10]);
        let mut out2 = [0.0f32; 10];
        let filled2 = consumer.fill_output(&mut out2);
        assert_eq!(filled2, 10);
        assert!(out2.iter().all(|&s| (s - 0.11).abs() < 0.001));
    }

    /// `set_output_gate(true)` (re-enabling) does not request a flush
    /// either — it should never touch the flush epoch.
    #[test]
    fn set_output_gate_true_never_flushes() {
        let (engine, _consumer) = AudioEngine::new(64);
        let flushes_before = engine.flush_count.load(Ordering::Acquire);

        engine.set_output_gate(false);
        assert_eq!(
            engine.flush_count.load(Ordering::Acquire),
            flushes_before,
            "set_output_gate(false) must not flush"
        );

        engine.set_output_gate(true);
        assert_eq!(
            engine.flush_count.load(Ordering::Acquire),
            flushes_before,
            "set_output_gate(true) must not flush"
        );
    }

    /// Gate-off / gate-on cycle preserves samples enqueued *while* gated
    /// off (the unchecked-enqueue path used during priming).
    #[test]
    fn gate_cycle_preserves_samples_enqueued_while_gated_off() {
        let (engine, mut consumer) = AudioEngine::new(256);
        engine.set_output_format(48_000, 2);

        // Start with some audio playing.
        engine.enqueue_output_samples(&[0.5; 40]);
        let mut out = [0.0f32; 20];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 20);
        assert!(out.iter().all(|&s| (s - 0.5).abs() < 0.001));
        // 20 samples remain in ring.

        // Gate off (no flush).
        engine.set_output_gate(false);

        // While gated off, priming samples arrive (unchecked path).
        let priming = vec![0.77; 60];
        let pushed = engine.enqueue_output_samples_unchecked(&priming);
        assert_eq!(pushed, 60);

        // Gate back on.
        engine.set_output_gate(true);

        // The 20 old samples + 60 priming = 80 should all be there.
        let mut out2 = [0.0f32; 100];
        let filled2 = consumer.fill_output(&mut out2);
        assert_eq!(filled2, 80);
        // First 20 are old 0.5 values.
        assert!(out2[..20].iter().all(|&s| (s - 0.5).abs() < 0.001));
        // Next 60 are priming 0.77 values.
        assert!(out2[20..80].iter().all(|&s| (s - 0.77).abs() < 0.001));
        assert!(out2[80..].iter().all(|&s| s == 0.0));
    }

    // ---------------------------------------------------------------------------
    // Phase 2 — frame-safe enqueue, bulk writes, and duration sizing tests.
    // ---------------------------------------------------------------------------

    /// Four-channel output: incomplete trailing frame (< 4 samples) must be
    /// rejected and counted as overflow.
    #[test]
    fn enqueue_rejects_partial_4_channel_frame() {
        let (engine, _consumer) = AudioEngine::new(32);
        engine.set_output_format(48_000, 4);
        // 7 samples = 1 complete 4-ch frame + 3 trailing
        let result = engine.enqueue_output_frames(&[0.1; 7]);
        assert_eq!(result.channels, 4);
        assert_eq!(result.requested_frames, 1); // floor(7/4)
        assert_eq!(result.accepted_frames, 1);
        assert_eq!(result.rejected_frames, 0);
        assert_eq!(result.trailing_samples, 3);
        assert_eq!(result.requested_samples(), 7); // 1*4 + 3
        assert_eq!(result.accepted_samples(), 4);
        assert_eq!(result.rejected_samples(), 3); // 0*4 + 3

        let s = engine.status();
        assert_eq!(s.queued_samples, 4);
        // The 3 trailing samples are counted as overflow.
        assert_eq!(s.producer_overflow_samples, 3);
    }

    /// When ring-buffer vacancy is smaller than one complete frame, no
    /// samples are accepted and everything is counted as overflow.
    #[test]
    fn vacancy_smaller_than_one_frame_rejects_all() {
        // Capacity 3 samples, stereo → 1 complete frame (2 samples).
        let (engine, _consumer) = AudioEngine::new(3);
        engine.set_output_format(48_000, 2);
        // Fill with 1 frame (2 samples) → vacancy = 1 sample < 1 frame.
        assert_eq!(engine.enqueue_output_samples(&[1.0, 2.0]), 2);
        assert_eq!(engine.available_frames(), 0);
        assert_eq!(engine.available_samples(), 0);

        // Try to push 2 frames (4 samples) → rejected entirely.
        let result = engine.enqueue_output_frames(&[3.0; 4]);
        assert_eq!(result.requested_frames, 2);
        assert_eq!(result.accepted_frames, 0);
        assert_eq!(result.rejected_frames, 2);
        assert_eq!(engine.status().producer_overflow_samples, 4);
    }

    /// Bulk enqueue preserves sample order when pushing multiple frames at once.
    #[test]
    fn bulk_enqueue_preserves_sample_order() {
        let (engine, mut consumer) = AudioEngine::new(1024);
        engine.set_output_format(48_000, 2);
        // Push 100 stereo frames in one call.
        let mut input = Vec::with_capacity(200);
        for i in 0..200 {
            input.push(i as f32 * 0.01);
        }
        let result = engine.enqueue_output_frames(&input);
        assert_eq!(result.accepted_frames, 100);
        assert_eq!(result.rejected_frames, 0);

        // Read back — order must be preserved.
        let mut out = vec![0.0f32; 200];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 200);
        for (i, &s) in out.iter().enumerate() {
            assert!(
                (s - i as f32 * 0.01).abs() < 0.0001,
                "sample {i}: expected {}, got {s}",
                i as f32 * 0.01
            );
        }
    }

    /// Duration-based sizing at 44.1 kHz stereo with 150 ms → ceil(44100*150/1000)*2.
    #[test]
    fn duration_sizing_44100_stereo_150ms() {
        let (engine, _consumer) = AudioEngine::new_for_output(44_100, 2, 150);
        let s = engine.status();
        assert_eq!(s.output_sample_rate, 44_100);
        assert_eq!(s.output_channels, 2);
        // ceil(44100 * 150 / 1000) * 2 = ceil(6615.0) * 2 = 6615 * 2 = 13230
        assert_eq!(s.capacity_samples, 13230);
        assert_eq!(s.capacity_frames, 6615);
    }

    /// Duration-based sizing at 48 kHz, 6-channel with 200 ms.
    #[test]
    fn duration_sizing_48000_6ch_200ms() {
        let (engine, _consumer) = AudioEngine::new_for_output(48_000, 6, 200);
        let s = engine.status();
        assert_eq!(s.output_sample_rate, 48_000);
        assert_eq!(s.output_channels, 6);
        // ceil(48000 * 200 / 1000) * 6 = ceil(9600.0) * 6 = 9600 * 6 = 57600
        assert_eq!(s.capacity_samples, 57600);
        assert_eq!(s.capacity_frames, 9600);
    }

    /// Duration sizing with a sub-millisecond rounding case.
    #[test]
    fn duration_sizing_rounds_up_to_next_frame() {
        // 48 kHz, 2 ch, 1 ms → ceil(48) * 2 = 96
        let (engine, _consumer) = AudioEngine::new_for_output(48_000, 2, 1);
        let s = engine.status();
        assert_eq!(s.capacity_samples, 96);
        assert_eq!(s.capacity_frames, 48);
    }

    /// new_for_output with zero or extreme values is clamped safely.
    #[test]
    fn duration_sizing_clamps_zero_values() {
        let (engine, _consumer) = AudioEngine::new_for_output(0, 0, 0);
        // Everything clamped to max(1).
        let s = engine.status();
        assert_eq!(s.output_sample_rate, 1);
        assert_eq!(s.output_channels, 1);
        assert_eq!(s.capacity_samples, 1); // ceil(1*1/1000)*1 = 1
    }

    /// EnqueueResult sample helpers return correct values including trailing samples.
    #[test]
    fn enqueue_result_sample_helpers() {
        let result = EnqueueResult {
            requested_frames: 10,
            accepted_frames: 7,
            rejected_frames: 3,
            trailing_samples: 2,
            channels: 4,
        };
        assert_eq!(result.requested_samples(), 42); // 10*4 + 2
        assert_eq!(result.accepted_samples(), 28); // 7*4
        assert_eq!(result.rejected_samples(), 14); // 3*4 + 2
    }

    /// available_frames and available_samples are channel-aligned.
    #[test]
    fn available_frames_is_channel_aligned() {
        let (engine, _consumer) = AudioEngine::new(10);
        engine.set_output_format(48_000, 2);

        // 10 samples capacity → 5 frames. All available.
        assert_eq!(engine.available_frames(), 5);
        assert_eq!(engine.available_samples(), 10);

        // Enqueue 4 samples (2 frames) → 3 frames remain.
        engine.enqueue_output_samples(&[1.0; 4]);
        assert_eq!(engine.available_frames(), 3);
        assert_eq!(engine.available_samples(), 6);
    }

    /// Stereo output: incomplete trailing sample must be reflected in
    /// the EnqueueResult and counted as overflow.
    #[test]
    fn enqueue_rejects_partial_stereo_frame_with_trailing() {
        let (engine, _consumer) = AudioEngine::new(16);
        engine.set_output_format(48_000, 2);
        // 5 samples = 2 complete stereo frames + 1 trailing
        let result = engine.enqueue_output_frames(&[0.1; 5]);
        assert_eq!(result.channels, 2);
        assert_eq!(result.requested_frames, 2);
        assert_eq!(result.accepted_frames, 2);
        assert_eq!(result.rejected_frames, 0);
        assert_eq!(result.trailing_samples, 1);
        assert_eq!(result.requested_samples(), 5); // 2*2 + 1
        assert_eq!(result.rejected_samples(), 1); // 0*2 + 1

        let s = engine.status();
        assert_eq!(s.queued_samples, 4);
        assert_eq!(s.producer_overflow_samples, 1);
    }

    /// new_for_output with u32::MAX / u16::MAX inputs must not panic,
    /// must allocate bounded channel-aligned capacity ≥ 1 frame.
    #[test]
    fn new_for_output_extreme_inputs_bounded() {
        let (engine, _consumer) = AudioEngine::new_for_output(u32::MAX, u16::MAX, u32::MAX);
        let s = engine.status();
        assert!(s.capacity_samples > 0);
        assert!(s.capacity_samples <= MAX_CAPACITY_SAMPLES);
        // Channel-aligned.
        assert_eq!(s.capacity_samples % s.output_channels.max(1) as usize, 0);
    }

    /// new_for_output with an enormous fifo_ms clamps to the
    /// MAX_PCM_FIFO_MS ceiling and does not exceed MAX_CAPACITY_SAMPLES.
    #[test]
    fn new_for_output_max_fifo_clamped() {
        // 10_000 ms at 192 kHz stereo → would be huge but must be capped.
        let (engine, _consumer) = AudioEngine::new_for_output(192_000, 2, 50_000);
        let s = engine.status();
        assert!(s.capacity_samples > 0);
        assert!(s.capacity_samples <= MAX_CAPACITY_SAMPLES);
        assert_eq!(s.capacity_samples % 2, 0);
    }

    /// new_for_output with MAX_PCM_FIFO_MS at max channel count is bounded.
    #[test]
    fn new_for_output_max_channels_bounded() {
        let (engine, _consumer) = AudioEngine::new_for_output(384_000, u16::MAX, MAX_PCM_FIFO_MS);
        let s = engine.status();
        assert!(s.capacity_samples > 0);
        assert!(s.capacity_samples <= MAX_CAPACITY_SAMPLES);
        assert_eq!(s.capacity_samples % s.output_channels.max(1) as usize, 0);
    }
}
