use anyhow::Context;
use cpal::{
    I24, SampleFormat, Stream, U24,
    traits::{DeviceTrait, HostTrait, StreamTrait},
};
use parking_lot::Mutex;
use ringbuf::{
    HeapRb,
    traits::{Consumer, Split},
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

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
    playback_enabled: Arc<AtomicBool>,
    callback_underrun_samples: Arc<AtomicUsize>,
    flush_epoch: Arc<AtomicU64>,
    /// The last flush epoch observed by this consumer. On mismatch the
    /// consumer drains the ring buffer up to `flush_target_write_index`
    /// before producing output.
    last_seen_flush_epoch: u64,
    /// Write-index boundary captured at the moment of the latest flush request.
    /// The consumer pops samples only up to (but not past) this index.
    flush_target_write_index: Arc<AtomicUsize>,
}

pub struct AudioOutput {
    _stream: Stream,
    pub sample_rate: u32,
    pub channels: u16,
    pub sample_format: SampleFormat,
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

    /// Select the CPAL device, create an [`AudioEngine`] with capacity
    /// derived from `config.audio.pcm_fifo_ms` and the actual sample rate /
    /// channel count, build the output stream, and return both.
    ///
    /// The [`AudioConsumer`] is created internally and moved into the
    /// output callback — the caller only receives the engine (for the
    /// producer path) and the output handle (to keep the stream alive).
    ///
    /// If the output stream cannot be created the engine is still returned
    /// so the application can continue (RTP enqueue will still function;
    /// samples will overflow once the ring is full).
    pub fn create_engine_and_output(&self) -> (AudioEngine, anyhow::Result<AudioOutput>) {
        // normalize() is idempotent — Config::load already normalized, but
        // tests may construct AudioConfig directly, so keep this safety net.
        let mut config = self.config.clone();
        config.normalize();

        let device_result = self.open_device();
        let (device, stream_config, sample_format) = match device_result {
            Ok(t) => t,
            Err(err) => {
                let (engine, _consumer) = AudioEngine::new_for_output(44100, 2, config.pcm_fifo_ms);
                return (engine, Err(err));
            }
        };

        let (engine, consumer) = AudioEngine::new_for_output(
            stream_config.sample_rate,
            stream_config.channels,
            config.pcm_fifo_ms,
        );

        tracing::info!(
            sample_rate = stream_config.sample_rate,
            channels = stream_config.channels,
            sample_format = ?sample_format,
            pcm_fifo_ms = config.pcm_fifo_ms,
            "CPAL output stream format"
        );

        let output = self.build_stream(device, &stream_config, sample_format, consumer);
        (engine, output)
    }

    /// Select the CPAL host and output device; return the device, its
    /// stream config, and sample format.
    fn open_device(&self) -> anyhow::Result<(cpal::Device, cpal::StreamConfig, SampleFormat)> {
        let host_id = match self.config.host {
            AudioHostName::Default => cpal::default_host().id(),
            host => host_to_cpal(host)
                .context("requested CPAL host is not available on this platform")?,
        };
        let host = cpal::host_from_id(host_id).context("failed to initialise CPAL host")?;
        let device = if let Some(selected) = &self.config.device {
            host.output_devices()?
                .find(|device| {
                    #[allow(deprecated)]
                    let name = device.name().unwrap_or_default();
                    format!("{host_id:?}:{name}") == *selected
                })
                .or_else(|| host.default_output_device())
        } else {
            host.default_output_device()
        }
        .context("no CPAL output device available")?;
        let (stream_config, sample_format) = choose_stream_config(&device)?;
        Ok((device, stream_config, sample_format))
    }

    /// Build and start the output stream, moving `consumer` into the
    /// real-time callback.
    fn build_stream(
        &self,
        device: cpal::Device,
        stream_config: &cpal::StreamConfig,
        sample_format: SampleFormat,
        mut consumer: AudioConsumer,
    ) -> anyhow::Result<AudioOutput> {
        let err_fn = |err| tracing::warn!(%err, "CPAL output stream error");
        let stream = match sample_format {
            SampleFormat::F32 => device.build_output_stream(
                stream_config,
                move |data: &mut [f32], _| {
                    consumer.fill_output(data);
                },
                err_fn,
                None,
            )?,
            SampleFormat::F64 => device.build_output_stream(
                stream_config,
                move |data: &mut [f64], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I8 => device.build_output_stream(
                stream_config,
                move |data: &mut [i8], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I16 => device.build_output_stream(
                stream_config,
                move |data: &mut [i16], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I24 => device.build_output_stream(
                stream_config,
                move |data: &mut [I24], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I32 => device.build_output_stream(
                stream_config,
                move |data: &mut [i32], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I64 => device.build_output_stream(
                stream_config,
                move |data: &mut [i64], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U8 => device.build_output_stream(
                stream_config,
                move |data: &mut [u8], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U16 => device.build_output_stream(
                stream_config,
                move |data: &mut [u16], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U24 => device.build_output_stream(
                stream_config,
                move |data: &mut [U24], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U32 => device.build_output_stream(
                stream_config,
                move |data: &mut [u32], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U64 => device.build_output_stream(
                stream_config,
                move |data: &mut [u64], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            sample_format => anyhow::bail!("unsupported CPAL sample format {sample_format:?}"),
        };
        stream.play()?;
        Ok(AudioOutput {
            _stream: stream,
            sample_rate: stream_config.sample_rate,
            channels: stream_config.channels,
            sample_format,
        })
    }

    /// Legacy API — create an output stream from a pre-existing engine and consumer.
    ///
    /// Prefer [`create_engine_and_output`] for new code; this method
    /// exists for backward compatibility and tests.
    pub fn start_output(
        &self,
        engine: &AudioEngine,
        consumer: AudioConsumer,
    ) -> anyhow::Result<AudioOutput> {
        let host_id = match self.config.host {
            AudioHostName::Default => cpal::default_host().id(),
            host => host_to_cpal(host)
                .context("requested CPAL host is not available on this platform")?,
        };
        let host = cpal::host_from_id(host_id).context("failed to initialise CPAL host")?;
        let device = if let Some(selected) = &self.config.device {
            host.output_devices()?
                .find(|device| {
                    #[allow(deprecated)]
                    let name = device.name().unwrap_or_default();
                    format!("{host_id:?}:{name}") == *selected
                })
                .or_else(|| host.default_output_device())
        } else {
            host.default_output_device()
        }
        .context("no CPAL output device available")?;

        let (stream_config, sample_format) = choose_stream_config(&device)?;
        engine.set_output_format(stream_config.sample_rate, stream_config.channels);
        tracing::info!(
            sample_rate = stream_config.sample_rate,
            channels = stream_config.channels,
            sample_format = ?sample_format,
            "CPAL output stream format"
        );
        self.build_stream(device, &stream_config, sample_format, consumer)
    }
}

fn fill_converted<T>(output: &mut [T], consumer: &mut AudioConsumer)
where
    T: cpal::Sample + cpal::FromSample<f32>,
{
    consumer.fill_output_converted(output);
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
            flush_target_write_index: Arc::clone(&flush_target_write_index),
            max_observed_occupancy: Arc::new(AtomicUsize::new(0)),
        };
        let audio_consumer = AudioConsumer {
            consumer,
            volume_gain_bits,
            playback_enabled,
            callback_underrun_samples,
            flush_epoch,
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

    /// Return the output channel count (≥ 1).
    fn output_channels(&self) -> u16 {
        self.output_format.lock().channels.max(1)
    }

    pub fn set_volume_db(&self, db: f64) {
        let gain = if db <= -144.0 {
            0.0
        } else {
            10.0f64.powf(db.clamp(-144.0, 0.0) / 20.0) as f32
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
        if input_sample_rate != output_format.sample_rate {
            let mut cache = self.resampler_cache.lock();
            cache.resample(
                &converted_channels,
                input_sample_rate,
                output_format.sample_rate,
                output_format.channels,
            )
        } else {
            converted_channels
        }
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
            return 0;
        }
        let gain = f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
        let mut filled = 0usize;
        let mut underrun = 0usize;
        for sample in output.iter_mut() {
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
            return 0;
        }
        let gain = f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
        let mut filled = 0usize;
        let mut underrun = 0usize;
        for sample in output.iter_mut() {
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
        assert!((out[0] - 0.501_187_2).abs() < 0.000_01);
        assert!((out[1] - 0.501_187_2).abs() < 0.000_01);
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
    // Known-defect tests — #[ignore] with precise reason strings.
    // These document current behaviour that is intentionally left unchanged
    // in earlier phases.
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

    /// In the AP2 buffered-audio path, `handle_buffered_stream` enables audio
    /// playback (`set_playback_enabled(true)`) as soon as the first decoded
    /// block is successfully enqueued (via `enqueue_decoded_frame_for_later`).
    /// This means the output callback can start pulling from a near-empty ring
    /// buffer after a single packet, causing an immediate underrun burst.
    ///
    /// Desired priming invariant: playback should not be enabled until at least
    /// `MIN_START_WATERMARK_MS` of audio is buffered.  One typical AP2 packet
    /// (~704 samples at 48 kHz stereo ≈ 7.3 ms) is far below any reasonable
    /// start watermark, so this test encodes the invariant and fails today.
    #[test]
    #[ignore = "bug: AP2 enables playback after only one decoded packet, before enough audio is buffered for glitch-free start"]
    fn ap2_playback_prematurely_enabled_after_one_packet() {
        // Simulate the enqueue_decoded_frame_for_later path: unchecked enqueue
        // while playback is disabled (the waiting_for_title state).
        let (engine, _consumer) = AudioEngine::new(4096);
        engine.set_playback_enabled(false);
        engine.set_output_format(48_000, 2);

        // One typical AP2 audio frame is ~352 frames × 2 channels = 704 samples.
        let one_frame = vec![0.25; 704];
        let pushed = engine.enqueue_output_samples_unchecked(&one_frame);
        assert!(pushed > 0, "first frame was enqueued");

        // Production code would then call set_playback_enabled(true) after
        // just one successful enqueue.  Desired: only enable when enough
        // audio is buffered to avoid immediate underruns.

        let status = engine.status();

        // Desired priming invariant: at least 20 ms of audio must be buffered
        // before enabling playback.  One packet is ~7.3 ms — far below this.
        const MIN_START_WATERMARK_MS: u64 = 20;
        assert!(
            status.queued_ms >= MIN_START_WATERMARK_MS,
            "priming invariant: need ≥ {MIN_START_WATERMARK_MS} ms buffered \
             before enabling playback, got only {:.1} ms from one packet. \
             This causes immediate underrun bursts on the first callback.",
            status.queued_ms as f64
        );
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
