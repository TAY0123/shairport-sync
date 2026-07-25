use anyhow::Context;
use cpal::{
    I24, SampleFormat, Stream, U24,
    traits::{DeviceTrait, HostTrait, StreamTrait},
};
use parking_lot::Mutex;
use ringbuf::{
    HeapRb,
    traits::{Consumer, Producer, Split},
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

use crate::codec;
use crate::config::{AudioConfig, AudioHostName};

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

    pub fn start_output(
        &self,
        engine: &AudioEngine,
        mut consumer: AudioConsumer,
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
        let err_fn = |err| tracing::warn!(%err, "CPAL output stream error");
        let stream = match sample_format {
            SampleFormat::F32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [f32], _| {
                    consumer.fill_output(data);
                },
                err_fn,
                None,
            )?,
            SampleFormat::F64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [f64], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I8 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i8], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i16], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I24 => device.build_output_stream(
                &stream_config,
                move |data: &mut [I24], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i32], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::I64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i64], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U8 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u8], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u16], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U24 => device.build_output_stream(
                &stream_config,
                move |data: &mut [U24], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u32], _| fill_converted(data, &mut consumer),
                err_fn,
                None,
            )?,
            SampleFormat::U64 => device.build_output_stream(
                &stream_config,
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

    pub fn set_volume_db(&self, db: f64) {
        let gain = if db <= -144.0 {
            0.0
        } else {
            10.0f64.powf(db.clamp(-144.0, 0.0) / 20.0) as f32
        };
        self.volume_gain_bits
            .store(gain.to_bits(), Ordering::Release);
    }

    pub fn set_playback_enabled(&self, enabled: bool) {
        self.playback_enabled.store(enabled, Ordering::Release);
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
        let enqueued = self.enqueue_output_samples(&converted);
        (enqueued, total)
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

    pub fn enqueue_output_samples(&self, samples: &[f32]) -> usize {
        if !self.playback_enabled.load(Ordering::Acquire) {
            return 0;
        }
        self.enqueue_output_samples_unchecked(samples)
    }

    pub fn enqueue_output_samples_unchecked(&self, samples: &[f32]) -> usize {
        let mut producer = self.producer.lock();
        let pushed = samples
            .iter()
            .copied()
            .take_while(|sample| producer.try_push(*sample).is_ok())
            .count();
        let overflow = samples.len() - pushed;
        if overflow > 0 {
            self.producer_overflow_samples
                .fetch_add(overflow, Ordering::Release);
        }
        // Track max observed occupancy from the ring buffer's true occupancy.
        use ringbuf::traits::Observer;
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
        pushed
    }

    /// Number of samples that can still be enqueued without overflow.
    pub fn available_samples(&self) -> usize {
        self.capacity.saturating_sub(self.occupied_len())
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
    use crate::player::Player;

    // ---------------------------------------------------------------------------
    // Existing tests (preserved, adapted to new API)
    // ---------------------------------------------------------------------------

    #[test]
    fn audio_engine_preserves_sample_order_and_zeros_underrun() {
        let (engine, mut consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        assert_eq!(engine.enqueue_interleaved(&[0.1, 0.2, 0.3]), 3);
        let mut out = [1.0; 5];
        assert_eq!(consumer.fill_output(&mut out), 3);
        assert_eq!(out, [0.1, 0.2, 0.3, 0.0, 0.0]);
    }

    #[test]
    fn audio_engine_applies_volume_gain() {
        let (engine, mut consumer) = AudioEngine::new(4);
        engine.set_output_format(48_000, 2);
        engine.set_volume_db(-6.0);
        assert_eq!(engine.enqueue_interleaved(&[1.0]), 1);
        let mut out = [0.0; 1];
        consumer.fill_output(&mut out);
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
        // Only 5 fit (capacity), the rest overflow.
        assert_eq!(engine.enqueue_output_samples(&[0.1; 7]), 5);
        assert_eq!(engine.status().producer_overflow_samples, 2);
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
        engine.enqueue_output_samples(&[3.0; 15]);

        let mut out = [0.0f32; 32];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 15, "only the 15 post-flush samples survive");
        assert!(
            out[..15].iter().all(|&s| (s - 3.0).abs() < 0.001),
            "surviving samples are from the last batch (value 3.0)"
        );
        assert!(
            out[15..].iter().all(|&s| s.abs() < 0.001),
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

        engine.enqueue_output_samples(&[0.8; 3]);
        let read = consumer.consumer.read_index();
        let target = engine.flush_target_write_index.load(Ordering::Acquire);
        let occupied = consumer.consumer.occupied_len();
        let modulus = 2 * consumer.consumer.capacity().get();
        let distance = (target + modulus - read) % modulus;
        assert!(
            distance > occupied,
            "pending boundary must be behind the current occupied region"
        );

        let mut out = [0.0f32; 5];
        let filled = consumer.fill_output(&mut out);
        assert_eq!(filled, 3);
        assert!(out[..3].iter().all(|&s| (s - 0.8).abs() < 0.001));
        assert!(out[3..].iter().all(|&s| s == 0.0));
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
            engine.enqueue_output_samples(&[0.1; 5]);
            engine.request_flush();
            let post_value = 0.5 + round as f32 / 1000.0;
            engine.enqueue_output_samples(&[post_value; 3]);
            assert!(engine.ring_occupied_len() <= CAP);

            command_tx.send(Command::Callback).unwrap();
            let (filled, output) = result_rx.recv().unwrap();
            assert_eq!(filled, 3, "round {round}");
            assert!(
                output[..3]
                    .iter()
                    .all(|&sample| (sample - post_value).abs() < 0.000_01),
                "round {round}: post-boundary samples were not preserved"
            );
            assert!(output[3..].iter().all(|&sample| sample == 0.0));
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

    /// `enqueue_output_samples` operates on individual f32 samples, not audio
    /// frames. When the output is stereo an odd-length slice produces a
    /// dangling half-frame that the consumer reads as a lone left-channel
    /// sample followed by zero (underrun) for the right channel.
    ///
    /// Desired frame-safe invariant: for stereo output (2 channels), every
    /// enqueued sample count must be even — no partial frame is ever accepted.
    #[test]
    #[ignore = "bug: sample-oriented enqueue accepts an odd number of samples, producing a partial stereo frame"]
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

    /// The `Player` struct has a fully implemented `pull_samples()` method,
    /// but the audio output callback (`fill_output`) reads directly from the
    /// `AudioEngine` ring buffer — it never calls `Player::pull_samples`.
    /// The `Player` accumulates timing-aware frames from the RTP path but has
    /// no consumer in the production audio pipeline.
    ///
    /// Sentinel: this test encodes a desired invariant that cannot be satisfied
    /// until `Player::pull_samples` is wired into the audio output callback.
    /// It asserts that after audio output consumption, the Player's
    /// `total_frames_played` counter should advance.  Today, because
    /// `fill_output` bypasses the Player entirely, the counter stays at 0.
    #[test]
    #[ignore = "bug: Player::pull_samples has no call site in the audio output callback; the Player fills independently and is never drained"]
    fn player_not_integrated_with_audio_output() {
        // Set up a Player with a buffered audio frame (simulating the RTP path).
        let mut player = Player::new();
        player.start(100);
        player.push_frame(200, vec![0.8; 960], 48_000, 2);
        assert_eq!(
            player.status().buffered_frames,
            1,
            "precondition: Player has data"
        );

        // Create an AudioEngine — in the desired architecture the output
        // callback would pull from the Player and feed the engine.
        let (engine, mut consumer) = AudioEngine::new(2048);
        engine.set_output_format(48_000, 2);

        // The real output callback runs fill_output, which today pulls
        // directly from the engine's ring buffer, bypassing the Player.
        let mut out = [0.0f32; 480];
        consumer.fill_output(&mut out);

        // Sentinel assertion: in a correctly integrated system,
        // total_frames_played would have advanced because the output
        // callback consumed audio from the Player.  Because fill_output
        // ignores the Player, total_frames_played remains 0.
        assert!(
            player.status().total_frames_played > 0,
            "SENTINEL: total_frames_played = {} — Player::pull_samples must be \
             called from the audio output path.  Today fill_output reads the \
             AudioEngine ring buffer directly, so the Player is never drained.",
            player.status().total_frames_played
        );
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
}
