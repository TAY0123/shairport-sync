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
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
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

#[allow(dead_code)]
#[derive(Clone)]
pub struct AudioEngine {
    producer: Arc<Mutex<ringbuf::HeapProd<f32>>>,
    consumer: Arc<Mutex<ringbuf::HeapCons<f32>>>,
    queued_samples: Arc<AtomicUsize>,
    capacity: usize,
    output_format: Arc<Mutex<AudioOutputFormat>>,
    resampler_cache: Arc<Mutex<codec::ResamplerCache>>,
    volume_gain_bits: Arc<AtomicU32>,
    playback_enabled: Arc<AtomicBool>,
    /// Cumulative samples written as silence in the output callback due to ring-buffer underrun.
    callback_underrun_samples: Arc<AtomicUsize>,
    /// Cumulative samples the producer could not push because the ring buffer was full.
    producer_overflow_samples: Arc<AtomicUsize>,
    /// Number of times the output buffer was cleared (flush events).
    flush_count: Arc<AtomicUsize>,
    /// Maximum observed value of queued_samples (peak occupancy in samples).
    max_observed_occupancy: Arc<AtomicUsize>,
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

    pub fn start_output(&self, engine: AudioEngine) -> anyhow::Result<AudioOutput> {
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
                    engine.fill_output(data);
                },
                err_fn,
                None,
            )?,
            SampleFormat::F64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [f64], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::I8 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i8], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::I16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i16], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::I24 => device.build_output_stream(
                &stream_config,
                move |data: &mut [I24], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::I32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i32], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::I64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i64], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::U8 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u8], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::U16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u16], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::U24 => device.build_output_stream(
                &stream_config,
                move |data: &mut [U24], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::U32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u32], _| fill_converted(data, &engine),
                err_fn,
                None,
            )?,
            SampleFormat::U64 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u64], _| fill_converted(data, &engine),
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

fn fill_converted<T>(output: &mut [T], engine: &AudioEngine)
where
    T: cpal::Sample + cpal::FromSample<f32>,
{
    engine.fill_output_converted(output);
}

impl AudioEngine {
    pub fn new(capacity_samples: usize) -> Self {
        let rb = HeapRb::<f32>::new(capacity_samples);
        let (producer, consumer) = rb.split();
        Self {
            producer: Arc::new(Mutex::new(producer)),
            consumer: Arc::new(Mutex::new(consumer)),
            queued_samples: Arc::new(AtomicUsize::new(0)),
            capacity: capacity_samples,
            output_format: Arc::new(Mutex::new(AudioOutputFormat {
                sample_rate: 48_000,
                channels: 2,
            })),
            resampler_cache: Arc::new(Mutex::new(codec::ResamplerCache::new())),
            volume_gain_bits: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            playback_enabled: Arc::new(AtomicBool::new(true)),
            callback_underrun_samples: Arc::new(AtomicUsize::new(0)),
            producer_overflow_samples: Arc::new(AtomicUsize::new(0)),
            flush_count: Arc::new(AtomicUsize::new(0)),
            max_observed_occupancy: Arc::new(AtomicUsize::new(0)),
        }
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
            self.clear_output_samples();
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
        let new_occupancy = self.queued_samples.fetch_add(pushed, Ordering::Release) + pushed;
        // Track max observed occupancy (best-effort, not strictly monotonic under races)
        let mut prev = self.max_observed_occupancy.load(Ordering::Acquire);
        while new_occupancy > prev {
            match self.max_observed_occupancy.compare_exchange_weak(
                prev,
                new_occupancy,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => prev = current,
            }
        }
        pushed
    }

    pub fn available_samples(&self) -> usize {
        self.capacity - self.queued_samples.load(Ordering::Acquire)
    }

    pub fn fill_output(&self, output: &mut [f32]) -> usize {
        if !self.playback_enabled.load(Ordering::Acquire) {
            output.fill(0.0);
            return 0;
        }
        let gain = f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
        let mut consumer = self.consumer.lock();
        let mut filled = 0;
        let mut underrun = 0usize;
        for sample in output.iter_mut() {
            match consumer.try_pop() {
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
        if filled > 0 {
            self.queued_samples.fetch_sub(filled, Ordering::Release);
        }
        filled
    }

    fn fill_output_converted<T>(&self, output: &mut [T]) -> usize
    where
        T: cpal::Sample + cpal::FromSample<f32>,
    {
        if !self.playback_enabled.load(Ordering::Acquire) {
            for sample in output.iter_mut() {
                *sample = T::from_sample(0.0);
            }
            return 0;
        }
        let gain = f32::from_bits(self.volume_gain_bits.load(Ordering::Acquire));
        let mut consumer = self.consumer.lock();
        let mut filled = 0;
        let mut underrun = 0usize;
        for sample in output.iter_mut() {
            match consumer.try_pop() {
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
        if filled > 0 {
            self.queued_samples.fetch_sub(filled, Ordering::Release);
        }
        filled
    }

    pub fn clear_output_samples(&self) {
        let mut consumer = self.consumer.lock();
        while consumer.try_pop().is_some() {}
        self.queued_samples.store(0, Ordering::Release);
        self.flush_count.fetch_add(1, Ordering::Release);
    }

    pub fn status(&self) -> AudioEngineStatus {
        let output_format = *self.output_format.lock();
        let channels = output_format.channels.max(1) as usize;
        let rate = output_format.sample_rate.max(1) as u64;
        let queued = self.queued_samples.load(Ordering::Acquire);
        let capacity = self.capacity;
        let und_run = self.callback_underrun_samples.load(Ordering::Acquire);
        let over = self.producer_overflow_samples.load(Ordering::Acquire);
        let flushes = self.flush_count.load(Ordering::Acquire) as u64;
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
    /// This is the ground-truth value that `queued_samples` SHOULD match.
    fn ring_occupied_len(&self) -> usize {
        use ringbuf::traits::Observer;
        self.consumer.lock().occupied_len()
    }

    /// Directly overwrite the queued_samples counter (used to simulate the
    /// unconditional store(0) in clear_output_samples).
    fn set_queued_samples(&self, value: usize) {
        self.queued_samples.store(value, Ordering::Release);
    }

    /// Drain the consumer ring buffer without touching the queued_samples
    /// counter (used to simulate the first half of clear_output_samples).
    fn drain_consumer_silently(&self) {
        let mut consumer = self.consumer.lock();
        while consumer.try_pop().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::player::Player;

    // ---------------------------------------------------------------------------
    // Existing tests (preserved)
    // ---------------------------------------------------------------------------

    #[test]
    fn audio_engine_preserves_sample_order_and_zeros_underrun() {
        let engine = AudioEngine::new(4);
        assert_eq!(engine.enqueue_interleaved(&[0.1, 0.2, 0.3]), 3);
        let mut out = [1.0; 5];
        assert_eq!(engine.fill_output(&mut out), 3);
        assert_eq!(out, [0.1, 0.2, 0.3, 0.0, 0.0]);
    }

    #[test]
    fn audio_engine_applies_volume_gain() {
        let engine = AudioEngine::new(4);
        engine.set_volume_db(-6.0);
        assert_eq!(engine.enqueue_interleaved(&[1.0]), 1);
        let mut out = [0.0; 1];
        engine.fill_output(&mut out);
        assert!((out[0] - 0.501_187_2).abs() < 0.000_01);
    }

    #[test]
    fn audio_engine_drops_samples_when_playback_disabled() {
        let engine = AudioEngine::new(4);
        engine.set_playback_enabled(false);
        assert_eq!(engine.enqueue_interleaved(&[0.1, 0.2]), 0);
        let mut out = [1.0; 2];
        assert_eq!(engine.fill_output(&mut out), 0);
        assert_eq!(out, [0.0, 0.0]);
    }

    #[test]
    fn audio_engine_resamples_to_output_rate() {
        let engine = AudioEngine::new(256);
        engine.set_output_format(44_100, 2);
        let input = vec![0.0; 96];
        let (enqueued, total) = engine.enqueue_interleaved_for_output(&input, 48_000, 2);
        assert_eq!(enqueued, total);
        assert!(total < input.len());
    }

    #[test]
    fn audio_engine_expands_stereo_to_multichannel_output() {
        let engine = AudioEngine::new(16);
        engine.set_output_format(48_000, 4);
        let (enqueued, total) =
            engine.enqueue_interleaved_for_output(&[1.0, -1.0, 0.5, -0.5], 48_000, 2);
        assert_eq!(enqueued, 8);
        assert_eq!(total, 8);
        let mut out = [9.0; 8];
        engine.fill_output(&mut out);
        assert_eq!(out, [1.0, -1.0, 0.0, 0.0, 0.5, -0.5, 0.0, 0.0]);
    }

    // ---------------------------------------------------------------------------
    // New metric tests — non-failing, run with the normal test suite
    // ---------------------------------------------------------------------------

    #[test]
    fn status_derived_fields_match_output_format() {
        // 48000 Hz stereo → each frame = 2 samples, ~0.0208 ms per sample
        let engine = AudioEngine::new(960); // 480 frames = 10 ms
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
        let engine = AudioEngine::new(512);
        engine.set_output_format(44_100, 2);
        let s = engine.status();
        assert_eq!(s.queued_samples, 0);
        assert_eq!(s.queued_frames, 0);
        assert_eq!(s.queued_ms, 0);
        assert_eq!(s.capacity_ms, 5); // 512/2/44100*1000 = trunc(5.80) = 5
    }

    #[test]
    fn status_derived_handles_mono_output() {
        let engine = AudioEngine::new(441); // 10 ms at 44100 Hz mono
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
        let engine = AudioEngine::new(8);
        engine.set_output_format(48_000, 2);

        // Nothing enqueued — all output slots are underruns.
        let mut out = [0.0f32; 4];
        engine.fill_output(&mut out);
        assert_eq!(engine.status().callback_underrun_samples, 4);
        assert_eq!(engine.status().callback_underrun_frames, 2);

        // Second call accumulates.
        let mut out2 = [0.0f32; 6];
        engine.fill_output(&mut out2);
        assert_eq!(engine.status().callback_underrun_samples, 10);
    }

    #[test]
    fn callback_underrun_only_counts_playback_enabled() {
        let engine = AudioEngine::new(8);
        engine.set_playback_enabled(false);
        let mut out = [0.0f32; 4];
        engine.fill_output(&mut out);
        // Zeros produced because playback was disabled, not because of underrun.
        assert_eq!(engine.status().callback_underrun_samples, 0);
    }

    #[test]
    fn producer_overflow_counter_increments_on_full_buffer() {
        let engine = AudioEngine::new(4);
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
        let engine = AudioEngine::new(5);
        // 3 fit, 4 overflow.
        assert_eq!(engine.enqueue_output_samples(&[0.1; 7]), 5);
        assert_eq!(engine.status().producer_overflow_samples, 2);
    }

    #[test]
    fn flush_counter_increments_on_clear() {
        let engine = AudioEngine::new(8);
        engine.enqueue_interleaved(&[1.0; 4]);
        engine.clear_output_samples();
        assert_eq!(engine.status().flush_count, 1);
        engine.clear_output_samples();
        assert_eq!(engine.status().flush_count, 2);
    }

    #[test]
    fn max_occupancy_tracks_peak() {
        let engine = AudioEngine::new(100);
        engine.set_output_format(48_000, 2);

        engine.enqueue_output_samples(&[0.1; 30]);
        assert_eq!(engine.status().max_observed_occupancy, 30);

        engine.enqueue_output_samples(&[0.1; 50]);
        assert_eq!(engine.status().max_observed_occupancy, 80);

        // Drain some, then push less — peak should stay at 80.
        let mut out = [0.0f32; 40];
        engine.fill_output(&mut out);
        engine.enqueue_output_samples(&[0.1; 10]);
        assert_eq!(engine.status().max_observed_occupancy, 80);
    }

    #[test]
    fn status_serde_roundtrip_preserves_all_fields() {
        let engine = AudioEngine::new(1024);
        engine.set_output_format(96_000, 6);
        engine.enqueue_output_samples(&[0.5; 300]);
        let mut out = [0.0f32; 64];
        engine.fill_output(&mut out); // underrun: 300 enqueued, 64 drained
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
    // Known-defect tests — #[ignore] with precise reason strings.
    // These document current behaviour that is intentionally left unchanged
    // in Phase 0 (diagnostics only).
    // ---------------------------------------------------------------------------

    /// The occupancy counter can diverge when enqueue and clear interleave:
    /// `clear_output_samples()` drains the consumer under one mutex while the
    /// producer can concurrently push under a separate mutex, and the final
    /// `store(0)` unconditionally overwrites any concurrent increment.
    ///
    /// This test uses a deterministic three-step interleaving to simulate the
    /// race without threads or timing loops:
    ///   1. Drain the consumer silently (no counter change).
    ///   2. Push more samples through the producer (counter increments).
    ///   3. Apply the unconditional store(0) that `clear_output_samples` does.
    ///
    /// After these steps, the counter claims 0 but the ring buffer still holds
    /// the samples from step 2.  We detect the divergence by comparing the
    /// counter against `ring_occupied_len()` (the ground truth from the
    /// ringbuf Observer).
    #[test]
    #[ignore = "bug: queued_samples can diverge after interleaved enqueue/clear due to separate producer/consumer locks and unconditional store(0)"]
    fn occupancy_diverges_after_enqueue_clear_interleaving() {
        let engine = AudioEngine::new(1024);
        engine.enqueue_output_samples(&[1.0; 500]);

        // Step 1: drain consumer without touching the counter
        // (this is the first half of clear_output_samples).
        engine.drain_consumer_silently();

        // Step 2: a concurrent push arrives before the store(0)
        // — exactly the interleaving that causes the divergence.
        let pushed = engine.enqueue_output_samples(&[2.0; 200]);
        assert_eq!(
            pushed, 200,
            "all 200 samples should fit in the now-empty ring"
        );

        // Step 3: the unconditional store(0) from clear_output_samples
        // clobbers the increment from step 2.
        engine.set_queued_samples(0);

        // The counter now reports 0, but the ring buffer actually holds
        // the 200 samples pushed in step 2.
        let counter = engine.status().queued_samples;
        let actual = engine.ring_occupied_len();
        assert_eq!(
            counter, actual,
            "BUG: queued_samples counter ({counter}) diverged from actual ring \
             occupancy ({actual}) after interleaved enqueue/clear. \
             The store(0) in clear_output_samples clobbered a concurrent increment."
        );
    }

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
        let engine = AudioEngine::new(16);
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
        let engine = AudioEngine::new(2048);
        engine.set_output_format(48_000, 2);

        // The real output callback runs fill_output, which today pulls
        // directly from the engine's ring buffer, bypassing the Player.
        let mut out = [0.0f32; 480];
        engine.fill_output(&mut out);

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
        let engine = AudioEngine::new(4096);
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
