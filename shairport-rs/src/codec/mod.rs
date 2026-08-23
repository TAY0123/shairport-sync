/// Unified audio decoder interface backed by Symphonia.
use anyhow::{Context, anyhow};
use rubato::audioadapter_buffers::direct::InterleavedSlice;
use rubato::{
    Async, FixedAsync, Resampler, SincInterpolationParameters, SincInterpolationType,
    WindowFunction, calculate_cutoff,
};
use symphonia::core::{
    audio::{AudioBufferRef, Layout, SampleBuffer},
    codecs::{CODEC_TYPE_AAC, CODEC_TYPE_ALAC, CodecParameters, Decoder, DecoderOptions},
    formats::Packet,
};

/// Supported audio formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioFormat {
    Alac44100S16Stereo,
    Alac48000S24Stereo,
    Aac44100F24Stereo,
    Aac48000F24Stereo,
    Aac48000F24_5_1,
    Aac48000F24_7_1,
}

impl AudioFormat {
    pub fn sample_rate(&self) -> u32 {
        match self {
            Self::Alac44100S16Stereo | Self::Aac44100F24Stereo => 44100,
            _ => 48000,
        }
    }

    pub fn channels(&self) -> u16 {
        match self {
            Self::Aac48000F24_5_1 => 6,
            Self::Aac48000F24_7_1 => 8,
            _ => 2,
        }
    }

    pub fn bits_per_sample(&self) -> u32 {
        match self {
            Self::Alac44100S16Stereo => 16,
            _ => 24,
        }
    }

    pub fn frames_per_packet(&self) -> usize {
        match self {
            Self::Alac44100S16Stereo | Self::Alac48000S24Stereo => 352,
            _ => 1024,
        }
    }

    /// Detect format from AP2 SSRC value.
    pub fn from_ssrc(ssrc: u32) -> Option<Self> {
        match ssrc {
            0x0000_FACE => Some(Self::Alac44100S16Stereo),
            0x1500_0000 => Some(Self::Alac48000S24Stereo),
            0x1600_0000 => Some(Self::Aac44100F24Stereo),
            0x1700_0000 => Some(Self::Aac48000F24Stereo),
            0x2700_0000 => Some(Self::Aac48000F24_5_1),
            0x2800_0000 => Some(Self::Aac48000F24_7_1),
            _ => None,
        }
    }

    /// Detect format from the AP2 `audioFormat` setup bitmask.
    pub fn from_ap2_audio_format(audio_format: u64) -> Option<Self> {
        match audio_format {
            0x0004_0000 => Some(Self::Alac44100S16Stereo),
            0x0020_0000 => Some(Self::Alac48000S24Stereo),
            0x0040_0000 => Some(Self::Aac44100F24Stereo),
            0x0080_0000 => Some(Self::Aac48000F24Stereo),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Alac44100S16Stereo => "ALAC/44100/S16_LE/2",
            Self::Alac48000S24Stereo => "ALAC/48000/S24_LE/2",
            Self::Aac44100F24Stereo => "AAC/44100/F24/2",
            Self::Aac48000F24Stereo => "AAC/48000/F24/2",
            Self::Aac48000F24_5_1 => "AAC/48000/F24/5.1",
            Self::Aac48000F24_7_1 => "AAC/48000/F24/7.1",
        }
    }

    pub fn is_alac(&self) -> bool {
        matches!(self, Self::Alac44100S16Stereo | Self::Alac48000S24Stereo)
    }

    pub fn is_playable(&self) -> bool {
        !matches!(self, Self::Aac48000F24_5_1 | Self::Aac48000F24_7_1)
    }
}

/// Result of decoding one audio frame.
pub struct DecodedFrame {
    pub samples: Vec<f32>,
    pub sample_rate: u32,
    pub channels: u16,
}

/// Stateful Symphonia decoder for one AirPlay audio format.
pub struct AudioDecoder {
    decoder: Box<dyn Decoder>,
    format: AudioFormat,
    frames_per_packet: usize,
    next_ts: u64,
}

impl AudioDecoder {
    pub fn new_for_format(
        format: AudioFormat,
        magic_cookie: Option<&[u8]>,
    ) -> anyhow::Result<Self> {
        if !format.is_playable() {
            return Err(anyhow!(
                "unsupported playback format {}",
                format.description()
            ));
        }

        if format.is_alac() {
            let cookie = magic_cookie.context("ALAC magic cookie is required")?;
            return Self::new_alac(
                format.bits_per_sample(),
                format.channels(),
                format.sample_rate(),
                format.frames_per_packet(),
                cookie,
            );
        }

        Self::new_aac(format)
    }

    pub fn new_alac(
        sample_size: u32,
        channels: u16,
        sample_rate: u32,
        frames_per_packet: usize,
        magic_cookie: &[u8],
    ) -> anyhow::Result<Self> {
        if magic_cookie.len() < 24 {
            return Err(anyhow!("ALAC magic cookie too short"));
        }

        let mut params = CodecParameters::new();
        params
            .for_codec(CODEC_TYPE_ALAC)
            .with_sample_rate(sample_rate)
            .with_bits_per_sample(sample_size)
            .with_bits_per_coded_sample(sample_size)
            .with_max_frames_per_packet(frames_per_packet as u64)
            .with_extra_data(Box::from(magic_cookie));
        apply_channel_layout(&mut params, channels)?;

        let format = match (sample_rate, sample_size) {
            (48_000, 24) => AudioFormat::Alac48000S24Stereo,
            _ => AudioFormat::Alac44100S16Stereo,
        };
        Self::from_params(format, frames_per_packet, params)
    }

    pub fn new_aac(format: AudioFormat) -> anyhow::Result<Self> {
        if !matches!(
            format,
            AudioFormat::Aac44100F24Stereo | AudioFormat::Aac48000F24Stereo
        ) {
            return Err(anyhow!(
                "unsupported AAC playback format {}",
                format.description()
            ));
        }

        let mut params = CodecParameters::new();
        params
            .for_codec(CODEC_TYPE_AAC)
            .with_sample_rate(format.sample_rate())
            .with_bits_per_sample(format.bits_per_sample())
            .with_max_frames_per_packet(format.frames_per_packet() as u64);
        apply_channel_layout(&mut params, format.channels())?;

        Self::from_params(format, format.frames_per_packet(), params)
    }

    fn from_params(
        format: AudioFormat,
        frames_per_packet: usize,
        params: CodecParameters,
    ) -> anyhow::Result<Self> {
        let decoder = symphonia::default::get_codecs()
            .make(&params, &DecoderOptions::default())
            .with_context(|| format!("failed to create decoder for {}", format.description()))?;
        Ok(Self {
            decoder,
            format,
            frames_per_packet,
            next_ts: 0,
        })
    }

    pub fn decode(&mut self, input: &[u8]) -> anyhow::Result<DecodedFrame> {
        if input.is_empty() {
            return Err(anyhow!("empty audio packet"));
        }

        let duration = self.frames_per_packet as u64;
        let packet = Packet::new_from_slice(0, self.next_ts, duration, input);
        self.next_ts = self.next_ts.wrapping_add(duration);

        let decoded = self
            .decoder
            .decode(&packet)
            .with_context(|| format!("Symphonia failed to decode {}", self.format.description()))?;
        interleaved_f32(decoded)
    }
}

fn apply_channel_layout(params: &mut CodecParameters, channels: u16) -> anyhow::Result<()> {
    let layout = match channels {
        1 => Layout::Mono,
        2 => Layout::Stereo,
        6 => Layout::FivePointOne,
        _ => return Err(anyhow!("unsupported channel count {channels}")),
    };
    params.with_channel_layout(layout);
    Ok(())
}

fn interleaved_f32(decoded: AudioBufferRef<'_>) -> anyhow::Result<DecodedFrame> {
    let spec = *decoded.spec();
    let frames = decoded.frames();
    let mut samples = SampleBuffer::<f32>::new(frames as u64, spec);
    samples.copy_interleaved_ref(decoded);
    Ok(DecodedFrame {
        samples: samples.samples().to_vec(),
        sample_rate: spec.rate,
        channels: spec.channels.count() as u16,
    })
}

/// Convert decoded multi-channel float samples to stereo (simple mixdown).
pub fn mixdown_to_stereo(samples: &[f32], input_channels: u16) -> Vec<f32> {
    if input_channels <= 2 {
        return samples.to_vec();
    }
    let frames = samples.len() / input_channels as usize;
    let mut stereo = Vec::with_capacity(frames * 2);
    for frame in 0..frames {
        let offset = frame * input_channels as usize;
        // Simple mix: FL/FR for stereo, mix center into both, mix LFE, spread surrounds
        let fl = samples[offset];
        let fr = samples.get(offset + 1).copied().unwrap_or(0.0);
        let center = samples.get(offset + 2).copied().unwrap_or(0.0);
        let lfe = samples.get(offset + 3).copied().unwrap_or(0.0);
        let bl = if input_channels >= 6 {
            samples.get(offset + 4).copied().unwrap_or(0.0)
        } else {
            0.0
        };
        let br = if input_channels >= 6 {
            samples.get(offset + 5).copied().unwrap_or(0.0)
        } else {
            0.0
        };

        let l = fl + center * 0.5 + lfe * 0.3 + bl * 0.5;
        let r = fr + center * 0.5 + lfe * 0.3 + br * 0.5;
        stereo.push(l);
        stereo.push(r);
    }
    stereo
}

/// Sample rate conversion cache with optional drift correction.
///
/// When [`correction_ppm`] is non-zero the resample ratio is adjusted
/// by that fraction even when the nominal input and output rates are
/// equal, allowing AP2 clock drift to be compensated.
///
/// The rubato `Async<f32>` resampler supports dynamic ratio changes via
/// [`Resampler::set_resample_ratio`] with a ramped transition, so small
/// drift-correction updates do not require rebuilding the resampler.
/// Rebuilding only occurs when the format or block shape changes
/// (input/output rate, channels, or input frame count).
///
/// [`correction_ppm`]: Self::set_correction_ppm
pub struct ResamplerCache {
    cached_input_rate: u32,
    cached_output_rate: u32,
    cached_channels: u16,
    cached_input_frames: usize,
    resampler: Option<Async<f32>>,

    /// Drift correction in parts per million applied on top of the
    /// nominal resample ratio.  Zero means no correction (passthrough
    /// when input == output rate).
    correction_ppm: f64,
    /// The ratio most recently set on the rubato resampler via
    /// [`set_resample_ratio`], or 0.0 if no resampler exists yet.
    resampler_ratio: f64,
}

impl ResamplerCache {
    pub fn new() -> Self {
        Self {
            cached_input_rate: 0,
            cached_output_rate: 0,
            cached_channels: 0,
            cached_input_frames: 0,
            resampler: None,
            correction_ppm: 0.0,
            resampler_ratio: 0.0,
        }
    }

    /// Set the drift correction in parts per million.
    ///
    /// A positive value speeds up the output relative to the input
    /// (compensates for a fast DAC).  A negative value slows it down.
    /// The change takes effect on the next [`resample`] call.
    ///
    /// [`resample`]: Self::resample
    pub fn set_correction_ppm(&mut self, ppm: f64) {
        self.correction_ppm = if ppm.is_finite() {
            ppm.clamp(-1_000.0, 1_000.0)
        } else {
            0.0
        };
    }

    pub fn resample(
        &mut self,
        input: &[f32],
        input_rate: u32,
        output_rate: u32,
        channels: u16,
    ) -> Vec<f32> {
        let ch = channels.max(1) as usize;
        let input_frames = input.len() / ch;
        if input_frames == 0 {
            return Vec::new();
        }

        let correction = self.correction_ppm / 1_000_000.0;
        let nominal_ratio = if input_rate == 0 || output_rate == 0 {
            1.0
        } else {
            output_rate as f64 / input_rate as f64
        };
        let effective_ratio = nominal_ratio * (1.0 + correction);

        // Fast path: no correction and rates already match → passthrough.
        if (effective_ratio - 1.0).abs() < 1e-12 {
            // Correction is effectively zero and rates equal → no resampling needed.
            if self.resampler.is_some() {
                self.resampler = None;
                self.resampler_ratio = 0.0;
            }
            return input.to_vec();
        }

        // Rebuild if format or block shape changed (rare).
        let shape_changed = self.cached_input_rate != input_rate
            || self.cached_output_rate != output_rate
            || self.cached_channels as usize != ch
            || self.cached_input_frames != input_frames;

        if shape_changed || self.resampler.is_none() {
            self.cached_input_rate = input_rate;
            self.cached_output_rate = output_rate;
            self.cached_channels = channels;
            self.cached_input_frames = input_frames;
            self.resampler = Self::build_resampler_with_ratio(effective_ratio, ch, input_frames);
            self.resampler_ratio = effective_ratio;
        } else if let Some(ref mut resampler) = self.resampler {
            // Dynamic ratio update via rubato's ramped set_resample_ratio.
            // This avoids rebuilding the entire resampler for small ppm changes.
            if (effective_ratio - self.resampler_ratio).abs() > 1e-12 {
                if resampler.set_resample_ratio(effective_ratio, true).is_err() {
                    // Fallback: rebuild if dynamic update fails (ratio out of bounds).
                    self.resampler =
                        Self::build_resampler_with_ratio(effective_ratio, ch, input_frames);
                }
                self.resampler_ratio = effective_ratio;
            }
        }

        self.resampler
            .as_mut()
            .and_then(|resampler| resample_with_rubato(resampler, input, ch, input_frames))
            .unwrap_or_else(|| {
                let adjusted_output_rate = if nominal_ratio > 0.0 {
                    (input_rate as f64 * effective_ratio).round() as u32
                } else {
                    output_rate
                }
                .max(1);
                linear_resample(input, input_rate, adjusted_output_rate, channels)
            })
    }

    /// Build a rubato `Async<f32>` resampler for the given effective ratio.
    fn build_resampler_with_ratio(
        effective_ratio: f64,
        channels: usize,
        input_frames: usize,
    ) -> Option<Async<f32>> {
        let window = WindowFunction::BlackmanHarris2;
        let sinc_len = 64;
        let params = SincInterpolationParameters {
            sinc_len,
            f_cutoff: calculate_cutoff::<f32>(sinc_len, window),
            interpolation: SincInterpolationType::Linear,
            oversampling_factor: 128,
            window,
        };

        Async::<f32>::new_sinc(
            effective_ratio,
            1.1,
            &params,
            input_frames,
            channels,
            FixedAsync::Input,
        )
        .ok()
    }
}

impl Default for ResamplerCache {
    fn default() -> Self {
        Self::new()
    }
}

fn resample_with_rubato(
    resampler: &mut Async<f32>,
    input: &[f32],
    channels: usize,
    input_frames: usize,
) -> Option<Vec<f32>> {
    let input = InterleavedSlice::new(input, channels, input_frames).ok()?;
    resampler
        .process(&input, 0, None)
        .ok()
        .map(|output| output.take_data())
}

/// Fallback sample rate conversion (linear interpolation).
fn linear_resample(input: &[f32], input_rate: u32, output_rate: u32, channels: u16) -> Vec<f32> {
    if input_rate == output_rate || input_rate == 0 || output_rate == 0 {
        return input.to_vec();
    }
    let ratio = output_rate as f64 / input_rate as f64;
    let input_frames = input.len() / channels.max(1) as usize;
    if input_frames == 0 {
        return Vec::new();
    }

    let output_frames = ((input_frames as f64 * ratio) as usize).clamp(1, 1_000_000);
    let mut output = vec![0.0f32; output_frames * channels as usize];

    for out_frame in 0..output_frames {
        let in_frame_f = out_frame as f64 / ratio;
        let in_frame = in_frame_f as usize;
        let frac = in_frame_f - in_frame as f64;
        let next_in = (in_frame + 1).min(input_frames - 1);

        for ch in 0..channels as usize {
            let in_idx = in_frame * channels as usize + ch;
            let next_idx = next_in * channels as usize + ch;
            let out_idx = out_frame * channels as usize + ch;
            let a = input.get(in_idx).copied().unwrap_or(0.0);
            let b = input.get(next_idx).copied().unwrap_or(0.0);
            output[out_idx] = a + (b - a) * frac as f32;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_format_from_ssrc() {
        assert_eq!(
            AudioFormat::from_ssrc(0x0000_FACE),
            Some(AudioFormat::Alac44100S16Stereo)
        );
        assert_eq!(
            AudioFormat::from_ssrc(0x1500_0000),
            Some(AudioFormat::Alac48000S24Stereo)
        );
        assert_eq!(
            AudioFormat::from_ssrc(0x1600_0000),
            Some(AudioFormat::Aac44100F24Stereo)
        );
        assert_eq!(
            AudioFormat::from_ssrc(0x1700_0000),
            Some(AudioFormat::Aac48000F24Stereo)
        );
        assert_eq!(AudioFormat::from_ssrc(0x99999999), None);
    }

    #[test]
    fn surround_formats_are_recognized_but_not_playable() {
        assert_eq!(
            AudioFormat::from_ssrc(0x2700_0000),
            Some(AudioFormat::Aac48000F24_5_1)
        );
        assert_eq!(
            AudioFormat::from_ssrc(0x2800_0000),
            Some(AudioFormat::Aac48000F24_7_1)
        );
        assert!(!AudioFormat::Aac48000F24_5_1.is_playable());
        assert!(!AudioFormat::Aac48000F24_7_1.is_playable());
    }

    #[test]
    fn audio_format_from_ap2_setup_format() {
        assert_eq!(
            AudioFormat::from_ap2_audio_format(0x0080_0000),
            Some(AudioFormat::Aac48000F24Stereo)
        );
        assert_eq!(AudioFormat::from_ap2_audio_format(0x0000_0001), None);
    }

    #[test]
    fn mixdown_stereo_passthrough() {
        let input = vec![0.5, -0.5, 0.3, -0.3];
        let output = mixdown_to_stereo(&input, 2);
        assert_eq!(output, input);
    }

    #[test]
    fn mixdown_5_1_to_stereo() {
        // FL, FR, C, LFE, BL, BR
        let input = vec![1.0, -1.0, 0.5, 0.3, 0.2, -0.2];
        let output = mixdown_to_stereo(&input, 6);
        assert_eq!(output.len(), 2);
        // L = 1.0 + 0.5*0.5 + 0.3*0.3 + 0.2*0.5 = 1.0 + 0.25 + 0.09 + 0.10 = 1.44
        assert!((output[0] - 1.44).abs() < 0.01);
    }

    #[test]
    fn resample_same_rate_passthrough() {
        let input = vec![0.5, -0.5, 0.3, -0.3];
        let output = linear_resample(&input, 44100, 44100, 2);
        assert_eq!(output, input);
    }

    #[test]
    fn resample_changes_length() {
        let input = vec![0.0; 100];
        let output = linear_resample(&input, 44100, 48000, 2);
        // 100 samples at 44100 Hz = 50 frames
        // At 48000 Hz, 50 frames = 50 * 48000/44100 ≈ 54 frames = 108 samples
        assert!(output.len() > 100);
    }

    #[test]
    fn resampler_cache_doubles_48k_stereo_to_96k() {
        let mut cache = ResamplerCache::new();
        let input = vec![0.0; 2048];
        let output = cache.resample(&input, 48_000, 96_000, 2);
        let output_frames = output.len() / 2;
        assert!(
            output_frames.abs_diff(2048) <= 8,
            "native sinc delay must stay small, got {output_frames} frames"
        );
    }

    #[test]
    fn resampler_cache_does_not_pad_filtered_blocks_with_repeated_tail_frames() {
        let mut cache = ResamplerCache::new();
        cache.set_correction_ppm(300.0);
        let mut input = Vec::with_capacity(1024 * 2);
        for frame in 0..1024 {
            let sample = (frame as f32 * 0.013).sin();
            input.extend_from_slice(&[sample, -sample]);
        }

        let output = cache.resample(&input, 48_000, 48_000, 2);
        let left_tail = output
            .chunks_exact(2)
            .rev()
            .take(8)
            .map(|frame| frame[0])
            .collect::<Vec<_>>();

        assert!(
            left_tail
                .windows(2)
                .any(|pair| (pair[0] - pair[1]).abs() > 1e-6),
            "filtered output tail must not be extended by repeating one frame"
        );
    }

    #[test]
    fn resampler_cache_applies_fractional_correction_at_equal_nominal_rate() {
        let input = vec![0.25f32; 1_000 * 2];
        let mut faster = ResamplerCache::new();
        faster.set_correction_ppm(1_000.0);
        let mut faster_frames = 0usize;
        for _ in 0..10 {
            faster_frames += faster.resample(&input, 48_000, 48_000, 2).len() / 2;
        }
        assert!(faster_frames > 10_000);

        let mut slower = ResamplerCache::new();
        slower.set_correction_ppm(-1_000.0);
        let mut slower_frames = 0usize;
        for _ in 0..10 {
            slower_frames += slower.resample(&input, 48_000, 48_000, 2).len() / 2;
        }
        assert!(slower_frames < 10_000);
    }

    #[test]
    fn resampler_cache_sanitizes_non_finite_correction() {
        let input = vec![0.25f32; 128 * 2];
        let mut cache = ResamplerCache::new();
        cache.set_correction_ppm(f64::NAN);
        assert_eq!(cache.resample(&input, 48_000, 48_000, 2), input);
    }

    #[test]
    fn constructs_stereo_symphonia_decoders() {
        let alac_441 = alac_specific_config(AudioFormat::Alac44100S16Stereo);
        let alac_480 = alac_specific_config(AudioFormat::Alac48000S24Stereo);

        assert!(AudioDecoder::new_for_format(AudioFormat::Aac44100F24Stereo, None).is_ok());
        assert!(AudioDecoder::new_for_format(AudioFormat::Aac48000F24Stereo, None).is_ok());
        assert!(
            AudioDecoder::new_for_format(AudioFormat::Alac44100S16Stereo, Some(&alac_441)).is_ok()
        );
        assert!(
            AudioDecoder::new_for_format(AudioFormat::Alac48000S24Stereo, Some(&alac_480)).is_ok()
        );
        assert!(AudioDecoder::new_for_format(AudioFormat::Aac48000F24_5_1, None).is_err());
    }

    #[test]
    fn decoder_rejects_empty_packet() {
        let mut decoder = AudioDecoder::new_for_format(AudioFormat::Aac44100F24Stereo, None)
            .expect("AAC decoder should construct");
        assert!(decoder.decode(&[]).is_err());
    }

    fn alac_specific_config(format: AudioFormat) -> [u8; 24] {
        // Duplicated from airplay::playout_decoder for test convenience.
        let mut config = [0u8; 24];
        let fps = format.frames_per_packet() as u32;
        config[0..4].copy_from_slice(&fps.to_be_bytes());
        config[4] = 0;
        config[5] = format.bits_per_sample() as u8;
        config[6] = 40;
        config[7] = 10;
        config[8] = 14;
        config[9] = 2;
        config[10..12].copy_from_slice(&255u16.to_be_bytes());
        config[12..16].copy_from_slice(&0u32.to_be_bytes());
        config[16..20].copy_from_slice(&0u32.to_be_bytes());
        config[20..24].copy_from_slice(&format.sample_rate().to_be_bytes());
        config
    }
}
