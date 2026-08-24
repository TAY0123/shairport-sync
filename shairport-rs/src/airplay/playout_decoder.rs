//! AirPlay packet decoder — bridges shared [`AppState`] / per-packet format
//! metadata into the generic [`PacketDecoder`] trait.
//!
//! Classic AP1 streams carry format metadata inside the ANNOUNCE SDP
//! (stored in [`AppState`]).  AirPlay 2 buffered streams carry the
//! format on each [`TimedPacket`] as an [`AudioFormat`] field.
//!
//! [`AppState`]: crate::state::AppState
//! [`TimedPacket`]: crate::playout::packet::TimedPacket
//! [`AudioFormat`]: crate::codec::AudioFormat

use anyhow::{Context, anyhow};

use crate::codec;
use crate::playout::packet::{StreamProtocol, TimedPacket};
use crate::playout::scheduler::{DecodedAudio, PacketDecoder};
use crate::state::AppState;

/// Cache key that determines when the inner decoder must be re-created.
///
/// For AP1 the key captures every AppState field that influences the ALAC
/// decoder configuration, including the exact magic-cookie bytes so
/// that a new cookie (e.g. after a track transition) forces
/// reinitialisation.
///
/// For AP2 the key is the packet's [`AudioFormat`].
#[derive(Clone, Debug, Eq, PartialEq)]
enum DecoderKey {
    ClassicAp1 {
        sample_size: u32,
        channels: u16,
        sample_rate: u32,
        frames_per_packet: u32,
        /// Exact ALAC magic cookie bytes — owned so that
        /// `ensure_decoder` never re-reads AppState after key
        /// creation, avoiding hash collisions and state-change
        /// races.
        cookie: Vec<u8>,
    },
    AirPlay2Buffered {
        format: codec::AudioFormat,
    },
}

/// Generates a 24-byte ALAC magic cookie / specific-config blob for
/// Symphonia, matching the Apple ALAC bitstream.
///
/// All format-dependent fields (frames-per-packet, bits-per-sample,
/// sample rate) are read from the supplied [`AudioFormat`].
///
/// Layout:
///
/// | offset | size | description                           |
/// |--------|------|---------------------------------------|
/// | 0      | 4    | `frames_per_packet` (big-endian u32)  |
/// | 4      | 1    | 0x00                                  |
/// | 5      | 1    | `bits_per_sample`                     |
/// | 6      | 1    | 0x28 (40)                             |
/// | 7      | 1    | 0x0A (10)                             |
/// | 8      | 1    | 0x0E (14)                             |
/// | 9      | 1    | `channels`                            |
/// | 10–11  | 2    | 0x00, 0xFF (maxRun = 255, big-endian) |
/// | 12–15  | 4    | 0x00_00_00_00                         |
/// | 16–19  | 4    | 0x00_00_00_00                         |
/// | 20–23  | 4    | `sample_rate` (big-endian u32)        |
pub fn alac_specific_config(format: codec::AudioFormat) -> [u8; 24] {
    alac_specific_config_fields(
        format.frames_per_packet() as u32,
        format.bits_per_sample(),
        format.channels(),
        format.sample_rate(),
    )
}

/// Build a 24-byte ALAC magic cookie from explicit field values.
fn alac_specific_config_fields(
    frames_per_packet: u32,
    bits_per_sample: u32,
    channels: u16,
    sample_rate: u32,
) -> [u8; 24] {
    let mut config = [0u8; 24];
    config[0..4].copy_from_slice(&frames_per_packet.to_be_bytes());
    config[4] = 0;
    config[5] = bits_per_sample as u8;
    config[6] = 40;
    config[7] = 10;
    config[8] = 14;
    config[9] = channels as u8;
    // maxRun = 255 = 0x00FF (big-endian)
    config[10..12].copy_from_slice(&255u16.to_be_bytes());
    config[12..16].copy_from_slice(&0u32.to_be_bytes());
    config[16..20].copy_from_slice(&0u32.to_be_bytes());
    config[20..24].copy_from_slice(&sample_rate.to_be_bytes());
    config
}

/// Stateful packet decoder for AirPlay audio streams.
///
/// Owns a shared [`AppState`] for AP1 format metadata and an optional
/// inner [`codec::AudioDecoder`] that is lazily created and re-created
/// when the protocol or audio format changes.
pub struct AirPlayPacketDecoder {
    state: AppState,
    /// Current decoder and its cache key, or `None` if not yet
    /// initialised / after a reset.
    inner: Option<(DecoderKey, codec::AudioDecoder)>,
}

impl AirPlayPacketDecoder {
    /// Create a new decoder that reads AP1 format info from `state`.
    pub fn new(state: AppState) -> Self {
        Self { state, inner: None }
    }

    /// Return a reference to the shared [`AppState`].
    #[allow(dead_code)]
    pub fn state(&self) -> &AppState {
        &self.state
    }

    // ── decoder lifecycle ──────────────────────────────────────────

    /// Ensure the inner decoder matches the given key, creating or
    /// replacing it if necessary.
    fn ensure_decoder(&mut self, key: DecoderKey) -> anyhow::Result<&mut codec::AudioDecoder> {
        if self.inner.as_ref().is_some_and(|(k, _)| *k == key) {
            // Fast path: reuse existing decoder.
            return Ok(&mut self.inner.as_mut().unwrap().1);
        }

        // Drop old decoder and build a new one.
        let decoder = match &key {
            DecoderKey::ClassicAp1 {
                sample_size: sz,
                channels: ch,
                sample_rate: rate,
                frames_per_packet: fps,
                cookie,
            } => codec::AudioDecoder::new_alac(*sz, *ch, *rate, *fps as usize, cookie)?,
            DecoderKey::AirPlay2Buffered { format } => {
                let magic_cookie: Option<Vec<u8>> = if format.is_alac() {
                    Some(alac_specific_config(*format).to_vec())
                } else {
                    None
                };
                codec::AudioDecoder::new_for_format(*format, magic_cookie.as_deref())?
            }
        };

        self.inner = Some((key, decoder));
        Ok(&mut self.inner.as_mut().unwrap().1)
    }

    /// Build a [`DecoderKey`] from a packet and the current [`AppState`].
    ///
    /// For AP1 packets the key captures every format-relevant field from
    /// AppState so that a change to any of them (or the cookie) triggers
    /// decoder re-creation.
    fn key_for(&self, packet: &TimedPacket) -> Option<DecoderKey> {
        match packet.protocol {
            StreamProtocol::ClassicAp1 => {
                let sample_size = *self.state.alac_sample_size.read();
                let channels = *self.state.alac_channels.read();
                let sample_rate = *self.state.alac_sample_rate.read();
                let frames_per_packet = *self.state.frames_per_packet.read();
                let cookie = self.state.alac_magic_cookie.read().clone();

                // Every field must be set for a valid decoder.
                let (sz, ch, rate, fps, cookie_bytes) = match (
                    sample_size,
                    channels,
                    sample_rate,
                    frames_per_packet,
                    cookie,
                ) {
                    (Some(sz), Some(ch), Some(rate), Some(fps), Some(cookie)) => {
                        (sz, ch, rate, fps, cookie)
                    }
                    _ => return None,
                };

                Some(DecoderKey::ClassicAp1 {
                    sample_size: sz,
                    channels: ch,
                    sample_rate: rate,
                    frames_per_packet: fps,
                    cookie: cookie_bytes,
                })
            }
            StreamProtocol::AirPlay2Buffered | StreamProtocol::AirPlay2Realtime => {
                let format = packet.format?;
                Some(DecoderKey::AirPlay2Buffered { format })
            }
        }
    }

    // ── concealment helpers ─────────────────────────────────────────

    /// Return the format context for AP1 concealment from [`AppState`].
    fn ap1_concealment_ctx(&self) -> anyhow::Result<(usize, u32, u16)> {
        let frames =
            self.state
                .frames_per_packet
                .read()
                .context("AP1 frames_per_packet not set for concealment")? as usize;
        let rate = self
            .state
            .alac_sample_rate
            .read()
            .context("AP1 sample_rate not set for concealment")?;
        let ch = self
            .state
            .alac_channels
            .read()
            .context("AP1 channels not set for concealment")?;
        Ok((frames, rate, ch))
    }

    /// Return the format context for AP2 concealment from a packet's
    /// format field.
    fn ap2_concealment_ctx_from_packet(packet: &TimedPacket) -> anyhow::Result<(usize, u32, u16)> {
        let format = packet
            .format
            .context("AP2 packet missing AudioFormat for concealment")?;
        Ok((
            format.frames_per_packet(),
            format.sample_rate(),
            format.channels(),
        ))
    }

    /// Generate a whole-frame silence block.
    fn silence(frames: usize, sample_rate: u32, channels: u16) -> DecodedAudio {
        let samples = vec![0.0f32; frames * channels as usize];
        DecodedAudio {
            samples,
            sample_rate,
            channels,
        }
    }
}

impl PacketDecoder for AirPlayPacketDecoder {
    fn reset(&mut self) {
        self.inner = None;
    }

    fn decode(&mut self, packet: &TimedPacket) -> anyhow::Result<DecodedAudio> {
        let key = self
            .key_for(packet)
            .context("cannot build decoder key — missing format metadata")?;
        let decoder = self.ensure_decoder(key)?;
        let decoded = decoder.decode(&packet.payload)?;
        Ok(DecodedAudio {
            samples: decoded.samples,
            sample_rate: decoded.sample_rate,
            channels: decoded.channels,
        })
    }

    fn conceal_missing(
        &mut self,
        _expected_sequence: u64,
        last_packet: Option<&TimedPacket>,
    ) -> anyhow::Result<DecodedAudio> {
        // Prefer last_packet when available; otherwise fall back to the
        // active decoder context or AppState.
        let (frames, rate, ch) = match last_packet {
            Some(pkt) if pkt.protocol == StreamProtocol::ClassicAp1 => {
                self.ap1_concealment_ctx()?
            }
            Some(pkt) if pkt.protocol.is_airplay2_audio() => {
                Self::ap2_concealment_ctx_from_packet(pkt)?
            }
            Some(pkt) => {
                return Err(anyhow!(
                    "unsupported protocol {:?} for concealment",
                    pkt.protocol
                ));
            }
            None => {
                // No last packet — try the active decoder context.
                match &self.inner {
                    Some((DecoderKey::ClassicAp1 { .. }, _)) => self.ap1_concealment_ctx()?,
                    Some((DecoderKey::AirPlay2Buffered { format }, _)) => (
                        format.frames_per_packet(),
                        format.sample_rate(),
                        format.channels(),
                    ),
                    None => {
                        return Err(anyhow!(
                            "cannot conceal missing packet: no last-packet and no active decoder"
                        ));
                    }
                }
            }
        };
        Ok(Self::silence(frames, rate, ch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::AudioFormat;
    use crate::config::Config;
    use crate::playout::packet::TimedPacket;
    use bytes::Bytes;
    use std::time::Instant;

    // ── helpers ─────────────────────────────────────────────────────

    fn dummy_app_state() -> AppState {
        AppState::new(Config::default())
    }

    fn ap1_packet(payload: &[u8]) -> TimedPacket {
        TimedPacket::new(
            StreamProtocol::ClassicAp1,
            0,
            0,
            0,
            0,
            None,
            Bytes::copy_from_slice(payload),
            Instant::now(),
            false,
            0,
        )
    }

    fn ap2_packet(payload: &[u8], format: AudioFormat) -> TimedPacket {
        TimedPacket::new(
            StreamProtocol::AirPlay2Buffered,
            0,
            0,
            0,
            0,
            Some(format),
            Bytes::copy_from_slice(payload),
            Instant::now(),
            false,
            0,
        )
    }

    /// Set all AP1 format fields on the given AppState.
    fn set_ap1_state(state: &AppState, sz: u32, ch: u16, rate: u32, fps: u32) {
        let cookie = alac_specific_config(match (rate, sz) {
            (48_000, 24) => AudioFormat::Alac48000S24Stereo,
            _ => AudioFormat::Alac44100S16Stereo,
        });
        state.alac_magic_cookie.write().replace(cookie.to_vec());
        state.alac_sample_size.write().replace(sz);
        state.alac_channels.write().replace(ch);
        state.alac_sample_rate.write().replace(rate);
        state.frames_per_packet.write().replace(fps);
    }

    // ── DecoderKey tests ────────────────────────────────────────────

    #[test]
    fn decoder_key_ap1_captures_all_state_fields() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let decoder = AirPlayPacketDecoder::new(state.clone());
        let pkt = ap1_packet(b"dummy");

        let key1 = decoder.key_for(&pkt).expect("key should be buildable");
        // Same state → same key.
        let key2 = decoder.key_for(&pkt).expect("key should be buildable");
        assert_eq!(key1, key2, "same state must produce same key");

        // Change sample size → different key.
        state.alac_sample_size.write().replace(24);
        let key3 = decoder.key_for(&pkt).expect("key should be buildable");
        assert_ne!(key1, key3, "sample size change must change key");
    }

    #[test]
    fn decoder_key_ap1_changes_on_cookie_change() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);
        let decoder = AirPlayPacketDecoder::new(state.clone());
        let pkt = ap1_packet(b"dummy");

        let key1 = decoder.key_for(&pkt).expect("key buildable");

        // Replace the cookie with a different one (different format).
        let new_cookie = alac_specific_config(AudioFormat::Alac48000S24Stereo);
        state.alac_magic_cookie.write().replace(new_cookie.to_vec());
        let key2 = decoder.key_for(&pkt).expect("key buildable");
        assert_ne!(key1, key2, "cookie change must change key");
    }

    #[test]
    fn decoder_key_ap1_different_cookie_bytes_produce_different_keys() {
        // Two different cookie byte arrays must produce different keys,
        // proving that ClassicAp1 owns and compares the actual bytes,
        // not a truncated hash.
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);
        let decoder = AirPlayPacketDecoder::new(state.clone());
        let pkt = ap1_packet(b"dummy");

        let key1 = decoder.key_for(&pkt).expect("key buildable");

        // Replace with a cookie that differs only in sample-rate bytes.
        let different_cookie = alac_specific_config_fields(352, 16, 2, 48000);
        state
            .alac_magic_cookie
            .write()
            .replace(different_cookie.to_vec());
        let key2 = decoder.key_for(&pkt).expect("key buildable");
        assert_ne!(
            key1, key2,
            "different cookie bytes must produce different keys"
        );

        // Verify the exact cookie is stored in the key.
        if let DecoderKey::ClassicAp1 { cookie, .. } = &key2 {
            assert_eq!(cookie, &different_cookie.to_vec());
        } else {
            panic!("expected ClassicAp1 key");
        }

        // Mutate AppState to an invalid cookie after building a valid key.
        // Decoder construction must still succeed from key-owned bytes.
        state.alac_magic_cookie.write().replace(vec![0xAA; 4]);
        let mut decoder = AirPlayPacketDecoder::new(state);
        assert!(
            decoder.ensure_decoder(key2).is_ok(),
            "ensure_decoder must use the cookie captured in DecoderKey"
        );
    }

    #[test]
    fn decoder_key_ap1_returns_none_when_fields_missing() {
        let state = dummy_app_state();
        // Only set some fields — cookie is missing.
        state.alac_sample_size.write().replace(16);
        state.alac_channels.write().replace(2);
        state.alac_sample_rate.write().replace(44100);
        // frames_per_packet and cookie are None.

        let decoder = AirPlayPacketDecoder::new(state);
        let pkt = ap1_packet(b"dummy");
        assert!(decoder.key_for(&pkt).is_none());
    }

    #[test]
    fn decoder_key_ap2_uses_packet_format() {
        let state = dummy_app_state();
        let decoder = AirPlayPacketDecoder::new(state);

        let pkt1 = ap2_packet(b"dummy", AudioFormat::Alac44100S16Stereo);
        let pkt2 = ap2_packet(b"dummy", AudioFormat::Aac44100F24Stereo);

        let key1 = decoder.key_for(&pkt1).expect("AP2 key buildable");
        let key2 = decoder.key_for(&pkt2).expect("AP2 key buildable");
        assert_ne!(key1, key2, "different AP2 formats must give different keys");
    }

    #[test]
    fn decoder_key_ap2_returns_none_without_format() {
        let state = dummy_app_state();
        let decoder = AirPlayPacketDecoder::new(state);

        let pkt = TimedPacket::new(
            StreamProtocol::AirPlay2Buffered,
            0,
            0,
            0,
            0,
            None,
            Bytes::new(),
            Instant::now(),
            false,
            0,
        );
        assert!(decoder.key_for(&pkt).is_none());
    }

    // ── ALAC config tests ───────────────────────────────────────────

    #[test]
    fn alac_config_44100_16bit() {
        let config = alac_specific_config(AudioFormat::Alac44100S16Stereo);
        // frames_per_packet = 352 (big-endian)
        assert_eq!(&config[0..4], &[0x00, 0x00, 0x01, 0x60]); // 352
        assert_eq!(config[4], 0x00);
        assert_eq!(config[5], 16);
        assert_eq!(config[6], 40);
        assert_eq!(config[7], 10);
        assert_eq!(config[8], 14);
        assert_eq!(config[9], 2); // channels = 2
        // maxRun = 255 = 0x00FF (big-endian)
        assert_eq!(&config[10..12], &[0x00, 0xFF]);
        assert_eq!(&config[12..16], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&config[16..20], &[0x00, 0x00, 0x00, 0x00]);
        // sample_rate = 44100 = 0x0000_AC44 (big-endian)
        assert_eq!(&config[20..24], &[0x00, 0x00, 0xAC, 0x44]);
    }

    #[test]
    fn alac_config_48000_24bit() {
        let config = alac_specific_config(AudioFormat::Alac48000S24Stereo);
        // frames_per_packet = 352
        assert_eq!(&config[0..4], &[0x00, 0x00, 0x01, 0x60]); // 352
        assert_eq!(config[5], 24);
        // maxRun = 255 = 0x00FF
        assert_eq!(&config[10..12], &[0x00, 0xFF]);
        // sample_rate = 48000 = 0x0000_BB80 (big-endian)
        assert_eq!(&config[20..24], &[0x00, 0x00, 0xBB, 0x80]);
    }

    #[test]
    fn alac_config_custom_fields() {
        // Test with explicit custom fields that don't match any
        // built-in AudioFormat variant.
        let config = alac_specific_config_fields(4096, 20, 1, 96000);
        // frames_per_packet = 4096 = 0x0000_1000 (big-endian)
        assert_eq!(&config[0..4], &[0x00, 0x00, 0x10, 0x00]);
        assert_eq!(config[4], 0x00);
        assert_eq!(config[5], 20); // bits_per_sample
        assert_eq!(config[6], 40);
        assert_eq!(config[7], 10);
        assert_eq!(config[8], 14);
        assert_eq!(config[9], 1); // channels = 1
        // maxRun = 255 = 0x00FF (big-endian)
        assert_eq!(&config[10..12], &[0x00, 0xFF]);
        assert_eq!(&config[12..16], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&config[16..20], &[0x00, 0x00, 0x00, 0x00]);
        // sample_rate = 96000 = 0x0001_7700 (big-endian)
        assert_eq!(&config[20..24], &[0x00, 0x01, 0x77, 0x00]);
    }

    #[test]
    fn alac_config_is_always_24_bytes() {
        assert_eq!(
            alac_specific_config(AudioFormat::Alac44100S16Stereo).len(),
            24
        );
        assert_eq!(
            alac_specific_config(AudioFormat::Alac48000S24Stereo).len(),
            24
        );
    }

    // ── Reset / reinit bookkeeping ─────────────────────────────────

    #[test]
    fn reset_clears_inner_decoder() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let mut decoder = AirPlayPacketDecoder::new(state.clone());

        // Build a real decoder and inject it directly to test reset.
        let key = DecoderKey::ClassicAp1 {
            sample_size: 16,
            channels: 2,
            sample_rate: 44100,
            frames_per_packet: 352,
            cookie: alac_specific_config(AudioFormat::Alac44100S16Stereo).to_vec(),
        };
        let codec_decoder = codec::AudioDecoder::new_alac(
            16,
            2,
            44100,
            352,
            &alac_specific_config(AudioFormat::Alac44100S16Stereo),
        )
        .expect("valid ALAC decoder should construct");
        decoder.inner = Some((key, codec_decoder));
        assert!(decoder.inner.is_some());

        // Reset should clear it.
        decoder.reset();
        assert!(decoder.inner.is_none());
    }

    #[test]
    fn protocol_change_reinitializes_decoder() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let mut decoder = AirPlayPacketDecoder::new(state.clone());

        // Inject an AP1-keyed decoder.
        let ap1_key = DecoderKey::ClassicAp1 {
            sample_size: 16,
            channels: 2,
            sample_rate: 44100,
            frames_per_packet: 352,
            cookie: alac_specific_config(AudioFormat::Alac44100S16Stereo).to_vec(),
        };
        let ap1_codec = codec::AudioDecoder::new_alac(
            16,
            2,
            44100,
            352,
            &alac_specific_config(AudioFormat::Alac44100S16Stereo),
        )
        .expect("valid ALAC decoder");
        decoder.inner = Some((ap1_key, ap1_codec));

        // Call ensure_decoder with an AP2 key — this must replace the
        // inner decoder.
        let ap2_key = DecoderKey::AirPlay2Buffered {
            format: AudioFormat::Aac44100F24Stereo,
        };
        let result = decoder.ensure_decoder(ap2_key);
        // AAC decoder should construct fine.
        assert!(result.is_ok());
        let new_key = &decoder.inner.as_ref().unwrap().0;
        assert!(matches!(new_key, DecoderKey::AirPlay2Buffered { .. }));
    }

    #[test]
    fn same_key_reuses_decoder() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let mut decoder = AirPlayPacketDecoder::new(state.clone());

        let key = DecoderKey::ClassicAp1 {
            sample_size: 16,
            channels: 2,
            sample_rate: 44100,
            frames_per_packet: 352,
            cookie: alac_specific_config(AudioFormat::Alac44100S16Stereo).to_vec(),
        };
        let codec_decoder = codec::AudioDecoder::new_alac(
            16,
            2,
            44100,
            352,
            &alac_specific_config(AudioFormat::Alac44100S16Stereo),
        )
        .expect("valid ALAC decoder");
        decoder.inner = Some((key.clone(), codec_decoder));

        // ensure_decoder with the same key must return without replacing.
        assert!(decoder.ensure_decoder(key.clone()).is_ok());
        assert!(decoder.inner.is_some());
        assert_eq!(decoder.inner.as_ref().unwrap().0, key);
    }

    #[test]
    fn state_field_change_reinitializes() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let mut decoder = AirPlayPacketDecoder::new(state.clone());

        // Build and inject first decoder.
        let key1 = DecoderKey::ClassicAp1 {
            sample_size: 16,
            channels: 2,
            sample_rate: 44100,
            frames_per_packet: 352,
            cookie: alac_specific_config(AudioFormat::Alac44100S16Stereo).to_vec(),
        };
        decoder.inner = Some((
            key1,
            codec::AudioDecoder::new_alac(
                16,
                2,
                44100,
                352,
                &alac_specific_config(AudioFormat::Alac44100S16Stereo),
            )
            .unwrap(),
        ));

        // Change sample_rate in AppState — the new key won't match.
        state.alac_sample_rate.write().replace(48000);
        let pkt = ap1_packet(b"dummy");
        let new_key = decoder.key_for(&pkt).expect("key should build");

        assert_ne!(decoder.inner.as_ref().unwrap().0, new_key);
        // ensure_decoder with the new key replaces the inner.
        let result = decoder.ensure_decoder(new_key.clone());
        assert!(result.is_ok());
        assert_eq!(decoder.inner.as_ref().unwrap().0, new_key);
    }

    // ── AP1 missing concealment ────────────────────────────────────

    #[test]
    fn ap1_conceal_missing_produces_silence() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let mut decoder = AirPlayPacketDecoder::new(state.clone());

        let last_pkt = ap1_packet(b"dummy");
        let result = decoder
            .conceal_missing(5, Some(&last_pkt))
            .expect("AP1 concealment should succeed");

        assert_eq!(result.sample_rate, 44100);
        assert_eq!(result.channels, 2);
        assert_eq!(result.frames(), 352);
        // All samples must be zero.
        assert!(result.samples.iter().all(|&s| s == 0.0));
    }

    #[test]
    fn ap1_conceal_missing_fails_without_state() {
        let state = dummy_app_state();
        // No ALAC parameters set.
        let mut decoder = AirPlayPacketDecoder::new(state);
        let last_pkt = ap1_packet(b"dummy");
        let result = decoder.conceal_missing(5, Some(&last_pkt));
        assert!(result.is_err());
    }

    // ── AP2 missing concealment ────────────────────────────────────

    #[test]
    fn ap2_conceal_missing_produces_silence() {
        let state = dummy_app_state();
        let mut decoder = AirPlayPacketDecoder::new(state);

        let last_pkt = ap2_packet(b"dummy", AudioFormat::Alac44100S16Stereo);
        let result = decoder
            .conceal_missing(10, Some(&last_pkt))
            .expect("AP2 concealment should succeed");

        assert_eq!(result.sample_rate, 44100);
        assert_eq!(result.channels, 2);
        assert_eq!(result.frames(), 352);
        assert!(result.samples.iter().all(|&s| s == 0.0));
    }

    #[test]
    fn ap2_conceal_missing_fails_without_format() {
        let state = dummy_app_state();
        let mut decoder = AirPlayPacketDecoder::new(state);

        // AP2 packet without format field.
        let last_pkt = TimedPacket::new(
            StreamProtocol::AirPlay2Buffered,
            0,
            0,
            0,
            0,
            None,
            Bytes::new(),
            Instant::now(),
            false,
            0,
        );
        let result = decoder.conceal_missing(5, Some(&last_pkt));
        assert!(result.is_err());
    }

    // ── AAC concealment context from AP2 packet ────────────────────

    #[test]
    fn ap2_aac_conceal_uses_format_frames_per_packet() {
        let state = dummy_app_state();
        let mut decoder = AirPlayPacketDecoder::new(state);

        let last_pkt = ap2_packet(b"dummy", AudioFormat::Aac44100F24Stereo);
        let result = decoder
            .conceal_missing(3, Some(&last_pkt))
            .expect("AAC concealment should succeed");

        // AAC has frames_per_packet = 1024.
        assert_eq!(result.frames(), 1024);
        assert_eq!(result.sample_rate, 44100);
        assert_eq!(result.channels, 2);
    }

    // ── conceal_missing without last_packet (fallback to active decoder) ──

    #[test]
    fn conceal_missing_fails_without_last_packet_and_no_active_decoder() {
        let state = dummy_app_state();
        let mut decoder = AirPlayPacketDecoder::new(state);
        // No last packet and no active decoder → error.
        let result = decoder.conceal_missing(5, None);
        assert!(result.is_err());
    }

    #[test]
    fn ap1_conceal_without_last_packet_uses_app_state() {
        let state = dummy_app_state();
        set_ap1_state(&state, 16, 2, 44100, 352);

        let mut decoder = AirPlayPacketDecoder::new(state.clone());

        // Inject an active AP1 decoder so the fallback has context.
        let key = DecoderKey::ClassicAp1 {
            sample_size: 16,
            channels: 2,
            sample_rate: 44100,
            frames_per_packet: 352,
            cookie: alac_specific_config(AudioFormat::Alac44100S16Stereo).to_vec(),
        };
        decoder.inner = Some((
            key,
            codec::AudioDecoder::new_alac(
                16,
                2,
                44100,
                352,
                &alac_specific_config(AudioFormat::Alac44100S16Stereo),
            )
            .unwrap(),
        ));

        // No last packet, but active decoder key gives AP1 context.
        let result = decoder
            .conceal_missing(5, None)
            .expect("should use AppState fallback");
        assert_eq!(result.frames(), 352);
        assert_eq!(result.sample_rate, 44100);
        assert_eq!(result.channels, 2);
    }

    #[test]
    fn ap2_conceal_without_last_packet_uses_active_decoder_format() {
        let state = dummy_app_state();
        let mut decoder = AirPlayPacketDecoder::new(state);

        // Inject an active AP2 decoder.
        let format = AudioFormat::Aac44100F24Stereo;
        decoder.inner = Some((
            DecoderKey::AirPlay2Buffered { format },
            codec::AudioDecoder::new_for_format(format, None).unwrap(),
        ));

        // No last packet, but active decoder key gives AP2 context.
        let result = decoder
            .conceal_missing(7, None)
            .expect("should use active decoder format");
        assert_eq!(result.frames(), 1024); // AAC
        assert_eq!(result.sample_rate, 44100);
        assert_eq!(result.channels, 2);
    }
}
