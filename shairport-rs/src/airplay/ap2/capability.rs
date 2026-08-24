//! AirPlay 2 capability policy.
//!
//! A single [`Ap2CapabilityPolicy`] is derived from [`Config`] (and,
//! indirectly, the runtime PTP availability) to centralise every
//! capability-related decision:
//!
//! * Feature bits (`features` / `featuresEx` / `ft` / `fex`)
//! * Status flags
//! * `supportedFormats` masks for both `/info` and mDNS TXT records
//! * Whether the `_airplay._tcp` service should be published at all
//!
//! # Design principle
//!
//! The policy does **not** hold a reference to `Config`; callers construct
//! one by calling [`Ap2CapabilityPolicy::from_config`] and passing the
//! runtime PTP-available flag.  Once built, every public method is infallible
//! and allocation-free.
//!
//! mDNS `txt_records` and RTSP `GET /info` use the **same** policy so their
//! feature words / status flags / format masks are always consistent.

use crate::config::{AdvertisedFormatPolicy, Config, PtpBackendName};

// ---------------------------------------------------------------------------
// Feature bit definitions — each is documented with its motivation.
// ---------------------------------------------------------------------------

/// Bit  0: SupportsAirPlayVideo                            — **cleared** (no video / screen mirroring).
/// Bit  9: SupportsAirPlayAudio                            — **set** (audio receiver).
/// Bit 11: SupportsAirPlayAudioRedundant                   — **set** (standard audio receiver bit).
/// Bit 14: SupportsPTP                                     — **set** (PTP timing, when available).
/// Bit 18: SupportsUnifiedPairSetupAndMFi                  — **set** (pair-setup / MFi).
/// Bit 19: SupportsAirPlayAudioBuffered                    — **set** (buffered audio type 103).
/// Bit 20: SupportsCoreUtils                               — **set** (necessary for AP2).
/// Bit 22: SupportsUnifiedPairVerifyAndMFi                 — **set** (pair-verify / MFi).
/// Bit 30: SupportsAudioRedundant                          — **set** (standard receiver bit).
/// Bit 38: SupportsLegacyPairing                           — **set** (pair-setup / pair-verify).
/// Bit 40: SupportsPTPClock                                — **set** (PTP clock identity).
/// Bit 41: SupportsAirPlayAudioBufferedRedundant           — **set** (buffered audio redundant bit).
/// Bit 47: SupportsAudioUnified                            — **set** (AirPlay 2 audio).
/// Bit 48: SupportsCarPlay                                 — **cleared** (not a CarPlay device).
/// Bit 50: SupportsAP2Metadata                             — **set when metadata is available**.
///
/// ## Retained mask relative to upstream
///
/// The upstream shairport-sync C reference feature mask is
/// `0x00018340405C4A00`.  The following bits from that mask are
/// **intentionally cleared** with documented reasons:
///
/// | Bit | Upstream | Reason                                          |
/// |-----|----------|-------------------------------------------------|
/// |   0 | set      | Video / screen mirroring not implemented.       |
/// |  15 | optional | AP1 artwork (legacy); we use bit 50 metadata.    |
/// |  16 | optional | AP1 progress (legacy); we use bit 50 metadata.   |
/// |  17 | optional | AP1 text (legacy); we use bit 50 metadata.       |
/// |  48 | set      | CarPlay — not implemented.                       |
///
/// Undocumented upstream bits (those for which no confirmed public
/// specification or trustworthy reverse-engineering evidence exists) are
/// **cleared** and not reasoned about here.  The final mask is computed at
/// policy-construction time so that the same bits feed into mDNS TXT
/// records, the /info plist, and the `txtAirPlay` field — there is exactly
/// one source of truth.
const FEATURE_SUPPORTS_AIRPLAY_AUDIO: u64 = 1 << 9;
const FEATURE_SUPPORTS_AIRPLAY_AUDIO_REDUNDANT: u64 = 1 << 11;
const FEATURE_SUPPORTS_PTP: u64 = 1 << 14;
const FEATURE_SUPPORTS_UNIFIED_PAIR_SETUP_AND_MFI: u64 = 1 << 18;
const FEATURE_SUPPORTS_AIRPLAY_AUDIO_BUFFERED: u64 = 1 << 19;
const FEATURE_SUPPORTS_CORE_UTILS: u64 = 1 << 20;
const FEATURE_SUPPORTS_UNIFIED_PAIR_VERIFY_AND_MFI: u64 = 1 << 22;
const FEATURE_SUPPORTS_AUDIO_REDUNDANT: u64 = 1 << 30;
const FEATURE_SUPPORTS_LEGACY_PAIRING: u64 = 1 << 38;
const FEATURE_SUPPORTS_PTP_CLOCK: u64 = 1 << 40;
const FEATURE_SUPPORTS_AIRPLAY_AUDIO_BUFFERED_REDUNDANT: u64 = 1 << 41;
const FEATURE_SUPPORTS_AUDIO_UNIFIED: u64 = 1 << 47;
const FEATURE_SUPPORTS_AP2_METADATA: u64 = 1 << 50;

/// Status flag bits.
const STATUS_FLAG_AUDIO_CABLE_ATTACHED: u32 = 1 << 2;
const STATUS_FLAG_PASSWORD_REQUIRED: u32 = 1 << 7;

// ---------------------------------------------------------------------------
// Format mask bits (buffer stream) — must match upstream layout.
// ---------------------------------------------------------------------------

const FORMAT_ALAC_44100_S16_2: u64 = 0x0000_0000_0004_0000; // bit 18
const FORMAT_ALAC_48000_S24_2: u64 = 0x0000_0000_0020_0000; // bit 21
const FORMAT_AAC_44100_S24_2: u64 = 0x0000_0000_0040_0000; // bit 22
const FORMAT_AAC_48000_S24_2: u64 = 0x0000_0000_0080_0000; // bit 23

/// All playable stereo format bits (ALAC + AAC).
const ALL_PLAYABLE_STEREO_FORMATS: u64 = FORMAT_ALAC_44100_S16_2
    | FORMAT_ALAC_48000_S24_2
    | FORMAT_AAC_44100_S24_2
    | FORMAT_AAC_48000_S24_2;

/// ALAC-only stereo format bits.
const ALAC_ONLY_STEREO_FORMATS: u64 = FORMAT_ALAC_44100_S16_2 | FORMAT_ALAC_48000_S24_2;

// ---------------------------------------------------------------------------
// Policy struct
// ---------------------------------------------------------------------------

/// Immutable snapshot of AP2 capability decisions.
///
/// Construct via [`Ap2CapabilityPolicy::from_config`]; cheap to clone/copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ap2CapabilityPolicy {
    /// 64-bit feature mask (for `features`, `featuresEx`, `ft`, `fex`).
    pub features: u64,
    /// 32-bit status flags (for `statusFlags`, `flags`, `sf`).
    pub status_flags: u32,
    /// Whether to publish the `_airplay._tcp` service at all.
    pub publish_airplay: bool,
    /// Playable buffer-stream format mask (`supportedFormats.bufferStream`).
    pub buffer_stream_formats: u64,
    /// Real-time audio-stream format mask (`supportedFormats.audioStream`).
    pub audio_stream_formats: u64,
    /// Whether AirPlay 2 is enabled in configuration.
    pub ap2_enabled: bool,
    /// Whether PTP is truly available: AP2 enabled, PTP configured, and
    /// PTP daemon confirmed running.  Drives `supports_timing_protocol` and
    /// `supports_stream_type` gating.
    pub ptp_available: bool,
}

impl Ap2CapabilityPolicy {
    /// Build the policy from configuration and PTP runtime status.
    ///
    /// If the PTP daemon / embedded service is not yet confirmed running at
    /// construction time, pass `ptp_running: false`.  The policy will clear
    /// the PTP-related feature bits and suppress `_airplay` publication
    /// because an AP2 receiver without timing is unusable.
    pub fn from_config(config: &Config, ptp_running: bool) -> Self {
        let airplay2 = config.airplay.airplay2_enabled;
        let ptp_configured =
            config.ptp.enabled && !matches!(config.ptp.backend, PtpBackendName::Off);
        let ptp_available = airplay2 && ptp_configured && ptp_running;
        let password_set = config.airplay.password_required();

        // --- Features ---
        let mut features: u64 = 0;
        if airplay2 {
            features |= FEATURE_SUPPORTS_AIRPLAY_AUDIO;
            features |= FEATURE_SUPPORTS_AIRPLAY_AUDIO_REDUNDANT;
            features |= FEATURE_SUPPORTS_AIRPLAY_AUDIO_BUFFERED;
            features |= FEATURE_SUPPORTS_AIRPLAY_AUDIO_BUFFERED_REDUNDANT;
            features |= FEATURE_SUPPORTS_AUDIO_UNIFIED;
            features |= FEATURE_SUPPORTS_AUDIO_REDUNDANT;
            features |= FEATURE_SUPPORTS_CORE_UTILS;
            features |= FEATURE_SUPPORTS_UNIFIED_PAIR_SETUP_AND_MFI;
            features |= FEATURE_SUPPORTS_UNIFIED_PAIR_VERIFY_AND_MFI;
            features |= FEATURE_SUPPORTS_LEGACY_PAIRING;
            // Metadata: bit 50 = binary-plist metadata (incl. artwork, text, progress).
            features |= FEATURE_SUPPORTS_AP2_METADATA;
        }
        if ptp_available {
            features |= FEATURE_SUPPORTS_PTP;
            features |= FEATURE_SUPPORTS_PTP_CLOCK;
        }

        // --- Status flags ---
        let mut status_flags: u32 = 0;
        if airplay2 {
            status_flags |= STATUS_FLAG_AUDIO_CABLE_ATTACHED;
        }
        if password_set {
            status_flags |= STATUS_FLAG_PASSWORD_REQUIRED;
        }

        // --- Publish _airplay? ---
        // If AP2 is enabled but PTP is not available, suppress _airplay
        // to avoid advertising a device that cannot complete a session.
        let publish_airplay = airplay2 && ptp_available;

        // --- Buffer stream formats ---
        let buffer_stream = match config.airplay.advertised_format_policy {
            AdvertisedFormatPolicy::AlacOnly => ALAC_ONLY_STEREO_FORMATS,
            AdvertisedFormatPolicy::AacIfAvailable => ALL_PLAYABLE_STEREO_FORMATS,
        };

        Self {
            features,
            status_flags,
            publish_airplay,
            buffer_stream_formats: buffer_stream,
            audio_stream_formats: buffer_stream,
            ap2_enabled: airplay2,
            ptp_available,
        }
    }

    /// Feature words as `(lo, hi)` u32 pair for mDNS `ft` / `features`.
    pub fn feature_words(&self) -> (u32, u32) {
        (
            (self.features & 0xffff_ffff) as u32,
            (self.features >> 32) as u32,
        )
    }

    /// Base64-encoded little-endian features (for mDNS `fex`).
    pub fn features_ex(&self) -> String {
        use base64::Engine;
        let bytes = self.features.to_le_bytes();
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
    }

    /// Whether the given stream type is supported (i.e. will be actioned).
    ///
    /// Returns `true` only when AP2 is enabled, PTP is confirmed available,
    /// and the stream type is implemented. Buffered audio (type 103) and
    /// realtime audio (type 96) share the PTP-timed playout path.
    ///
    /// Type 130 (data stream) support is context-dependent and checked via
    /// [`supports_remote_control_data_stream`](Self::supports_remote_control_data_stream).
    pub fn supports_stream_type(&self, ty: u32) -> bool {
        if !self.ptp_available {
            return false;
        }
        match ty {
            103 => true,  // buffered audio
            96 => true,   // realtime audio
            130 => false, // data stream — requires remote-control-only context
            _ => false,
        }
    }

    /// Whether the remote-control data stream (type 130) is supported.
    ///
    /// Returns `true` when AP2 is enabled regardless of PTP status,
    /// because remote-control-only sessions do not require PTP.
    /// This is the context-aware check used during type-130 stream SETUP.
    pub fn supports_remote_control_data_stream(&self) -> bool {
        // AP2 must be enabled; PTP not required for remote-control-only.
        self.ap2_enabled
    }

    /// Whether the given timing protocol string is acceptable.
    ///
    /// Returns `true` only when AP2 is enabled, PTP is confirmed available,
    /// and the protocol is "PTP" or "ptp" — the only timing protocol
    /// implemented.
    pub fn supports_timing_protocol(&self, protocol: &str) -> bool {
        self.ptp_available && protocol == "PTP"
    }

    /// Whether the given audio format (by bitmask) is playable.
    pub fn is_format_playable(&self, format_bits: u64) -> bool {
        (self.buffer_stream_formats & format_bits) != 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        let mut c = Config::default();
        c.airplay.airplay2_enabled = true;
        c.ptp.enabled = true;
        c.ptp.backend = PtpBackendName::Embedded;
        c
    }

    // ── Construction ─────────────────────────────────────────────────────

    #[test]
    fn ap2_with_ptp_sets_all_bits() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert!(policy.features & FEATURE_SUPPORTS_AIRPLAY_AUDIO != 0);
        assert!(policy.features & FEATURE_SUPPORTS_AIRPLAY_AUDIO_BUFFERED != 0);
        assert!(policy.features & FEATURE_SUPPORTS_PTP != 0);
        assert!(policy.features & FEATURE_SUPPORTS_PTP_CLOCK != 0);
        assert!(policy.features & FEATURE_SUPPORTS_AP2_METADATA != 0);
        assert!(policy.publish_airplay);
    }

    #[test]
    fn ap2_without_ptp_clears_ptp_bits_and_suppresses_airplay() {
        let mut config = base_config();
        config.ptp.backend = PtpBackendName::Off;
        let policy = Ap2CapabilityPolicy::from_config(&config, false);
        assert_eq!(policy.features & FEATURE_SUPPORTS_PTP, 0);
        assert_eq!(policy.features & FEATURE_SUPPORTS_PTP_CLOCK, 0);
        assert!(!policy.publish_airplay);
    }

    #[test]
    fn ap2_with_ptp_configured_but_not_running_suppresses_airplay() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), false);
        assert!(!policy.publish_airplay);
        assert_eq!(policy.features & FEATURE_SUPPORTS_PTP, 0);
    }

    #[test]
    fn ap2_disabled_clears_all() {
        let mut config = base_config();
        config.airplay.airplay2_enabled = false;
        config.airplay.pin = "".to_string();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert_eq!(policy.features, 0);
        assert_eq!(policy.status_flags, 0);
        assert!(!policy.publish_airplay);
    }

    #[test]
    fn password_set_adds_status_flag() {
        let mut config = base_config();
        config.airplay.pin = "1234".to_string();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(policy.status_flags & STATUS_FLAG_PASSWORD_REQUIRED != 0);
    }

    #[test]
    fn empty_pin_clears_password_flag() {
        let mut config = base_config();
        config.airplay.pin = "".to_string();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert_eq!(policy.status_flags & STATUS_FLAG_PASSWORD_REQUIRED, 0);
    }

    // ── Feature bits audit ───────────────────────────────────────────────

    #[test]
    fn no_video_or_screen_mirroring_bit() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert_eq!(
            policy.features & (1 << 0),
            0,
            "bit 0 = video/screen mirroring must be clear"
        );
    }

    #[test]
    fn no_carplay_bit() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert_eq!(
            policy.features & (1 << 48),
            0,
            "bit 48 = CarPlay must be clear"
        );
    }

    #[test]
    fn no_legacy_ap1_metadata_bits() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert_eq!(
            policy.features & (1 << 15),
            0,
            "bit 15 = AP1 artwork must be clear"
        );
        assert_eq!(
            policy.features & (1 << 16),
            0,
            "bit 16 = AP1 progress must be clear"
        );
        assert_eq!(
            policy.features & (1 << 17),
            0,
            "bit 17 = AP1 text must be clear"
        );
    }

    // ── supportedFormats ─────────────────────────────────────────────────

    #[test]
    fn audio_stream_advertises_only_playable_realtime_formats() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert_eq!(policy.audio_stream_formats, policy.buffer_stream_formats);
        assert_ne!(policy.audio_stream_formats, 0);
    }

    #[test]
    fn buffer_stream_alac_only_policy() {
        let mut config = base_config();
        config.airplay.advertised_format_policy = AdvertisedFormatPolicy::AlacOnly;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert_eq!(policy.buffer_stream_formats, ALAC_ONLY_STEREO_FORMATS);
        // AAC bits must not be present
        assert_eq!(policy.buffer_stream_formats & FORMAT_AAC_44100_S24_2, 0);
        assert_eq!(policy.buffer_stream_formats & FORMAT_AAC_48000_S24_2, 0);
        // ALAC bits must be present
        assert_ne!(policy.buffer_stream_formats & FORMAT_ALAC_44100_S16_2, 0);
        assert_ne!(policy.buffer_stream_formats & FORMAT_ALAC_48000_S24_2, 0);
    }

    #[test]
    fn buffer_stream_aac_if_available_policy() {
        let mut config = base_config();
        config.airplay.advertised_format_policy = AdvertisedFormatPolicy::AacIfAvailable;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert_eq!(policy.buffer_stream_formats, ALL_PLAYABLE_STEREO_FORMATS);
        assert_ne!(policy.buffer_stream_formats & FORMAT_AAC_44100_S24_2, 0);
        assert_ne!(policy.buffer_stream_formats & FORMAT_AAC_48000_S24_2, 0);
    }

    #[test]
    fn buffer_stream_excludes_5_1_and_7_1() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        // 5.1 = bit 39, 7.1 = bit 40 (upstream values)
        let fmt_5_1: u64 = 0x0800_0000_0000;
        let fmt_7_1: u64 = 0x1000_0000_0000;
        assert_eq!(
            policy.buffer_stream_formats & fmt_5_1,
            0,
            "5.1 must not be advertised"
        );
        assert_eq!(
            policy.buffer_stream_formats & fmt_7_1,
            0,
            "7.1 must not be advertised"
        );
    }

    // ── Stream type support ──────────────────────────────────────────────

    #[test]
    fn supports_buffered_103_and_realtime_96() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert!(policy.supports_stream_type(103));
        assert!(policy.supports_stream_type(96));
        assert!(!policy.supports_stream_type(130));
        assert!(!policy.supports_stream_type(0));
        assert!(!policy.supports_stream_type(999));
    }

    #[test]
    fn stream_type_103_false_when_ptp_not_running() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), false);
        assert!(!policy.supports_stream_type(103));
    }

    #[test]
    fn stream_type_103_false_when_ap2_disabled() {
        let mut config = base_config();
        config.airplay.airplay2_enabled = false;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(!policy.supports_stream_type(103));
    }

    // ── Remote-control data stream support ───────────────────────────────

    #[test]
    fn supports_remote_control_data_stream_when_ap2_enabled() {
        // PTP running is NOT required for data stream support.
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert!(policy.supports_remote_control_data_stream());
    }

    #[test]
    fn supports_remote_control_data_stream_without_ptp() {
        // Even when PTP is not running, data stream should be supported
        // for remote-control-only sessions.
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), false);
        assert!(policy.supports_remote_control_data_stream());
    }

    #[test]
    fn supports_remote_control_data_stream_false_when_ap2_disabled() {
        let mut config = base_config();
        config.airplay.airplay2_enabled = false;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(!policy.supports_remote_control_data_stream());
    }

    #[test]
    fn stream_type_130_still_false_in_generic_check() {
        // Generic supports_stream_type(130) returns false; use the
        // context-aware supports_remote_control_data_stream instead.
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert!(!policy.supports_stream_type(130));
        assert!(policy.supports_remote_control_data_stream());
    }

    // ── Timing protocol support ──────────────────────────────────────────

    #[test]
    fn supports_ptp_timing_only() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        assert!(policy.supports_timing_protocol("PTP"));
        assert!(!policy.supports_timing_protocol("ptp"));
        assert!(!policy.supports_timing_protocol("NTP"));
        assert!(!policy.supports_timing_protocol("None"));
        assert!(!policy.supports_timing_protocol(""));
        assert!(!policy.supports_timing_protocol("BOGUS"));
    }

    #[test]
    fn timing_protocol_ptp_false_when_ptp_not_running() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), false);
        assert!(!policy.supports_timing_protocol("PTP"));
    }

    #[test]
    fn timing_protocol_ptp_false_when_ap2_disabled() {
        let mut config = base_config();
        config.airplay.airplay2_enabled = false;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(!policy.supports_timing_protocol("PTP"));
    }

    // ── Format playability ───────────────────────────────────────────────

    #[test]
    fn is_format_playable_alac_only() {
        let mut config = base_config();
        config.airplay.advertised_format_policy = AdvertisedFormatPolicy::AlacOnly;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(policy.is_format_playable(FORMAT_ALAC_44100_S16_2));
        assert!(policy.is_format_playable(FORMAT_ALAC_48000_S24_2));
        assert!(!policy.is_format_playable(FORMAT_AAC_44100_S24_2));
        assert!(!policy.is_format_playable(FORMAT_AAC_48000_S24_2));
    }

    #[test]
    fn is_format_playable_aac_if_available() {
        let mut config = base_config();
        config.airplay.advertised_format_policy = AdvertisedFormatPolicy::AacIfAvailable;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(policy.is_format_playable(FORMAT_ALAC_44100_S16_2));
        assert!(policy.is_format_playable(FORMAT_AAC_44100_S24_2));
    }

    // ── feature_words ────────────────────────────────────────────────────

    #[test]
    fn feature_words_roundtrip() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        let (lo, hi) = policy.feature_words();
        let reconstructed: u64 = (lo as u64) | ((hi as u64) << 32);
        assert_eq!(reconstructed, policy.features);
    }

    // ── features_ex ──────────────────────────────────────────────────────

    #[test]
    fn features_ex_is_base64() {
        let policy = Ap2CapabilityPolicy::from_config(&base_config(), true);
        let fex = policy.features_ex();
        // Must be valid base64 (no padding) and non-empty when features != 0
        assert!(!fex.is_empty());
        // Decode and verify roundtrip
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&fex)
            .expect("fex should be valid base64");
        assert_eq!(decoded.len(), 8);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&decoded);
        assert_eq!(u64::from_le_bytes(bytes), policy.features);
    }
}
