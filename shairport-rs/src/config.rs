use std::{fmt, fs, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Maximum ring-buffer duration in milliseconds (10 seconds).
/// Prevents absurd memory allocations from misconfigured values.
pub const MAX_PCM_FIFO_MS: u32 = 10_000;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub airplay: AirplayConfig,
    pub mdns: MdnsConfig,
    pub audio: AudioConfig,
    pub ptp: PtpConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AirplayConfig {
    pub enabled: bool,
    pub airplay2_enabled: bool,
    pub bind: String,
    pub ap2_bind_ip: Option<String>,
    pub advertised_format_policy: AdvertisedFormatPolicy,
    pub device_id: String,
    pub pin: String,
    pub identity_key_path: Option<String>,
    pub pairing_db_path: Option<String>,
    pub audio_port: u16,
    pub control_port: u16,
    pub timing_port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdvertisedFormatPolicy {
    AlacOnly,
    AacIfAvailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MdnsConfig {
    pub backend: MdnsBackendName,
    pub interface: Option<String>,
    pub hostname: String,
    pub service_name: String,
    pub external_command: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MdnsBackendName {
    Auto,
    Builtin,
    Avahi,
    DnsSd,
    External,
    Off,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AudioConfig {
    pub backend: AudioBackendName,
    pub host: AudioHostName,
    pub device: Option<String>,
    /// Ring-buffer capacity in milliseconds of PCM audio (≥ 1).
    #[serde(default = "default_pcm_fifo_ms")]
    pub pcm_fifo_ms: u32,
    /// Producer start watermark in milliseconds (≤ pcm_fifo_ms).
    #[serde(default = "default_start_watermark_ms")]
    pub start_watermark_ms: u32,
    /// Producer low watermark in milliseconds (≤ pcm_fifo_ms).
    #[serde(default = "default_low_watermark_ms")]
    pub low_watermark_ms: u32,
    /// Producer target watermark in milliseconds (≤ pcm_fifo_ms).
    #[serde(default = "default_target_watermark_ms")]
    pub target_watermark_ms: u32,
}

fn default_pcm_fifo_ms() -> u32 {
    150
}
fn default_start_watermark_ms() -> u32 {
    80
}
fn default_low_watermark_ms() -> u32 {
    40
}
fn default_target_watermark_ms() -> u32 {
    80
}

impl AudioConfig {
    /// Clamp watermarks so they never exceed the ring-buffer duration,
    /// `pcm_fifo_ms` is clamped to `[1, MAX_PCM_FIFO_MS]`, and
    /// watermarks are ordered: `low ≤ target ≤ start ≤ pcm_fifo_ms`.
    pub fn normalize(&mut self) {
        self.pcm_fifo_ms = self.pcm_fifo_ms.clamp(1, MAX_PCM_FIFO_MS);
        // Clamp to pcm_fifo_ms first so none exceed the capacity.
        self.start_watermark_ms = self.start_watermark_ms.min(self.pcm_fifo_ms);
        self.target_watermark_ms = self.target_watermark_ms.min(self.pcm_fifo_ms);
        self.low_watermark_ms = self.low_watermark_ms.min(self.pcm_fifo_ms);
        // Enforce low ≤ target ≤ start.
        self.target_watermark_ms = self.target_watermark_ms.max(self.low_watermark_ms);
        self.start_watermark_ms = self.start_watermark_ms.max(self.target_watermark_ms);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudioBackendName {
    Cpal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudioHostName {
    Default,
    Alsa,
    Coreaudio,
    Wasapi,
    Asio,
    Jack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct PtpConfig {
    pub enabled: bool,
    pub backend: PtpBackendName,
    pub event_port: u16,
    pub general_port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PtpBackendName {
    Embedded,
    Nqptp,
    Off,
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            let mut config = Self::default();
            config.audio.normalize();
            return Ok(config);
        };
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.audio.normalize();
        Ok(config)
    }
}

impl Default for AirplayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            airplay2_enabled: false,
            pin: "3939".to_string(),
            identity_key_path: None,
            pairing_db_path: None,
            bind: "0.0.0.0:7000".to_string(),
            ap2_bind_ip: None,
            advertised_format_policy: AdvertisedFormatPolicy::AacIfAvailable,
            device_id: "00:11:22:33:44:55".to_string(),
            audio_port: 6000,
            control_port: 6001,
            timing_port: 6002,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3689".to_string(),
        }
    }
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            backend: MdnsBackendName::Auto,
            interface: None,
            hostname: "shairport-rs".to_string(),
            service_name: "Shairport RS".to_string(),
            external_command: None,
        }
    }
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 150,
            start_watermark_ms: 80,
            low_watermark_ms: 40,
            target_watermark_ms: 80,
        }
    }
}

impl Default for PtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: PtpBackendName::Embedded,
            event_port: 319,
            general_port: 320,
        }
    }
}

impl fmt::Display for PtpBackendName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Embedded => "embedded",
            Self::Nqptp => "nqptp",
            Self::Off => "off",
        };
        f.write_str(value)
    }
}

impl fmt::Display for MdnsBackendName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Auto => "auto",
            Self::Builtin => "builtin",
            Self::Avahi => "avahi",
            Self::DnsSd => "dns-sd",
            Self::External => "external",
            Self::Off => "off",
        };
        f.write_str(value)
    }
}

impl fmt::Display for AudioHostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Default => "default",
            Self::Alsa => "alsa",
            Self::Coreaudio => "coreaudio",
            Self::Wasapi => "wasapi",
            Self::Asio => "asio",
            Self::Jack => "jack",
        };
        f.write_str(value)
    }
}

impl fmt::Display for AdvertisedFormatPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::AlacOnly => "alac-only",
            Self::AacIfAvailable => "aac-if-available",
        };
        f.write_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_public_config_shape() {
        let config: Config = toml::from_str(
            r#"
            [mdns]
            backend = "auto"
            interface = "eth0"
            hostname = "living-room"
            service_name = "Living Room"

            [audio]
            backend = "cpal"
            host = "asio"
            pcm_fifo_ms = 200
            start_watermark_ms = 100
            low_watermark_ms = 50
            target_watermark_ms = 100

            [ptp]
            backend = "nqptp"
            
            [airplay]
            advertised_format_policy = "alac-only"
            "#,
        )
        .unwrap();

        assert_eq!(config.mdns.backend, MdnsBackendName::Auto);
        assert_eq!(config.audio.host, AudioHostName::Asio);
        assert_eq!(config.ptp.backend, PtpBackendName::Nqptp);
        assert_eq!(
            config.airplay.advertised_format_policy,
            AdvertisedFormatPolicy::AlacOnly
        );
        assert_eq!(config.audio.pcm_fifo_ms, 200);
        assert_eq!(config.audio.start_watermark_ms, 100);
        assert_eq!(config.audio.low_watermark_ms, 50);
        assert_eq!(config.audio.target_watermark_ms, 100);
    }

    #[test]
    fn audio_config_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.audio.pcm_fifo_ms, 150);
        assert_eq!(config.audio.start_watermark_ms, 80);
        assert_eq!(config.audio.low_watermark_ms, 40);
        assert_eq!(config.audio.target_watermark_ms, 80);
    }

    #[test]
    fn audio_config_normalize_clamps_watermarks() {
        let mut audio = AudioConfig {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 0, // below minimum
            start_watermark_ms: 999,
            low_watermark_ms: 999,
            target_watermark_ms: 999,
        };
        audio.normalize();
        assert_eq!(audio.pcm_fifo_ms, 1);
        assert_eq!(audio.start_watermark_ms, 1);
        assert_eq!(audio.low_watermark_ms, 1);
        assert_eq!(audio.target_watermark_ms, 1);
    }

    #[test]
    fn audio_config_normalize_preserves_valid_values() {
        let mut audio = AudioConfig {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 200,
            start_watermark_ms: 100,
            low_watermark_ms: 40,
            target_watermark_ms: 80,
        };
        audio.normalize();
        assert_eq!(audio.pcm_fifo_ms, 200);
        assert_eq!(audio.start_watermark_ms, 100);
        assert_eq!(audio.low_watermark_ms, 40);
        assert_eq!(audio.target_watermark_ms, 80);
    }

    #[test]
    fn audio_config_normalize_clamps_over_maximum_fifo() {
        let mut audio = AudioConfig {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 20_000, // above MAX_PCM_FIFO_MS (10_000)
            start_watermark_ms: 15_000,
            low_watermark_ms: 5_000,
            target_watermark_ms: 10_000,
        };
        audio.normalize();
        assert_eq!(audio.pcm_fifo_ms, MAX_PCM_FIFO_MS);
        // All watermarks must be ≤ pcm_fifo_ms and ordered.
        assert!(audio.start_watermark_ms <= MAX_PCM_FIFO_MS);
        assert!(audio.low_watermark_ms <= audio.target_watermark_ms);
        assert!(audio.target_watermark_ms <= audio.start_watermark_ms);
        assert!(audio.start_watermark_ms <= audio.pcm_fifo_ms);
    }

    #[test]
    fn audio_config_normalize_fixes_inverted_watermarks() {
        let mut audio = AudioConfig {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 200,
            start_watermark_ms: 30, // lower than low → inverted
            low_watermark_ms: 100,  // higher than target → inverted
            target_watermark_ms: 50,
        };
        audio.normalize();
        // After normalization: low ≤ target ≤ start ≤ pcm_fifo_ms
        assert!(audio.low_watermark_ms <= audio.target_watermark_ms);
        assert!(audio.target_watermark_ms <= audio.start_watermark_ms);
        assert!(audio.start_watermark_ms <= audio.pcm_fifo_ms);
        // Verify concrete post-normalization values:
        // low=100, target=max(50,100)=100, start=max(30,100)=100, pcm=200
        assert_eq!(audio.low_watermark_ms, 100);
        assert_eq!(audio.target_watermark_ms, 100);
        assert_eq!(audio.start_watermark_ms, 100);
        assert_eq!(audio.pcm_fifo_ms, 200);
    }
}
