use std::{fmt, path::Path};

use anyhow::Context;
use clap::{Args, ValueEnum};
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
    pub system_media: SystemMediaConfig,
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
    /// Optional privacy-safe AP2 interoperability transcript (JSON Lines).
    pub transcript_path: Option<String>,
    pub audio_port: u16,
    pub control_port: u16,
    pub timing_port: u16,
}

impl AirplayConfig {
    /// Whether the receiver should advertise that a user-supplied AirPlay
    /// password is required.
    pub fn password_required(&self) -> bool {
        !self.pin.is_empty()
    }

    /// PIN used by HomeKit pair-setup. Upstream shairport-sync uses the
    /// protocol-standard 3939 value when no user-facing password is set.
    pub fn pairing_pin(&self) -> &str {
        if self.pin.is_empty() {
            "3939"
        } else {
            &self.pin
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum AudioBackendName {
    Cpal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct SystemMediaConfig {
    /// Publish now-playing information and accept host OS media-key commands.
    pub enabled: bool,
    /// Human-readable player name shown by the host OS.
    pub identity: String,
    /// Linux MPRIS D-Bus suffix (`org.mpris.MediaPlayer2.<bus_name>`).
    pub bus_name: String,
    /// Linux desktop-entry basename used by GNOME/KDE for player identity/icon.
    pub desktop_entry: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum PtpBackendName {
    Embedded,
    Nqptp,
    Off,
}

#[derive(Clone, Debug, Default, Args)]
pub struct ConfigOverrides {
    #[command(flatten)]
    server: ServerOverrides,
    #[command(flatten)]
    airplay: AirplayOverrides,
    #[command(flatten)]
    mdns: MdnsOverrides,
    #[command(flatten)]
    audio: AudioOverrides,
    #[command(flatten)]
    ptp: PtpOverrides,
    #[command(flatten)]
    system_media: SystemMediaOverrides,
}

#[derive(Clone, Debug, Default, Args)]
struct ServerOverrides {
    /// Local HTTP API bind address.
    #[arg(long = "server-bind", value_name = "ADDR")]
    server_bind: Option<String>,
}

#[derive(Clone, Debug, Default, Args)]
struct AirplayOverrides {
    /// Enable or disable the AirPlay listener.
    #[arg(long = "airplay-enabled", value_name = "BOOL", action = clap::ArgAction::Set)]
    airplay_enabled: Option<bool>,
    /// Enable or disable AirPlay 2 capabilities.
    #[arg(long = "airplay2-enabled", value_name = "BOOL", action = clap::ArgAction::Set)]
    airplay2_enabled: Option<bool>,
    /// RTSP/AirPlay bind address.
    #[arg(long = "airplay-bind", value_name = "ADDR")]
    airplay_bind: Option<String>,
    /// AP2 interface IP used for dynamically negotiated listeners.
    #[arg(long = "airplay-ap2-bind-ip", value_name = "IP")]
    ap2_bind_ip: Option<String>,
    /// Audio formats advertised to AirPlay senders.
    #[arg(long = "airplay-advertised-format-policy", value_enum)]
    advertised_format_policy: Option<AdvertisedFormatPolicy>,
    /// Receiver device ID / RAOP MAC-style identifier.
    #[arg(long = "airplay-device-id", value_name = "ID")]
    device_id: Option<String>,
    /// User-facing AirPlay PIN/password. An empty value disables password advertising.
    #[arg(long = "airplay-pin", value_name = "PIN")]
    pin: Option<String>,
    /// Persistent identity key path.
    #[arg(long = "airplay-identity-key-path", value_name = "PATH")]
    identity_key_path: Option<String>,
    /// Persistent pairing database path.
    #[arg(long = "airplay-pairing-db-path", value_name = "PATH")]
    pairing_db_path: Option<String>,
    /// Privacy-safe AP2 interoperability transcript path.
    #[arg(long = "airplay-transcript-path", value_name = "PATH")]
    transcript_path: Option<String>,
    /// Classic AirPlay audio UDP port.
    #[arg(long = "airplay-audio-port", value_name = "PORT")]
    audio_port: Option<u16>,
    /// Classic AirPlay control UDP port.
    #[arg(long = "airplay-control-port", value_name = "PORT")]
    control_port: Option<u16>,
    /// Classic AirPlay timing UDP port.
    #[arg(long = "airplay-timing-port", value_name = "PORT")]
    timing_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Args)]
struct MdnsOverrides {
    /// mDNS backend: auto, builtin, avahi, dns-sd, external, or off.
    #[arg(long = "mdns-backend", value_enum)]
    mdns_backend: Option<MdnsBackendName>,
    /// Network interface used for mDNS publication.
    #[arg(long = "mdns-interface", value_name = "INTERFACE")]
    interface: Option<String>,
    /// Hostname published in mDNS records.
    #[arg(long = "mdns-hostname", value_name = "HOSTNAME")]
    hostname: Option<String>,
    /// AirPlay service instance name.
    #[arg(long = "mdns-service-name", value_name = "NAME")]
    service_name: Option<String>,
    /// External mDNS publisher command.
    #[arg(long = "mdns-external-command", value_name = "COMMAND")]
    external_command: Option<String>,
}

#[derive(Clone, Debug, Default, Args)]
struct AudioOverrides {
    /// Audio output backend.
    #[arg(long = "audio-backend", value_enum)]
    audio_backend: Option<AudioBackendName>,
    /// CPAL host API.
    #[arg(long = "audio-host", value_enum)]
    host: Option<AudioHostName>,
    /// Preferred output device name.
    #[arg(long = "audio-device", value_name = "DEVICE")]
    device: Option<String>,
    /// PCM ring-buffer capacity in milliseconds.
    #[arg(long = "audio-pcm-fifo-ms", value_name = "MS")]
    pcm_fifo_ms: Option<u32>,
    /// Producer start watermark in milliseconds.
    #[arg(long = "audio-start-watermark-ms", value_name = "MS")]
    start_watermark_ms: Option<u32>,
    /// Producer low watermark in milliseconds.
    #[arg(long = "audio-low-watermark-ms", value_name = "MS")]
    low_watermark_ms: Option<u32>,
    /// Producer target watermark in milliseconds.
    #[arg(long = "audio-target-watermark-ms", value_name = "MS")]
    target_watermark_ms: Option<u32>,
}

#[derive(Clone, Debug, Default, Args)]
struct PtpOverrides {
    /// Enable or disable PTP timing.
    #[arg(long = "ptp-enabled", value_name = "BOOL", action = clap::ArgAction::Set)]
    ptp_enabled: Option<bool>,
    /// PTP timing backend.
    #[arg(long = "ptp-backend", value_enum)]
    ptp_backend: Option<PtpBackendName>,
    /// PTP event UDP port.
    #[arg(long = "ptp-event-port", value_name = "PORT")]
    event_port: Option<u16>,
    /// PTP general UDP port.
    #[arg(long = "ptp-general-port", value_name = "PORT")]
    general_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Args)]
struct SystemMediaOverrides {
    /// Enable or disable host OS media integration.
    #[arg(long = "system-media-enabled", value_name = "BOOL", action = clap::ArgAction::Set)]
    system_media_enabled: Option<bool>,
    /// Human-readable OS media player identity.
    #[arg(long = "system-media-identity", value_name = "NAME")]
    identity: Option<String>,
    /// Linux MPRIS D-Bus suffix.
    #[arg(long = "system-media-bus-name", value_name = "NAME")]
    bus_name: Option<String>,
    /// Linux desktop-entry basename.
    #[arg(long = "system-media-desktop-entry", value_name = "NAME")]
    desktop_entry: Option<String>,
}

impl Config {
    pub fn load(path: Option<&Path>, overrides: &ConfigOverrides) -> anyhow::Result<Self> {
        Self::load_with_environment(path, overrides, runtime_environment())
    }

    fn load_with_environment(
        path: Option<&Path>,
        overrides: &ConfigOverrides,
        environment: config::Environment,
    ) -> anyhow::Result<Self> {
        let defaults = config::Config::try_from(&Self::default())
            .context("failed to serialize default configuration")?;
        let mut builder = config::Config::builder().add_source(defaults);

        if let Some(path) = path {
            builder = builder.add_source(
                config::File::from(path)
                    .format(config::FileFormat::Toml)
                    .required(true),
            );
        }

        builder = builder.add_source(environment);

        macro_rules! override_option {
            ($key:literal, $value:expr) => {
                builder = builder.set_override_option($key, $value)?;
            };
        }

        override_option!("server.bind", overrides.server.server_bind.clone());

        override_option!("airplay.enabled", overrides.airplay.airplay_enabled);
        override_option!(
            "airplay.airplay2_enabled",
            overrides.airplay.airplay2_enabled
        );
        override_option!("airplay.bind", overrides.airplay.airplay_bind.clone());
        override_option!("airplay.ap2_bind_ip", overrides.airplay.ap2_bind_ip.clone());
        override_option!(
            "airplay.advertised_format_policy",
            overrides
                .airplay
                .advertised_format_policy
                .map(|value| value.to_string())
        );
        override_option!("airplay.device_id", overrides.airplay.device_id.clone());
        override_option!("airplay.pin", overrides.airplay.pin.clone());
        override_option!(
            "airplay.identity_key_path",
            overrides.airplay.identity_key_path.clone()
        );
        override_option!(
            "airplay.pairing_db_path",
            overrides.airplay.pairing_db_path.clone()
        );
        override_option!(
            "airplay.transcript_path",
            overrides.airplay.transcript_path.clone()
        );
        override_option!("airplay.audio_port", overrides.airplay.audio_port);
        override_option!("airplay.control_port", overrides.airplay.control_port);
        override_option!("airplay.timing_port", overrides.airplay.timing_port);

        override_option!(
            "mdns.backend",
            overrides.mdns.mdns_backend.map(|value| value.to_string())
        );
        override_option!("mdns.interface", overrides.mdns.interface.clone());
        override_option!("mdns.hostname", overrides.mdns.hostname.clone());
        override_option!("mdns.service_name", overrides.mdns.service_name.clone());
        override_option!(
            "mdns.external_command",
            overrides.mdns.external_command.clone()
        );

        override_option!(
            "audio.backend",
            overrides.audio.audio_backend.map(|value| value.to_string())
        );
        override_option!(
            "audio.host",
            overrides.audio.host.map(|value| value.to_string())
        );
        override_option!("audio.device", overrides.audio.device.clone());
        override_option!("audio.pcm_fifo_ms", overrides.audio.pcm_fifo_ms);
        override_option!(
            "audio.start_watermark_ms",
            overrides.audio.start_watermark_ms
        );
        override_option!("audio.low_watermark_ms", overrides.audio.low_watermark_ms);
        override_option!(
            "audio.target_watermark_ms",
            overrides.audio.target_watermark_ms
        );

        override_option!("ptp.enabled", overrides.ptp.ptp_enabled);
        override_option!(
            "ptp.backend",
            overrides.ptp.ptp_backend.map(|value| value.to_string())
        );
        override_option!("ptp.event_port", overrides.ptp.event_port);
        override_option!("ptp.general_port", overrides.ptp.general_port);

        override_option!(
            "system_media.enabled",
            overrides.system_media.system_media_enabled
        );
        override_option!(
            "system_media.identity",
            overrides.system_media.identity.clone()
        );
        override_option!(
            "system_media.bus_name",
            overrides.system_media.bus_name.clone()
        );
        override_option!(
            "system_media.desktop_entry",
            overrides.system_media.desktop_entry.clone()
        );

        let mut resolved: Self = builder
            .build()
            .context("failed to merge configuration layers")?
            .try_deserialize()
            .context("failed to deserialize merged configuration")?;
        resolved.audio.normalize();
        Ok(resolved)
    }
}

fn runtime_environment() -> config::Environment {
    config::Environment::with_prefix("SHAIRPORT_RS")
        .prefix_separator("_")
        .separator("__")
        .try_parsing(true)
}

impl Default for AirplayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            airplay2_enabled: false,
            // Empty means no user-facing AirPlay password. HomeKit SRP still
            // uses the protocol-standard 3939 value internally.
            pin: String::new(),
            identity_key_path: None,
            pairing_db_path: None,
            transcript_path: None,
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

impl Default for SystemMediaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            identity: "Shairport RS".to_string(),
            bus_name: "ShairportRS".to_string(),
            desktop_entry: "shairport-rs".to_string(),
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

impl fmt::Display for AudioBackendName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Cpal => "cpal",
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
    fn airplay_defaults_to_no_user_password_but_keeps_pairing_pin() {
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.airplay.password_required());
        assert_eq!(config.airplay.pairing_pin(), "3939");

        let configured: Config = toml::from_str(
            r#"
            [airplay]
            pin = "1234"
            "#,
        )
        .unwrap();
        assert!(configured.airplay.password_required());
        assert_eq!(configured.airplay.pairing_pin(), "1234");
    }

    #[test]
    fn system_media_defaults_enabled_and_can_be_disabled() {
        let defaults: Config = toml::from_str("").unwrap();
        assert!(defaults.system_media.enabled);
        assert_eq!(defaults.system_media.identity, "Shairport RS");
        assert_eq!(defaults.system_media.bus_name, "ShairportRS");

        let disabled: Config = toml::from_str(
            r#"
            [system_media]
            enabled = false
            "#,
        )
        .unwrap();
        assert!(!disabled.system_media.enabled);
    }

    #[test]
    fn system_media_public_config_shape_parses() {
        let config: Config = toml::from_str(
            r#"
            [system_media]
            enabled = true
            identity = "Living Room Receiver"
            bus_name = "LivingRoomReceiver"
            desktop_entry = "shairport-rs"
            "#,
        )
        .unwrap();
        assert_eq!(config.system_media.identity, "Living Room Receiver");
        assert_eq!(config.system_media.bus_name, "LivingRoomReceiver");
        assert_eq!(config.system_media.desktop_entry, "shairport-rs");
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

    #[test]
    fn layered_configuration_precedence_is_cli_then_env_then_file_then_defaults() {
        let path =
            std::env::temp_dir().join(format!("shairport-rs-config-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            r#"
            [airplay]
            audio_port = 6100

            [mdns]
            backend = "builtin"
            hostname = "from-file"
            service_name = "From File"
            "#,
        )
        .unwrap();

        let mut env = std::collections::HashMap::new();
        env.insert(
            "SHAIRPORT_RS_AIRPLAY__AUDIO_PORT".to_string(),
            "6200".to_string(),
        );
        env.insert(
            "SHAIRPORT_RS_MDNS__BACKEND".to_string(),
            "dns-sd".to_string(),
        );
        env.insert(
            "SHAIRPORT_RS_MDNS__HOSTNAME".to_string(),
            "from-env".to_string(),
        );
        env.insert(
            "SHAIRPORT_RS_SYSTEM_MEDIA__ENABLED".to_string(),
            "false".to_string(),
        );
        let environment = config::Environment::with_prefix("SHAIRPORT_RS")
            .prefix_separator("_")
            .separator("__")
            .try_parsing(true)
            .source(Some(env));

        let overrides = ConfigOverrides {
            airplay: AirplayOverrides {
                audio_port: Some(6300),
                ..Default::default()
            },
            mdns: MdnsOverrides {
                mdns_backend: Some(MdnsBackendName::Off),
                ..Default::default()
            },
            ..Default::default()
        };

        let resolved = Config::load_with_environment(Some(&path), &overrides, environment).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(resolved.airplay.audio_port, 6300); // CLI > env > file
        assert_eq!(resolved.mdns.backend, MdnsBackendName::Off); // CLI > env > file
        assert_eq!(resolved.mdns.hostname, "from-env"); // env > file
        assert_eq!(resolved.mdns.service_name, "From File"); // file > default
        assert!(!resolved.system_media.enabled); // env > default
        assert_eq!(resolved.server.bind, "127.0.0.1:3689"); // default
    }
}
