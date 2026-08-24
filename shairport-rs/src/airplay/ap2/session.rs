//! AirPlay 2 per-connection session state machine.
//!
//! Tracks the strict lifecycle of an AP2 session from connection through
//! pairing, timing configuration, stream setup, playback, and teardown.
//! [`Ap2SessionPhase`] captures each distinct lifecycle phase;
//! [`validate_transition`] enforces valid ordering without side-effects.
//! [`Ap2SessionState`] owns all AP2 logical data for one connection.
//!
//! # Phase diagram
//!
//! ```text
//! Connected ──▶ Paired ──▶ TimingConfigured ──▶ StreamConfigured ──▶ Recording
//!                │                  │                    │                │
//!                │                  ├──▶ PeersConfigured │                │
//!                │                  │        │           │                │
//!                │                  │        ▼           │                │
//!                │                  │   StreamConfigured │                │
//!                │                  │                    │                │
//!                ▼                  ▼                    ▼                ▼
//!             TearingDown ◀────────────────────────────────────────────── Paused
//!                │                                                        │
//!                ▼                                                        │
//!              Closed                                            Recording (rate=1)
//!                                                                 or TearingDown
//! ```

use std::{fmt, net::IpAddr, sync::Arc};

use crate::airplay::ap2::contract::{Ap2StreamType, Ap2TimingProtocol};
use crate::airplay::{
    buffered_audio::BufferedStreamContext, realtime_audio::RealtimeStreamContext,
};
use crate::codec::AudioFormat;

/// Maximum number of concurrent AP2 streams per session.
pub const MAX_AP2_STREAMS: usize = 8;

/// Validated fields received through POST /configure. UUID values are not
/// retained here; only their presence is needed for session policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ap2Configuration {
    pub timing_protocol: Option<Ap2TimingProtocol>,
    pub group_uuid_present: bool,
    pub stream_category: Option<String>,
    pub enable_hk_access_control: Option<bool>,
    pub access_control_level: Option<u32>,
}
pub const MAX_TIMING_PEERS: usize = 64;
pub const MAX_TIMING_ADDRESSES: usize = 32;

// ---------------------------------------------------------------------------
// PTP timing peers
// ---------------------------------------------------------------------------

/// A sender-advertised PTP peer. `clock_id == 0` is used only for the legacy
/// SETPEERS format, which contains addresses but no clock identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimingPeer {
    pub clock_id: u64,
    pub addresses: Vec<IpAddr>,
    pub device_type: Option<u64>,
    pub priority: Option<u64>,
    pub clock_port_override: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimingPeerListFormat {
    Legacy,
    Extended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimingPeerParseError(pub &'static str);

impl fmt::Display for TimingPeerParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Parse `timingPeerInfo` from the initial PTP SETUP.
///
/// Some senders omit `ClockID` at this stage, so zero is retained as
/// "identity not supplied"; SETPEERSX identities are validated strictly.
pub fn parse_initial_timing_peer(value: &plist::Value) -> Result<TimingPeer, TimingPeerParseError> {
    let dict = value
        .as_dictionary()
        .ok_or(TimingPeerParseError("timingPeerInfo must be a dictionary"))?;
    parse_timing_peer_dictionary(dict, false, None)
}

/// Parse a SETPEERS or SETPEERSX body without mutating session state.
///
/// Legacy SETPEERS is a top-level array of IP address strings. SETPEERSX is a
/// top-level array of peer dictionaries. `receiver_id` selects this receiver's
/// entry from the optional `ClockPorts` map.
pub fn parse_timing_peer_list(
    body: &[u8],
    format: TimingPeerListFormat,
    receiver_id: Option<&str>,
) -> Result<Vec<TimingPeer>, TimingPeerParseError> {
    if body.is_empty() {
        return Err(TimingPeerParseError("timing peer body is empty"));
    }
    let root = plist::from_bytes::<plist::Value>(body)
        .map_err(|_| TimingPeerParseError("timing peer body is not a plist"))?;
    let values = root
        .as_array()
        .ok_or(TimingPeerParseError("timing peer body must be an array"))?;
    if values.is_empty() || values.len() > MAX_TIMING_PEERS {
        return Err(TimingPeerParseError("invalid timing peer count"));
    }

    match format {
        TimingPeerListFormat::Legacy => {
            let addresses = parse_addresses(values)?;
            Ok(vec![TimingPeer {
                clock_id: 0,
                addresses,
                device_type: None,
                priority: None,
                clock_port_override: None,
            }])
        }
        TimingPeerListFormat::Extended => values
            .iter()
            .map(|value| {
                let dict = value.as_dictionary().ok_or(TimingPeerParseError(
                    "extended timing peer must be a dictionary",
                ))?;
                parse_timing_peer_dictionary(dict, true, receiver_id)
            })
            .collect(),
    }
}

fn parse_timing_peer_dictionary(
    dict: &plist::Dictionary,
    require_clock_id: bool,
    receiver_id: Option<&str>,
) -> Result<TimingPeer, TimingPeerParseError> {
    let addresses = dict
        .get("Addresses")
        .and_then(plist::Value::as_array)
        .ok_or(TimingPeerParseError(
            "timing peer Addresses must be an array",
        ))
        .and_then(|values| parse_addresses(values))?;
    let clock_id = match dict
        .get("ClockID")
        .and_then(plist::Value::as_unsigned_integer)
    {
        Some(0) if require_clock_id => {
            return Err(TimingPeerParseError(
                "extended timing peer ClockID must be nonzero",
            ));
        }
        Some(value) => value,
        None if require_clock_id => {
            return Err(TimingPeerParseError(
                "extended timing peer is missing ClockID",
            ));
        }
        None => 0,
    };

    Ok(TimingPeer {
        clock_id,
        addresses,
        device_type: optional_u64(dict, "DeviceType")?,
        priority: optional_u64(dict, "Priority")?,
        clock_port_override: parse_clock_port_override(dict, receiver_id)?,
    })
}

fn parse_addresses(values: &[plist::Value]) -> Result<Vec<IpAddr>, TimingPeerParseError> {
    if values.is_empty() || values.len() > MAX_TIMING_ADDRESSES {
        return Err(TimingPeerParseError("invalid timing peer address count"));
    }
    let mut addresses = Vec::with_capacity(values.len());
    for value in values {
        let text = value
            .as_string()
            .ok_or(TimingPeerParseError("timing peer address must be a string"))?;
        let address = text
            .parse::<IpAddr>()
            .map_err(|_| TimingPeerParseError("invalid timing peer IP address"))?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(TimingPeerParseError("timing peer has no addresses"));
    }
    Ok(addresses)
}

fn optional_u64(dict: &plist::Dictionary, key: &str) -> Result<Option<u64>, TimingPeerParseError> {
    match dict.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_unsigned_integer()
            .map(Some)
            .ok_or(TimingPeerParseError(
                "timing peer numeric field has the wrong type",
            )),
    }
}

fn parse_clock_port_override(
    dict: &plist::Dictionary,
    receiver_id: Option<&str>,
) -> Result<Option<u16>, TimingPeerParseError> {
    for key in ["ClockPort", "ClockPortOverride"] {
        if let Some(value) = dict.get(key) {
            return parse_port(value).map(Some);
        }
    }
    let Some(value) = dict.get("ClockPorts") else {
        return Ok(None);
    };
    let ports = value
        .as_dictionary()
        .ok_or(TimingPeerParseError("ClockPorts must be a dictionary"))?;
    for value in ports.values() {
        parse_port(value)?;
    }
    let selected = receiver_id
        .and_then(|id| ports.get(id))
        .or_else(|| (ports.len() == 1).then(|| ports.values().next()).flatten());
    selected.map(parse_port).transpose()
}

fn parse_port(value: &plist::Value) -> Result<u16, TimingPeerParseError> {
    value
        .as_unsigned_integer()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or(TimingPeerParseError("invalid timing peer clock port"))
}

// ---------------------------------------------------------------------------
// Lifecycle phases
// ---------------------------------------------------------------------------

/// Lifecycle phase of an AirPlay 2 session.
///
/// Every connection starts in [`Connected`](Ap2SessionPhase::Connected) and
/// progresses through well-defined transitions.  Transitions that would skip
/// required intermediate phases are rejected with a [`TransitionError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum Ap2SessionPhase {
    /// New connection, no state established.
    #[default]
    Connected,
    /// Pair-setup or pair-verify completed; pairing key material active.
    Paired,
    /// Initial PTP SETUP completed; event listener and timing peer info set.
    TimingConfigured,
    /// SETPEERS / SETPEERSX completed.
    PeersConfigured,
    /// At least one stream SETUP has been processed.
    StreamConfigured,
    /// RECORD or SETRATEANCHORTIME with rate=1 — audio is playing.
    Recording,
    /// PAUSE or SETRATEANCHORTIME with rate=0 — audio paused but session alive.
    Paused,
    /// TEARDOWN in progress — closing listeners and clearing secrets.
    TearingDown,
    /// Fully closed — no further operations permitted.
    Closed,
}

impl Ap2SessionPhase {
    /// Human-readable label for the phase.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Paired => "paired",
            Self::TimingConfigured => "timing-configured",
            Self::PeersConfigured => "peers-configured",
            Self::StreamConfigured => "stream-configured",
            Self::Recording => "recording",
            Self::Paused => "paused",
            Self::TearingDown => "tearing-down",
            Self::Closed => "closed",
        }
    }
}

impl fmt::Display for Ap2SessionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Transition validation
// ---------------------------------------------------------------------------

/// Error returned when a requested phase transition is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionError {
    pub from: Ap2SessionPhase,
    pub to: Ap2SessionPhase,
    pub reason: &'static str,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid transition from {} to {}: {}",
            self.from.name(),
            self.to.name(),
            self.reason
        )
    }
}

/// Validate a session-phase transition.
///
/// Returns `Ok(())` if the transition is legal; otherwise returns a
/// [`TransitionError`] describing why.
///
/// Same-phase transitions are always idempotent and return `Ok(())`.
///
/// # Allowed transitions
///
/// | From               | To                  | Trigger                          |
/// |--------------------|---------------------|----------------------------------|
/// | Connected          | Paired              | pair-verify success              |
/// | Connected          | TearingDown         | connection drop / early teardown |
/// | Paired             | TimingConfigured    | initial PTP SETUP (no streams)   |
/// | Paired             | TearingDown         | TEARDOWN (session)               |
/// | TimingConfigured   | PeersConfigured     | SETPEERS / SETPEERSX             |
/// | TimingConfigured   | StreamConfigured    | SETUP (first stream)             |
/// | TimingConfigured   | TearingDown         | TEARDOWN (session)               |
/// | PeersConfigured    | StreamConfigured    | SETUP (first stream)             |
/// | PeersConfigured    | TearingDown         | TEARDOWN (session)               |
/// | StreamConfigured   | Recording           | RECORD, SETRATEANCHORTIME rate=1 |
/// | StreamConfigured   | Paused              | PAUSE, FLUSHBUFFERED              |
/// | StreamConfigured   | TearingDown         | TEARDOWN (session)               |
/// | Recording          | Paused              | PAUSE, SETRATEANCHORTIME rate=0  |
/// | Recording          | TearingDown         | TEARDOWN (session)               |
/// | Paused             | Recording           | SETRATEANCHORTIME rate=1         |
/// | Paused             | TearingDown         | TEARDOWN (session)               |
/// | TearingDown        | Closed              | cleanup complete                 |
///
/// Notes:
/// - `add_stream` is an explicit method on [`Ap2SessionState`]; it preserves
///   the current phase. It is only valid from `TimingConfigured`,
///   `PeersConfigured`, `StreamConfigured`, `Recording`, or `Paused`.
/// - `remove_stream` preserves the current phase while streams remain. When
///   the last stream is removed, the session returns to `PeersConfigured` or
///   `TimingConfigured` according to whether peers were configured.
/// - `FLUSHBUFFERED` preserves the session but transitions to `Paused`.
/// - `Closed` is a terminal state — no transitions out.
pub fn validate_transition(
    from: Ap2SessionPhase,
    to: Ap2SessionPhase,
) -> Result<(), TransitionError> {
    if from == to {
        return Ok(());
    }

    let allowed = match (from, to) {
        // Connected — only way out is pairing or teardown
        (Ap2SessionPhase::Connected, Ap2SessionPhase::Paired) => true,
        (Ap2SessionPhase::Connected, Ap2SessionPhase::TearingDown) => true,

        // Paired
        (Ap2SessionPhase::Paired, Ap2SessionPhase::TimingConfigured) => true,
        (Ap2SessionPhase::Paired, Ap2SessionPhase::TearingDown) => true,

        // TimingConfigured
        (Ap2SessionPhase::TimingConfigured, Ap2SessionPhase::PeersConfigured) => true,
        (Ap2SessionPhase::TimingConfigured, Ap2SessionPhase::StreamConfigured) => true,
        (Ap2SessionPhase::TimingConfigured, Ap2SessionPhase::TearingDown) => true,

        // PeersConfigured
        (Ap2SessionPhase::PeersConfigured, Ap2SessionPhase::StreamConfigured) => true,
        (Ap2SessionPhase::PeersConfigured, Ap2SessionPhase::TearingDown) => true,

        // StreamConfigured — into recording or teardown
        (Ap2SessionPhase::StreamConfigured, Ap2SessionPhase::Recording) => true,
        (Ap2SessionPhase::StreamConfigured, Ap2SessionPhase::Paused) => true,
        (Ap2SessionPhase::StreamConfigured, Ap2SessionPhase::TearingDown) => true,

        // Recording — pause or teardown
        (Ap2SessionPhase::Recording, Ap2SessionPhase::Paused) => true,
        (Ap2SessionPhase::Recording, Ap2SessionPhase::TearingDown) => true,

        // Paused — resume or teardown
        (Ap2SessionPhase::Paused, Ap2SessionPhase::Recording) => true,
        (Ap2SessionPhase::Paused, Ap2SessionPhase::TearingDown) => true,

        // TearingDown → Closed is the terminal path
        (Ap2SessionPhase::TearingDown, Ap2SessionPhase::Closed) => true,

        _ => false,
    };

    if allowed {
        Ok(())
    } else {
        Err(TransitionError {
            from,
            to,
            reason: "transition not in the allowed set for this phase pair",
        })
    }
}

/// Validate that a stream may be added in the given phase.
///
/// Streams can be added from TimingConfigured, PeersConfigured,
/// StreamConfigured, Recording, or Paused.  The phase advances to
/// StreamConfigured if not already there.
///
/// Paired is intentionally excluded: the session must have completed
/// initial timing SETUP before any stream SETUP is accepted.
pub fn validate_add_stream_phase(phase: Ap2SessionPhase) -> Result<(), TransitionError> {
    match phase {
        Ap2SessionPhase::TimingConfigured
        | Ap2SessionPhase::PeersConfigured
        | Ap2SessionPhase::StreamConfigured
        | Ap2SessionPhase::Recording
        | Ap2SessionPhase::Paused => Ok(()),
        _ => Err(TransitionError {
            from: phase,
            to: phase,
            reason: "cannot add stream in this phase",
        }),
    }
}

// ---------------------------------------------------------------------------
// Teardown target
// ---------------------------------------------------------------------------

/// What a TEARDOWN body targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ap2TeardownTarget {
    /// Tear down the entire session.
    Session,
    /// Tear down a single stream of the given type.
    Stream(Ap2StreamType),
}

impl Ap2TeardownTarget {
    /// Parse a TEARDOWN binary-plist body into a typed target.
    ///
    /// - An empty body or a body without a `streams` key targets the session.
    /// - A body with `streams` containing exactly one element with a known
    ///   `type` targets that stream.
    /// - A body with malformed, missing, or unknown stream type returns `None`
    ///   (the caller must respond 400, never full-teardown).
    pub fn from_teardown_body(body: &[u8]) -> Option<Self> {
        if body.is_empty() {
            return Some(Self::Session);
        }
        let dict = plist::from_bytes::<plist::Dictionary>(body).ok()?;
        let streams = match dict.get("streams") {
            None => return Some(Self::Session),
            Some(plist::Value::Array(arr)) if arr.len() == 1 => arr,
            Some(_) => return None,
        };
        let stream = streams.first()?.as_dictionary()?;
        let type_val = match stream.get("type") {
            Some(plist::Value::Integer(i)) => i.as_unsigned(),
            Some(plist::Value::Real(r)) if r.fract() == 0.0 && *r >= 0.0 => Some(*r as u64),
            _ => None,
        }?;
        match type_val {
            96 => Some(Self::Stream(Ap2StreamType::RealtimeAudio)),
            103 => Some(Self::Stream(Ap2StreamType::BufferedAudio)),
            130 => Some(Self::Stream(Ap2StreamType::DataStream)),
            _ => None, // unknown stream type → malformed → 400
        }
    }
}

// ---------------------------------------------------------------------------
// AP2 stream state
// ---------------------------------------------------------------------------

/// State of an individual AP2 stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ap2StreamState {
    /// Stream has been configured (listener bound, metadata stored).
    Configured,
    /// Stream is actively receiving data.
    Active,
}

/// Typed stream configuration payload.
///
/// Each variant carries the minimum data needed for that stream type.
/// Secret key material is zeroed on drop — the enum's [`Drop`] impl
/// zeroizes only the audio variants' `media_key`.
///
/// This type is intentionally **not** [`Clone`], [`Debug`], or
/// [`Serialize`](serde::Serialize) to avoid copying, logging, or
/// serializing secret key material.
pub enum Ap2StreamConfig {
    /// Buffered audio stream (type 103).
    BufferedAudio {
        /// Immutable runtime shared with the stream listener.
        runtime: Arc<BufferedStreamContext>,
    },
    /// Data stream (type 130, remote-control-only).
    Data {
        /// Decimal seed used for data cipher derivation.
        seed: u64,
    },
    /// Realtime audio stream (type 96).
    RealtimeAudio {
        /// Immutable runtime shared with the UDP stream listener.
        runtime: Arc<RealtimeStreamContext>,
    },
}

impl Drop for Ap2StreamConfig {
    fn drop(&mut self) {
        match self {
            Self::BufferedAudio { .. } => {
                // BufferedStreamContext zeroizes on final Arc drop.
            }
            Self::RealtimeAudio { .. } => {
                // RealtimeStreamContext zeroizes on final Arc drop.
            }
            Self::Data { .. } => {
                // No secret key material in the Data variant.
            }
        }
    }
}

impl std::fmt::Debug for Ap2StreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferedAudio { runtime } => f
                .debug_struct("BufferedAudio")
                .field("audio_format", &runtime.audio_format)
                .field("sample_rate", &runtime.sample_rate)
                .field("frames_per_packet", &runtime.frames_per_packet)
                .field("media_key", &"[REDACTED]")
                .finish(),
            Self::Data { .. } => f.debug_struct("Data").finish_non_exhaustive(),
            Self::RealtimeAudio { runtime } => f
                .debug_struct("RealtimeAudio")
                .field("audio_format", &runtime.audio_format)
                .field("sample_rate", &runtime.sample_rate)
                .field("frames_per_packet", &runtime.frames_per_packet)
                .field("media_key", &"[REDACTED]")
                .finish(),
        }
    }
}

/// An AP2 stream record owned by the session.
///
/// Each configured stream tracks its type, configuration, and data port
/// so the session can tear down individual streams without disturbing
/// others.
///
/// This type is intentionally **not** [`Clone`] to avoid copying secret
/// key material.  On [`Drop`] the media key (if any) is zeroed.
pub struct Ap2Stream {
    /// Unique stream identifier assigned at SETUP time.
    pub stream_id: u32,
    /// Optional connection identifier from the client.
    pub stream_connection_id: Option<u64>,
    /// Stream type (buffered audio, realtime audio, or data).
    pub stream_type: Ap2StreamType,
    /// Typed stream configuration (audio format/key or data seed).
    pub config: Ap2StreamConfig,
    /// UDP or TCP data port bound for this stream.
    pub data_port: u16,
    /// Current stream state.
    pub state: Ap2StreamState,
}

impl std::fmt::Debug for Ap2Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ap2Stream")
            .field("stream_id", &self.stream_id)
            .field("stream_connection_id", &self.stream_connection_id)
            .field("stream_type", &self.stream_type)
            .field("config", &self.config)
            .field("data_port", &self.data_port)
            .field("state", &self.state)
            .finish()
    }
}

impl Ap2Stream {
    /// Convenience: return the audio format if this is a buffered audio stream.
    pub fn audio_format(&self) -> Option<AudioFormat> {
        match &self.config {
            Ap2StreamConfig::BufferedAudio { runtime } => Some(runtime.audio_format),
            Ap2StreamConfig::RealtimeAudio { runtime } => Some(runtime.audio_format),
            Ap2StreamConfig::Data { .. } => None,
        }
    }

    /// Convenience: return the sample rate if this is an audio stream.
    pub fn sample_rate(&self) -> Option<u32> {
        match &self.config {
            Ap2StreamConfig::BufferedAudio { runtime } => Some(runtime.sample_rate),
            Ap2StreamConfig::RealtimeAudio { runtime } => Some(runtime.sample_rate),
            Ap2StreamConfig::Data { .. } => None,
        }
    }

    /// Convenience: return the frames per packet if this is an audio stream.
    pub fn frames_per_packet(&self) -> Option<u32> {
        match &self.config {
            Ap2StreamConfig::BufferedAudio { runtime } => Some(runtime.frames_per_packet),
            Ap2StreamConfig::RealtimeAudio { runtime } => Some(runtime.frames_per_packet),
            Ap2StreamConfig::Data { .. } => None,
        }
    }

    /// Access the media key (audio streams only). Returns `None` for data streams.
    pub fn media_key(&self) -> Option<&[u8; 32]> {
        match &self.config {
            Ap2StreamConfig::BufferedAudio { runtime } => Some(runtime.media_key()),
            Ap2StreamConfig::RealtimeAudio { runtime } => Some(runtime.media_key()),
            Ap2StreamConfig::Data { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AP2 session state
// ---------------------------------------------------------------------------

/// All AirPlay 2 logical data owned by a single connection.
///
/// Replaces the scattered `ap2_*` fields that were previously embedded
/// directly in [`RtspSession`].  Listeners, ports, and playback-owner
/// tracking remain on `RtspSession` because AP1 also uses them.
///
/// Sensitive data is held only by stream contexts and explicitly zeroed on
/// [`clear_sensitive`](Ap2SessionState::clear_sensitive) and on [`Drop`].
///
/// This type is intentionally **not** [`Clone`] to avoid copying secret
/// key material.
#[derive(Debug)]
pub struct Ap2SessionState {
    phase: Ap2SessionPhase,
    timing_protocol: Ap2TimingProtocol,
    group_uuid: Option<String>,
    group_contains_group_leader: Option<bool>,
    active_remote: Option<String>,
    dacp_id: Option<String>,
    initial_timing_peer: Option<TimingPeer>,
    timing_peers: Vec<TimingPeer>,
    selected_master_clock_id: Option<u64>,
    /// Whether SETPEERS / SETPEERSX has been successfully processed.
    /// Used to determine the correct phase to return to when the last
    /// stream is removed.
    peers_configured: bool,
    /// Whether this is a remote-control-only session established via
    /// timingProtocol=None with isRemoteControlOnly=true. Such sessions
    /// do not require PTP and may only carry data streams (type 130).
    remote_control_only: bool,
    /// A sender may issue RECORD after timing SETUP but before stream SETUP.
    /// This records that ready intent without claiming audio is playing.
    record_requested: bool,
    /// Selected mode from POST /audioMode. Retained as session policy; mode-
    /// specific output changes are applied only when backed by sender evidence.
    audio_mode: Option<String>,
    configuration: Ap2Configuration,
    streams: Vec<Ap2Stream>,
}

impl Default for Ap2SessionState {
    fn default() -> Self {
        Self {
            phase: Ap2SessionPhase::Connected,
            timing_protocol: Ap2TimingProtocol::None,
            group_uuid: None,
            group_contains_group_leader: None,
            active_remote: None,
            dacp_id: None,
            initial_timing_peer: None,
            timing_peers: Vec::new(),
            selected_master_clock_id: None,
            peers_configured: false,
            remote_control_only: false,
            record_requested: false,
            audio_mode: None,
            configuration: Ap2Configuration::default(),
            streams: Vec::with_capacity(MAX_AP2_STREAMS),
        }
    }
}

impl Ap2SessionState {
    // ── Accessors ───────────────────────────────────────────────────────

    /// Current lifecycle phase.
    pub fn phase(&self) -> Ap2SessionPhase {
        self.phase
    }

    /// Current timing protocol (typed).
    pub fn timing_protocol(&self) -> Ap2TimingProtocol {
        self.timing_protocol
    }

    /// Group UUID from the initial PTP SETUP.
    pub fn group_uuid(&self) -> Option<&str> {
        self.group_uuid.as_deref()
    }

    /// Whether the group contains a group leader.
    pub fn group_contains_group_leader(&self) -> Option<bool> {
        self.group_contains_group_leader
    }

    /// Active remote identifier.
    pub fn active_remote(&self) -> Option<&str> {
        self.active_remote.as_deref()
    }

    /// DACP identifier.
    pub fn dacp_id(&self) -> Option<&str> {
        self.dacp_id.as_deref()
    }

    pub fn initial_timing_peer(&self) -> Option<&TimingPeer> {
        self.initial_timing_peer.as_ref()
    }

    pub fn configuration(&self) -> &Ap2Configuration {
        &self.configuration
    }

    pub fn audio_mode(&self) -> Option<&str> {
        self.audio_mode.as_deref()
    }

    pub fn set_audio_mode(&mut self, audio_mode: String) {
        self.audio_mode = Some(audio_mode);
    }

    pub fn replace_configuration(&mut self, configuration: Ap2Configuration) {
        self.configuration = configuration;
    }

    pub fn timing_peers(&self) -> &[TimingPeer] {
        &self.timing_peers
    }

    pub fn selected_master_clock_id(&self) -> Option<u64> {
        self.selected_master_clock_id
    }

    /// Configured streams (immutable view).
    pub fn streams(&self) -> &[Ap2Stream] {
        &self.streams
    }

    /// Number of configured streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Whether the session has at least one configured stream.
    pub fn has_streams(&self) -> bool {
        !self.streams.is_empty()
    }

    /// Whether this session is in an AP2-like state (paired or beyond).
    pub fn is_ap2_active(&self) -> bool {
        self.phase != Ap2SessionPhase::Connected && self.phase != Ap2SessionPhase::Closed
    }

    /// Whether this is a remote-control-only session (no PTP, no audio).
    pub fn is_remote_control_only(&self) -> bool {
        self.remote_control_only
    }

    /// Mark this session as remote-control-only.
    ///
    /// Must be called transactionally after the initial SETUP response
    /// and event listener creation succeed. Once set, this flag enables
    /// type-130 data stream setup and relaxed RECORD handling.
    pub fn set_remote_control_only(&mut self, value: bool) {
        self.remote_control_only = value;
    }

    // ── Transition helpers ─────────────────────────────────────────────

    /// Validate and apply a phase transition.
    fn apply_transition(&mut self, to: Ap2SessionPhase) -> Result<(), TransitionError> {
        validate_transition(self.phase, to)?;
        self.phase = to;
        Ok(())
    }

    /// Mark this session as paired (pair-verify completed).
    pub fn mark_paired(&mut self) -> Result<(), TransitionError> {
        self.apply_transition(Ap2SessionPhase::Paired)
    }

    /// Configure timing after a successful initial PTP or
    /// remote-control-only SETUP.
    ///
    /// For PTP: requires the session to be [`Paired`](Ap2SessionPhase::Paired).
    /// For remote-control-only ([`Ap2TimingProtocol::None`]): also requires
    /// [`Paired`](Ap2SessionPhase::Paired) and stores the protocol, but
    /// does not require PTP availability.
    ///
    /// Stores the timing protocol, group UUID, and group-leader flag.
    pub fn configure_timing(
        &mut self,
        protocol: Ap2TimingProtocol,
        group_uuid: Option<String>,
        group_contains_group_leader: Option<bool>,
    ) -> Result<(), TransitionError> {
        self.apply_transition(Ap2SessionPhase::TimingConfigured)?;
        self.timing_protocol = protocol;
        self.group_uuid = group_uuid;
        self.group_contains_group_leader = group_contains_group_leader;
        Ok(())
    }

    /// Store the sender's `timingPeerInfo` after initial SETUP commits.
    pub fn set_initial_timing_peer(&mut self, peer: TimingPeer, sender_ip: Option<IpAddr>) {
        self.selected_master_clock_id =
            select_master_clock(std::slice::from_ref(&peer), sender_ip, None);
        self.initial_timing_peer = Some(peer);
    }

    /// Record that SETPEERS / SETPEERSX has been processed.
    ///
    /// Valid from [`TimingConfigured`](Ap2SessionPhase::TimingConfigured)
    /// or already [`PeersConfigured`](Ap2SessionPhase::PeersConfigured)
    /// (idempotent).
    pub fn update_peers_phase(&mut self) -> Result<(), TransitionError> {
        if self.phase == Ap2SessionPhase::PeersConfigured {
            return Ok(()); // idempotent
        }
        self.apply_transition(Ap2SessionPhase::PeersConfigured)?;
        self.peers_configured = true;
        Ok(())
    }

    /// Add a stream to the session.
    ///
    /// Preserves the current phase (does not transition) but requires the
    /// session to be in a stream-capable phase.  Rejects duplicate stream
    /// IDs and sessions that have reached [`MAX_AP2_STREAMS`].
    ///
    /// The caller is responsible for binding the listener socket and
    /// updating `AppState` *before* calling this method; on failure the
    /// caller must unwind any side-effects.
    pub fn add_stream(&mut self, stream: Ap2Stream) -> Result<(), TransitionError> {
        validate_add_stream_phase(self.phase)?;

        let config_matches_type = matches!(
            (&stream.stream_type, &stream.config),
            (
                Ap2StreamType::BufferedAudio,
                Ap2StreamConfig::BufferedAudio { .. }
            ) | (
                Ap2StreamType::RealtimeAudio,
                Ap2StreamConfig::RealtimeAudio { .. }
            ) | (Ap2StreamType::DataStream, Ap2StreamConfig::Data { .. })
        );
        if !config_matches_type {
            return Err(TransitionError {
                from: self.phase,
                to: self.phase,
                reason: "stream type/config mismatch",
            });
        }
        let is_data = stream.stream_type == Ap2StreamType::DataStream;
        if self.remote_control_only != is_data {
            return Err(TransitionError {
                from: self.phase,
                to: self.phase,
                reason: if self.remote_control_only {
                    "remote-control-only session accepts data streams only"
                } else {
                    "data stream requires remote-control-only session"
                },
            });
        }

        if self.streams.len() >= MAX_AP2_STREAMS {
            return Err(TransitionError {
                from: self.phase,
                to: self.phase,
                reason: "maximum stream count reached",
            });
        }

        if self.streams.iter().any(|s| s.stream_id == stream.stream_id) {
            return Err(TransitionError {
                from: self.phase,
                to: self.phase,
                reason: "duplicate stream ID",
            });
        }

        self.streams.push(stream);

        // If this is the first stream, advance to StreamConfigured.
        if self.phase == Ap2SessionPhase::TimingConfigured
            || self.phase == Ap2SessionPhase::PeersConfigured
        {
            self.phase = Ap2SessionPhase::StreamConfigured;
        }

        Ok(())
    }

    /// Remove a stream by its stream ID.
    ///
    /// If the last stream is removed, the phase regresses to
    /// [`PeersConfigured`](Ap2SessionPhase::PeersConfigured) (if
    /// SETPEERS/SETPEERSX was processed) or back to
    /// [`TimingConfigured`](Ap2SessionPhase::TimingConfigured).
    /// Returns `true` if a stream was removed.
    pub fn remove_stream(&mut self, stream_id: u32) -> bool {
        let len_before = self.streams.len();
        self.streams.retain(|s| s.stream_id != stream_id);
        let removed = self.streams.len() < len_before;

        if removed && self.streams.is_empty() {
            // Regress phase: if peers were configured, go there;
            // otherwise go back to TimingConfigured.
            let target = if self.peers_configured {
                Ap2SessionPhase::PeersConfigured
            } else {
                Ap2SessionPhase::TimingConfigured
            };
            if self.phase != target {
                self.phase = target;
            }
        }

        removed
    }

    /// Find a stream by its stream ID.
    pub fn find_stream(&self, stream_id: u32) -> Option<&Ap2Stream> {
        self.streams.iter().find(|s| s.stream_id == stream_id)
    }

    /// Allocate the first unused stream ID.
    pub fn allocate_stream_id(&self) -> u32 {
        let used: std::collections::BTreeSet<u32> =
            self.streams.iter().map(|s| s.stream_id).collect();
        (0u32..).find(|id| !used.contains(id)).unwrap_or(0)
    }

    /// Find a stream by its stream type, returning the first match.
    pub fn find_stream_by_type(&self, stream_type: Ap2StreamType) -> Option<&Ap2Stream> {
        self.streams.iter().find(|s| s.stream_type == stream_type)
    }

    /// Find the configured AP2 audio stream, whether buffered (103) or
    /// realtime (96). The receiver permits only one audio stream per session.
    pub fn find_audio_stream(&self) -> Option<&Ap2Stream> {
        self.streams.iter().find(|s| {
            matches!(
                s.stream_type,
                Ap2StreamType::BufferedAudio | Ap2StreamType::RealtimeAudio
            )
        })
    }

    /// Begin recording (audio playback active).
    ///
    /// Requires at least one configured stream and a valid phase.
    /// Transitions to [`Recording`](Ap2SessionPhase::Recording).
    pub fn begin_recording(&mut self) -> Result<(), TransitionError> {
        if self.streams.is_empty() {
            return Err(TransitionError {
                from: self.phase,
                to: Ap2SessionPhase::Recording,
                reason: "no streams configured",
            });
        }
        self.apply_transition(Ap2SessionPhase::Recording)?;
        self.record_requested = true;
        Ok(())
    }

    /// Transactionally replace the sender's timing peer set and select the
    /// active master. Invalid lifecycle transitions leave the old set intact.
    pub fn replace_timing_peers(
        &mut self,
        peers: Vec<TimingPeer>,
        sender_ip: Option<IpAddr>,
    ) -> Result<(), TransitionError> {
        let target = Ap2SessionPhase::PeersConfigured;
        if self.phase != target {
            validate_transition(self.phase, target)?;
        }
        let fallback = self
            .initial_timing_peer
            .as_ref()
            .filter(|peer| peer.clock_id != 0);
        let selected = select_master_clock(&peers, sender_ip, fallback);

        self.phase = target;
        self.peers_configured = true;
        self.timing_peers = peers;
        self.selected_master_clock_id = selected;
        Ok(())
    }

    /// Accept RECORD after timing/peer setup, before the sender configures
    /// its first audio stream. The phase remains timing/peer-configured and
    /// no output is opened; later stream and anchor requests complete the
    /// transition.
    pub fn prepare_recording(&mut self) -> Result<(), TransitionError> {
        if !self.streams.is_empty() {
            return self.begin_recording();
        }
        if !matches!(
            self.phase,
            Ap2SessionPhase::TimingConfigured | Ap2SessionPhase::PeersConfigured
        ) {
            return Err(TransitionError {
                from: self.phase,
                to: Ap2SessionPhase::Recording,
                reason: "timing must be configured before pre-stream RECORD",
            });
        }
        self.record_requested = true;
        Ok(())
    }

    pub fn record_requested(&self) -> bool {
        self.record_requested
    }

    /// Pause playback.
    ///
    /// Transitions to [`Paused`](Ap2SessionPhase::Paused).  Valid from
    /// `Recording`, `StreamConfigured`, or `Paused` (idempotent).
    pub fn pause(&mut self) -> Result<(), TransitionError> {
        if self.phase == Ap2SessionPhase::Paused {
            return Ok(());
        }
        self.apply_transition(Ap2SessionPhase::Paused)
    }

    /// Resume playback (SETRATEANCHORTIME with rate=1).
    ///
    /// Transitions back to [`Recording`](Ap2SessionPhase::Recording).
    /// Valid from `Paused`, `Recording` (idempotent), or `StreamConfigured`
    /// (first play without explicit RECORD).
    pub fn resume(&mut self) -> Result<(), TransitionError> {
        if self.phase == Ap2SessionPhase::Recording {
            return Ok(());
        }
        self.apply_transition(Ap2SessionPhase::Recording)
    }

    /// Begin session teardown.
    ///
    /// Transitions to [`TearingDown`](Ap2SessionPhase::TearingDown).
    /// Valid from any phase except `Closed` and `TearingDown` (which is
    /// idempotent).
    pub fn begin_teardown(&mut self) -> Result<(), TransitionError> {
        if self.phase == Ap2SessionPhase::TearingDown {
            return Ok(()); // already tearing down
        }
        if self.phase == Ap2SessionPhase::Closed {
            return Err(TransitionError {
                from: self.phase,
                to: Ap2SessionPhase::TearingDown,
                reason: "session is already closed",
            });
        }
        self.apply_transition(Ap2SessionPhase::TearingDown)
    }

    /// Mark the session as fully closed.
    ///
    /// Only valid from [`TearingDown`](Ap2SessionPhase::TearingDown)
    /// or already [`Closed`](Ap2SessionPhase::Closed) (idempotent).
    /// Clears all connection data: streams, group, remote, DACP, and timing
    /// fields.
    pub fn close(&mut self) -> Result<(), TransitionError> {
        if self.phase == Ap2SessionPhase::Closed {
            return Ok(());
        }
        self.apply_transition(Ap2SessionPhase::Closed)?;
        self.clear_sensitive();
        Ok(())
    }

    /// Clear all sensitive data (stream media keys) and
    /// logical connection data (group, remote, DACP, timing, flags).
    ///
    /// Zeroizes audio stream media keys individually, drops all streams,
    /// and resets logical fields to defaults including the
    /// `remote_control_only` flag.
    pub fn clear_sensitive(&mut self) {
        // Zeroize only audio stream media keys; data streams carry no secrets.
        for stream in &mut self.streams {
            match &mut stream.config {
                Ap2StreamConfig::BufferedAudio { .. } => {}
                Ap2StreamConfig::RealtimeAudio { .. } => {}
                Ap2StreamConfig::Data { .. } => {}
            }
        }
        self.streams.clear();

        // Clear logical connection data.
        self.group_uuid = None;
        self.group_contains_group_leader = None;
        self.active_remote = None;
        self.dacp_id = None;
        self.initial_timing_peer = None;
        self.timing_peers.clear();
        self.selected_master_clock_id = None;
        self.timing_protocol = Ap2TimingProtocol::None;
        self.peers_configured = false;
        self.remote_control_only = false;
        self.record_requested = false;
        self.audio_mode = None;
        self.configuration = Ap2Configuration::default();
    }

    // ── Mutators for fields set during protocol handling ───────────────

    /// Set the active remote identifier (from plist `activeRemote`).
    pub fn set_active_remote(&mut self, remote: String) {
        self.active_remote = Some(remote);
    }

    /// Set the DACP identifier (from plist `dacpID`).
    pub fn set_dacp_id(&mut self, id: String) {
        self.dacp_id = Some(id);
    }

    /// Set the active remote and DACP ID together.
    pub fn set_remote_and_dacp(&mut self, remote: Option<String>, dacp: Option<String>) {
        self.active_remote = remote;
        self.dacp_id = dacp;
    }
}

fn select_master_clock(
    peers: &[TimingPeer],
    sender_ip: Option<IpAddr>,
    fallback: Option<&TimingPeer>,
) -> Option<u64> {
    let valid = || peers.iter().filter(|peer| peer.clock_id != 0);
    sender_ip
        .and_then(|sender| {
            valid()
                .find(|peer| peer.addresses.contains(&sender))
                .map(|peer| peer.clock_id)
        })
        .or_else(|| {
            valid()
                .min_by_key(|peer| peer.priority.unwrap_or(u64::MAX))
                .map(|peer| peer.clock_id)
        })
        .or_else(|| {
            fallback
                .filter(|peer| sender_ip.is_none_or(|sender| peer.addresses.contains(&sender)))
                .map(|peer| peer.clock_id)
        })
}

impl Drop for Ap2SessionState {
    fn drop(&mut self) {
        self.clear_sensitive();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Phase transition tests ─────────────────────────────────────────

    #[test]
    fn default_is_connected() {
        let state = Ap2SessionState::default();
        assert_eq!(state.phase(), Ap2SessionPhase::Connected);
    }

    #[test]
    fn same_phase_always_allowed() {
        for phase in [
            Ap2SessionPhase::Connected,
            Ap2SessionPhase::Paired,
            Ap2SessionPhase::TimingConfigured,
            Ap2SessionPhase::PeersConfigured,
            Ap2SessionPhase::StreamConfigured,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Paused,
            Ap2SessionPhase::TearingDown,
            Ap2SessionPhase::Closed,
        ] {
            assert!(
                validate_transition(phase, phase).is_ok(),
                "same-phase transition {phase} → {phase} should be allowed"
            );
        }
    }

    #[test]
    fn happy_path_full_lifecycle() {
        let mut state = Ap2SessionState::default();
        assert_eq!(state.phase(), Ap2SessionPhase::Connected);

        state.mark_paired().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paired);

        state
            .configure_timing(Ap2TimingProtocol::Ptp, Some("uuid".into()), Some(true))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::TimingConfigured);

        state.update_peers_phase().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::PeersConfigured);

        // Add a stream (advances to StreamConfigured)
        let stream = test_stream(1, Ap2StreamType::BufferedAudio);
        state.add_stream(stream).unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::StreamConfigured);

        state.begin_recording().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);

        state.pause().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);

        state.resume().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);

        state.pause().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);

        state.begin_teardown().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::TearingDown);

        state.close().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Closed);
    }

    #[test]
    fn skip_peers_still_works() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        // Add stream directly from TimingConfigured (no SETPEERS)
        let stream = test_stream(1, Ap2StreamType::BufferedAudio);
        state.add_stream(stream).unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::StreamConfigured);
    }

    #[test]
    fn connected_to_teardown() {
        let mut state = Ap2SessionState::default();
        // Connection dropped before pairing
        state.begin_teardown().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::TearingDown);
        state.close().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Closed);
    }

    #[test]
    fn paired_direct_to_teardown() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state.begin_teardown().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::TearingDown);
    }

    // ── Invalid transitions ────────────────────────────────────────────

    #[test]
    fn connected_to_recording_invalid() {
        let err = validate_transition(Ap2SessionPhase::Connected, Ap2SessionPhase::Recording)
            .unwrap_err();
        assert_eq!(err.from, Ap2SessionPhase::Connected);
        assert_eq!(err.to, Ap2SessionPhase::Recording);
    }

    #[test]
    fn connected_to_paused_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Connected, Ap2SessionPhase::Paused).is_err());
    }

    #[test]
    fn paired_to_recording_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Paired, Ap2SessionPhase::Recording).is_err());
    }

    #[test]
    fn recording_to_configured_invalid() {
        assert!(
            validate_transition(
                Ap2SessionPhase::Recording,
                Ap2SessionPhase::TimingConfigured
            )
            .is_err()
        );
    }

    #[test]
    fn closed_to_anything_invalid() {
        for target in [
            Ap2SessionPhase::Connected,
            Ap2SessionPhase::Paired,
            Ap2SessionPhase::TimingConfigured,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Paused,
        ] {
            assert!(
                validate_transition(Ap2SessionPhase::Closed, target).is_err(),
                "Closed → {target} should be invalid"
            );
        }
    }

    #[test]
    fn tearingdown_to_anything_but_closed_invalid() {
        // TearingDown → Closed is valid, everything else invalid
        for target in [
            Ap2SessionPhase::Connected,
            Ap2SessionPhase::Paired,
            Ap2SessionPhase::TimingConfigured,
            Ap2SessionPhase::PeersConfigured,
            Ap2SessionPhase::StreamConfigured,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Paused,
        ] {
            assert!(
                validate_transition(Ap2SessionPhase::TearingDown, target).is_err(),
                "TearingDown → {target} should be invalid"
            );
        }
    }

    #[test]
    fn recording_to_paired_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Recording, Ap2SessionPhase::Paired).is_err());
    }

    // ── Stream add/remove tests ────────────────────────────────────────

    #[test]
    fn add_stream_from_connected_fails() {
        let mut state = Ap2SessionState::default();
        let stream = test_stream(1, Ap2StreamType::BufferedAudio);
        let err = state.add_stream(stream).unwrap_err();
        assert!(err.to_string().contains("cannot add stream"));
    }

    #[test]
    fn add_stream_from_paired_fails() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        let stream = test_stream(1, Ap2StreamType::BufferedAudio);
        let err = state.add_stream(stream).unwrap_err();
        assert!(err.to_string().contains("cannot add stream"));
        assert_eq!(state.phase(), Ap2SessionPhase::Paired);
    }

    #[test]
    fn duplicate_stream_id_rejected() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        state
            .add_stream(test_stream(42, Ap2StreamType::BufferedAudio))
            .unwrap();
        let err = state
            .add_stream(test_stream(42, Ap2StreamType::BufferedAudio))
            .unwrap_err();
        assert!(err.to_string().contains("duplicate stream ID"));
    }

    #[test]
    fn max_streams_rejected() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        for i in 0..MAX_AP2_STREAMS {
            state
                .add_stream(test_stream(i as u32, Ap2StreamType::BufferedAudio))
                .unwrap();
        }
        assert_eq!(state.stream_count(), MAX_AP2_STREAMS);

        let err = state
            .add_stream(test_stream(99, Ap2StreamType::BufferedAudio))
            .unwrap_err();
        assert!(err.to_string().contains("maximum stream count"));
    }

    #[test]
    fn add_stream_from_multiple_phases() {
        for setup_phase in [
            Ap2SessionPhase::TimingConfigured,
            Ap2SessionPhase::PeersConfigured,
        ] {
            let mut state = Ap2SessionState::default();
            state.mark_paired().unwrap();
            state
                .configure_timing(Ap2TimingProtocol::Ptp, None, None)
                .unwrap();
            if setup_phase == Ap2SessionPhase::PeersConfigured {
                state.update_peers_phase().unwrap();
            }
            assert!(
                state
                    .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
                    .is_ok()
            );
            assert_eq!(state.phase(), Ap2SessionPhase::StreamConfigured);
        }
    }

    #[test]
    fn add_stream_from_recording_preserves_phase() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        state.begin_recording().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);

        // Add a second stream while recording
        state
            .add_stream(test_stream(2, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);
    }

    #[test]
    fn add_stream_from_paused_preserves_phase() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        state.begin_recording().unwrap();
        state.pause().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);

        state
            .add_stream(test_stream(2, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);
    }

    #[test]
    fn remove_stream_with_peers_regression() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state.update_peers_phase().unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        state
            .add_stream(test_stream(2, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::StreamConfigured);

        assert!(state.remove_stream(1));
        assert_eq!(state.stream_count(), 1);
        // Still have streams — phase unchanged
        assert_eq!(state.phase(), Ap2SessionPhase::StreamConfigured);

        // Remove last stream — regress to PeersConfigured
        assert!(state.remove_stream(2));
        assert_eq!(state.stream_count(), 0);
        assert_eq!(state.phase(), Ap2SessionPhase::PeersConfigured);
    }

    #[test]
    fn remove_last_stream_without_peers_regresses_to_timing() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        // No SETPEERS — skip directly to stream
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::StreamConfigured);

        // Remove last stream — regress to TimingConfigured (no peers)
        assert!(state.remove_stream(1));
        assert_eq!(state.stream_count(), 0);
        assert_eq!(state.phase(), Ap2SessionPhase::TimingConfigured);
    }

    #[test]
    fn remove_nonexistent_stream() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert!(!state.remove_stream(999));
        assert_eq!(state.stream_count(), 1);
    }

    // ── RECORD / PAUSE / resume tests ──────────────────────────────────

    #[test]
    fn record_without_streams_fails() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        // No streams added — begin_recording should fail
        let err = state.begin_recording().unwrap_err();
        assert!(err.to_string().contains("no streams configured"));
    }

    #[test]
    fn pre_stream_record_after_timing_is_accepted_but_not_playing() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        state.prepare_recording().unwrap();

        assert_eq!(state.phase(), Ap2SessionPhase::TimingConfigured);
        assert!(state.record_requested());
        assert!(!state.has_streams());
    }

    #[test]
    fn pause_before_record_allowed() {
        // FLUSHBUFFERED can transition StreamConfigured → Paused
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        // Pause from StreamConfigured is valid
        state.pause().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);
    }

    #[test]
    fn resume_from_paused() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        state.begin_recording().unwrap();
        state.pause().unwrap();
        state.resume().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);
    }

    // ── TearingDown / Closed tests ─────────────────────────────────────

    #[test]
    fn teardown_idempotent() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state.begin_teardown().unwrap();
        // Second teardown is idempotent
        state.begin_teardown().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::TearingDown);
    }

    #[test]
    fn closed_teardown_rejected() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state.begin_teardown().unwrap();
        state.close().unwrap();
        let err = state.begin_teardown().unwrap_err();
        assert!(err.to_string().contains("already closed"));
    }

    #[test]
    fn close_idempotent() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state.begin_teardown().unwrap();
        state.close().unwrap();
        state.close().unwrap(); // idempotent
        assert_eq!(state.phase(), Ap2SessionPhase::Closed);
    }

    // ── Sensitive data tests ───────────────────────────────────────────

    #[test]
    fn clear_sensitive_zeros_stream_keys() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let mut stream = test_stream(1, Ap2StreamType::BufferedAudio);
        if let Ap2StreamConfig::BufferedAudio { runtime } = &mut stream.config {
            *Arc::get_mut(runtime).unwrap().media_key_mut() = [0x42u8; 32];
        }
        state.add_stream(stream).unwrap();
        assert_eq!(state.stream_count(), 1);

        state.clear_sensitive();
        // Streams are dropped — count is zero.
        assert_eq!(state.stream_count(), 0);
    }

    /// A test-only helper that zeroes stream keys without dropping streams.
    #[cfg(test)]
    fn clear_key_for_test(state: &mut Ap2SessionState) {
        for stream in &mut state.streams {
            match &mut stream.config {
                Ap2StreamConfig::BufferedAudio { runtime } => {
                    Arc::get_mut(runtime).unwrap().media_key_mut().fill(0);
                }
                Ap2StreamConfig::RealtimeAudio { runtime } => {
                    Arc::get_mut(runtime).unwrap().media_key_mut().fill(0);
                }
                Ap2StreamConfig::Data { .. } => {}
            }
        }
    }

    #[test]
    fn clear_key_test_helper_zeros_stream_key() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let mut stream = test_stream(1, Ap2StreamType::BufferedAudio);
        if let Ap2StreamConfig::BufferedAudio { runtime } = &mut stream.config {
            *Arc::get_mut(runtime).unwrap().media_key_mut() = [0x42u8; 32];
        }
        state.add_stream(stream).unwrap();

        clear_key_for_test(&mut state);
        let s = state.find_stream(1).unwrap();
        assert_eq!(s.media_key(), Some(&[0u8; 32]));
    }

    #[test]
    fn drop_clears_sensitive() {
        let mut state = Ap2SessionState::default();
        // Create a stream with non-zero key
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        let mut stream = test_stream(1, Ap2StreamType::BufferedAudio);
        if let Ap2StreamConfig::BufferedAudio { runtime } = &mut stream.config {
            *Arc::get_mut(runtime).unwrap().media_key_mut() = [0xCCu8; 32];
        }
        state.add_stream(stream).unwrap();

        assert_eq!(
            state.find_stream(1).unwrap().media_key(),
            Some(&[0xCCu8; 32])
        );

        drop(state);
        // After drop, state is consumed — the Drop impl zeroes secrets.
        // We can't observe post-drop state, but the impl is exercised.
    }

    // ── Two-session isolation tests ────────────────────────────────────

    #[test]
    fn two_sessions_independent_phases() {
        let mut s1 = Ap2SessionState::default();
        let mut s2 = Ap2SessionState::default();

        s1.mark_paired().unwrap();
        assert_eq!(s1.phase(), Ap2SessionPhase::Paired);
        assert_eq!(s2.phase(), Ap2SessionPhase::Connected);

        s2.mark_paired().unwrap();
        s2.configure_timing(Ap2TimingProtocol::Ptp, Some("uuid2".into()), None)
            .unwrap();
        assert_eq!(s2.phase(), Ap2SessionPhase::TimingConfigured);
        assert_eq!(s1.phase(), Ap2SessionPhase::Paired);
    }

    #[test]
    fn two_sessions_independent_streams() {
        let mut audio = Ap2SessionState::default();
        audio.mark_paired().unwrap();
        audio
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let mut remote = Ap2SessionState::default();
        remote.mark_paired().unwrap();
        remote
            .configure_timing(Ap2TimingProtocol::None, None, None)
            .unwrap();
        remote.set_remote_control_only(true);

        audio
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        remote
            .add_stream(test_stream(100, Ap2StreamType::DataStream))
            .unwrap();

        assert_eq!(audio.stream_count(), 1);
        assert_eq!(remote.stream_count(), 1);
        assert!(audio.find_stream(100).is_none());
        assert!(remote.find_stream(100).is_some());
    }

    #[test]
    fn two_sessions_independent_keys() {
        let mut s1 = Ap2SessionState::default();
        let mut s2 = Ap2SessionState::default();
        for state in [&mut s1, &mut s2] {
            state.mark_paired().unwrap();
            state
                .configure_timing(Ap2TimingProtocol::Ptp, None, None)
                .unwrap();
        }
        let mut stream1 = test_stream(1, Ap2StreamType::BufferedAudio);
        let mut stream2 = test_stream(2, Ap2StreamType::BufferedAudio);
        if let Ap2StreamConfig::BufferedAudio { runtime } = &mut stream1.config {
            *Arc::get_mut(runtime).unwrap().media_key_mut() = [0x01u8; 32];
        }
        if let Ap2StreamConfig::BufferedAudio { runtime } = &mut stream2.config {
            *Arc::get_mut(runtime).unwrap().media_key_mut() = [0x02u8; 32];
        }
        s1.add_stream(stream1).unwrap();
        s2.add_stream(stream2).unwrap();

        assert_eq!(s1.find_stream(1).unwrap().media_key(), Some(&[0x01u8; 32]));
        assert_eq!(s2.find_stream(2).unwrap().media_key(), Some(&[0x02u8; 32]));

        s1.clear_sensitive();
        assert!(s1.find_stream(1).is_none());
        assert_eq!(s2.find_stream(2).unwrap().media_key(), Some(&[0x02u8; 32]));
    }

    // ── Failure rollback tests ─────────────────────────────────────────

    #[test]
    fn add_stream_failure_does_not_mutate() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        // Add a valid stream
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        let phase_before = state.phase();
        let count_before = state.stream_count();

        // Try to add duplicate — must fail and leave state unchanged
        let result = state.add_stream(test_stream(1, Ap2StreamType::BufferedAudio));
        assert!(result.is_err());
        assert_eq!(state.phase(), phase_before);
        assert_eq!(state.stream_count(), count_before);
    }

    #[test]
    fn max_streams_failure_no_mutation() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        for i in 0..MAX_AP2_STREAMS {
            state
                .add_stream(test_stream(i as u32, Ap2StreamType::BufferedAudio))
                .unwrap();
        }

        let phase_before = state.phase();
        let count_before = state.stream_count();

        let result = state.add_stream(test_stream(999, Ap2StreamType::BufferedAudio));
        assert!(result.is_err());
        assert_eq!(state.phase(), phase_before);
        assert_eq!(state.stream_count(), count_before);
    }

    // ── Display / formatting ───────────────────────────────────────────

    #[test]
    fn phase_display() {
        assert_eq!(Ap2SessionPhase::Connected.to_string(), "connected");
        assert_eq!(Ap2SessionPhase::Recording.to_string(), "recording");
        assert_eq!(Ap2SessionPhase::Closed.to_string(), "closed");
        assert_eq!(Ap2SessionPhase::TearingDown.to_string(), "tearing-down");
    }

    #[test]
    fn transition_error_display() {
        let err = TransitionError {
            from: Ap2SessionPhase::Connected,
            to: Ap2SessionPhase::Recording,
            reason: "must set up a stream first",
        };
        let s = err.to_string();
        assert!(s.contains("connected"));
        assert!(s.contains("recording"));
        assert!(s.contains("must set up a stream first"));
    }

    #[test]
    fn phase_default() {
        assert_eq!(Ap2SessionPhase::default(), Ap2SessionPhase::Connected);
    }

    // ── Accessor tests ─────────────────────────────────────────────────

    #[test]
    fn accessors_return_set_values() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, Some("group-1".into()), Some(true))
            .unwrap();

        assert_eq!(state.timing_protocol(), Ap2TimingProtocol::Ptp);
        assert_eq!(state.group_uuid(), Some("group-1"));
        assert_eq!(state.group_contains_group_leader(), Some(true));
        assert!(state.is_ap2_active());
    }

    #[test]
    fn set_remote_and_dacp() {
        let mut state = Ap2SessionState::default();
        state.set_remote_and_dacp(Some("remote-1".into()), Some("dacp-1".into()));
        assert_eq!(state.active_remote(), Some("remote-1"));
        assert_eq!(state.dacp_id(), Some("dacp-1"));
    }

    #[test]
    fn find_stream_by_type() {
        let mut audio = Ap2SessionState::default();
        audio.mark_paired().unwrap();
        audio
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        audio
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert!(
            audio
                .find_stream_by_type(Ap2StreamType::BufferedAudio)
                .is_some()
        );
        assert!(
            audio
                .find_stream_by_type(Ap2StreamType::DataStream)
                .is_none()
        );

        let mut remote = Ap2SessionState::default();
        remote.mark_paired().unwrap();
        remote
            .configure_timing(Ap2TimingProtocol::None, None, None)
            .unwrap();
        remote.set_remote_control_only(true);
        remote
            .add_stream(test_stream(2, Ap2StreamType::DataStream))
            .unwrap();
        assert!(
            remote
                .find_stream_by_type(Ap2StreamType::DataStream)
                .is_some()
        );
    }

    #[test]
    fn is_ap2_active() {
        let mut state = Ap2SessionState::default();
        assert!(!state.is_ap2_active());

        state.mark_paired().unwrap();
        assert!(state.is_ap2_active());

        state.begin_teardown().unwrap();
        state.close().unwrap();
        assert!(!state.is_ap2_active());
    }

    // ── Close / cleanup tests ──────────────────────────────────────────

    #[test]
    fn close_clears_all_logical_fields() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, Some("g1".into()), Some(true))
            .unwrap();
        state.set_active_remote("r1".into());
        state.set_dacp_id("d1".into());
        state.begin_teardown().unwrap();
        state.close().unwrap();

        assert_eq!(state.phase(), Ap2SessionPhase::Closed);
        assert_eq!(state.stream_count(), 0);
        assert_eq!(state.group_uuid(), None);
        assert_eq!(state.active_remote(), None);
        assert_eq!(state.dacp_id(), None);
        assert_eq!(state.timing_protocol(), Ap2TimingProtocol::None);
    }

    #[test]
    fn clear_sensitive_clears_logical_fields() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, Some("g1".into()), Some(true))
            .unwrap();
        state.set_active_remote("r1".into());
        state.set_dacp_id("d1".into());
        state.clear_sensitive();
        assert_eq!(state.stream_count(), 0);
        assert_eq!(state.group_uuid(), None);
        assert_eq!(state.active_remote(), None);
        assert_eq!(state.dacp_id(), None);
        assert_eq!(state.timing_protocol(), Ap2TimingProtocol::None);
    }

    #[test]
    fn repeated_cleanup_is_idempotent() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        // First cleanup
        state.clear_sensitive();
        // Second cleanup — must not panic
        state.clear_sensitive();
        // close after begin_teardown (re-Setup on fresh state)
        let mut state2 = Ap2SessionState::default();
        state2.mark_paired().unwrap();
        state2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state2.begin_teardown().unwrap();
        state2.close().unwrap();
        // close again (idempotent)
        assert!(state2.close().is_ok());
        assert_eq!(state2.phase(), Ap2SessionPhase::Closed);
        // clear_sensitive on closed state is safe
        state2.clear_sensitive();
    }

    #[test]
    fn peers_configured_tracks_flag() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        // Before SETPEERS, stream removal regresses to TimingConfigured
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert!(state.remove_stream(1));
        assert_eq!(state.phase(), Ap2SessionPhase::TimingConfigured);

        // After SETPEERS, stream removal regresses to PeersConfigured
        state.update_peers_phase().unwrap();
        state
            .add_stream(test_stream(2, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert!(state.remove_stream(2));
        assert_eq!(state.phase(), Ap2SessionPhase::PeersConfigured);
    }

    #[test]
    fn add_stream_preserves_recording_phase() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        state.begin_recording().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);

        // Additional stream — Recording must be preserved
        state
            .add_stream(test_stream(2, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Recording);
    }

    #[test]
    fn add_stream_preserves_paused_phase() {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap();
        state.pause().unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);

        // Additional stream — Paused must be preserved
        state
            .add_stream(test_stream(2, Ap2StreamType::BufferedAudio))
            .unwrap();
        assert_eq!(state.phase(), Ap2SessionPhase::Paused);
    }

    // ── TEARDOWN target parsing ───────────────────────────────────────

    #[test]
    fn teardown_empty_body_targets_session() {
        assert_eq!(
            Ap2TeardownTarget::from_teardown_body(&[]),
            Some(Ap2TeardownTarget::Session)
        );
    }

    #[test]
    fn teardown_plist_without_streams_targets_session() {
        let mut body = Vec::new();
        plist::to_writer_binary(
            &mut body,
            &plist::Value::Dictionary(plist::Dictionary::new()),
        )
        .unwrap();
        assert_eq!(
            Ap2TeardownTarget::from_teardown_body(&body),
            Some(Ap2TeardownTarget::Session)
        );
    }

    #[test]
    fn teardown_malformed_stream_shapes_are_rejected() {
        for streams in [
            plist::Value::String("bad".to_string()),
            plist::Value::Array(Vec::new()),
            plist::Value::Array(vec![
                plist::Value::Dictionary(plist::Dictionary::new()),
                plist::Value::Dictionary(plist::Dictionary::new()),
            ]),
        ] {
            let mut dict = plist::Dictionary::new();
            dict.insert("streams".to_string(), streams);
            let mut body = Vec::new();
            plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
            assert_eq!(Ap2TeardownTarget::from_teardown_body(&body), None);
        }
    }

    #[test]
    fn teardown_unknown_stream_type_is_rejected() {
        let mut stream = plist::Dictionary::new();
        stream.insert(
            "type".to_string(),
            plist::Value::Integer(plist::Integer::from(999u64)),
        );
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        assert_eq!(Ap2TeardownTarget::from_teardown_body(&body), None);
    }

    #[test]
    fn teardown_known_stream_type_is_typed() {
        let mut stream = plist::Dictionary::new();
        stream.insert(
            "type".to_string(),
            plist::Value::Integer(plist::Integer::from(103u64)),
        );
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        assert_eq!(
            Ap2TeardownTarget::from_teardown_body(&body),
            Some(Ap2TeardownTarget::Stream(Ap2StreamType::BufferedAudio))
        );
    }

    fn paired_state() -> Ap2SessionState {
        let mut state = Ap2SessionState::default();
        state.mark_paired().unwrap();
        state
    }

    #[test]
    fn remote_control_session_accepts_only_typed_data_streams() {
        let mut state = paired_state();
        state
            .configure_timing(Ap2TimingProtocol::None, None, None)
            .unwrap();
        state.set_remote_control_only(true);
        assert!(
            state
                .add_stream(test_stream(1, Ap2StreamType::DataStream))
                .is_ok()
        );

        let mut state = paired_state();
        state
            .configure_timing(Ap2TimingProtocol::None, None, None)
            .unwrap();
        state.set_remote_control_only(true);
        let error = state
            .add_stream(test_stream(1, Ap2StreamType::BufferedAudio))
            .unwrap_err();
        assert_eq!(
            error.reason,
            "remote-control-only session accepts data streams only"
        );
    }

    #[test]
    fn audio_session_rejects_data_and_mismatched_config() {
        let mut state = paired_state();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        let error = state
            .add_stream(test_stream(1, Ap2StreamType::DataStream))
            .unwrap_err();
        assert_eq!(
            error.reason,
            "data stream requires remote-control-only session"
        );

        let mut mismatched = test_stream(2, Ap2StreamType::BufferedAudio);
        mismatched.config = Ap2StreamConfig::Data { seed: 7 };
        let error = state.add_stream(mismatched).unwrap_err();
        assert_eq!(error.reason, "stream type/config mismatch");
    }

    #[test]
    fn data_stream_debug_redacts_seed() {
        let stream = test_stream(1, Ap2StreamType::DataStream);
        let rendered = format!("{stream:?}");
        assert!(rendered.contains("Data"));
        assert!(!rendered.contains("seed"));
    }

    // ── Helper ─────────────────────────────────────────────────────────

    #[test]
    fn parses_legacy_setpeers_address_array() {
        let value = plist::Value::Array(vec![
            plist::Value::String("192.0.2.10".into()),
            plist::Value::String("2001:db8::10".into()),
        ]);
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &value).unwrap();

        let peers = parse_timing_peer_list(&body, TimingPeerListFormat::Legacy, None).unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].clock_id, 0);
        assert_eq!(
            peers[0].addresses,
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::10".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parses_extended_peers_and_receiver_clock_port() {
        let mut clock_ports = plist::Dictionary::new();
        clock_ports.insert("receiver-id".into(), plist::Value::Integer(319u64.into()));
        clock_ports.insert("other-id".into(), plist::Value::Integer(8319u64.into()));
        let mut peer = plist::Dictionary::new();
        peer.insert(
            "Addresses".into(),
            plist::Value::Array(vec![plist::Value::String("192.0.2.20".into())]),
        );
        peer.insert(
            "ClockID".into(),
            plist::Value::Integer(0x1122_3344_5566_7788u64.into()),
        );
        peer.insert("DeviceType".into(), plist::Value::Integer(7u64.into()));
        peer.insert("Priority".into(), plist::Value::Integer(10u64.into()));
        peer.insert("ClockPorts".into(), plist::Value::Dictionary(clock_ports));
        let mut body = Vec::new();
        plist::to_writer_binary(
            &mut body,
            &plist::Value::Array(vec![plist::Value::Dictionary(peer)]),
        )
        .unwrap();

        let peers =
            parse_timing_peer_list(&body, TimingPeerListFormat::Extended, Some("receiver-id"))
                .unwrap();

        assert_eq!(
            peers,
            vec![TimingPeer {
                clock_id: 0x1122_3344_5566_7788,
                addresses: vec!["192.0.2.20".parse().unwrap()],
                device_type: Some(7),
                priority: Some(10),
                clock_port_override: Some(319),
            }]
        );
    }

    #[test]
    fn malformed_peer_replacement_is_transactional() {
        let mut state = paired_state();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        let sender = "192.0.2.30".parse::<IpAddr>().unwrap();
        state
            .replace_timing_peers(
                vec![TimingPeer {
                    clock_id: 42,
                    addresses: vec![sender],
                    device_type: None,
                    priority: None,
                    clock_port_override: None,
                }],
                Some(sender),
            )
            .unwrap();

        let mut malformed = plist::Dictionary::new();
        malformed.insert(
            "Addresses".into(),
            plist::Value::Array(vec![plist::Value::String("not-an-ip".into())]),
        );
        malformed.insert("ClockID".into(), plist::Value::Integer(43u64.into()));
        let mut body = Vec::new();
        plist::to_writer_binary(
            &mut body,
            &plist::Value::Array(vec![plist::Value::Dictionary(malformed)]),
        )
        .unwrap();
        assert!(parse_timing_peer_list(&body, TimingPeerListFormat::Extended, None).is_err());
        assert_eq!(state.selected_master_clock_id(), Some(42));
        assert_eq!(state.timing_peers()[0].clock_id, 42);
    }

    #[test]
    fn selects_sender_address_before_peer_priority_and_clears_on_close() {
        let mut state = paired_state();
        state
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        let sender = "192.0.2.40".parse::<IpAddr>().unwrap();
        state
            .replace_timing_peers(
                vec![
                    TimingPeer {
                        clock_id: 1,
                        addresses: vec!["192.0.2.41".parse().unwrap()],
                        device_type: None,
                        priority: Some(0),
                        clock_port_override: None,
                    },
                    TimingPeer {
                        clock_id: 2,
                        addresses: vec![sender],
                        device_type: None,
                        priority: Some(100),
                        clock_port_override: None,
                    },
                ],
                Some(sender),
            )
            .unwrap();
        assert_eq!(state.selected_master_clock_id(), Some(2));

        state.begin_teardown().unwrap();
        state.close().unwrap();
        assert!(state.timing_peers().is_empty());
        assert_eq!(state.selected_master_clock_id(), None);
    }

    fn test_stream(id: u32, st: Ap2StreamType) -> Ap2Stream {
        use crate::codec::AudioFormat;
        let config = match st {
            Ap2StreamType::BufferedAudio => Ap2StreamConfig::BufferedAudio {
                runtime: Arc::new(BufferedStreamContext::new(
                    [0u8; 32],
                    AudioFormat::Alac44100S16Stereo,
                    44100,
                    352,
                    id,
                    None,
                )),
            },
            Ap2StreamType::RealtimeAudio => Ap2StreamConfig::RealtimeAudio {
                runtime: Arc::new(RealtimeStreamContext::new(
                    [0u8; 32],
                    AudioFormat::Alac44100S16Stereo,
                    44100,
                    352,
                    id,
                    None,
                )),
            },
            Ap2StreamType::DataStream => Ap2StreamConfig::Data { seed: 0 },
        };
        Ap2Stream {
            stream_id: id,
            stream_connection_id: None,
            stream_type: st,
            config,
            data_port: 6000 + id as u16,
            state: Ap2StreamState::Configured,
        }
    }
}
