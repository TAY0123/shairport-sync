//! AirPlay 2 API contract registry and validation.
//!
//! Every AP2 endpoint is described by a [`Ap2Contract`] entry in the static
//! [`AP2_CONTRACTS`] slice.  Validation functions classify a lightweight
//! [`Ap2RequestView`] against the registry and produce structured
//! [`ContractError`] values.
//!
//! # Contract entries (21 total)
//!
//! | # | Method              | URI           | Phase          |
//! |---|---------------------|---------------|----------------|
//! | 1 | GET                 | /info         | Discovery      |
//! | 2 | POST                | /pair-setup   | Pairing        |
//! | 3 | POST                | /pair-verify  | Pairing        |
//! | 4 | POST                | /pair-add     | Pairing        |
//! | 5 | POST                | /pair-remove  | Pairing        |
//! | 6 | POST                | /pair-list    | Pairing        |
//! | 7 | POST                | /fp-setup     | FairPlay       |
//! | 8 | POST                | /configure    | Configuration  |
//! | 9 | POST                | /audioMode    | Audio          |
//! |10 | POST                | /command      | Control        |
//! |11 | POST                | /feedback     | Feedback       |
//! |12 | SETUP               | * (initial)   | Stream setup   |
//! |13 | SETUP               | * (stream)    | Stream add     |
//! |14 | SETPEERS            | *             | Peers          |
//! |15 | SETPEERSX           | *             | Peers ext.     |
//! |16 | RECORD              | *             | Playback       |
//! |17 | SETRATEANCHORTIME   | *             | Timing         |
//! |18 | PAUSE               | *             | Playback       |
//! |19 | FLUSHBUFFERED       | *             | Playback       |
//! |20 | TEARDOWN            | * (stream)    | Teardown       |
//! |21 | TEARDOWN            | * (session)   | Teardown       |

use std::fmt;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Every RTSP / HTTP method used by the AirPlay 2 protocol surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2Method {
    Get,
    Post,
    Setup,
    Record,
    Pause,
    FlushBuffered,
    Teardown,
    SetPeers,
    SetPeersX,
    SetRateAnchorTime,
}

impl Ap2Method {
    /// Best-effort parse from a case-insensitive method string.
    pub fn from_str(s: &str) -> Option<Self> {
        let upper = s.to_ascii_uppercase();
        match upper.as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "SETUP" => Some(Self::Setup),
            "RECORD" => Some(Self::Record),
            "PAUSE" => Some(Self::Pause),
            "FLUSHBUFFERED" => Some(Self::FlushBuffered),
            "TEARDOWN" => Some(Self::Teardown),
            "SETPEERS" => Some(Self::SetPeers),
            "SETPEERSX" => Some(Self::SetPeersX),
            "SETRATEANCHORTIME" | "SETRATEANCHORTI" => Some(Self::SetRateAnchorTime),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Setup => "SETUP",
            Self::Record => "RECORD",
            Self::Pause => "PAUSE",
            Self::FlushBuffered => "FLUSHBUFFERED",
            Self::Teardown => "TEARDOWN",
            Self::SetPeers => "SETPEERS",
            Self::SetPeersX => "SETPEERSX",
            Self::SetRateAnchorTime => "SETRATEANCHORTIME",
        }
    }
}

impl fmt::Display for Ap2Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Known AirPlay 2 URI paths.  Methods with variable URIs (SETUP, RECORD, …)
/// use [`Ap2Endpoint::Any`] and are disambiguated by method + content-type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2Endpoint {
    /// Exact path, e.g. `/info`
    Path(&'static str),
    /// Matches any URI (used for RTSP methods where the path is free-form).
    Any,
}

impl Ap2Endpoint {
    pub fn matches(&self, uri: &str) -> bool {
        match self {
            Self::Path(p) => uri.eq_ignore_ascii_case(p),
            Self::Any => true,
        }
    }
}

impl fmt::Display for Ap2Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(p) => f.write_str(p),
            Self::Any => f.write_str("*"),
        }
    }
}

/// Expected request/response content type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2ContentType {
    /// `application/x-apple-binary-plist`
    BinaryPlist,
    /// `application/octet-stream`
    OctetStream,
    /// `text/parameters` (classic AirPlay SETUP)
    TextParameters,
    /// No body / content-type not required.
    None,
}

impl Ap2ContentType {
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            Self::BinaryPlist => Some("application/x-apple-binary-plist"),
            Self::OctetStream => Some("application/octet-stream"),
            Self::TextParameters => Some("text/parameters"),
            Self::None => None,
        }
    }

    /// Check whether a given `Content-Type` header value matches.
    ///
    /// Matching is case-insensitive and ignores charset parameters — we only
    /// require that `actual` *contains* the expected media-type substring.
    pub fn matches_header(&self, actual: Option<&str>) -> bool {
        let expected = match self.as_str() {
            Some(ct) => ct,
            None => return actual.is_none(),
        };
        let Some(actual) = actual else { return false };
        actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase())
    }
}

/// Timing protocol negotiated during SETUP.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2TimingProtocol {
    /// Precision Time Protocol (IEEE 1588).
    Ptp,
    /// Network Time Protocol.
    Ntp,
    /// No timing protocol — realtime streams only.
    None,
}

impl Ap2TimingProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "PTP" | "ptp" => Some(Self::Ptp),
            "NTP" | "ntp" => Some(Self::Ntp),
            "None" | "none" | "" => Some(Self::None),
            _ => None,
        }
    }
}

/// AP2 stream types as they appear in SETUP/TEARDOWN plist `streams[].type`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2StreamType {
    /// Realtime audio (UDP, type 96).
    RealtimeAudio = 96,
    /// Buffered audio (TCP, type 103).
    BufferedAudio = 103,
    /// Data / event stream (type 130).
    DataStream = 130,
}

impl Ap2StreamType {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            96 => Some(Self::RealtimeAudio),
            103 => Some(Self::BufferedAudio),
            130 => Some(Self::DataStream),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> u64 {
        *self as u64
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::RealtimeAudio => "realtime-audio",
            Self::BufferedAudio => "buffered-audio",
            Self::DataStream => "data-stream",
        }
    }
}

/// Side-effect a successful operation has on session / playback state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2StateEffect {
    /// Establishes pairing state (shared secret, encryption keys).
    PairingEstablished,
    /// Activates control cipher.
    ControlCipherActive,
    /// Activates event cipher.
    EventCipherActive,
    /// Session ID assigned.
    SessionCreated,
    /// Audio ports opened and bound.
    AudioPortsOpen,
    /// Playback transitions to Playing.
    PlaybackStarted,
    /// Playback starts only for audio sessions; control-only RECORD is an acknowledgement.
    PlaybackConditionallyStarted,
    /// Playback transitions to Paused.
    PlaybackPaused,
    /// Playback stops, listeners aborted, keys cleared.
    PlaybackStopped,
    /// Encrypted AP2 data-stream TCP port opened.
    DataPortOpen,
    /// Single stream listener aborted.
    StreamListenerClosed,
    /// Media key derived / refreshed.
    MediaKeyDerived,
    /// Timing protocol and peer identity configured.
    TimingConfigured,
    /// AP2 event listener opened.
    EventPortOpen,
    /// Timing anchor applied.
    TimingAnchorSet,
    /// Volume / audio mode changed.
    AudioModeChanged,
    /// Peer list updated.
    PeersUpdated,
    /// Player state set to Active (waiting for stream).
    ActiveSet,
    /// General diagnostic / metadata update.
    DiagnosticUpdate,
    /// Session phase changed (connected → paired → configured → …).
    PhaseTransition,
    /// AP2 stream added to session.
    StreamAdded,
    /// AP2 stream removed from session.
    StreamRemoved,
}

impl fmt::Display for Ap2StateEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PairingEstablished => "pairing-established",
            Self::ControlCipherActive => "control-cipher-active",
            Self::EventCipherActive => "event-cipher-active",
            Self::SessionCreated => "session-created",
            Self::AudioPortsOpen => "audio-ports-open",
            Self::PlaybackStarted => "playback-started",
            Self::PlaybackConditionallyStarted => "playback-conditionally-started",
            Self::PlaybackPaused => "playback-paused",
            Self::PlaybackStopped => "playback-stopped",
            Self::DataPortOpen => "data-port-open",
            Self::StreamListenerClosed => "stream-listener-closed",
            Self::MediaKeyDerived => "media-key-derived",
            Self::TimingConfigured => "timing-configured",
            Self::EventPortOpen => "event-port-open",
            Self::TimingAnchorSet => "timing-anchor-set",
            Self::AudioModeChanged => "audio-mode-changed",
            Self::PeersUpdated => "peers-updated",
            Self::ActiveSet => "active-set",
            Self::DiagnosticUpdate => "diagnostic-update",
            Self::PhaseTransition => "phase-transition",
            Self::StreamAdded => "stream-added",
            Self::StreamRemoved => "stream-removed",
        })
    }
}

/// Whether repeating the same request is safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2Idempotency {
    /// Repeating the request is safe and should produce the same result.
    Idempotent,
    /// Repeating the request may have side-effects (e.g. double-setup).
    NotIdempotent,
}

/// How the server handles errors for a given endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2ErrorPolicy {
    /// Malformed request → 400; internal failure → 500/503.
    Standard,
    /// The endpoint is a firewall: bad input → 400, anything else → ignored.
    BestEffort,
    /// The endpoint never fails from the client's perspective (always 200).
    AlwaysOk,
}

/// Implementation fidelity of each contract entry in the current codebase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2ImplementationStatus {
    /// Endpoint recognised but handler is a placeholder / no-op.
    Stub,
    /// Core logic exists but edge cases / spec details may be missing.
    Partial,
    /// Full protocol implementation believed complete.
    Implemented,
}

impl fmt::Display for Ap2ImplementationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stub => "Stub",
            Self::Partial => "Partial",
            Self::Implemented => "Implemented",
        })
    }
}

/// Extra predicate for disambiguating contracts that share the same
/// (method, endpoint, content-type) signature.
///
/// When two or more contracts have identical method/endpoint/CT, the
/// discriminator inspects the parsed plist dictionary to pick the correct
/// entry.  This makes classification independent of registry order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2RequestDiscriminator {
    /// No extra check — contract matches on method/URI/CT alone.
    None,
    /// The plist dictionary must contain the given key for the contract to
    /// match. When `plist_dict` is `None` the discriminator fails.
    HasPlistKey(&'static str),
    /// The plist dictionary must contain `required` and must not contain
    /// `excluded`. This disambiguates initial SETUP from stream SETUP when
    /// both use the same method, URI, and content type.
    HasPlistKeyWithout {
        required: &'static str,
        excluded: &'static str,
    },
    /// Initial PTP SETUP: `timingProtocol=PTP` and no `streams` key.
    InitialPtpSetup,
    /// Initial control-only SETUP: `timingProtocol=None`,
    /// `isRemoteControlOnly=true`, and no `streams` key.
    InitialRemoteControlSetup,
    /// Stream SETUP whose first stream dictionary has the given numeric type.
    StreamType(u64),
}

// ---------------------------------------------------------------------------
// Contract struct
// ---------------------------------------------------------------------------

/// One entry in the AirPlay 2 API conformance matrix.
#[derive(Clone, Debug)]
pub struct Ap2Contract {
    /// RTSP method (GET, POST, SETUP, …).
    pub method: Ap2Method,
    /// URI path or [`Ap2Endpoint::Any`].
    pub endpoint: Ap2Endpoint,
    /// Human-readable label for the operation.
    pub operation: &'static str,
    /// Expected `Content-Type` on the request.
    pub request_content_type: Ap2ContentType,
    /// Keys that **must** appear in a binary-plist request body.
    pub required_request_keys: &'static [&'static str],
    /// Keys that **may** appear in a binary-plist request body.
    pub optional_request_keys: &'static [&'static str],
    /// Expected HTTP/RTSP status code on success.
    pub expected_status: u16,
    /// Expected `Content-Type` on the response.
    pub response_content_type: Ap2ContentType,
    /// Keys that **must** appear in a binary-plist response body.
    pub required_response_keys: &'static [&'static str],
    /// Whether the operation is safe to repeat.
    pub idempotency: Ap2Idempotency,
    /// State / playback effects of a successful invocation.
    pub state_effects: &'static [Ap2StateEffect],
    /// How errors are surfaced to the client.
    pub error_policy: Ap2ErrorPolicy,
    /// Current implementation fidelity.
    pub implementation: Ap2ImplementationStatus,
    /// Extra predicate for disambiguating contracts that share the same
    /// (method, endpoint, content-type) triple.  `None` for most entries.
    pub discriminator: Ap2RequestDiscriminator,
}

// ---------------------------------------------------------------------------
// Validation error
// ---------------------------------------------------------------------------

/// A single contract-validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// Unknown or unsupported method.
    UnknownMethod(String),
    /// No contract entry matches (method + URI + content-type).
    UnsupportedOperation {
        method: String,
        uri: String,
        content_type: Option<String>,
    },
    /// Content-Type header is missing.
    MissingContentType { expected: String },
    /// Content-Type header does not match the expected value.
    WrongContentType { expected: String, actual: String },
    /// A required plist key is absent.
    MissingRequiredKey { key: &'static str },
    /// The request body is not valid binary plist.
    InvalidPlistBody(String),
    /// A required response key is absent.
    MissingResponseKey { key: &'static str },
    /// Response status does not match the contract.
    WrongResponseStatus { expected: u16, actual: u16 },
    /// Response Content-Type does not match the contract.
    WrongResponseContentType { expected: String, actual: String },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMethod(m) => write!(f, "unknown method: {m}"),
            Self::UnsupportedOperation {
                method,
                uri,
                content_type,
            } => {
                write!(
                    f,
                    "unsupported operation: {method} {uri} (content-type: {})",
                    content_type.as_deref().unwrap_or("none")
                )
            }
            Self::MissingContentType { expected } => {
                write!(f, "missing Content-Type header (expected {expected})")
            }
            Self::WrongContentType { expected, actual } => {
                write!(f, "wrong Content-Type: expected {expected}, got {actual}")
            }
            Self::MissingRequiredKey { key } => {
                write!(f, "missing required plist key: {key}")
            }
            Self::InvalidPlistBody(e) => write!(f, "invalid plist body: {e}"),
            Self::MissingResponseKey { key } => {
                write!(f, "missing required response plist key: {key}")
            }
            Self::WrongResponseStatus { expected, actual } => {
                write!(
                    f,
                    "wrong response status: expected {expected}, got {actual}"
                )
            }
            Self::WrongResponseContentType { expected, actual } => {
                write!(
                    f,
                    "wrong response Content-Type: expected {expected}, got {actual}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Static contract registry
// ---------------------------------------------------------------------------

/// Complete AirPlay 2 API contract registry.
///
/// Entries are ordered by logical protocol phase: discovery → pairing →
/// FairPlay → configuration → stream setup → playback → teardown.
///
/// # Implementation status notes
///
/// We only mark an entry **Implemented** when the handler in `rtsp.rs` fully
/// implements the sub-protocol.  Entries like `/pair-setup` and
/// `/pair-verify` have complete SRP + Ed25519 logic in `pairing.rs` →
/// Implemented.  `/fp-setup` and `/configure` are acknowledged but the
/// FairPlay implementation is a stub → Stub. `SETUP` with buffered audio
/// (type 103) + PTP timing is Partial because timeline anchors are not yet
/// applied to scheduler deadlines. Remote-control-only initial SETUP is
/// implemented. Data-stream SETUP and encrypted transport (type 130) are
/// Partial because MediaRemote protobuf decoding/dispatch is not implemented.
/// Realtime audio (type 96), NTP timing, and bare no-timing mode are rejected.
///
/// See `docs/AP2_API_CONFORMANCE.md` for rationale.
pub static AP2_CONTRACTS: &[Ap2Contract] = &[
    // ── Discovery ──────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Get,
        endpoint: Ap2Endpoint::Path("/info"),
        operation: "GET /info",
        request_content_type: Ap2ContentType::None,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::BinaryPlist,
        required_response_keys: &[
            "vv",
            "deviceID",
            "features",
            "statusFlags",
            "name",
            "model",
            "pi",
            "pk",
            "srcvers",
            "supportedFormats",
        ],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[],
        error_policy: Ap2ErrorPolicy::AlwaysOk,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── Pairing ────────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/pair-setup"),
        operation: "POST /pair-setup",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[Ap2StateEffect::PairingEstablished],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/pair-verify"),
        operation: "POST /pair-verify",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[
            Ap2StateEffect::PairingEstablished,
            Ap2StateEffect::ControlCipherActive,
            Ap2StateEffect::EventCipherActive,
        ],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/pair-add"),
        operation: "POST /pair-add",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[Ap2StateEffect::PeersUpdated],
        error_policy: Ap2ErrorPolicy::Standard,
        // pair-add is handled by the PairingService — the RTSP handler
        // dispatches to it.  The C reference implements full add/remove/list.
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/pair-remove"),
        operation: "POST /pair-remove",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[Ap2StateEffect::PeersUpdated],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/pair-list"),
        operation: "POST /pair-list",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── FairPlay ───────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/fp-setup"),
        operation: "POST /fp-setup",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[],
        error_policy: Ap2ErrorPolicy::BestEffort,
        // Handler echoes the request body — no real FairPlay implementation.
        implementation: Ap2ImplementationStatus::Stub,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── Configuration ──────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/configure"),
        operation: "POST /configure",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &[],
        optional_request_keys: &["timingProtocol", "groupUUID", "streamCategory"],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[],
        error_policy: Ap2ErrorPolicy::BestEffort,
        // Always acknowledged with 200; body is ignored.
        implementation: Ap2ImplementationStatus::Stub,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/audioMode"),
        operation: "POST /audioMode",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &[],
        optional_request_keys: &["audioMode"],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[Ap2StateEffect::AudioModeChanged],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── Control ────────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/command"),
        operation: "POST /command",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::OctetStream,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[Ap2StateEffect::DiagnosticUpdate],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Post,
        endpoint: Ap2Endpoint::Path("/feedback"),
        operation: "POST /feedback",
        request_content_type: Ap2ContentType::OctetStream,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[Ap2StateEffect::DiagnosticUpdate],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── Stream setup ───────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Setup,
        endpoint: Ap2Endpoint::Any,
        operation: "SETUP (initial — AP2 buffered, type 103, PTP)",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &["timingProtocol"],
        optional_request_keys: &[
            "activeRemote",
            "dacpID",
            "groupUUID",
            "streamConnectionID",
            "isMediaExtensionAllowed",
        ],
        expected_status: 200,
        response_content_type: Ap2ContentType::BinaryPlist,
        required_response_keys: &["timingPeerInfo", "eventPort", "timingPort"],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[
            Ap2StateEffect::SessionCreated,
            Ap2StateEffect::EventPortOpen,
            Ap2StateEffect::TimingConfigured,
        ],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::InitialPtpSetup,
    },
    Ap2Contract {
        method: Ap2Method::Setup,
        endpoint: Ap2Endpoint::Any,
        operation: "SETUP (initial — remote-control-only)",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &["timingProtocol", "isRemoteControlOnly"],
        optional_request_keys: &["activeRemote", "dacpID"],
        expected_status: 200,
        response_content_type: Ap2ContentType::BinaryPlist,
        required_response_keys: &["eventPort"],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[
            Ap2StateEffect::SessionCreated,
            Ap2StateEffect::EventPortOpen,
            Ap2StateEffect::TimingConfigured,
        ],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::InitialRemoteControlSetup,
    },
    Ap2Contract {
        method: Ap2Method::Setup,
        endpoint: Ap2Endpoint::Any,
        operation: "SETUP (stream — buffered audio type 103)",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &["streams"],
        optional_request_keys: &[
            "activeRemote",
            "dacpID",
            "timingProtocol",
            "groupUUID",
            "streamConnectionID",
        ],
        expected_status: 200,
        response_content_type: Ap2ContentType::BinaryPlist,
        required_response_keys: &["streams"],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[Ap2StateEffect::AudioPortsOpen, Ap2StateEffect::StreamAdded],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::StreamType(103),
    },
    Ap2Contract {
        method: Ap2Method::Setup,
        endpoint: Ap2Endpoint::Any,
        operation: "SETUP (stream — remote-control data type 130)",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &["streams"],
        optional_request_keys: &["activeRemote", "dacpID", "timingProtocol"],
        expected_status: 200,
        response_content_type: Ap2ContentType::BinaryPlist,
        required_response_keys: &["streams"],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[Ap2StateEffect::DataPortOpen, Ap2StateEffect::StreamAdded],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::StreamType(130),
    },
    // ── Peers ──────────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::SetPeers,
        endpoint: Ap2Endpoint::Any,
        operation: "SETPEERS",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &[],
        optional_request_keys: &["peers"],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[
            Ap2StateEffect::PeersUpdated,
            Ap2StateEffect::DiagnosticUpdate,
        ],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Stub,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::SetPeersX,
        endpoint: Ap2Endpoint::Any,
        operation: "SETPEERSX",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &[],
        optional_request_keys: &["peers"],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[
            Ap2StateEffect::PeersUpdated,
            Ap2StateEffect::DiagnosticUpdate,
        ],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Stub,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── Playback ───────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Record,
        endpoint: Ap2Endpoint::Any,
        operation: "RECORD",
        request_content_type: Ap2ContentType::None,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[
            Ap2StateEffect::PlaybackConditionallyStarted,
            Ap2StateEffect::DiagnosticUpdate,
        ],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::SetRateAnchorTime,
        endpoint: Ap2Endpoint::Any,
        operation: "SETRATEANCHORTIME",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &["rate"],
        optional_request_keys: &[
            "networkTimeTimelineID",
            "networkTimeSecs",
            "networkTimeFrac",
            "rtpTime",
        ],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::NotIdempotent,
        state_effects: &[
            Ap2StateEffect::TimingAnchorSet,
            Ap2StateEffect::DiagnosticUpdate,
        ],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Pause,
        endpoint: Ap2Endpoint::Any,
        operation: "PAUSE",
        request_content_type: Ap2ContentType::None,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[Ap2StateEffect::PlaybackPaused],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::FlushBuffered,
        endpoint: Ap2Endpoint::Any,
        operation: "FLUSHBUFFERED",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &[],
        optional_request_keys: &[
            "flushFromSeq",
            "flushFromTS",
            "flushUntilSeq",
            "flushUntilTS",
        ],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[Ap2StateEffect::PlaybackPaused],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Partial,
        discriminator: Ap2RequestDiscriminator::None,
    },
    // ── Teardown ───────────────────────────────────────────────────────────
    Ap2Contract {
        method: Ap2Method::Teardown,
        endpoint: Ap2Endpoint::Any,
        operation: "TEARDOWN (stream)",
        request_content_type: Ap2ContentType::BinaryPlist,
        required_request_keys: &["streams"],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[Ap2StateEffect::StreamListenerClosed],
        error_policy: Ap2ErrorPolicy::BestEffort,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
    Ap2Contract {
        method: Ap2Method::Teardown,
        endpoint: Ap2Endpoint::Any,
        operation: "TEARDOWN (session)",
        request_content_type: Ap2ContentType::None,
        required_request_keys: &[],
        optional_request_keys: &[],
        expected_status: 200,
        response_content_type: Ap2ContentType::None,
        required_response_keys: &[],
        idempotency: Ap2Idempotency::Idempotent,
        state_effects: &[
            Ap2StateEffect::PlaybackStopped,
            Ap2StateEffect::StreamListenerClosed,
        ],
        error_policy: Ap2ErrorPolicy::Standard,
        implementation: Ap2ImplementationStatus::Implemented,
        discriminator: Ap2RequestDiscriminator::None,
    },
];

// ---------------------------------------------------------------------------
// Classification & validation
// ---------------------------------------------------------------------------

fn first_stream_type(dict: &plist::Dictionary) -> Option<u64> {
    dict.get("streams")
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary)
        .and_then(|stream| stream.get("type"))
        .and_then(plist::Value::as_unsigned_integer)
}

/// Classify a request view against the contract registry.
///
/// Returns the first matching [`Ap2Contract`], or `None` if no entry matches.
/// For ambiguous endpoints (e.g. `SETUP` with `Any`), the
/// [`Ap2RequestDiscriminator`] inspects the plist dictionary to select the
/// correct entry, making classification independent of registry order.
pub fn classify(view: &super::request::Ap2RequestView<'_>) -> Option<&'static Ap2Contract> {
    let method = Ap2Method::from_str(view.method)?;

    AP2_CONTRACTS.iter().find(|c| {
        if c.method != method {
            return false;
        }
        if !c.endpoint.matches(view.uri) {
            return false;
        }
        // Content-type match: for `None` we accept absence; otherwise the
        // header must contain the expected media-type.
        if !c.request_content_type.matches_header(view.content_type) {
            return false;
        }
        // Extra discriminator check (e.g. plist-key presence for SETUP).
        match c.discriminator {
            Ap2RequestDiscriminator::None => true,
            Ap2RequestDiscriminator::HasPlistKey(key) => {
                view.plist_dict.is_some_and(|d| d.contains_key(key))
            }
            Ap2RequestDiscriminator::HasPlistKeyWithout { required, excluded } => view
                .plist_dict
                .is_some_and(|d| d.contains_key(required) && !d.contains_key(excluded)),
            Ap2RequestDiscriminator::InitialPtpSetup => view.plist_dict.is_some_and(|d| {
                !d.contains_key("streams")
                    && d.get("timingProtocol").and_then(plist::Value::as_string) == Some("PTP")
            }),
            Ap2RequestDiscriminator::InitialRemoteControlSetup => {
                view.plist_dict.is_some_and(|d| {
                    !d.contains_key("streams")
                        && d.get("timingProtocol").and_then(plist::Value::as_string) == Some("None")
                        && d.get("isRemoteControlOnly")
                            .and_then(plist::Value::as_boolean)
                            == Some(true)
                })
            }
            Ap2RequestDiscriminator::StreamType(stream_type) => view
                .plist_dict
                .and_then(first_stream_type)
                .is_some_and(|actual| actual == stream_type),
        }
    })
}

/// Validate a request against a specific contract entry.
///
/// Returns a (possibly empty) list of [`ContractError`] values.  An empty
/// list means the request satisfies the contract for the fields we can check
/// statically (method, URI, content-type, required plist keys).
pub fn validate_request(
    contract: &Ap2Contract,
    view: &super::request::Ap2RequestView<'_>,
) -> Vec<ContractError> {
    let mut errors = Vec::new();

    // Content-Type
    match contract.request_content_type {
        Ap2ContentType::None => {
            // Ok if absent
        }
        ct => {
            let expected = ct
                .as_str()
                .expect("non-None content type must have a string");
            match view.content_type {
                None => {
                    errors.push(ContractError::MissingContentType {
                        expected: expected.to_string(),
                    });
                }
                Some(actual) if !ct.matches_header(Some(actual)) => {
                    errors.push(ContractError::WrongContentType {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                _ => {}
            }
        }
    }

    // Required plist keys (only if a plist dict was parsed from the body)
    if let Some(dict) = view.plist_dict {
        for &key in contract.required_request_keys {
            if !dict.contains_key(key) {
                errors.push(ContractError::MissingRequiredKey { key });
            }
        }
    } else if !contract.required_request_keys.is_empty() {
        // Body should be a plist but we received something else or nothing.
        // We flag this as "missing required key" for each required key since
        // no dictionary is available.
        for &key in contract.required_request_keys {
            errors.push(ContractError::MissingRequiredKey { key });
        }
    }

    errors
}

/// Validate a response against a specific contract entry.
///
/// Checks status code, Content-Type, and required plist keys.
pub fn validate_response(
    contract: &Ap2Contract,
    view: &super::response::Ap2ResponseView<'_>,
) -> Vec<ContractError> {
    let mut errors = Vec::new();

    if view.status != contract.expected_status {
        errors.push(ContractError::WrongResponseStatus {
            expected: contract.expected_status,
            actual: view.status,
        });
    }

    match contract.response_content_type {
        Ap2ContentType::None => {
            // Ok if absent
        }
        ct => {
            let expected = ct
                .as_str()
                .expect("non-None content type must have a string");
            match view.content_type {
                None => {
                    errors.push(ContractError::MissingContentType {
                        expected: expected.to_string(),
                    });
                }
                Some(actual) if !ct.matches_header(Some(actual)) => {
                    errors.push(ContractError::WrongContentType {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                _ => {}
            }
        }
    }

    if let Some(dict) = view.plist_dict {
        for &key in contract.required_response_keys {
            if !dict.contains_key(key) {
                errors.push(ContractError::MissingResponseKey { key });
            }
        }
    } else if !contract.required_response_keys.is_empty() {
        for &key in contract.required_response_keys {
            errors.push(ContractError::MissingResponseKey { key });
        }
    }

    errors
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Build a valid binary-plist empty dictionary body.
    fn empty_plist_body() -> Vec<u8> {
        let dict = plist::Dictionary::new();
        binary_plist_from_dict(&dict)
    }

    fn binary_plist_from_dict(dict: &plist::Dictionary) -> Vec<u8> {
        let mut out = Vec::new();
        plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dict.clone()))
            .expect("binary plist serialisation");
        out
    }

    fn parse_plist_dict(body: &[u8]) -> Option<plist::Dictionary> {
        plist::from_bytes::<plist::Dictionary>(body).ok()
    }

    fn mk_view<'a>(
        method: &'a str,
        uri: &'a str,
        content_type: Option<&'a str>,
        dict: Option<&'a plist::Dictionary>,
    ) -> crate::airplay::ap2::request::Ap2RequestView<'a> {
        crate::airplay::ap2::request::Ap2RequestView {
            method,
            uri,
            content_type,
            plist_dict: dict,
        }
    }

    fn mk_response_view<'a>(
        status: u16,
        content_type: Option<&'a str>,
        dict: Option<&'a plist::Dictionary>,
    ) -> crate::airplay::ap2::response::Ap2ResponseView<'a> {
        crate::airplay::ap2::response::Ap2ResponseView {
            status,
            content_type,
            plist_dict: dict,
        }
    }

    // ── Ap2Method parsing ───────────────────────────────────────────────

    #[test]
    fn method_parse_known() {
        assert_eq!(Ap2Method::from_str("GET"), Some(Ap2Method::Get));
        assert_eq!(Ap2Method::from_str("get"), Some(Ap2Method::Get));
        assert_eq!(Ap2Method::from_str("POST"), Some(Ap2Method::Post));
        assert_eq!(Ap2Method::from_str("SETUP"), Some(Ap2Method::Setup));
        assert_eq!(Ap2Method::from_str("RECORD"), Some(Ap2Method::Record));
        assert_eq!(Ap2Method::from_str("PAUSE"), Some(Ap2Method::Pause));
        assert_eq!(
            Ap2Method::from_str("FLUSHBUFFERED"),
            Some(Ap2Method::FlushBuffered)
        );
        assert_eq!(
            Ap2Method::from_str("flushbuffered"),
            Some(Ap2Method::FlushBuffered)
        );
        assert_eq!(Ap2Method::from_str("TEARDOWN"), Some(Ap2Method::Teardown));
        assert_eq!(Ap2Method::from_str("SETPEERS"), Some(Ap2Method::SetPeers));
        assert_eq!(Ap2Method::from_str("SETPEERSX"), Some(Ap2Method::SetPeersX));
        assert_eq!(
            Ap2Method::from_str("SETRATEANCHORTIME"),
            Some(Ap2Method::SetRateAnchorTime)
        );
        // Short form
        assert_eq!(
            Ap2Method::from_str("SETRATEANCHORTI"),
            Some(Ap2Method::SetRateAnchorTime)
        );
    }

    #[test]
    fn method_parse_unknown() {
        assert_eq!(Ap2Method::from_str("OPTIONS"), None);
        assert_eq!(Ap2Method::from_str("ANNOUNCE"), None);
        assert_eq!(Ap2Method::from_str(""), None);
    }

    #[test]
    fn method_display_roundtrip() {
        for input in [
            "GET",
            "POST",
            "SETUP",
            "RECORD",
            "PAUSE",
            "FLUSHBUFFERED",
            "TEARDOWN",
            "SETPEERS",
            "SETPEERSX",
            "SETRATEANCHORTIME",
        ] {
            let m = Ap2Method::from_str(input).unwrap();
            assert_eq!(m.to_string(), input);
        }
    }

    // ── Ap2ContentType matching ─────────────────────────────────────────

    #[test]
    fn content_type_binary_plist_match() {
        let ct = Ap2ContentType::BinaryPlist;
        assert!(ct.matches_header(Some("application/x-apple-binary-plist")));
        assert!(ct.matches_header(Some("Application/X-Apple-Binary-Plist")));
        // Subtype with charset is fine — contains the base string
        assert!(!ct.matches_header(Some("application/octet-stream")));
        assert!(!ct.matches_header(None));
    }

    #[test]
    fn content_type_none() {
        let ct = Ap2ContentType::None;
        assert!(ct.matches_header(None));
        assert!(!ct.matches_header(Some("anything")));
    }

    // ── classify: positive ──────────────────────────────────────────────

    #[test]
    fn classify_get_info() {
        let v = mk_view("GET", "/info", None, None);
        let c = classify(&v).expect("should classify GET /info");
        assert_eq!(c.operation, "GET /info");
        assert_eq!(c.implementation, Ap2ImplementationStatus::Implemented);
    }

    #[test]
    fn classify_post_pair_setup() {
        let v = mk_view(
            "POST",
            "/pair-setup",
            Some("application/octet-stream"),
            None,
        );
        let c = classify(&v).expect("should classify POST /pair-setup");
        assert_eq!(c.operation, "POST /pair-setup");
    }

    #[test]
    fn classify_post_pair_verify() {
        let v = mk_view(
            "POST",
            "/pair-verify",
            Some("application/octet-stream"),
            None,
        );
        let c = classify(&v).expect("should classify POST /pair-verify");
        assert_eq!(c.operation, "POST /pair-verify");
    }

    #[test]
    fn classify_setup_ap2() {
        // A SETUP without a plist body cannot be classified because the
        // discriminator requires plist keys to distinguish initial vs stream.
        let v = mk_view("SETUP", "*", Some("application/x-apple-binary-plist"), None);
        assert!(
            classify(&v).is_none(),
            "SETUP without plist body should not classify"
        );
    }

    #[test]
    fn classify_record() {
        let v = mk_view("RECORD", "*", None, None);
        let c = classify(&v).expect("should classify RECORD");
        assert_eq!(c.operation, "RECORD");
    }

    #[test]
    fn classify_pause() {
        let v = mk_view("PAUSE", "*", None, None);
        let c = classify(&v).expect("should classify PAUSE");
        assert_eq!(c.operation, "PAUSE");
    }

    #[test]
    fn classify_flushbuffered() {
        let v = mk_view(
            "FLUSHBUFFERED",
            "*",
            Some("application/x-apple-binary-plist"),
            None,
        );
        let c = classify(&v).expect("should classify FLUSHBUFFERED");
        assert_eq!(c.operation, "FLUSHBUFFERED");
    }

    #[test]
    fn classify_teardown_stream() {
        let v = mk_view(
            "TEARDOWN",
            "*",
            Some("application/x-apple-binary-plist"),
            None,
        );
        let c = classify(&v).expect("should classify TEARDOWN");
        assert_eq!(c.operation, "TEARDOWN (stream)");
    }

    #[test]
    fn classify_teardown_session() {
        let v = mk_view("TEARDOWN", "*", None, None);
        let c = classify(&v).expect("should classify TEARDOWN (session)");
        assert_eq!(c.operation, "TEARDOWN (session)");
    }

    #[test]
    fn classify_setrateanchortime() {
        let v = mk_view(
            "SETRATEANCHORTIME",
            "*",
            Some("application/x-apple-binary-plist"),
            None,
        );
        let c = classify(&v).expect("should classify SETRATEANCHORTIME");
        assert_eq!(c.operation, "SETRATEANCHORTIME");
    }

    #[test]
    fn classify_setpeers() {
        let v = mk_view(
            "SETPEERS",
            "*",
            Some("application/x-apple-binary-plist"),
            None,
        );
        let c = classify(&v).expect("should classify SETPEERS");
        assert_eq!(c.operation, "SETPEERS");
    }

    #[test]
    fn classify_setpeersx() {
        let v = mk_view(
            "SETPEERSX",
            "*",
            Some("application/x-apple-binary-plist"),
            None,
        );
        let c = classify(&v).expect("should classify SETPEERSX");
        assert_eq!(c.operation, "SETPEERSX");
    }

    // ── classify: negative ──────────────────────────────────────────────

    #[test]
    fn classify_unsupported_method() {
        let v = mk_view("OPTIONS", "*", None, None);
        assert!(classify(&v).is_none());
    }

    #[test]
    fn classify_unsupported_operation() {
        let v = mk_view("POST", "/nonexistent", None, None);
        assert!(classify(&v).is_none());
    }

    #[test]
    fn classify_wrong_content_type() {
        // SETUP expects binary plist; text/parameters should not match.
        let v = mk_view("SETUP", "*", Some("text/parameters"), None);
        assert!(classify(&v).is_none());
    }

    // ── classify: SETUP discriminator (plist-key based) ──────────────────

    #[test]
    fn classify_setup_initial_ptp_without_streams() {
        // Initial SETUP with timingProtocol but no streams.
        let mut dict = plist::Dictionary::new();
        dict.insert("timingProtocol".into(), plist::Value::String("PTP".into()));
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let c = classify(&v).expect("should classify as initial SETUP");
        assert!(
            c.operation.contains("initial"),
            "expected initial SETUP, got '{}'",
            c.operation
        );
    }

    #[test]
    fn classify_setup_initial_remote_control_only() {
        let mut dict = plist::Dictionary::new();
        dict.insert("timingProtocol".into(), plist::Value::String("None".into()));
        dict.insert("isRemoteControlOnly".into(), plist::Value::Boolean(true));
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let contract = classify(&v).expect("remote-control SETUP should classify");
        assert_eq!(contract.operation, "SETUP (initial — remote-control-only)");
        assert_eq!(contract.required_response_keys, &["eventPort"]);
    }

    #[test]
    fn classify_setup_data_stream_type130() {
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(130.into()));
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let contract = classify(&v).expect("type-130 SETUP should classify");
        assert_eq!(
            contract.operation,
            "SETUP (stream — remote-control data type 130)"
        );
        assert!(
            contract
                .state_effects
                .contains(&Ap2StateEffect::DataPortOpen)
        );
    }

    #[test]
    fn classify_setup_stream_with_streams() {
        // Stream SETUP with streams but no timingProtocol.
        let mut dict = plist::Dictionary::new();
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(103.into()));
        dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let c = classify(&v).expect("should classify as stream SETUP");
        assert!(
            c.operation.contains("stream"),
            "expected stream SETUP, got '{}'",
            c.operation
        );
    }

    #[test]
    fn classify_setup_both_keys_is_stream() {
        // Runtime SETUP handling gives the streams shape precedence when
        // both keys are present, so the contract classifier must agree.
        let mut dict = plist::Dictionary::new();
        dict.insert("timingProtocol".into(), plist::Value::String("PTP".into()));
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(103.into()));
        dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let c = classify(&v).expect("should classify when both keys present");
        assert!(
            c.operation.contains("stream"),
            "expected stream SETUP when both keys present, got '{}'",
            c.operation
        );
    }

    #[test]
    fn classify_setup_neither_key_returns_none() {
        // Malformed SETUP — neither timingProtocol nor streams.
        let dict = plist::Dictionary::new();
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        assert!(
            classify(&v).is_none(),
            "SETUP with neither key should not classify"
        );
    }

    // ── validate_request ────────────────────────────────────────────────

    #[test]
    fn validate_setup_required_keys_present() {
        let mut dict = plist::Dictionary::new();
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(103.into()));
        dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        dict.insert("timingProtocol".into(), plist::Value::String("PTP".into()));
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let c = classify(&v).unwrap();
        let errs = validate_request(c, &v);
        assert!(errs.is_empty(), "expected no errors, got {errs:?}");
    }

    #[test]
    fn validate_setup_missing_required_key() {
        // SETRATEANCHORTIME with missing "rate" key flags MissingRequiredKey.
        let dict = plist::Dictionary::new();
        let v = mk_view(
            "SETRATEANCHORTIME",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let c = classify(&v).unwrap();
        let errs = validate_request(c, &v);
        assert_eq!(errs.len(), 1);
        assert!(matches!(
            errs[0],
            ContractError::MissingRequiredKey { key: "rate" }
        ));
    }

    #[test]
    fn validate_missing_content_type() {
        let v = mk_view("SETUP", "*", None, None);
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.method == Ap2Method::Setup)
            .unwrap();
        let errs = validate_request(c, &v);
        assert!(
            errs.iter()
                .any(|e| matches!(e, ContractError::MissingContentType { .. })),
            "expected MissingContentType in {errs:?}"
        );
    }

    #[test]
    fn validate_wrong_content_type() {
        let v = mk_view("SETUP", "*", Some("text/plain"), None);
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.method == Ap2Method::Setup)
            .unwrap();
        let errs = validate_request(c, &v);
        assert!(
            errs.iter()
                .any(|e| matches!(e, ContractError::WrongContentType { .. })),
            "expected WrongContentType in {errs:?}"
        );
    }

    #[test]
    fn validate_malformed_plist_body_no_error_from_contract() {
        // The contract module doesn't parse plists — it only checks keys
        // against an already-parsed dict (or absence thereof).
        // A malformed body that fails to parse is represented as plist_dict=None
        // and any required keys will be flagged.
        let v = mk_view("SETUP", "*", Some("application/x-apple-binary-plist"), None);
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.method == Ap2Method::Setup)
            .unwrap();
        let errs = validate_request(c, &v);
        // Initial SETUP now only requires timingProtocol.
        assert!(!errs.is_empty());
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ContractError::MissingRequiredKey {
                    key: "timingProtocol"
                }
            )),
            "expected MissingRequiredKey for 'timingProtocol', got {errs:?}"
        );
    }

    #[test]
    fn validate_optional_keys_are_not_enforced() {
        let mut dict = plist::Dictionary::new();
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(103.into()));
        dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        dict.insert("timingProtocol".into(), plist::Value::String("PTP".into()));
        // Optional keys like "activeRemote", "dacpID" are absent — that's fine.
        let v = mk_view(
            "SETUP",
            "*",
            Some("application/x-apple-binary-plist"),
            Some(&dict),
        );
        let c = classify(&v).unwrap();
        let errs = validate_request(c, &v);
        assert!(errs.is_empty());
    }

    // ── validate_response ───────────────────────────────────────────────

    #[test]
    fn validate_response_get_info() {
        let mut dict = plist::Dictionary::new();
        dict.insert("vv".into(), plist::Value::Integer(2.into()));
        dict.insert(
            "deviceID".into(),
            plist::Value::String("AA:BB:CC:DD:EE:FF".into()),
        );
        dict.insert("features".into(), plist::Value::Integer(0.into()));
        dict.insert("statusFlags".into(), plist::Value::Integer(0.into()));
        dict.insert("name".into(), plist::Value::String("test".into()));
        dict.insert("model".into(), plist::Value::String("TestModel".into()));
        dict.insert("pi".into(), plist::Value::String("pi-uuid".into()));
        dict.insert("pk".into(), plist::Value::Data(vec![0u8; 32]));
        dict.insert("srcvers".into(), plist::Value::String("366.0".into()));
        let mut fmt = plist::Dictionary::new();
        fmt.insert("audioStream".into(), plist::Value::Integer(0.into()));
        fmt.insert("bufferStream".into(), plist::Value::Integer(0.into()));
        dict.insert("supportedFormats".into(), plist::Value::Dictionary(fmt));

        let rv = mk_response_view(200, Some("application/x-apple-binary-plist"), Some(&dict));
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.operation == "GET /info")
            .unwrap();
        let errs = validate_response(c, &rv);
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
    }

    #[test]
    fn validate_response_wrong_status() {
        let rv = mk_response_view(500, None, None);
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.operation == "GET /info")
            .unwrap();
        let errs = validate_response(c, &rv);
        assert!(errs.iter().any(|e| matches!(
            e,
            ContractError::WrongResponseStatus {
                expected: 200,
                actual: 500
            }
        )),);
    }

    #[test]
    fn validate_response_missing_key() {
        let mut dict = plist::Dictionary::new();
        dict.insert("vv".into(), plist::Value::Integer(2.into()));
        // Missing deviceID and many other required /info keys
        let rv = mk_response_view(200, Some("application/x-apple-binary-plist"), Some(&dict));
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.operation == "GET /info")
            .unwrap();
        let errs = validate_response(c, &rv);
        // Should have multiple missing-key errors
        assert!(!errs.is_empty());
        // At least "deviceID" should be flagged
        assert!(
            errs.iter()
                .any(|e| matches!(e, ContractError::MissingResponseKey { key: "deviceID" })),
            "expected MissingResponseKey for deviceID, got {errs:?}"
        );
    }

    // ── Binary plist fixture builder ────────────────────────────────────

    #[test]
    fn binary_plist_fixture_roundtrip() {
        let mut dict = plist::Dictionary::new();
        dict.insert("key".into(), plist::Value::String("value".into()));
        let body = binary_plist_from_dict(&dict);
        let parsed = parse_plist_dict(&body).expect("should parse");
        assert_eq!(parsed.get("key").and_then(|v| v.as_string()), Some("value"));
    }

    #[test]
    fn empty_plist_body_roundtrip() {
        let body = empty_plist_body();
        let parsed = parse_plist_dict(&body).expect("should parse");
        assert!(parsed.is_empty());
    }

    // ── Registry completeness ───────────────────────────────────────────

    #[test]
    fn registry_has_exactly_expected_count() {
        // 21 contract entries (see the table in the module doc comment)
        assert_eq!(AP2_CONTRACTS.len(), 23);
    }

    #[test]
    fn every_contract_has_a_description() {
        for c in AP2_CONTRACTS {
            assert!(
                !c.operation.is_empty(),
                "contract {:?} {} has no operation name",
                c.method,
                c.endpoint
            );
        }
    }

    #[test]
    fn every_entry_classifiable_by_own_view() {
        // For each contract, construct a matching view and check classify.
        // Contracts with a plist-key discriminator need a minimal plist
        // dict containing the required discriminator key.
        for c in AP2_CONTRACTS {
            let uri = match c.endpoint {
                Ap2Endpoint::Path(p) => p,
                Ap2Endpoint::Any => "*",
            };
            let ct = c.request_content_type.as_str();

            // Build a plist dict if the contract has a plist-key discriminator.
            let owned_dict: Option<plist::Dictionary>;
            let dict_ref: Option<&plist::Dictionary> = match c.discriminator {
                Ap2RequestDiscriminator::HasPlistKey(key) => {
                    let mut d = plist::Dictionary::new();
                    d.insert(key.into(), plist::Value::String("test".into()));
                    owned_dict = Some(d);
                    owned_dict.as_ref()
                }
                Ap2RequestDiscriminator::HasPlistKeyWithout { required, .. } => {
                    let mut d = plist::Dictionary::new();
                    d.insert(required.into(), plist::Value::String("test".into()));
                    owned_dict = Some(d);
                    owned_dict.as_ref()
                }
                Ap2RequestDiscriminator::InitialPtpSetup => {
                    let mut d = plist::Dictionary::new();
                    d.insert("timingProtocol".into(), plist::Value::String("PTP".into()));
                    owned_dict = Some(d);
                    owned_dict.as_ref()
                }
                Ap2RequestDiscriminator::InitialRemoteControlSetup => {
                    let mut d = plist::Dictionary::new();
                    d.insert("timingProtocol".into(), plist::Value::String("None".into()));
                    d.insert("isRemoteControlOnly".into(), plist::Value::Boolean(true));
                    owned_dict = Some(d);
                    owned_dict.as_ref()
                }
                Ap2RequestDiscriminator::StreamType(stream_type) => {
                    let mut stream = plist::Dictionary::new();
                    stream.insert("type".into(), plist::Value::Integer(stream_type.into()));
                    let mut d = plist::Dictionary::new();
                    d.insert(
                        "streams".into(),
                        plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
                    );
                    owned_dict = Some(d);
                    owned_dict.as_ref()
                }
                Ap2RequestDiscriminator::None => None,
            };

            let v = mk_view(c.method.as_str(), uri, ct, dict_ref);
            let found = classify(&v);
            assert!(
                found.is_some(),
                "contract '{}' should classify its own view",
                c.operation
            );
        }
    }

    // ── Ap2StreamType ───────────────────────────────────────────────────

    #[test]
    fn stream_type_from_u64() {
        assert_eq!(
            Ap2StreamType::from_u64(96),
            Some(Ap2StreamType::RealtimeAudio)
        );
        assert_eq!(
            Ap2StreamType::from_u64(103),
            Some(Ap2StreamType::BufferedAudio)
        );
        assert_eq!(
            Ap2StreamType::from_u64(130),
            Some(Ap2StreamType::DataStream)
        );
        assert_eq!(Ap2StreamType::from_u64(0), None);
        assert_eq!(Ap2StreamType::from_u64(999), None);
    }

    #[test]
    fn stream_type_as_u64_roundtrip() {
        for st in [
            Ap2StreamType::RealtimeAudio,
            Ap2StreamType::BufferedAudio,
            Ap2StreamType::DataStream,
        ] {
            assert_eq!(Ap2StreamType::from_u64(st.as_u64()), Some(st));
        }
    }

    // ── Ap2TimingProtocol ───────────────────────────────────────────────

    #[test]
    fn timing_protocol_from_str() {
        assert_eq!(
            Ap2TimingProtocol::from_str("PTP"),
            Some(Ap2TimingProtocol::Ptp)
        );
        assert_eq!(
            Ap2TimingProtocol::from_str("ptp"),
            Some(Ap2TimingProtocol::Ptp)
        );
        assert_eq!(
            Ap2TimingProtocol::from_str("NTP"),
            Some(Ap2TimingProtocol::Ntp)
        );
        assert_eq!(
            Ap2TimingProtocol::from_str("None"),
            Some(Ap2TimingProtocol::None)
        );
        assert_eq!(
            Ap2TimingProtocol::from_str(""),
            Some(Ap2TimingProtocol::None)
        );
        assert_eq!(Ap2TimingProtocol::from_str("BOGUS"), None);
    }

    #[test]
    fn record_contract_marks_playback_as_conditional() {
        let view = mk_view("RECORD", "*", None, None);
        let contract = classify(&view).expect("RECORD should classify");
        assert!(
            contract
                .state_effects
                .contains(&Ap2StateEffect::PlaybackConditionallyStarted)
        );
        assert!(
            !contract
                .state_effects
                .contains(&Ap2StateEffect::PlaybackStarted)
        );
    }

    // ── Ap2ImplementationStatus display ─────────────────────────────────

    #[test]
    fn impl_status_display() {
        assert_eq!(Ap2ImplementationStatus::Stub.to_string(), "Stub");
        assert_eq!(Ap2ImplementationStatus::Partial.to_string(), "Partial");
        assert_eq!(
            Ap2ImplementationStatus::Implemented.to_string(),
            "Implemented"
        );
    }
}
