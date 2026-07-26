# AirPlay 2 API Conformance Matrix

**Target profile:** PTP + buffered audio (type 103).
Realtime audio (type 96), NTP timing, and No-timing modes are
**truthfully rejected** — the SETUP handler returns `status=1` for
unsupported stream types and `400 Bad Request` for unsupported
timing protocols (`NTP`, `None`).  No listener or state activation
fires for unsupported streams.

## Capability policy

Feature bits, status flags, supported formats (buffer-stream and
audio-stream), and the `_airplay._tcp` mDNS publish decision are
centralised in [`Ap2CapabilityPolicy`]
(`src/airplay/ap2/capability.rs`).  The policy is built once from
`Config` + runtime PTP status and is **immutable** — every consumer
(`GET /info`, mDNS TXT records, `SETUP` handler, AP2 event
channel) reads the same snapshot.  This guarantees that `/info`
feature words, `txtAirPlay`, and mDNS `_raop._tcp` / `_airplay._tcp`
TXT records are always consistent.

### Feature bit audit (vs upstream shairport-sync C)

| Bit | Name                                     | Status             | Reason                                          |
|-----|------------------------------------------|--------------------|-------------------------------------------------|
|   0 | SupportsAirPlayVideo                     | **cleared**        | No video / screen mirroring.                    |
|   9 | SupportsAirPlayAudio                     | **set**            | Audio receiver.                                 |
|  11 | SupportsAirPlayAudioRedundant            | **set**            | Standard audio receiver bit.                    |
|  14 | SupportsPTP                              | **set (cond.)**    | Only when PTP is confirmed available.           |
|  15 | SupportsAirPlayArtwork                   | **cleared**        | Legacy AP1 artwork; AP2 metadata (bit 50) used. |
|  16 | SupportsAirPlayProgress                  | **cleared**        | Legacy AP1 progress; AP2 metadata (bit 50) used.|
|  17 | SupportsAirPlayText                      | **cleared**        | Legacy AP1 text; AP2 metadata (bit 50) used.    |
|  18 | SupportsUnifiedPairSetupAndMFi           | **set**            | Pair-setup + MFi.                               |
|  19 | SupportsAirPlayAudioBuffered             | **set**            | Buffered audio (type 103).                      |
|  20 | SupportsCoreUtils                        | **set**            | Required for AP2.                               |
|  22 | SupportsUnifiedPairVerifyAndMFi          | **set**            | Pair-verify + MFi.                              |
|  30 | SupportsAudioRedundant                   | **set**            | Standard receiver bit.                          |
|  38 | SupportsLegacyPairing                    | **set**            | Pair-setup / pair-verify.                       |
|  40 | SupportsPTPClock                         | **set (cond.)**    | PTP clock identity.                             |
|  41 | SupportsAirPlayAudioBufferedRedundant    | **set**            | Buffered audio redundant bit.                   |
|  47 | SupportsAudioUnified                     | **set**            | AirPlay 2 audio.                                |
|  48 | SupportsCarPlay                          | **cleared**        | Not a CarPlay device.                           |
|  50 | SupportsAP2Metadata                      | **set**            | Binary-plist metadata (artwork/text/progress).  |

The final feature value is documented and tested in `capability.rs`.
Bits that deviate from the C upstream base `0x00018340405C4A00` are
explained in the inline comments there.

## Supported operations

| # | Method            | URI          | Kind        | Status      |
|---|-------------------|--------------|-------------|-------------|
| 1 | GET               | /info        | Discovery   | Implemented |
| 2 | POST              | /pair-setup  | Pairing     | Implemented |
| 3 | POST              | /pair-verify | Pairing     | Implemented |
| 4 | POST              | /pair-add    | Pairing     | Implemented |
| 5 | POST              | /pair-remove | Pairing     | Implemented |
| 6 | POST              | /pair-list   | Pairing     | Implemented |
| 7 | POST              | /fp-setup    | FairPlay    | Stub        |
| 8 | POST              | /configure   | Config      | Stub        |
| 9 | POST              | /audioMode   | Audio       | Partial     |
|10 | POST              | /command     | Control     | Partial     |
|11 | POST              | /feedback    | Feedback    | Partial     |
|12 | SETUP             | * (initial)  | Stream      | Partial     |
|13 | SETUP             | * (stream)   | Stream add  | Partial     |
|14 | SETPEERS          | *            | Peers       | Stub        |
|15 | SETPEERSX         | *            | Peers ext.  | Stub        |
|16 | RECORD            | *            | Playback    | Partial     |
|17 | SETRATEANCHORTIME | *            | Timing      | Partial     |
|18 | PAUSE             | *            | Playback    | Implemented |
|19 | FLUSHBUFFERED     | *            | Playback    | Partial     |
|20 | TEARDOWN          | * (stream)   | Teardown    | Implemented |
|21 | TEARDOWN          | * (session)  | Teardown    | Implemented |

## Status definitions

| Status      | Meaning                                                                 |
|-------------|-------------------------------------------------------------------------|
| Stub        | Endpoint recognised but handler is a placeholder / no-op.               |
| Partial     | Core logic exists but edge cases, spec details, or data-paths may be    |
|             | missing.  Works for the happy path with the target profile.            |
| Implemented | Full protocol implementation believed complete.                        |

## Contract registry

The authoritative machine-readable contract matrix lives in
`src/airplay/ap2/contract.rs` (`AP2_CONTRACTS` static slice).
Every entry records:

- RTSP method and URI
- Expected request `Content-Type`
- Required and optional binary-plist request keys
- Expected response status and `Content-Type`
- Required binary-plist response keys
- Idempotency classification
- State / playback side-effects (`Ap2StateEffect`)
- Error policy
- Implementation status

Validation helpers (`classify`, `validate_request`, `validate_response`)
are pure functions that consume lightweight borrowed views
(`Ap2RequestView` / `Ap2ResponseView`) and return zero or more
`ContractError` values.  No production code path is modified.

## Session phase state machine

`src/airplay/ap2/session.rs` defines a strict per-connection lifecycle
state machine via `Ap2SessionState` and `Ap2SessionPhase`.  Every new
connection starts in `Connected` and progresses through well-defined
phases:

```text
Connected ──▶ Paired ──▶ TimingConfigured ──▶ StreamConfigured ──▶ Recording
               │                  │                    │                │
               │                  ├──▶ PeersConfigured │                │
               │                  │        │           │                │
               │                  │        ▼           │                │
               │                  │   StreamConfigured │                │
               │                  │                    │                │
               ▼                  ▼                    ▼                ▼
            TearingDown ◀────────────────────────────────────────────── Paused
               │                                                        │
               ▼                                                        │
             Closed                                            Recording (rate=1)
                                                               or TearingDown
```

`validate_transition(from, to)` enforces valid ordering and returns a
typed `TransitionError` for invalid attempts.  Same-phase transitions
are always idempotent.

### Phase definitions

| Phase             | Meaning                                                        |
|-------------------|----------------------------------------------------------------|
| Connected         | New connection; no state established (default).                |
| Paired            | Pair-setup or pair-verify completed; pairing key material active. |
| TimingConfigured  | Initial PTP SETUP succeeded; event listener open.             |
| PeersConfigured   | SETPEERS / SETPEERSX processed.                               |
| StreamConfigured  | At least one stream SETUP processed; audio ports bound.       |
| Recording         | RECORD or SETRATEANCHORTIME (rate=1) — audio playing.         |
| Paused            | PAUSE, FLUSHBUFFERED, or SETRATEANCHORTIME (rate=0).          |
| TearingDown       | TEARDOWN in progress — closing listeners.                     |
| Closed            | Fully closed; no further operations permitted.                |

### Stream management

`Ap2Stream` records track per-stream metadata (stream ID, type,
audio format, sample rate, frames-per-packet, media key, data port).
Up to `MAX_AP2_STREAMS` (8) concurrent streams are supported.
`add_stream` and `remove_stream` are explicit methods that preserve
the current phase when adding/removing streams from `Recording` or
`Paused`.  Duplicate stream IDs are rejected.

### Transaction methods

`Ap2SessionState` provides transaction-like methods that validate
phase preconditions before mutating:

| Method              | Precondition              | Postcondition             |
|---------------------|---------------------------|---------------------------|
| `mark_paired`       | Connected                 | Paired                    |
| `configure_timing`  | Paired                    | TimingConfigured          |
| `update_peers_phase`| TimingConfigured/Peers    | PeersConfigured           |
| `add_stream`        | Timing/Peers/Stream/Rec/Paused | StreamConfigured or preserves Rec/Paused |
| `remove_stream`     | any (no-op if missing)    | preserves phase while streams remain; otherwise Timing/Peers |
| `begin_recording`   | StreamConfigured/Rec/Paused| Recording                |
| `pause`             | StreamConfigured/Rec/Paused| Paused                   |
| `resume`            | StreamConfigured/Paused/Rec | Recording               |
| `begin_teardown`    | any except Closed         | TearingDown               |
| `close`             | TearingDown               | Closed                    |
| `clear_sensitive`   | any                       | zeros all keys            |

### Error responses

Invalid phase requests return `455 Method Not Valid in This State`
with a diagnostic `X-Reason` header.  The session state is never
mutated on error — all validation happens before any side-effect.

### Integration

`RtspSession` embeds a single `ap2: Ap2SessionState` field replacing
the previously scattered `ap2_timing_protocol`, `ap2_streams`,
`ap2_group_uuid`, `group_contains_group_leader`, `dacp_id`,
`active_remote`, and `session_key` fields.  Listener handles, ports,
and `is_playback_owner` remain on `RtspSession` because AP1 also uses them.

`perform_connection_cleanup` clears the session's AP2 secrets via
`clear_sensitive()` and aborts all listeners.  Non-owner cleanup
never clears another session's global playback state but always
clears its own AP2 secrets.

## Timing protocol support

| Protocol | Setup   | Data-path | Notes                                      |
|----------|---------|-----------|--------------------------------------------|
| PTP      | ✅      | Partial   | Embedded PTP service runs; scheduler anchor/deadline integration is pending. |
| NTP      | ❌ (400) | —        | Explicitly rejected in initial SETUP.      |
| None     | ❌ (400) | —        | Explicitly rejected in initial SETUP.      |

## Stream type support

| Type | Num | Transport | Status                              |
|------|-----|-----------|-------------------------------------|
| Real-time audio | 96  | —         | Rejected (status=1). No listener.   |
| Buffered audio  | 103 | TCP       | Framing, decrypt, decode, and bounded enqueue work; timed playout remains partial. |
| Data / event    | 130 | —         | Rejected (status=1). No listener.   |

## Known gaps (target profile: PTP + buffered 103)

1. **Realtime audio (type 96).**  The SETUP handler returns `status=1`
   without opening any listener.  No runtime resources are consumed.

2. **NTP / None timing.**  The initial SETUP returns `400 Bad Request`.
   Only `"PTP"` is accepted and wired through to the embedded
   PTP service. Timeline anchors are not yet applied to scheduler deadlines.

3. **Data stream (type 130).**  The SETUP handler returns `status=1`
   without opening any listener.  No runtime resources are consumed.

4. **FairPlay (`/fp-setup`).**  The handler echoes the request body
   back.  No license acquisition, content-key derivation, or SCP
   handshake is implemented.  FairPlay-protected content will not
   play.

5. **`/configure`.**  The body is ignored; no `timingProtocol`,
   `groupUUID`, or `streamCategory` fields are consumed.  The
   response is always `200 OK` with no payload.

6. **`/command`.**  Encrypted plist commands are decrypted and
   parsed for playback control (play/pause/stop/toggle), volume,
   and metadata updates.  Screen mirroring, Siri, and advanced
   MediaRemote commands are not handled.

7. **`/feedback`.**  The body is acknowledged but not inspected.
   Event-driven status push via the event channel is implemented.

8. **SETPEERS / SETPEERSX.**  Body lengths are recorded as
   diagnostics but the peer information is not stored or acted on.

## Test coverage

The `src/airplay/ap2/` module ships **~60 inline tests** covering:

- Method parsing (known + unknown + display round-trip)
- Content-type matching
- Classification of every contract entry (positive + negative)
- Request validation (required keys, optional keys, wrong/missing
  content-type, malformed plist body)
- Response validation (status, content-type, required keys)
- Binary plist fixture round-trip
- Registry completeness checks
- Session phase transitions (happy path, invalid transitions,
  additional SETUP from any phase)
- Transition error display
- Stream type and timing protocol parsing

The `capability.rs` module adds **~20 additional tests** verifying:
- Feature bit toggling per PTP availability and AP2 enable
- Password status flag
- `AlacOnly` vs `AacIfAvailable` format masks
- `feature_words()` round-trip and `features_ex()` base64
- Stream type acceptance (103 only)
- Timing protocol acceptance (PTP only)
- Format playability checks

The `rtsp.rs` AP2 SETUP tests cover:
- Buffered type 103 happy-path (ports + session key + audio format)
- Realtime type 96 rejection (status=1, no listener, no activation)
- Data type 130 rejection (status=1, no listener, no activation)
- Unknown stream type rejection (status=1)
- Unplayable format rejection (AAC under AlacOnly policy)
- NTP / None / empty timing protocol → 400
- GET /info binary plist field verification
- txtAirPlay / mDNS / info features cross-consistency

These tests run as part of `cargo test --all-targets` and are
independent of the RTSP server — no TCP sockets are opened for the
contract/validation tests, but the SETUP integration tests use a
Tokio runtime (via `#[tokio::test]`).
