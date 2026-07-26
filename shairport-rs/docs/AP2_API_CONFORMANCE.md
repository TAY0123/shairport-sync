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

## Pairing & control framing guarantees

### Pairing completion signal

The `PairingReply` carries a typed `PairingCompletion` enum
(`TransientSetup`, `FullSetup`, `Verify`).  A completion is signalled
**only** when the terminal pairing step succeeds and the response TLV
contains no error.  Apple sends TLV errors with HTTP 200 — the old
pattern of checking `status_code >= 200` for success was therefore
unsafe and has been replaced.  The RTSP handler installs the control
`PairCipher` and marks the `Ap2SessionState` as `Paired` exclusively
from the completion signal.

- **Transient pair-setup:** `TransientSetup { key, client_id: None }` after M3/M4 SRP
  proof verification.  `key` is the 64-byte SRP session key K.
- **Non-transient pair-setup:** `FullSetup { key, client_id }` after
  M5 identity verification and M6 generation.  The client is persisted
  to the `PairingDatabase` before the completion is signalled.
- **Pair-verify:** `Verify { shared_secret }` after M3 Ed25519
  signature verification.  `shared_secret` is the verified X25519
  ECDH shared secret.

### Pair management gate

`/pair-add`, `/pair-remove`, and `/pair-list` now reject unverified
sessions with a TLV authentication error (state M2 / error 2).
Previously `pair-remove` and `pair-list` accepted unverified callers,
which could leak pairing database contents or mutate state without
proof of identity.

### Stale state reset

`PairingSession` clears both setup and verify state on every new M1
request and resets the active exchange on any terminal authentication failure (bad SRP proof,
decryption failure, signature mismatch).  This prevents state from
a previous incomplete attempt from contaminating a retry.
`reset_setup()` and `reset_verify()` zero all associated secret
bytes via `Zeroize` before clearing the `Option`.

### Secret material hardening

- `DerivedKey`, `PairCipher`, `PairingCompletion`, `PairSetupState`, and `PairingSession`
  no longer implement `Clone`, `Debug`, `PartialEq`, `Eq`,
  `Serialize`, or `Deserialize`.  This prevents accidental copying
  or logging of key bytes.
- All types carrying secret bytes implement `Drop` or explicit
  zeroing via the `zeroize` crate.  `PairingSession::clear()`,
  `PairingSession::drop()`, and `PairCipher::drop()` zero their
  internal key material and counters.
- All logging of SRP private keys, SRP verifiers, X25519 shared
  secrets, derived encryption keys, decrypted pairing plaintext,
  and control ciphertext has been removed.  Only lengths,
  public keys/IDs, and success/failure indicators are logged.

### Control framing (`PairCipher`)

- **MAX_BLOCK = 1024.**  Any encrypted block with a length prefix
  larger than 1024 is rejected immediately without advancing the
  decryption counter.
- **Incomplete frames** return whatever complete blocks were consumed
  so far; the remainder is buffered by the caller.
- **Authentication failure** does not advance the decryption counter,
  so a legitimate sender can retry.
- **Counter exhaustion** is detected via checked arithmetic (`u64`
  overflow → `CounterExhausted` error) **before** nonce reuse.
- **Preflight encryption:** `encrypt_blocks` validates all blocks
  (size, counter range) before writing any output.  If any block
  would fail, no partial ciphertext is emitted.
- **Client-direction constructor**: `PairCipher::control_for_client`
  produces a cipher with swapped read/write keys for test round-trips.

### Coalesced plaintext → encrypted transition

When a terminal pairing request (e.g. pair-setup M3 or pair-verify
M3) activates the control cipher, its own response is sent as
plaintext (cipher state is captured *before* routing).  Any residual
bytes already in the plaintext buffer from the same TCP segment
are moved to the encrypted buffer, decrypted immediately, and
parsed as the next request.

### Buffer limits

RTSP control buffers are bounded at 16 MiB plaintext and 64 KiB
pending encrypted data. The larger plaintext limit accommodates metadata
and artwork bodies; exceeding either limit drops the connection.

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
   Event-driven status push via the event channel now sends
   `updateInfo` on each accepted connection and validates the
   encrypted 2xx acknowledgement.  No speculative live state
   pushes are generated yet — only the `updateInfo` command is
   sent on connect.

   The event channel transport lives in `src/airplay/ap2/event.rs`
   and provides:
   - `EventListener::bind()` — TCP listener with deterministic abort
     (aborting the listener also terminates the current worker).
   - `build_update_info_command()` — produces the exact `POST /command
     RTSP/1.0` wire format with `Content-Length` and `Content-Type:
     application/x-apple-binary-plist` (no `CSeq`).
   - `parse_rtsp_response()` — validates status line, case-insensitive
     headers, `Content-Length`, and complete-message boundary.
   - Only 2xx responses are accepted as successful acknowledgement;
     non-2xx, malformed, EOF, timeout, auth failure, oversize, or
     extra invalid data closes the worker but keeps the listener
     alive for reconnect.
   - At most one active connection: a new accepted connection aborts
     and replaces the previous worker.
   - The zeroizing pairing secret is used once to derive one
     session-lifetime event `PairCipher`. Workers share only the cipher;
     counters remain monotonic across reconnects and raw secret bytes are
     not retained by workers or logged.
   - Bounds: encrypted pending ≤ 4 096 bytes, decrypted response
     ≤ 8 192 bytes, `PairCipher::MAX_BLOCK` (1 024) enforced by the
     cipher.  All buffers use checked arithmetic.
   - Full test coverage (40 tests): wire format, binary-plist shape,
     RTSP response parser fragmented at every byte boundary,
     content-length body, malformed status/header/content-length,
     non-2xx, encrypted fragmented response, auth failure, encrypted/
     plaintext limit boundary and overflow, replacement of active
     connection, reconnect after failure, parent abort terminates
     worker, no payload log patterns.

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

The `pairing.rs` module adds **~25 tests** covering:
- Transient pair-setup M1→M4 completion (typed `TransientSetup` signal)
- Non-transient pair-setup M1→M3→M5→M6 completion (typed `FullSetup`
  signal, client persisted to DB)
- TLV-error HTTP-200 never signals completion or activates cipher
- Pair-verify M3 success/failure completion
- Stale setup state reset on new M1 and on auth failure
- Stale verify state reset on auth failure
- `reset_setup` / `clear` zeroization of session key
- `pair_add` rejection of unverified sessions
- `pair_remove` rejection of unverified sessions
- `pair_list` rejection of unverified sessions
- M6 inner TLV encryption/signature round-trip

The `crypto.rs` module adds **~12 tests** covering:
- Single-block, multi-block, and empty-plaintext encrypt/decrypt round-trips
- Exactly `MAX_BLOCK` boundary encryption
- Oversize length-prefix rejection (`BlockTooLarge`)
- Incomplete frame returns partial (0 consumed) then completes when rest arrives
- Auth failure does not advance decryption counter (retry works)
- Counter exhaustion detected before nonce reuse
- Multi-block encryption is transactional (preflight failure = no partial output)
- Client/server control cipher cross-direction round-trip
- Fragmented header at every byte boundary (accumulator pattern)

Full test count: **642** tests passing (`cargo test --all-targets`).

These tests run as part of `cargo test --all-targets` and are
independent of the RTSP server — no TCP sockets are opened for the
contract/validation tests, but the SETUP integration tests use a
Tokio runtime (via `#[tokio::test]`).
