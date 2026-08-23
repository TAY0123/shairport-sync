# AirPlay 2 API Conformance Matrix

**Target profile:** PTP + buffered audio (type 103), and
**remote-control-only** with encrypted data stream (type 130).

Realtime audio (type 96), NTP timing, and bare `None` timing (without
`isRemoteControlOnly`) are **truthfully rejected** — the SETUP handler
returns `status=1` for unsupported stream types and `400 Bad Request`
for unsupported timing protocols. Remote-control-only sessions
(`timingProtocol=None` with `isRemoteControlOnly=true`) are accepted
when paired and AP2 is enabled; PTP is not required for this path.

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
| 7 | POST              | /fp-setup    | FairPlay    | Partial     |
| 8 | POST              | /configure   | Config      | Partial     |
| 9 | POST              | /audioMode   | Audio       | Implemented |
|10 | POST              | /command     | Control     | Partial     |
|11 | POST              | /feedback    | Feedback    | Implemented |
|12 | SETUP             | * (initial)  | Stream      | Partial     |
|13 | SETUP             | * (stream)   | Stream add  | Partial     |
|14 | SETPEERS          | *            | Peers       | Implemented |
|15 | SETPEERSX         | *            | Peers ext.  | Implemented |
|16 | RECORD            | *            | Playback    | Partial     |
|17 | SETRATEANCHORTIME | *            | Timing      | Partial     |
|18 | PAUSE             | *            | Playback    | Implemented |
|19 | FLUSHBUFFERED     | *            | Playback    | Implemented |
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
| Recording         | RECORD accepted; scheduler priming while timing gate may remain closed. |
| Paused            | PAUSE, FLUSHBUFFERED, or SETRATEANCHORTIME (rate=0).          |
| TearingDown       | TEARDOWN in progress — closing listeners.                     |
| Closed            | Fully closed; no further operations permitted.                |

### Stream management

`Ap2Stream` owns an immutable buffered-audio context (stream and connection
IDs, audio format, sample rate, frames-per-packet, zeroizing media key) plus
its data port. Buffered workers receive this context directly and do not read
media keys or formats from global application state.
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
| PTP      | ✅      | Partial   | Selected-master servo drives anchor deadlines. AP2-only bounded PI drift correction adjusts the resampler from timeline-tail and PCM FIFO error, with master/lock/reset handling and hard resync. Runtime correction, error, saturation, and hard-resync counters are exposed at `/api/v1/playout/status`; long-duration real-device validation remains pending. |
| NTP      | ❌ (400) | —        | Explicitly rejected in initial SETUP.      |
| None     | ❌ (400) | —        | Explicitly rejected in initial SETUP.      |

## Stream type support

| Type | Num | Transport | Status                              |
|------|-----|-----------|-------------------------------------|
| Real-time audio | 96  | —         | Rejected (status=1). No listener.   |
| Buffered audio  | 103 | TCP       | Framing, decrypt, decode, and bounded enqueue work; timed playout remains partial. |
| Data stream     | 130 | TCP       | Encrypted channel for remote-control-only sessions. Sync reply protocol implemented. MediaRemote protobuf decoding/dispatch remains unsupported. |

## Pairing & control framing guarantees

### Pairing completion signal

The `PairingReply` carries a typed `PairingCompletion` enum
(`TransientSetup`, `FullSetup`, `Verify`).  A completion is signalled
**only** when the terminal pairing step succeeds and the response TLV
contains no error.  Apple sends TLV errors with HTTP 200 — the old
pattern of checking `status_code >= 200` for success was therefore
unsafe and has been replaced.  The RTSP handler marks the
`Ap2SessionState` as `Paired` exclusively from the completion signal.
Control encryption (`PairCipher`) is installed per the table below.

#### Control encryption activation

| Completion       | Marks Paired | Installs `control_cipher`              |
|------------------|:------------:|----------------------------------------|
| `TransientSetup` | ✓            | ✓ — SRP session key K                 |
| `FullSetup`      | ✓            | **no** — stays plaintext              |
| `Verify`         | ✓            | ✓ — X25519 shared secret              |

**Transient pair-setup** has no subsequent pair-verify; the SRP session
key K is therefore used directly to derive the control cipher.

**Non-transient (full) pair-setup** persists the client identity to the
`PairingDatabase` and marks the session `Paired`, but deliberately does
*not* activate RTSP control encryption.  The next pair-verify exchange
runs in plaintext; only a successful `Verify` completion installs the
control `PairCipher` (using the fresh X25519 shared secret, not the
stale SRP session key).  This matches Apple's protocol behaviour.

- **Transient pair-setup:** `TransientSetup { key, client_id: None }` after M3/M4 SRP
  proof verification.  `key` is the 64-byte SRP session key K.
- **Non-transient pair-setup:** `FullSetup { key, client_id }` after
  M5 identity verification and M6 generation.  The client is persisted
  to the `PairingDatabase` before the completion is signalled.
  The `key` is *not* used for control encryption (see above).
- **Pair-verify:** `Verify { shared_secret }` after M3 Ed25519
  signature verification.  `shared_secret` is the verified X25519
  ECDH shared secret used to derive the control cipher.

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

2. **NTP / None timing.**  The initial audio SETUP returns `400 Bad Request`.
   Only `"PTP"` is accepted for audio. Complete rate anchors are converted
   to local monotonic deadlines through the selected-master servo; output
   remains gated until lock, watermark, and presentation time all agree.

3. **Data stream MediaRemote decoding.**  The encrypted data stream
   (type 130) transport and sync reply protocol are implemented.
   Binary-plist payload shape is inspected for diagnostics, but
   protobuf messages (`DEVICE_INFO_MESSAGE`, etc.) are not decoded
   or dispatched.  The channel is fully operational as a transport;
   only the MRP-level message handling is missing.

4. **FairPlay (`/fp-setup`).** The observed two-stage exchange is validated
   strictly by version, message type, mode, declared length, and sequence,
   then answered with the upstream mode-specific constants. State is owned by
   the RTSP session and reset on teardown or connection failure. The upstream
   receiver treats the 32-byte type-103 `shk` as the direct
   ChaCha20-Poly1305 media key; the Rust buffered-wire regression verifies the
   upstream packet layout (`timestamp || SSRC` AAD, ciphertext/tag, trailing
   eight-byte nonce). Authentication with a packet captured from a real sender
   remains the interoperability exit criterion.

5. **`/configure`.** Binary-plist shape and known timing protocol,
   group-UUID presence, stream category, and nested HomeKit access-control
   fields are validated transactionally and stored per session. Enabling
   HomeKit access control returns the receiver identifier and public key.
   Unknown sender-specific configuration fields remain capture-driven.

6. **`/command`.**  Encrypted plist commands are decrypted and
   parsed for playback control (play/pause/stop/toggle), volume,
   and metadata updates.  Screen mirroring, Siri, and advanced
   MediaRemote commands are not handled.

7. **`/feedback` and `/audioMode`.** The captured sender sends `/feedback`
   without a body. While the owning session is recording a buffered stream,
   the response matches upstream with a binary plist containing
   `streams[0].type` and the negotiated sample rate in `streams[0].sr`.
   Before recording it returns an empty 200 response. `/audioMode` requires
   a bounded nonempty string and retains it in session-owned state;
   malformed updates are rejected transactionally. No mode-specific output
   change is invented without sender evidence.

   Event-driven status push via the event channel sends
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

8. **SETPEERS / SETPEERSX.** Legacy address arrays and extended peer
   dictionaries are parsed with strict bounds and lifecycle checks. Peer
   replacement is transactional. The sender-address match is preferred as
   PTP master, then peer priority; switching masters resets servo lock and
   stale timing samples. Connection cleanup clears owner-scoped selection.

## Test coverage

The `src/airplay/ap2/` modules ship focused inline tests covering:

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
- Buffered stream type 103 acceptance under PTP
- Context-aware type 130 acceptance for control-only sessions without PTP
- PTP timing acceptance and control-only `None` handling
- Format playability checks

The `rtsp.rs` AP2 SETUP tests cover:
- Buffered type 103 happy-path (ports + immutable session stream context)
- Privacy-safe real-sender prefix ordering, including RECORD before stream
  SETUP and omission of `sr`
- Route-to-TCP-ingress authentication of an independently generated
  encrypted packet using the exact `shk` supplied in stream SETUP
- Actual ingress/jitter-capacity-derived `audioBufferSize`
- Single buffered-stream enforcement and transactional listener rollback
- Realtime type 96 rejection (status=1, no listener, no activation)
- Data type 130 rejection without remote-control-only session (455)
- Remote-control-only None timing + isRemoteControlOnly SETUP
- Unknown stream type rejection (status=1)
- Unplayable format rejection (AAC under AlacOnly policy)
- NTP / None / empty timing protocol → appropriate error
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

The `crypto.rs` module contains **23 focused tests** covering:
- Single-block, multi-block, and empty-plaintext encrypt/decrypt round-trips
- Exactly `MAX_BLOCK` boundary encryption
- Oversize length-prefix rejection (`BlockTooLarge`)
- Incomplete frame returns partial (0 consumed) then completes when rest arrives
- Auth failure does not advance decryption counter (retry works)
- Counter exhaustion detected before nonce reuse
- Multi-block encryption is transactional (preflight failure = no partial output)
- Staged outbound encryption commits counters only after complete network writes
- Cancelled/failed uncertain writes poison outbound state instead of reusing a nonce
- Client/server control cipher cross-direction round-trip
- Fragmented header at every byte boundary (accumulator pattern)

The `ap2/data.rs` module contains **17 focused tests** covering:
- Exact 32-byte big-endian header parsing and canonical field prefixes
- Header fragmentation at every boundary, size limits, and zero padding
- Exact `sync` → `rply` bytes and sequence-number preservation
- Nested/direct binary-plist shape inspection and malformed-plist rejection
- Checked encrypted/plaintext accumulation bounds
- Real encrypted TCP sync round-trip with bytewise fragmentation
- Reconnect counter continuity and authentication-failure retry
- Sequential worker replacement and active-worker abort/drop cleanup
- Fixed partial-frame deadlines, non-sync no-reply behavior, and safe errors

Route-level RTSP integration tests additionally cover:
- Actual control-only initial SETUP with an encrypted event listener
- RECORD before a data stream without audio or playout side effects
- Type-130 response shape and real encrypted sync traffic on `dataPort`
- Strict/transactional seed, dedicated-socket, and control-type rejection
- Duplicate SETUP rollback, data-only TEARDOWN, and full session cleanup

Full test count: **787** tests passing (`cargo test --all-targets`).

Contract and pure validation tests do not open sockets. The event/data
transport and RTSP lifecycle integration tests intentionally use loopback TCP
listeners under Tokio to verify real ownership, framing, reconnect, and
teardown behavior.
