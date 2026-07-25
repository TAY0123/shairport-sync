# AirPlay 2 API Conformance Matrix

**Target profile:** PTP + buffered audio (type 103) first.
Realtime audio (type 96), NTP timing, and No-timing modes are
**unsupported until implemented** — they are recognised and
acknowledged by the SETUP handler but the data-path for realtime
UDP and NTP-based clock synchronisation is not wired.

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

`src/airplay/ap2/session.rs` defines a pure `Ap2SessionPhase` enum
and `validate_transition(from, to) -> Result<(), TransitionError>` that
enforces the valid lifecycle ordering:

```text
Idle ──▶ Paired ──▶ Configured ──▶ StreamSetup ──▶ Recording
                                                   │
                                         ┌─────────┼─────────┐
                                         ▼         ▼         ▼
                                       Paused   Flushed   Teardown
                                         │         │         │
                                         └────┬────┘         │
                                              ▼              │
                                         Recording ◀─────────┘
                                         or Idle (session TEARDOWN)
```

## Timing protocol support

| Protocol | Setup   | Data-path | Notes                                      |
|----------|---------|-----------|--------------------------------------------|
| PTP      | ✅      | ✅        | Embedded PTP service (`src/ptp/`).         |
| NTP      | Parsed  | ❌        | Acknowledged in SETUP; no clock servo.     |
| None     | Parsed  | ❌        | Acknowledged for realtime-only streams.    |

## Stream type support

| Type | Num | Transport | Status                              |
|------|-----|-----------|-------------------------------------|
| Real-time audio | 96  | UDP       | Port opened; data path not wired.   |
| Buffered audio  | 103 | TCP       | Full decrypt + decode + playout. ✅ |
| Data / event    | 130 | TCP       | Port opened; data path not wired.   |

## Known gaps (target profile: PTP + buffered 103)

1. **Real-time audio (type 96).**  The SETUP handler opens a UDP socket
   and advertises the port, but no `spawn_realtime_audio_receiver`
   exists — packets are silently dropped.

2. **NTP timing.**  The SETUP plist `timingProtocol` = `"NTP"` is
   accepted and diagnosed but there is no NTP client or clock
   discipline loop.  Only `"PTP"` is wired through to the embedded
   PTP service.

3. **Data stream (type 130).**  The TCP listener is spawned but the
   connection handler is a stub that reads and discards.

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

These tests run as part of `cargo test --all-targets` and are
independent of the RTSP server — no TCP sockets are opened.
