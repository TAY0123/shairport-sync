# C Shairport Sync parity review

This document compares `shairport-rs` with the C implementation in the repository root at
`origin/master` (`6f5d2fe8` at the time of review). It distinguishes features that the C receiver
already implements from protocol areas that are incomplete in both implementations.

## AirPlay protocol gaps

| Area | C implementation | Rust implementation | Priority |
| --- | --- | --- | --- |
| AP2 realtime audio, stream type 96 | Implemented with a UDP realtime-audio socket and `rtp_realtime_audio_receiver` (`rtsp.c`, type 96 SETUP) | Implemented with UDP RTP authentication/decrypt, immutable zeroizing stream context, and shared PTP-scheduled playout; real-device validation remains | Validation |
| AP2 six/eight-channel audio | Supported/configurable by the C audio/FFmpeg path (`six_channel_mode`, `eight_channel_mode`, channel layouts and mixdown) | 5.1/7.1 formats are deliberately excluded from AP2 advertised buffered formats | Medium |
| AP2 output channel mapping | C supports named FFmpeg channel layouts, explicit channel maps and automatic mixdown | Rust has basic remap/mixdown but no equivalent configurable channel-layout/mapping surface | Medium |
| AP1 resend policy tuning | C exposes first/check/last resend timings and diagnostic disable controls | Rust implements resend handling but does not expose the equivalent policy controls | Low |
| Session interruption/lifetime policy | C exposes session interruption and session timeout controls | Rust has receiver/session ownership but no equivalent user-facing policy knobs | Low |

### Shared AP2 gaps — not C parity regressions

These should not be counted as features the Rust rewrite lost:

- **AP2 NTP timing:** the C path explicitly logs that NTP stream handling is not implemented (`rtsp.c` around the NTP initial SETUP branch). Rust also rejects AP2 NTP audio.
- **Type-130 MediaRemote/MRP:** C creates the Remote Control data port and cipher context, but there is no data-socket consumer/MediaRemote decoder in the C tree. Rust now goes further: encrypted DataStream framing/sync plus an outbound Play/Pause/Toggle/Stop/Next/Previous MediaRemote command subset are implemented. Full inbound MediaRemote state/protobuf decoding remains incomplete.
- **FairPlay:** both implementations use the known `/fp-setup` reply material and consume the `shk` supplied during stream SETUP. Neither tree contains a complete independent FairPlay key-exchange implementation.

## Audio/output gaps

The C receiver has a substantially broader output and DSP surface. Rust currently uses CPAL as the
portable output abstraction, with supervised device recovery. Missing C-equivalent features include:

- dedicated ALSA hardware-mixer control, hardware mute, mmap/period/buffer controls and precision timing;
- native PipeWire, PulseAudio, sndio, libao, libsoundio and raw pipe/stdout backends;
- JACK-specific autoconnect/resampling controls beyond CPAL host selection;
- configurable output rate/PCM format/channel-count preference lists and dynamic format selection;
- volume range/max/profile policies and combined hardware/software attenuation;
- fixed backend-latency compensation and the C silent-lead-in controls;
- convolution filtering and loudness compensation;
- selectable SoXR/vernier/basic stuffing policies. Rust uses Rubato-based resampling/drift correction instead.

These are not required to prove basic AP2 playback, but matter for feature parity with mature Shairport Sync installations.

## Metadata, automation and control gaps

C features without Rust equivalents today:

- native Shairport Sync D-Bus control/configuration interface;
- metadata Unix pipe output and UDP/multicast metadata feed;
- MQTT metadata publishing, cover-art publishing, Home Assistant discovery and MQTT remote controls;
- cover-art disk cache/retention policy;
- configurable lifecycle hooks (`before/after active`, `before/after play`, volume-change hook, fatal-error hook);
- configurable system-vs-session bus selection for Linux D-Bus/MPRIS. Rust's Playwire MPRIS backend uses the user session bus.

Rust now exceeds the C tree in one integration area: it provides one cross-platform media-session layer
for Linux MPRIS, Windows SMTC and macOS Now Playing/Remote Command Center.

## Pause-to-sender behavior

The C MPRIS handler sends `pause` through DACP (`mpris-service.c` calls
`send_simple_dacp_command("pause")`). Rust follows the same authority model: system media Pause enters
`apply_remote_command`, pauses local output and sends `GET /ctrl-int/1/pause` to the discovered DACP
endpoint when `DACP-ID` and `Active-Remote` are present. A regression test verifies the actual request
is written to the sender endpoint.

For AP2 clients that do not expose DACP, Rust now falls back to the connected type-130 DataStream and
sends a MediaRemote Pause command. DACP remains preferred when available to avoid duplicate source
commands. Full inbound MediaRemote state handling remains future protocol work rather than C-parity work.

## Recommended implementation order

1. Keep real iPhone/macOS AP2 interoperability as the primary exit test for the existing type-103/PTP path.
2. Validate type-96 realtime audio and type-130 outbound MediaRemote controls against real iPhone/macOS senders.
3. Extend type-130 with inbound MediaRemote device/now-playing/supported-command state handling as required by captures.
4. Add six/eight-channel advertisement, decode and configurable channel-layout/mixdown support.
5. Add operational integrations in demand order: native D-Bus, metadata outputs/MQTT, then backend-specific audio/DSP features.
