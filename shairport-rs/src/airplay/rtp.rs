use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::{net::UdpSocket, task::JoinHandle};
use tracing::{debug, info, warn};

use crate::{
    config::AirplayConfig,
    decoder,
    playout::{
        ingress::IngressResult,
        packet::{StreamProtocol, TimedPacket},
        scheduler::PlayoutHandle,
        sequence::SequenceExtender16,
    },
    state::AppState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RtpChannel {
    Audio,
    Control,
    Timing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RtpPacket {
    pub version: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload_len: usize,
}

/// Handles returned by `spawn_rtp_receivers`.
pub struct RtpReceiverHandles {
    /// Network I/O tasks (UDP recv loops for audio, control, timing).
    pub network: Vec<JoinHandle<()>>,
}

pub async fn spawn_rtp_receivers(
    config: AirplayConfig,
    state: AppState,
    playout: PlayoutHandle,
) -> anyhow::Result<RtpReceiverHandles> {
    let audio_net = bind_audio_network(config.audio_port, state.clone(), playout).await?;
    let control = bind_channel(RtpChannel::Control, config.control_port, state.clone()).await?;
    let timing = bind_channel(RtpChannel::Timing, config.timing_port, state.clone()).await?;

    Ok(RtpReceiverHandles {
        network: vec![audio_net, control, timing],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ap1SubmitResult {
    WaitingForTitle,
    Accepted,
    Full,
    Closed,
}

/// Apply the AP1 title gate and submit one decrypted packet to the shared
/// playout service. This keeps diagnostics and drop behavior in one path that
/// can be tested without binding a UDP socket.
fn submit_ap1_packet(
    state: &AppState,
    playout: &PlayoutHandle,
    packet: TimedPacket,
    rtp: RtpPacket,
) -> Ap1SubmitResult {
    if state.is_waiting_for_track_title() {
        state.set_diagnostic("ap1_waiting_for_track_title", "true");
        return Ap1SubmitResult::WaitingForTitle;
    }
    state.set_diagnostic("ap1_waiting_for_track_title", "false");

    match playout.try_send_ap1(packet) {
        IngressResult::Accepted => {
            state.record_rtp_packet(RtpChannel::Audio, rtp);
            let diag = playout.ingress_diagnostics();
            state.set_diagnostic("ap1_ingress_max_depth", diag.max_depth.to_string());
            Ap1SubmitResult::Accepted
        }
        IngressResult::Full => {
            let diag = playout.ingress_diagnostics();
            state.set_diagnostic("ap1_ingress_full_drops", diag.full_drops.to_string());
            state.set_diagnostic("ap1_ingress_max_depth", diag.max_depth.to_string());
            Ap1SubmitResult::Full
        }
        IngressResult::Closed => {
            let diag = playout.ingress_diagnostics();
            state.set_diagnostic("ap1_ingress_closed_drops", diag.closed_drops.to_string());
            state.set_diagnostic("ap1_ingress_max_depth", diag.max_depth.to_string());
            Ap1SubmitResult::Closed
        }
    }
}

/// UDP receive loop: parses RTP, decrypts AES-CBC, extends sequence,
/// builds a [`TimedPacket`], and non-blocking `try_send`s it into the
/// bounded ingress.  No decoding or PCM enqueue happens here.
async fn bind_audio_network(
    port: u16,
    state: AppState,
    playout: PlayoutHandle,
) -> anyhow::Result<JoinHandle<()>> {
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("failed to bind RTP Audio socket on {bind}"))?;
    Ok(tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut seq_ext = SequenceExtender16::new();
        let mut first_packet = true;
        let mut last_epoch: u64 = 0;

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, _)) => {
                    if len < 12 {
                        continue;
                    }
                    let payload_type = buf[1] & 0x7f;
                    // Classic AP1 audio type: 0x60 (audio data) or 0x56 (resend)
                    if payload_type != 0x60 && payload_type != 0x56 {
                        continue;
                    }
                    let retransmitted = payload_type == 0x56;
                    let epoch = state.track_transition_epoch();
                    if epoch != last_epoch {
                        seq_ext.reset();
                        last_epoch = epoch;
                        info!(epoch, "AP1 sequence extender reset for track transition");
                    }

                    let payload = &buf[12..len];

                    // Wait until session crypto is available
                    let session_crypto = state.session_crypto.read();
                    let Some(ref crypto) = *session_crypto else {
                        debug!("no session crypto yet — buffering");
                        continue;
                    };
                    let aes_key = crypto.aes_key;
                    let aes_iv = crypto.aes_iv;

                    // Decrypt the AES-CBC payload in place.
                    let mut decrypted = payload.to_vec();
                    let aes_len = decrypted.len() & !0xf;

                    if let Err(e) = decoder::aes_cbc_decrypt_in_place(
                        &aes_key,
                        &aes_iv,
                        &mut decrypted[..aes_len],
                    ) {
                        warn!(%e, "AES-CBC decrypt failed");
                        continue;
                    }

                    // Parse RTP header fields for sequence extension and diagnostics.
                    let rtp = parse_rtp_packet_inner(&buf[..len]);
                    let seq_result = seq_ext.extend(rtp.sequence_number);

                    let pkt = TimedPacket::new(
                        StreamProtocol::ClassicAp1,
                        seq_result.extended_sequence,
                        rtp.sequence_number as u32,
                        rtp.timestamp,
                        rtp.ssrc,
                        None, // AP1 format is resolved from AppState by the decoder
                        Bytes::from(decrypted),
                        std::time::Instant::now(),
                        retransmitted,
                        epoch,
                    );

                    match submit_ap1_packet(&state, &playout, pkt, rtp) {
                        Ap1SubmitResult::WaitingForTitle => {
                            debug!("RTP audio packet drained while waiting for new title");
                        }
                        Ap1SubmitResult::Accepted => {
                            if first_packet {
                                info!("AP1 ingress: first packet accepted");
                                first_packet = false;
                            }
                        }
                        Ap1SubmitResult::Full => {
                            warn!("AP1 ingress full — packet dropped");
                        }
                        Ap1SubmitResult::Closed => {
                            warn!("AP1 ingress closed — shutting down audio network loop");
                            break;
                        }
                    }
                }
                Err(err) => warn!(?err, "RTP audio receive failed"),
            }
        }
    }))
}

async fn bind_channel(
    channel: RtpChannel,
    port: u16,
    state: AppState,
) -> anyhow::Result<JoinHandle<()>> {
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("failed to bind RTP {channel:?} socket on {bind}"))?;
    Ok(tokio::spawn(async move {
        let mut buf = [0u8; 65_536];
        let mut timing_reply_count: u64 = 0;
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, _)) => {
                    let data = &buf[..len];

                    // --- Apple AP1 control/timing packet detection ---
                    // These must be handled before standard RTP parsing to
                    // avoid misinterpreting Apple protocol fields as RTP headers.

                    if is_ap1_timing_reply(data) {
                        if let Some(reply) = parse_ap1_timing_reply(data) {
                            timing_reply_count += 1;
                            debug!(
                                seq = reply.seq,
                                origin_ntp = reply.origin_ntp,
                                receive_ntp = reply.receive_ntp,
                                transmit_ntp = reply.transmit_ntp,
                                count = timing_reply_count,
                                "AP1 timing reply received"
                            );
                            state.set_diagnostic(
                                "ap1_timing_reply_count",
                                timing_reply_count.to_string(),
                            );
                            state.set_diagnostic(
                                "ap1_timing_reply_remote_receive_ntp",
                                format!("{}", reply.receive_ntp),
                            );
                            state.set_diagnostic(
                                "ap1_timing_reply_remote_transmit_ntp",
                                format!("{}", reply.transmit_ntp),
                            );
                            state.record_rtp_packet(
                                channel,
                                RtpPacket {
                                    version: 2,
                                    marker: false,
                                    payload_type: 0xD3,
                                    sequence_number: reply.seq,
                                    timestamp: 0,
                                    ssrc: 0,
                                    payload_len: len.saturating_sub(12),
                                },
                            );
                        }
                        continue;
                    }

                    if is_ap1_timing_request(data) {
                        debug!(
                            len,
                            "AP1 timing request received (ignored — not sending replies yet)"
                        );
                        continue;
                    }

                    if is_ap1_resend_request(data) {
                        debug!(
                            len,
                            "AP1 resend request received (ignored — not sending resends yet)"
                        );
                        continue;
                    }

                    // Resend audio (type 0x56) on the control port: recognised
                    // and logged but not decoded in this phase.
                    if let Some(packet) = parse_ap1_resend_audio(data) {
                        debug!(
                            len,
                            seq = packet.sequence_number,
                            "AP1 resend audio on control port (recognised, not decoded)"
                        );
                        state.record_rtp_packet(channel, packet);
                        continue;
                    }

                    // Fall through to standard RTP parsing.
                    if let Some(packet) = parse_rtp_packet(data) {
                        debug!(
                            ?channel,
                            seq = packet.sequence_number,
                            "RTP packet received"
                        );
                        state.record_rtp_packet(channel, packet);
                    }
                }
                Err(err) => warn!(?channel, %err, "RTP receive failed"),
            }
        }
    }))
}

fn parse_rtp_packet_inner(buf: &[u8]) -> RtpPacket {
    let csrc_count = (buf[0] & 0x0f) as usize;
    let header_len = 12 + csrc_count * 4;
    RtpPacket {
        version: buf[0] >> 6,
        marker: buf[1] & 0x80 != 0,
        payload_type: buf[1] & 0x7f,
        sequence_number: u16::from_be_bytes([buf[2], buf[3]]),
        timestamp: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ssrc: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        payload_len: buf.len() - header_len,
    }
}

pub fn parse_rtp_packet(packet: &[u8]) -> Option<RtpPacket> {
    if packet.len() < 12 {
        return None;
    }
    let version = packet[0] >> 6;
    if version != 2 {
        return None;
    }
    let csrc_count = (packet[0] & 0x0f) as usize;
    let header_len = 12 + csrc_count * 4;
    if packet.len() < header_len {
        return None;
    }
    Some(RtpPacket {
        version,
        marker: packet[1] & 0x80 != 0,
        payload_type: packet[1] & 0x7f,
        sequence_number: u16::from_be_bytes([packet[2], packet[3]]),
        timestamp: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        ssrc: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        payload_len: packet.len() - header_len,
    })
}

// ---------------------------------------------------------------------------
// AP1 (classic AirPlay) control-channel packet codecs
// ---------------------------------------------------------------------------

/// Decoded AP1 timing reply packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ap1TimingReply {
    /// Echo of the sequence number in the corresponding timing request.
    pub seq: u16,
    /// Origin timestamp (NTP 64-bit fixed-point 32.32).
    pub origin_ntp: u64,
    /// Receive timestamp (NTP 64-bit fixed-point 32.32).
    pub receive_ntp: u64,
    /// Transmit timestamp (NTP 64-bit fixed-point 32.32).
    pub transmit_ntp: u64,
}

/// Build a 32-byte AP1 timing request packet.
///
/// Layout:
/// ```text
/// 0x80      — version/type marker
/// 0xD2      — timing request subtype
/// seq (BE)  — 2-byte sequence number
/// zeros     — remaining 28 bytes
/// ```
pub fn build_ap1_timing_request(seq: u16) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0] = 0x80;
    buf[1] = 0xD2;
    buf[2] = (seq >> 8) as u8;
    buf[3] = seq as u8;
    // bytes 4..32 remain zero
    buf
}

/// Parse a 32-byte AP1 timing reply packet.
///
/// Returns `None` if the buffer is fewer than 32 bytes or if the
/// second byte is not `0xD3` (timing reply subtype).
pub fn parse_ap1_timing_reply(data: &[u8]) -> Option<Ap1TimingReply> {
    if data.len() < 32 || data[0] != 0x80 || data[1] != 0xD3 {
        return None;
    }
    let seq = u16::from_be_bytes([data[2], data[3]]);
    // Bytes 4..8 are the Apple timing packet's 32-bit filler field.
    let origin_ntp = u64::from_be_bytes(data[8..16].try_into().ok()?);
    let receive_ntp = u64::from_be_bytes(data[16..24].try_into().ok()?);
    let transmit_ntp = u64::from_be_bytes(data[24..32].try_into().ok()?);
    Some(Ap1TimingReply {
        seq,
        origin_ntp,
        receive_ntp,
        transmit_ntp,
    })
}

/// Build an 8-byte AP1 resend request packet.
///
/// Layout:
/// ```text
/// 0x80            — version/type marker
/// 0xD5            — resend request subtype
/// request_seq (BE) — 2 bytes, this request's sequence number
/// first_missing (BE) — 2 bytes, sequence of first missing packet
/// count (BE)      — 2 bytes, number of missing packets requested
/// ```
pub fn build_ap1_resend_request(request_seq: u16, first_missing: u16, count: u16) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0] = 0x80;
    buf[1] = 0xD5;
    buf[2] = (request_seq >> 8) as u8;
    buf[3] = request_seq as u8;
    buf[4] = (first_missing >> 8) as u8;
    buf[5] = first_missing as u8;
    buf[6] = (count >> 8) as u8;
    buf[7] = count as u8;
    buf
}

// ---------------------------------------------------------------------------
// NTP 64-bit fixed-point (32.32) helpers
// ---------------------------------------------------------------------------

/// Convert an NTP 64-bit fixed-point timestamp (seconds:32, fraction:32)
/// to nanoseconds as a `u64`. The 32-bit NTP seconds range (about 136
/// years) fits in `u64` nanoseconds; checked arithmetic keeps the helper safe.
///
/// NTP epoch is 1900-01-01; this conversion intentionally does not
/// apply an epoch offset — callers that need wall-clock time difference
/// can subtract two NTP values and pass the difference here.
pub fn ntp64_to_nanos(ntp: u64) -> Option<u64> {
    let secs = ntp >> 32;
    let frac = ntp & 0xFFFF_FFFF;
    // Each fraction tick is 2^-32 seconds ≈ 0.2328 ns
    let nanos_from_secs = secs.checked_mul(1_000_000_000)?;
    // frac * 1e9 / 2^32  using 128-bit intermediate to avoid overflow
    let nanos_from_frac = (frac as u128 * 1_000_000_000u128 / (1u128 << 32)) as u64;
    nanos_from_secs.checked_add(nanos_from_frac)
}

/// Convert an NTP 64-bit difference (two NTP timestamps subtracted) into
/// a [`Duration`].  Saturates to [`Duration::MAX`] on overflow.
pub fn ntp64_delta_to_duration(ntp_delta: u64) -> Duration {
    match ntp64_to_nanos(ntp_delta) {
        Some(ns) => Duration::from_nanos(ns),
        None => Duration::MAX,
    }
}

// ---------------------------------------------------------------------------
// Apple control-channel packet detection helpers
// ---------------------------------------------------------------------------

/// Returns `true` when `data` looks like an Apple AP1 timing request
/// (length ≥ 4, first byte 0x80, second byte 0xD2).
pub fn is_ap1_timing_request(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x80 && data[1] == 0xD2
}

/// Returns `true` when `data` looks like an Apple AP1 timing reply
/// (length ≥ 32, first byte 0x80, second byte 0xD3).
pub fn is_ap1_timing_reply(data: &[u8]) -> bool {
    data.len() >= 32 && data[0] == 0x80 && data[1] == 0xD3
}

/// Returns `true` when `data` looks like an Apple AP1 resend request
/// (length ≥ 8, first byte 0x80, second byte 0xD5).
pub fn is_ap1_resend_request(data: &[u8]) -> bool {
    data.len() >= 8 && data[0] == 0x80 && data[1] == 0xD5
}

/// Parse an Apple AP1 retransmitted-audio packet.
///
/// The outer four-byte Apple wrapper has payload type `0x56`; the inner RTP
/// header begins at byte 4. Returned diagnostics use the inner RTP sequence,
/// timestamp, SSRC, and payload length while retaining `0x56` as the type.
pub fn parse_ap1_resend_audio(data: &[u8]) -> Option<RtpPacket> {
    if data.len() < 16 || data[0] >> 6 != 2 || (data[1] & 0x7f) != 0x56 {
        return None;
    }
    let inner = parse_rtp_packet(&data[4..])?;
    Some(RtpPacket {
        payload_type: 0x56,
        ..inner
    })
}

/// Returns `true` when `data` is a structurally valid AP1 resend-audio packet.
pub fn is_ap1_resend_audio(data: &[u8]) -> bool {
    parse_ap1_resend_audio(data).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playout::packet::{StreamProtocol, TimedPacket};
    use crate::playout::scheduler::PlayoutHandle;
    use std::time::Instant;

    /// Build a minimal AP1-style [`TimedPacket`] for ingress tests.
    fn ap1_packet(seq: u64) -> TimedPacket {
        TimedPacket::new(
            StreamProtocol::ClassicAp1,
            seq,
            seq as u32,
            seq as u32 * 352,
            0,
            None,
            bytes::Bytes::from_static(&[0; 16]),
            Instant::now(),
            false,
            0,
        )
    }

    fn rtp_diagnostic(seq: u64) -> RtpPacket {
        RtpPacket {
            version: 2,
            marker: false,
            payload_type: 0x60,
            sequence_number: seq as u16,
            timestamp: seq as u32 * 352,
            ssrc: 0x0102_0304,
            payload_len: 16,
        }
    }

    #[test]
    fn parses_rtp_header() {
        let mut packet = vec![0x80, 0xe0, 0, 7, 0, 0, 0, 9, 1, 2, 3, 4];
        packet.extend_from_slice(&[1, 2, 3]);
        let parsed = parse_rtp_packet(&packet).unwrap();
        assert_eq!(parsed.version, 2);
        assert!(parsed.marker);
        assert_eq!(parsed.payload_type, 0x60);
        assert_eq!(parsed.sequence_number, 7);
        assert_eq!(parsed.timestamp, 9);
        assert_eq!(parsed.ssrc, 0x01020304);
        assert_eq!(parsed.payload_len, 3);
    }

    #[test]
    fn submit_ap1_accepted_records_rtp_and_max_depth() {
        let state = AppState::new(crate::config::Config::default());
        let (playout, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(64);

        for seq in 0..5 {
            assert_eq!(
                submit_ap1_packet(&state, &playout, ap1_packet(seq), rtp_diagnostic(seq)),
                Ap1SubmitResult::Accepted
            );
        }

        let snapshot = state.snapshot();
        assert_eq!(snapshot.rtp.audio_packets, 5);
        assert_eq!(snapshot.rtp.last_audio_sequence, Some(4));
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap1_ingress_max_depth")
                .map(String::as_str),
            Some("5")
        );
        let diag = playout.ingress_diagnostics();
        assert_eq!(diag.accepted, 5);
        assert_eq!(diag.full_drops, 0);
        assert_eq!(diag.closed_drops, 0);
    }

    #[test]
    fn submit_ap1_full_updates_state_diagnostics() {
        let state = AppState::new(crate::config::Config::default());
        let (playout, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(1);

        assert_eq!(
            submit_ap1_packet(&state, &playout, ap1_packet(0), rtp_diagnostic(0)),
            Ap1SubmitResult::Accepted
        );
        assert_eq!(
            submit_ap1_packet(&state, &playout, ap1_packet(1), rtp_diagnostic(1)),
            Ap1SubmitResult::Full
        );

        let snapshot = state.snapshot();
        assert_eq!(snapshot.rtp.audio_packets, 1);
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap1_ingress_full_drops")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap1_ingress_max_depth")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn submit_ap1_closed_updates_state_diagnostics() {
        let state = AppState::new(crate::config::Config::default());
        let (playout, _cmd_rx, ingress_rx) = PlayoutHandle::command_channel_for_tests(64);
        drop(ingress_rx);

        assert_eq!(
            submit_ap1_packet(&state, &playout, ap1_packet(1), rtp_diagnostic(1)),
            Ap1SubmitResult::Closed
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.rtp.audio_packets, 0);
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap1_ingress_closed_drops")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn submit_ap1_waiting_title_uses_production_gate() {
        let state = AppState::new(crate::config::Config::default());
        state.clear_track_for_transition();
        let (playout, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(64);

        assert_eq!(
            submit_ap1_packet(&state, &playout, ap1_packet(0), rtp_diagnostic(0)),
            Ap1SubmitResult::WaitingForTitle
        );
        assert_eq!(playout.ingress_diagnostics().accepted, 0);
        let snapshot = state.snapshot();
        assert_eq!(snapshot.rtp.audio_packets, 0);
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap1_waiting_for_track_title")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn submit_ap1_title_ready_allows_production_submission() {
        let state = AppState::new(crate::config::Config::default());
        state.set_track_metadata(Some("Track".to_string()), None, None);
        let (playout, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(64);

        assert_eq!(
            submit_ap1_packet(&state, &playout, ap1_packet(0), rtp_diagnostic(0)),
            Ap1SubmitResult::Accepted
        );
        assert_eq!(playout.ingress_diagnostics().accepted, 1);
        assert_eq!(state.snapshot().rtp.audio_packets, 1);
        assert_eq!(
            state
                .snapshot()
                .diagnostics
                .get("ap1_waiting_for_track_title")
                .map(String::as_str),
            Some("false")
        );
    }

    // -------------------------------------------------------------------
    // AP1 timing request / reply codec tests
    // -------------------------------------------------------------------

    #[test]
    fn build_timing_request_byte_layout() {
        let pkt = build_ap1_timing_request(0x1234);
        assert_eq!(pkt[0], 0x80);
        assert_eq!(pkt[1], 0xD2);
        assert_eq!(pkt[2], 0x12); // seq hi
        assert_eq!(pkt[3], 0x34); // seq lo
        // remaining 28 bytes must be zero
        assert!(pkt[4..32].iter().all(|&b| b == 0));
        assert_eq!(pkt.len(), 32);
    }

    #[test]
    fn build_timing_request_seq_0() {
        let pkt = build_ap1_timing_request(0);
        assert_eq!(pkt[2], 0);
        assert_eq!(pkt[3], 0);
    }

    #[test]
    fn build_timing_request_seq_max() {
        let pkt = build_ap1_timing_request(0xFFFF);
        assert_eq!(pkt[2], 0xFF);
        assert_eq!(pkt[3], 0xFF);
    }

    #[test]
    fn parse_timing_reply_exact_values() {
        let mut data = [0u8; 32];
        data[0] = 0x80;
        data[1] = 0xD3;
        data[2] = 0x00;
        data[3] = 0x42; // seq = 66
        // bytes 4..8 are the 32-bit filler and must be ignored.
        data[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        // origin NTP: 0x00000001_00000002
        data[8..16].copy_from_slice(&0x00000001_00000002u64.to_be_bytes());
        // receive NTP: 0x00000003_00000004
        data[16..24].copy_from_slice(&0x00000003_00000004u64.to_be_bytes());
        // transmit NTP: 0x00000005_00000006
        data[24..32].copy_from_slice(&0x00000005_00000006u64.to_be_bytes());

        let reply = parse_ap1_timing_reply(&data).unwrap();
        assert_eq!(reply.seq, 66);
        assert_eq!(reply.origin_ntp, 0x00000001_00000002);
        assert_eq!(reply.receive_ntp, 0x00000003_00000004);
        assert_eq!(reply.transmit_ntp, 0x00000005_00000006);
    }

    #[test]
    fn parse_timing_reply_too_short() {
        let data = [0x80u8, 0xD3, 0, 0];
        assert!(parse_ap1_timing_reply(&data).is_none());
    }

    #[test]
    fn parse_timing_reply_wrong_subtype() {
        let mut data = [0u8; 32];
        data[0] = 0x80;
        data[1] = 0xD2; // timing request, not reply
        assert!(parse_ap1_timing_reply(&data).is_none());
    }

    #[test]
    fn parse_timing_reply_wrong_leader() {
        let mut data = [0u8; 32];
        data[0] = 0x00;
        data[1] = 0xD3;
        assert!(parse_ap1_timing_reply(&data).is_none());
    }

    #[test]
    fn parse_timing_reply_seq_wrap() {
        let mut data = [0u8; 32];
        data[0] = 0x80;
        data[1] = 0xD3;
        data[2] = 0xFF;
        data[3] = 0xFF; // seq = 65535
        let reply = parse_ap1_timing_reply(&data).unwrap();
        assert_eq!(reply.seq, 65535);
    }

    // -------------------------------------------------------------------
    // AP1 resend request codec tests
    // -------------------------------------------------------------------

    #[test]
    fn build_resend_request_byte_layout() {
        let pkt = build_ap1_resend_request(1, 100, 5);
        assert_eq!(pkt[0], 0x80);
        assert_eq!(pkt[1], 0xD5);
        assert_eq!(pkt[2], 0x00); // request_seq hi
        assert_eq!(pkt[3], 0x01); // request_seq lo
        assert_eq!(pkt[4], 0x00); // first_missing hi
        assert_eq!(pkt[5], 0x64); // first_missing lo = 100
        assert_eq!(pkt[6], 0x00); // count hi
        assert_eq!(pkt[7], 0x05); // count lo
        assert_eq!(pkt.len(), 8);
    }

    #[test]
    fn build_resend_request_max_fields() {
        let pkt = build_ap1_resend_request(0xFFFF, 0xFFFF, 0xFFFF);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0xFFFF);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0xFFFF);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0xFFFF);
    }

    // -------------------------------------------------------------------
    // NTP64 helper tests
    // -------------------------------------------------------------------

    #[test]
    fn ntp64_one_second() {
        // 1.0 seconds (1 << 32, fraction 0)
        let ntp = 1u64 << 32;
        assert_eq!(ntp64_to_nanos(ntp), Some(1_000_000_000));
    }

    #[test]
    fn ntp64_two_seconds() {
        let ntp = 2u64 << 32;
        assert_eq!(ntp64_to_nanos(ntp), Some(2_000_000_000));
    }

    #[test]
    fn ntp64_half_second() {
        // 0.5 seconds = 2^31 fraction ticks
        let ntp = 1u64 << 31;
        assert_eq!(ntp64_to_nanos(ntp), Some(500_000_000));
    }

    #[test]
    fn ntp64_zero() {
        assert_eq!(ntp64_to_nanos(0), Some(0));
    }

    #[test]
    fn ntp64_delta_to_duration_one_sec() {
        let delta = 1u64 << 32; // 1 second NTP
        let dur = ntp64_delta_to_duration(delta);
        assert_eq!(dur, Duration::from_secs(1));
    }

    #[test]
    fn ntp64_max_value_produces_large_duration() {
        // Top 32 bits are seconds, max is ~4.3 billion sec ≈ 136 years.
        // This fits in both u64 nanos and Duration, so no saturate.
        let ntp = u64::MAX;
        let dur = ntp64_delta_to_duration(ntp);
        assert!(dur > Duration::from_secs(4_000_000_000));
        assert!(dur < Duration::MAX);
    }

    // -------------------------------------------------------------------
    // Apple control-channel packet detection tests
    // -------------------------------------------------------------------

    #[test]
    fn detect_timing_request() {
        let pkt = build_ap1_timing_request(42);
        assert!(is_ap1_timing_request(&pkt));
    }

    #[test]
    fn detect_timing_request_too_short() {
        assert!(!is_ap1_timing_request(&[0x80, 0xD2]));
    }

    #[test]
    fn detect_timing_reply() {
        let mut data = [0u8; 32];
        data[0] = 0x80;
        data[1] = 0xD3;
        assert!(is_ap1_timing_reply(&data));
    }

    #[test]
    fn detect_timing_reply_too_short() {
        assert!(!is_ap1_timing_reply(&[0x80, 0xD3, 0, 0]));
    }

    #[test]
    fn detect_resend_request() {
        let pkt = build_ap1_resend_request(1, 100, 5);
        assert!(is_ap1_resend_request(&pkt));
    }

    #[test]
    fn detect_resend_audio_uses_inner_rtp_header() {
        let mut data = [0u8; 19];
        data[0] = 0x80;
        data[1] = 0xD6; // outer marker=1, payload_type=0x56
        data[2..4].copy_from_slice(&7u16.to_be_bytes()); // wrapper request sequence
        data[4] = 0x80; // inner RTP v2
        data[5] = 0x60; // inner audio payload type
        data[6..8].copy_from_slice(&0x1234u16.to_be_bytes());
        data[8..12].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        data[12..16].copy_from_slice(&0xA0B0_C0D0u32.to_be_bytes());
        data[16..].copy_from_slice(&[1, 2, 3]);

        assert!(is_ap1_resend_audio(&data));
        let parsed = parse_ap1_resend_audio(&data).unwrap();
        assert_eq!(parsed.payload_type, 0x56);
        assert_eq!(parsed.sequence_number, 0x1234);
        assert_eq!(parsed.timestamp, 0x0102_0304);
        assert_eq!(parsed.ssrc, 0xA0B0_C0D0);
        assert_eq!(parsed.payload_len, 3);
    }

    #[test]
    fn detect_resend_audio_not_resend() {
        let mut data = [0u8; 12];
        data[0] = 0x80;
        data[1] = 0x60; // no marker, payload_type=0x60 (audio)
        assert!(!is_ap1_resend_audio(&data));
    }

    #[test]
    fn standard_rtp_not_detected_as_apple() {
        let mut packet = vec![0x80, 0x60, 0, 7, 0, 0, 0, 9, 1, 2, 3, 4];
        packet.extend_from_slice(&[1, 2, 3]);
        assert!(!is_ap1_timing_request(&packet));
        assert!(!is_ap1_timing_reply(&packet));
        assert!(!is_ap1_resend_request(&packet));
    }
}
