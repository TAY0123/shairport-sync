use std::net::SocketAddr;

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
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, _)) => {
                    if let Some(packet) = parse_rtp_packet(&buf[..len]) {
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
}
