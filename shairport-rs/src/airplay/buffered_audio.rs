use std::net::SocketAddr;

use anyhow::Context;
use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time,
};
use tracing::{debug, info, warn};

use crate::{
    codec,
    config::AirplayConfig,
    playout::{
        ingress::IngressResult,
        packet::{StreamProtocol, TimedPacket},
        scheduler::PlayoutHandle,
        sequence::SequenceExtender23,
    },
    state::AppState,
};

/// SSRC constants for AP2 audio formats
const SSRC_ALAC_44100_S16_2: u32 = 0x0000_FACE;
const SSRC_ALAC_48000_S24_2: u32 = 0x1500_0000;
const SSRC_AAC_44100_F24_2: u32 = 0x1600_0000;
const SSRC_AAC_48000_F24_2: u32 = 0x1700_0000;

/// Spawn a TCP listener for AP2 buffered audio on the configured audio port.
pub async fn spawn_buffered_audio_receiver(
    config: AirplayConfig,
    state: AppState,
    playout: PlayoutHandle,
) -> anyhow::Result<JoinHandle<()>> {
    let bind = SocketAddr::from(([0, 0, 0, 0], config.audio_port));
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind buffered audio TCP on {bind}"))?;
    info!(port = config.audio_port, "AP2 buffered audio TCP listener");
    Ok(spawn_buffered_accept_loop(listener, state, playout))
}

/// Spawn an accept loop for buffered audio on an already-bound TcpListener.
pub fn spawn_buffered_accept_loop(
    listener: TcpListener,
    state: AppState,
    playout: PlayoutHandle,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    let playout = playout.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_buffered_stream(stream, peer, state, playout).await {
                            warn!(%peer, %e, "buffered audio stream error");
                        }
                    });
                }
                Err(e) => warn!(%e, "buffered audio accept error"),
            }
        }
    })
}

#[inline]
fn packet_matches_epoch(packet_epoch: u64, current_epoch: u64) -> bool {
    packet_epoch == current_epoch
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ap2SubmitResult {
    StaleEpoch,
    Accepted,
    Full,
    Closed,
}

/// Submit one decrypted AP2 packet to the shared playout service.
///
/// The helper validates the track-transition epoch immediately before the
/// awaited send, records synthetic RTP diagnostics only for accepted packets,
/// and publishes shared-ingress depth/drop counters to [`AppState`].
async fn submit_ap2_packet(
    state: &AppState,
    playout: &PlayoutHandle,
    packet: TimedPacket,
) -> Ap2SubmitResult {
    let current_epoch = state.track_transition_epoch();
    if !packet_matches_epoch(packet.transition_epoch, current_epoch) {
        state.set_diagnostic("ap2_stale_epoch_drops", packet.transition_epoch.to_string());
        return Ap2SubmitResult::StaleEpoch;
    }

    let rtp = crate::airplay::rtp::RtpPacket {
        version: 2,
        marker: false,
        payload_type: 96,
        sequence_number: packet.raw_sequence as u16,
        timestamp: packet.rtp_timestamp,
        ssrc: packet.ssrc,
        payload_len: packet.payload.len(),
    };

    let result = playout.send_ap2(packet).await;
    let diag = playout.ingress_diagnostics();
    state.set_diagnostic("ap2_ingress_max_depth", diag.max_depth.to_string());
    state.set_diagnostic(
        "ap2_waiting_for_track_title",
        state.is_waiting_for_track_title().to_string(),
    );

    match result {
        IngressResult::Accepted => {
            state.record_rtp_packet(crate::airplay::rtp::RtpChannel::Audio, rtp);
            Ap2SubmitResult::Accepted
        }
        IngressResult::Full => {
            state.set_diagnostic("ap2_ingress_full_drops", diag.full_drops.to_string());
            Ap2SubmitResult::Full
        }
        IngressResult::Closed => {
            state.set_diagnostic("ap2_ingress_closed_drops", diag.closed_drops.to_string());
            Ap2SubmitResult::Closed
        }
    }
}

/// Handle one buffered audio TCP connection.
///
/// The TCP read loop frames, decrypts, extends 23-bit sequences, and submits
/// [`TimedPacket`]s to the single shared playout service via awaited AP2 send.
/// Decoder state and PCM production are owned exclusively by that service.
pub async fn handle_buffered_stream(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: AppState,
    playout: PlayoutHandle,
) -> anyhow::Result<()> {
    info!(%peer, "buffered audio connection opened");

    // Wait until a session key is available (poll without holding guard across await)
    info!("buffered audio: waiting for session key...");
    let session_key = loop {
        {
            let key = state.ap2_media_key.read();
            if let Some(k) = *key {
                info!("buffered audio: session key obtained");
                break k;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };

    // Derive the data stream cipher
    let mut cipher = BufferedCipher::new(&session_key);
    info!("buffered audio: cipher initialized, reading first block");

    // ── TCP read loop: frame, decrypt, extend, submit ──────────────
    let mut word_buf = [0u8; 4];
    let mut seq_ext = SequenceExtender23::new();
    let mut block_count: u64 = 0;
    let mut first_block_logged = false;
    let mut current_epoch = state.track_transition_epoch();

    loop {
        // Read block length prefix (2 bytes, big-endian)
        let len_raw = match time::timeout(time::Duration::from_secs(5), stream.read_u16()).await {
            Ok(Ok(len)) => {
                if !first_block_logged {
                    info!(
                        block_len = len,
                        "buffered audio: first block length received, reading header..."
                    );
                    first_block_logged = true;
                }
                len
            }
            Ok(Err(e)) => {
                info!(%e, "buffered audio stream closed by client, blocks_processed={}", block_count);
                break;
            }
            Err(_) => {
                info!("buffered audio: read timeout (5s), stream may be idle");
                break;
            }
        };
        let block_len = len_raw as usize;
        let body_len = block_len.saturating_sub(2);
        if body_len < 12 || block_len > 65535 {
            warn!(
                block_len,
                blocks_processed = block_count,
                "invalid block length, breaking..."
            );
            break;
        }

        // Read block header: 4-byte seq (23-bit), 4-byte timestamp, 4-byte SSRC
        if stream.read_exact(&mut word_buf).await.is_err() {
            warn!("buffered audio: read seq failed");
            break;
        }
        let seq_23 = u32::from_be_bytes(word_buf) & 0x7FFFFF;

        if stream.read_exact(&mut word_buf).await.is_err() {
            warn!("buffered audio: read timestamp failed");
            break;
        }
        let timestamp = u32::from_be_bytes(word_buf);

        if stream.read_exact(&mut word_buf).await.is_err() {
            warn!("buffered audio: read SSRC failed");
            break;
        }
        let ssrc = u32::from_be_bytes(word_buf);

        // body_len - 12 header bytes = payload (ciphertext+tag+nonce)
        let payload_len = body_len.saturating_sub(12);
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 && stream.read_exact(&mut payload).await.is_err() {
            warn!("buffered audio: read payload failed");
            break;
        }

        block_count += 1;

        // Track transition handling: reset sequence extension. Packets are
        // tagged with their receive epoch and validated again immediately
        // before the awaited shared-ingress send.
        let new_epoch = state.track_transition_epoch();
        if new_epoch != current_epoch {
            seq_ext.reset();
            current_epoch = new_epoch;
            info!(
                epoch = current_epoch,
                "buffered audio sequence reset for track transition"
            );
        }

        // AAD = timestamp(4) + SSRC(4)
        let mut aad_buf = [0u8; 8];
        aad_buf[..4].copy_from_slice(&timestamp.to_be_bytes());
        aad_buf[4..].copy_from_slice(&ssrc.to_be_bytes());

        // Decrypt
        let plaintext = match cipher.decrypt_block(&payload, &aad_buf) {
            Ok(p) => {
                if block_count <= 3 {
                    let hex_first16: String = payload
                        .iter()
                        .take(16)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    info!(seq = seq_23, ssrc, blocks_processed = block_count, plaintext_len = p.len(), payload_first16 = %hex_first16, "buffered audio: block decrypted successfully");
                }
                p
            }
            Err(e) => {
                warn!(%e, seq = seq_23, ssrc, blocks_processed = block_count, block_len, payload_len, "block decrypt failed");
                continue;
            }
        };

        debug!(
            seq = seq_23,
            ts = timestamp,
            ssrc,
            payload_len = plaintext.len(),
            "buffered audio block"
        );

        let format =
            match codec::AudioFormat::from_ssrc(ssrc).or_else(|| *state.ap2_audio_format.read()) {
                Some(f) => f,
                None => {
                    warn!(
                        ssrc,
                        ssrc_hex = format_args!("{ssrc:#010x}"),
                        "unknown AP2 audio format"
                    );
                    continue;
                }
            };

        if !format.is_playable() {
            warn!(
                format = format.description(),
                "unsupported AP2 audio format"
            );
            continue;
        }

        let seq_result = seq_ext.extend(seq_23);

        let pkt = TimedPacket::new(
            StreamProtocol::AirPlay2Buffered,
            seq_result.extended_sequence,
            seq_23,
            timestamp,
            ssrc,
            Some(format),
            Bytes::from(plaintext),
            std::time::Instant::now(),
            false, // TCP is reliable — no retransmissions
            current_epoch,
        );

        // Awaited send applies TCP backpressure through the shared bounded
        // ingress. Waiting-for-title does not discard AP2 packets here; RTSP
        // metadata remains responsible for starting the scheduler.
        match submit_ap2_packet(&state, &playout, pkt).await {
            Ap2SubmitResult::Accepted | Ap2SubmitResult::StaleEpoch => {}
            Ap2SubmitResult::Full => {
                // Async send should not report Full, but retain defensive
                // handling for future ingress implementations.
                warn!("AP2 ingress unexpected Full on async send");
            }
            Ap2SubmitResult::Closed => {
                warn!("AP2 ingress closed — connection shutting down");
                break;
            }
        }
    }

    info!(%peer, blocks_processed = block_count, "buffered audio connection closed");
    Ok(())
}

/// Chacha20-Poly1305 cipher for buffered audio decryption.
struct BufferedCipher {
    key: [u8; 32],
}

impl BufferedCipher {
    fn new(session_key: &[u8; 32]) -> Self {
        Self { key: *session_key }
    }

    fn decrypt_block(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 + 8 {
            return Err("block too short");
        }

        let nonce_len = 8;
        let clen = ciphertext.len() - nonce_len;
        let nonce_raw = &ciphertext[clen..];

        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(nonce_raw);

        let key = chacha20poly1305::Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);

        let payload = Payload {
            msg: &ciphertext[..clen],
            aad,
        };

        cipher
            .decrypt(&nonce.into(), payload)
            .map_err(|_| "chacha20-poly1305 decrypt failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::AudioFormat;
    use crate::playout::scheduler::PlayoutHandle;

    fn ap2_packet(seq: u64, epoch: u64, format: AudioFormat) -> TimedPacket {
        TimedPacket::new(
            StreamProtocol::AirPlay2Buffered,
            seq,
            seq as u32,
            10_000 + seq as u32 * format.frames_per_packet() as u32,
            match format {
                AudioFormat::Alac44100S16Stereo => 0x0000_FACE,
                AudioFormat::Alac48000S24Stereo => 0x1500_0000,
                AudioFormat::Aac44100F24Stereo => 0x1600_0000,
                AudioFormat::Aac48000F24Stereo => 0x1700_0000,
                AudioFormat::Aac48000F24_5_1 => 0x2700_0000,
                AudioFormat::Aac48000F24_7_1 => 0x2800_0000,
            },
            Some(format),
            Bytes::from(vec![seq as u8; 16]),
            std::time::Instant::now(),
            false,
            epoch,
        )
    }

    #[test]
    fn ssrc_values_match_known_formats() {
        assert_eq!(SSRC_ALAC_44100_S16_2, 0x0000_FACE);
        assert_eq!(SSRC_ALAC_48000_S24_2, 0x1500_0000);
        assert_eq!(SSRC_AAC_44100_F24_2, 0x1600_0000);
        assert_eq!(SSRC_AAC_48000_F24_2, 0x1700_0000);
    }

    #[test]
    fn cipher_decrypt_fails_on_short_input() {
        let key = [0u8; 32];
        let mut cipher = BufferedCipher::new(&key);
        assert!(cipher.decrypt_block(&[0u8; 10], &[0u8; 8]).is_err());
    }

    #[test]
    fn epoch_policy_rejects_only_stale_packets() {
        assert!(packet_matches_epoch(0, 0));
        assert!(!packet_matches_epoch(0, 1));
        assert!(packet_matches_epoch(1, 1));
        assert!(!packet_matches_epoch(1, 2));
        assert!(packet_matches_epoch(2, 2));
    }

    #[tokio::test]
    async fn submit_ap2_accepted_preserves_packet_fields_and_diagnostics() {
        let state = AppState::new(crate::config::Config::default());
        let epoch = state.track_transition_epoch();
        let format = AudioFormat::Alac48000S24Stereo;
        let packet = ap2_packet(7, epoch, format);
        let expected_timestamp = packet.rtp_timestamp;
        let expected_ssrc = packet.ssrc;
        let (playout, _cmd_rx, mut ingress_rx) = PlayoutHandle::command_channel_for_tests(8);

        assert_eq!(
            submit_ap2_packet(&state, &playout, packet).await,
            Ap2SubmitResult::Accepted
        );
        let received = ingress_rx
            .recv()
            .await
            .expect("packet missing from ingress");
        assert_eq!(received.protocol, StreamProtocol::AirPlay2Buffered);
        assert_eq!(received.extended_sequence, 7);
        assert_eq!(received.raw_sequence, 7);
        assert_eq!(received.rtp_timestamp, expected_timestamp);
        assert_eq!(received.ssrc, expected_ssrc);
        assert_eq!(received.format, Some(format));
        assert!(!received.retransmitted);
        assert_eq!(received.transition_epoch, epoch);

        let snapshot = state.snapshot();
        assert_eq!(snapshot.rtp.audio_packets, 1);
        assert_eq!(snapshot.rtp.last_audio_sequence, Some(7));
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap2_ingress_max_depth")
                .map(String::as_str),
            Some("1")
        );
    }

    #[tokio::test]
    async fn submit_ap2_closed_updates_diagnostics() {
        let state = AppState::new(crate::config::Config::default());
        let epoch = state.track_transition_epoch();
        let (playout, _cmd_rx, ingress_rx) = PlayoutHandle::command_channel_for_tests(8);
        drop(ingress_rx);

        assert_eq!(
            submit_ap2_packet(
                &state,
                &playout,
                ap2_packet(1, epoch, AudioFormat::Alac44100S16Stereo),
            )
            .await,
            Ap2SubmitResult::Closed
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.rtp.audio_packets, 0);
        assert_eq!(
            snapshot
                .diagnostics
                .get("ap2_ingress_closed_drops")
                .map(String::as_str),
            Some("1")
        );
    }

    #[tokio::test]
    async fn waiting_title_does_not_drop_ap2_packet() {
        let state = AppState::new(crate::config::Config::default());
        state.clear_track_for_transition();
        let epoch = state.track_transition_epoch();
        let (playout, _cmd_rx, mut ingress_rx) = PlayoutHandle::command_channel_for_tests(8);

        assert_eq!(
            submit_ap2_packet(
                &state,
                &playout,
                ap2_packet(2, epoch, AudioFormat::Aac48000F24Stereo),
            )
            .await,
            Ap2SubmitResult::Accepted
        );
        let received = ingress_rx
            .recv()
            .await
            .expect("waiting-title packet dropped");
        assert_eq!(received.extended_sequence, 2);
        assert!(state.is_waiting_for_track_title());
        assert_eq!(
            state
                .snapshot()
                .diagnostics
                .get("ap2_waiting_for_track_title")
                .map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn stale_epoch_is_dropped_before_shared_ingress() {
        let state = AppState::new(crate::config::Config::default());
        let stale_epoch = state.track_transition_epoch();
        state.clear_track_for_transition();
        let (playout, _cmd_rx, mut ingress_rx) = PlayoutHandle::command_channel_for_tests(8);

        assert_eq!(
            submit_ap2_packet(
                &state,
                &playout,
                ap2_packet(3, stale_epoch, AudioFormat::Alac44100S16Stereo),
            )
            .await,
            Ap2SubmitResult::StaleEpoch
        );
        assert!(
            tokio::time::timeout(time::Duration::from_millis(10), ingress_rx.recv())
                .await
                .is_err()
        );
        assert_eq!(playout.ingress_diagnostics().accepted, 0);
        assert_eq!(state.snapshot().rtp.audio_packets, 0);
    }

    #[tokio::test]
    async fn submit_ap2_awaits_shared_ingress_backpressure() {
        let state = AppState::new(crate::config::Config::default());
        let epoch = state.track_transition_epoch();
        let (playout, _cmd_rx, mut ingress_rx) = PlayoutHandle::command_channel_for_tests(1);

        assert_eq!(
            submit_ap2_packet(
                &state,
                &playout,
                ap2_packet(10, epoch, AudioFormat::Alac44100S16Stereo),
            )
            .await,
            Ap2SubmitResult::Accepted
        );

        let state2 = state.clone();
        let playout2 = playout.clone();
        let pending = tokio::spawn(async move {
            submit_ap2_packet(
                &state2,
                &playout2,
                ap2_packet(11, epoch, AudioFormat::Alac44100S16Stereo),
            )
            .await
        });
        tokio::time::sleep(time::Duration::from_millis(20)).await;
        assert!(
            !pending.is_finished(),
            "AP2 send bypassed bounded backpressure"
        );

        let first = ingress_rx.recv().await.expect("first packet missing");
        assert_eq!(first.extended_sequence, 10);
        assert_eq!(pending.await.unwrap(), Ap2SubmitResult::Accepted);
        let second = ingress_rx.recv().await.expect("second packet missing");
        assert_eq!(second.extended_sequence, 11);
    }
}
