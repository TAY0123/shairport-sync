use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time,
};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

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
pub const MAX_BUFFERED_BLOCK_BYTES: usize = u16::MAX as usize;

pub fn advertised_audio_buffer_size(packet_capacity: usize) -> u32 {
    packet_capacity
        .saturating_mul(MAX_BUFFERED_BLOCK_BYTES)
        .min(u32::MAX as usize) as u32
}

/// Immutable, per-stream runtime shared by the owning AP2 session and its
/// buffered TCP listener. Secret material is zeroed when the final reference
/// is dropped.
pub struct BufferedStreamContext {
    media_key: Zeroizing<[u8; 32]>,
    pub audio_format: codec::AudioFormat,
    pub sample_rate: u32,
    pub frames_per_packet: u32,
    pub stream_id: u32,
    pub stream_connection_id: Option<u64>,
}

impl BufferedStreamContext {
    pub fn new(
        media_key: [u8; 32],
        audio_format: codec::AudioFormat,
        sample_rate: u32,
        frames_per_packet: u32,
        stream_id: u32,
        stream_connection_id: Option<u64>,
    ) -> Self {
        Self {
            media_key: Zeroizing::new(media_key),
            audio_format,
            sample_rate,
            frames_per_packet,
            stream_id,
            stream_connection_id,
        }
    }

    pub fn media_key(&self) -> &[u8; 32] {
        &self.media_key
    }

    #[cfg(test)]
    pub(crate) fn media_key_mut(&mut self) -> &mut [u8; 32] {
        &mut self.media_key
    }
}

impl std::fmt::Debug for BufferedStreamContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedStreamContext")
            .field("media_key", &"[REDACTED]")
            .field("audio_format", &self.audio_format)
            .field("sample_rate", &self.sample_rate)
            .field("frames_per_packet", &self.frames_per_packet)
            .field("stream_id", &self.stream_id)
            .field("stream_connection_id", &self.stream_connection_id)
            .finish()
    }
}

/// Spawn a TCP listener for AP2 buffered audio on the configured audio port.
pub async fn spawn_buffered_audio_receiver(
    config: AirplayConfig,
    state: AppState,
    playout: PlayoutHandle,
    context: Arc<BufferedStreamContext>,
) -> anyhow::Result<JoinHandle<()>> {
    let bind = SocketAddr::from(([0, 0, 0, 0], config.audio_port));
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind buffered audio TCP on {bind}"))?;
    info!(port = config.audio_port, "AP2 buffered audio TCP listener");
    Ok(spawn_buffered_accept_loop(
        listener, state, playout, context,
    ))
}

/// Spawn an accept loop for buffered audio on an already-bound TcpListener.
pub fn spawn_buffered_accept_loop(
    listener: TcpListener,
    state: AppState,
    playout: PlayoutHandle,
    context: Arc<BufferedStreamContext>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // The accept-loop task owns every accepted connection. Dropping this
        // JoinSet (including when the listener task is aborted by TEARDOWN)
        // aborts all in-flight workers, so a stream worker can never outlive
        // the AP2 session that supplied its immutable key/format context.
        let mut workers = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let state = state.clone();
                        let playout = playout.clone();
                        let context = context.clone();
                        workers.spawn(async move {
                            if let Err(e) =
                                handle_buffered_stream(stream, peer, state, playout, context).await
                            {
                                warn!(%peer, %e, "buffered audio stream error");
                            }
                        });
                    }
                    Err(e) => warn!(%e, "buffered audio accept error"),
                },
                completed = workers.join_next(), if !workers.is_empty() => {
                    if let Some(Err(e)) = completed
                        && !e.is_cancelled()
                    {
                        warn!(%e, "buffered audio worker task failed");
                    }
                }
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
    stream: TcpStream,
    peer: SocketAddr,
    state: AppState,
    playout: PlayoutHandle,
    context: Arc<BufferedStreamContext>,
) -> anyhow::Result<()> {
    handle_buffered_stream_with_idle_poll(
        stream,
        peer,
        state,
        playout,
        context,
        time::Duration::from_secs(5),
    )
    .await
}

async fn handle_buffered_stream_with_idle_poll(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: AppState,
    playout: PlayoutHandle,
    context: Arc<BufferedStreamContext>,
    idle_poll: time::Duration,
) -> anyhow::Result<()> {
    info!(%peer, "buffered audio connection opened");

    let mut cipher = BufferedCipher::new(context.media_key());
    info!("buffered audio: cipher initialized, reading first block");

    // ── TCP read loop: frame, decrypt, extend, submit ──────────────
    let mut word_buf = [0u8; 4];
    let mut seq_ext = SequenceExtender23::new();
    let mut block_count: u64 = 0;
    let mut first_block_logged = false;
    let mut current_epoch = state.track_transition_epoch();
    let mut length_prefix = [0u8; 2];
    let mut prefix_bytes = 0usize;

    'blocks: loop {
        // Poll readiness without consuming bytes. A quiet socket is normal at
        // a track boundary, so it must not terminate the AP2 stream. Using
        // readiness plus non-blocking reads also preserves a partially
        // received two-byte prefix across idle polls without corrupting
        // framing.
        while prefix_bytes < length_prefix.len() {
            match time::timeout(idle_poll, stream.readable()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    info!(%e, "buffered audio readiness failed, blocks_processed={}", block_count);
                    break 'blocks;
                }
                Err(_) if state.snapshot().player_state == crate::state::PlayerState::Stopped => {
                    debug!(
                        blocks_processed = block_count,
                        "buffered audio idle after playback stopped"
                    );
                    break 'blocks;
                }
                Err(_) => {
                    debug!(
                        blocks_processed = block_count,
                        "buffered audio connection idle; waiting for next track"
                    );
                    continue;
                }
            }

            match stream.try_read(&mut length_prefix[prefix_bytes..]) {
                Ok(0) => {
                    info!(
                        "buffered audio stream closed by client, blocks_processed={}",
                        block_count
                    );
                    break 'blocks;
                }
                Ok(read) => prefix_bytes += read,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    info!(%e, "buffered audio stream closed by client, blocks_processed={}", block_count);
                    break 'blocks;
                }
            }
        }

        let len_raw = u16::from_be_bytes(length_prefix);
        prefix_bytes = 0;
        if !first_block_logged {
            info!(
                block_len = len_raw,
                "buffered audio: first block length received, reading header..."
            );
            first_block_logged = true;
        }
        let block_len = len_raw as usize;
        let body_len = block_len.saturating_sub(2);
        if body_len < 12 {
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
                    info!(
                        seq = seq_23,
                        ssrc,
                        blocks_processed = block_count,
                        plaintext_len = p.len(),
                        "buffered audio: block decrypted successfully"
                    );
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

        let format = match codec::AudioFormat::from_ssrc(ssrc) {
            Some(format) if format != context.audio_format => {
                warn!(
                    ssrc,
                    negotiated = context.audio_format.description(),
                    received = format.description(),
                    "buffered packet format does not match stream SETUP"
                );
                continue;
            }
            Some(format) => format,
            None => context.audio_format,
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
        // ingress. AP2 playback is controlled by RECORD and the PTP timeline;
        // title metadata never gates buffered audio.
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
    key: Zeroizing<[u8; 32]>,
}

impl BufferedCipher {
    fn new(session_key: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*session_key),
        }
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

        let key = chacha20poly1305::Key::from_slice(self.key.as_ref());
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
    use tokio::io::AsyncWriteExt;

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
    fn stream_context_redacts_key_and_buffer_size_tracks_capacity() {
        let context = BufferedStreamContext::new(
            [0xAB; 32],
            AudioFormat::Alac44100S16Stereo,
            44_100,
            352,
            7,
            Some(9),
        );
        let rendered = format!("{context:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.to_ascii_lowercase().contains("abab"));
        assert_eq!(
            advertised_audio_buffer_size(768),
            (768usize * MAX_BUFFERED_BLOCK_BYTES) as u32
        );
        assert_eq!(advertised_audio_buffer_size(usize::MAX), u32::MAX);
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

    #[tokio::test]
    async fn upstream_buffered_wire_layout_decrypts_and_reaches_ingress() {
        // Independently generated ChaCha20-Poly1305 fixture:
        // key=00..1f, nonce=00000000||0102030405060708,
        // AAD=timestamp||SSRC, plaintext="ap2-buffered-fixture".
        const CIPHERTEXT_AND_TAG: [u8; 36] = [
            0x8e, 0x96, 0x97, 0xd5, 0xc7, 0xf9, 0xce, 0xfa, 0x75, 0xcd, 0x8d, 0xb2, 0xa7, 0x8a,
            0x4e, 0x26, 0xe1, 0xf9, 0x16, 0x34, 0x4d, 0xbc, 0xfa, 0xc4, 0x3b, 0x9b, 0x7b, 0xa8,
            0x3f, 0x4e, 0x55, 0xa3, 0x05, 0x42, 0x8e, 0x7e,
        ];
        const NONCE_SUFFIX: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        const SEQUENCE: u32 = 0x007f_fffe;
        const TIMESTAMP: u32 = 0x0102_0304;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = AppState::new(crate::config::Config::default());
        let (playout, _cmd_rx, mut ingress_rx) = PlayoutHandle::command_channel_for_tests(8);
        let context = Arc::new(BufferedStreamContext::new(
            std::array::from_fn(|index| index as u8),
            AudioFormat::Alac48000S24Stereo,
            48_000,
            1_024,
            17,
            Some(23),
        ));
        let server_state = state.clone();
        let server_playout = playout.clone();
        let server_context = context.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_buffered_stream(stream, peer, server_state, server_playout, server_context)
                .await
                .unwrap();
        });

        let mut wire = Vec::new();
        let payload_len = CIPHERTEXT_AND_TAG.len() + NONCE_SUFFIX.len();
        let block_len = 2 + 12 + payload_len;
        wire.extend_from_slice(&(block_len as u16).to_be_bytes());
        wire.extend_from_slice(&SEQUENCE.to_be_bytes());
        wire.extend_from_slice(&TIMESTAMP.to_be_bytes());
        wire.extend_from_slice(&SSRC_ALAC_48000_S24_2.to_be_bytes());
        wire.extend_from_slice(&CIPHERTEXT_AND_TAG);
        wire.extend_from_slice(&NONCE_SUFFIX);

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&wire).await.unwrap();
        client.shutdown().await.unwrap();

        let packet = time::timeout(time::Duration::from_secs(1), ingress_rx.recv())
            .await
            .expect("decrypted packet did not reach ingress")
            .expect("ingress closed");
        assert_eq!(packet.raw_sequence, SEQUENCE);
        assert_eq!(packet.extended_sequence, SEQUENCE as u64);
        assert_eq!(packet.rtp_timestamp, TIMESTAMP);
        assert_eq!(packet.ssrc, SSRC_ALAC_48000_S24_2);
        assert_eq!(packet.format, Some(AudioFormat::Alac48000S24Stereo));
        assert_eq!(packet.payload.as_ref(), b"ap2-buffered-fixture");
        time::timeout(time::Duration::from_secs(1), server)
            .await
            .expect("buffered stream task did not close")
            .unwrap();
    }

    #[tokio::test]
    async fn aborting_accept_loop_aborts_owned_connection_workers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = AppState::new(crate::config::Config::default());
        state.set_player_state(crate::state::PlayerState::Playing);
        let (playout, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(8);
        let context = Arc::new(BufferedStreamContext::new(
            [0u8; 32],
            AudioFormat::Alac44100S16Stereo,
            44_100,
            352,
            1,
            None,
        ));

        let server = spawn_buffered_accept_loop(listener, state, playout, context.clone());
        let _client = TcpStream::connect(address).await.unwrap();

        time::timeout(time::Duration::from_secs(1), async {
            while Arc::strong_count(&context) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted worker did not retain stream context");

        server.abort();
        let _ = server.await;
        time::timeout(time::Duration::from_secs(1), async {
            while Arc::strong_count(&context) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted worker outlived aborted listener");
    }

    #[tokio::test]
    async fn active_buffered_stream_survives_idle_track_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = AppState::new(crate::config::Config::default());
        state.set_player_state(crate::state::PlayerState::Playing);
        let (playout, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(8);
        let context = Arc::new(BufferedStreamContext::new(
            [0u8; 32],
            AudioFormat::Alac44100S16Stereo,
            44_100,
            352,
            1,
            None,
        ));

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_buffered_stream_with_idle_poll(
                stream,
                peer,
                server_state,
                playout,
                context,
                time::Duration::from_millis(20),
            )
            .await
            .unwrap();
        });
        let _client = TcpStream::connect(address).await.unwrap();

        time::sleep(time::Duration::from_millis(75)).await;
        assert!(
            !server.is_finished(),
            "an active AP2 stream must remain open while waiting for the next track"
        );

        state.set_player_state(crate::state::PlayerState::Stopped);
        time::timeout(time::Duration::from_millis(100), server)
            .await
            .expect("idle stream did not exit after playback stopped")
            .unwrap();
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
