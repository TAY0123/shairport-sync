//! AirPlay 2 realtime audio stream (type 96).
//!
//! The sender transmits RTP over UDP. Bytes 4..12 (RTP timestamp + SSRC) are
//! authenticated as AAD; the final eight packet bytes form the low eight bytes
//! of the ChaCha20-Poly1305 nonce. The bytes between the 12-byte RTP header and
//! nonce suffix are ciphertext plus the 16-byte authentication tag.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Context;
use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, task::JoinHandle};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::{
    airplay::buffered_audio::{Ap2SubmitResult, submit_ap2_packet},
    codec::AudioFormat,
    playout::{
        packet::{StreamProtocol, TimedPacket},
        scheduler::PlayoutHandle,
        sequence::SequenceExtender16,
    },
    state::AppState,
};

const RTP_HEADER_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;
const NONCE_SUFFIX_LEN: usize = 8;
const MIN_PACKET_LEN: usize = RTP_HEADER_LEN + AUTH_TAG_LEN + NONCE_SUFFIX_LEN;
const MAX_UDP_PACKET_LEN: usize = u16::MAX as usize;

/// Immutable per-stream runtime shared by the RTSP session and UDP receiver.
/// The negotiated media key is zeroed when the final reference is dropped.
pub struct RealtimeStreamContext {
    media_key: Zeroizing<[u8; 32]>,
    pub audio_format: AudioFormat,
    pub sample_rate: u32,
    pub frames_per_packet: u32,
    pub stream_id: u32,
    pub stream_connection_id: Option<u64>,
}

impl RealtimeStreamContext {
    pub fn new(
        media_key: [u8; 32],
        audio_format: AudioFormat,
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

impl std::fmt::Debug for RealtimeStreamContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealtimeStreamContext")
            .field("media_key", &"[REDACTED]")
            .field("audio_format", &self.audio_format)
            .field("sample_rate", &self.sample_rate)
            .field("frames_per_packet", &self.frames_per_packet)
            .field("stream_id", &self.stream_id)
            .field("stream_connection_id", &self.stream_connection_id)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RealtimePacketError {
    #[error("realtime RTP packet is too short")]
    TooShort,
    #[error("realtime RTP packet does not use RTP version 2")]
    InvalidRtpVersion,
    #[error("realtime audio authentication failed")]
    Authentication,
}

#[derive(Debug)]
struct DecryptedRealtimePacket {
    sequence: u16,
    rtp_timestamp: u32,
    ssrc: u32,
    payload: Bytes,
}

fn decrypt_packet(
    packet: &[u8],
    media_key: &[u8; 32],
) -> Result<DecryptedRealtimePacket, RealtimePacketError> {
    if packet.len() < MIN_PACKET_LEN {
        return Err(RealtimePacketError::TooShort);
    }
    if packet[0] >> 6 != 2 {
        return Err(RealtimePacketError::InvalidRtpVersion);
    }

    let nonce_start = packet.len() - NONCE_SUFFIX_LEN;
    let encrypted = &packet[RTP_HEADER_LEN..nonce_start];
    let aad = &packet[4..12];
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&packet[nonce_start..]);
    let cipher = ChaCha20Poly1305::new(media_key.into());
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: encrypted,
                aad,
            },
        )
        .map_err(|_| RealtimePacketError::Authentication)?;

    Ok(DecryptedRealtimePacket {
        sequence: u16::from_be_bytes(packet[2..4].try_into().expect("fixed RTP slice")),
        rtp_timestamp: u32::from_be_bytes(packet[4..8].try_into().expect("fixed RTP slice")),
        ssrc: u32::from_be_bytes(packet[8..12].try_into().expect("fixed RTP slice")),
        payload: Bytes::from(plaintext),
    })
}

/// Bind and spawn a type-96 UDP audio receiver.
pub fn spawn_realtime_audio_receiver(
    bind_addr: SocketAddr,
    state: AppState,
    playout: PlayoutHandle,
    context: Arc<RealtimeStreamContext>,
) -> anyhow::Result<(u16, JoinHandle<()>)> {
    let socket = match bind_addr {
        SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?,
        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(false)?;
            socket
        }
    };
    socket.set_reuse_address(true)?;
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("failed to bind AP2 realtime audio UDP on {bind_addr}"))?;
    socket.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(socket.into())?;
    let port = udp.local_addr()?.port();
    let handle = tokio::spawn(run_receiver(udp, state, playout, context));
    Ok((port, handle))
}

async fn run_receiver(
    udp: UdpSocket,
    state: AppState,
    playout: PlayoutHandle,
    context: Arc<RealtimeStreamContext>,
) {
    let mut buf = vec![0u8; MAX_UDP_PACKET_LEN];
    let mut sequences = SequenceExtender16::new();
    info!(
        port = udp.local_addr().ok().map(|addr| addr.port()),
        stream_id = context.stream_id,
        "AP2 realtime audio UDP listener"
    );

    loop {
        let (len, peer) = match udp.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(error) => {
                warn!(%error, "AP2 realtime audio UDP receiver stopped");
                return;
            }
        };

        let packet = match decrypt_packet(&buf[..len], context.media_key()) {
            Ok(packet) => packet,
            Err(error) => {
                debug!(%peer, %error, len, "AP2 realtime audio packet rejected");
                continue;
            }
        };
        let sequence = sequences.extend(packet.sequence);
        let timed = TimedPacket::new(
            StreamProtocol::AirPlay2Realtime,
            sequence.extended_sequence,
            u32::from(packet.sequence),
            packet.rtp_timestamp,
            packet.ssrc,
            Some(context.audio_format),
            packet.payload,
            Instant::now(),
            false,
            state.track_transition_epoch(),
        );

        match submit_ap2_packet(&state, &playout, timed).await {
            Ap2SubmitResult::Accepted => {}
            Ap2SubmitResult::StaleEpoch => {
                debug!(%peer, "AP2 realtime audio packet dropped at stale transition epoch");
            }
            Ap2SubmitResult::Full => {
                warn!(%peer, "AP2 realtime audio ingress backpressure");
            }
            Ap2SubmitResult::Closed => {
                debug!("AP2 realtime audio playout ingress closed");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;

    fn encrypted_packet(
        key: &[u8; 32],
        sequence: u16,
        timestamp: u32,
        ssrc: u32,
        plaintext: &[u8],
        nonce_suffix: [u8; 8],
    ) -> Vec<u8> {
        let mut header = [0u8; RTP_HEADER_LEN];
        header[0] = 0x80;
        header[1] = 0x60;
        header[2..4].copy_from_slice(&sequence.to_be_bytes());
        header[4..8].copy_from_slice(&timestamp.to_be_bytes());
        header[8..12].copy_from_slice(&ssrc.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&nonce_suffix);
        let cipher = ChaCha20Poly1305::new(key.into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &header[4..12],
                },
            )
            .unwrap();
        let mut packet = header.to_vec();
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&nonce_suffix);
        packet
    }

    #[test]
    fn decrypts_c_wire_layout_and_preserves_rtp_fields() {
        let key = [0x55; 32];
        let packet = encrypted_packet(
            &key,
            0xfffe,
            0x1020_3040,
            0x5060_7080,
            b"compressed audio",
            0x1122_3344_5566_7788u64.to_be_bytes(),
        );
        let decrypted = decrypt_packet(&packet, &key).unwrap();
        assert_eq!(decrypted.sequence, 0xfffe);
        assert_eq!(decrypted.rtp_timestamp, 0x1020_3040);
        assert_eq!(decrypted.ssrc, 0x5060_7080);
        assert_eq!(decrypted.payload.as_ref(), b"compressed audio");
    }

    #[test]
    fn rejects_modified_authenticated_header_and_tag() {
        let key = [0x42; 32];
        let original = encrypted_packet(&key, 7, 8, 9, b"audio", [3; 8]);

        let mut bad_aad = original.clone();
        bad_aad[4] ^= 1;
        assert!(matches!(
            decrypt_packet(&bad_aad, &key),
            Err(RealtimePacketError::Authentication)
        ));

        let mut bad_tag = original;
        let tag_byte = bad_tag.len() - NONCE_SUFFIX_LEN - 1;
        bad_tag[tag_byte] ^= 1;
        assert!(matches!(
            decrypt_packet(&bad_tag, &key),
            Err(RealtimePacketError::Authentication)
        ));
    }

    #[test]
    fn rejects_short_and_non_rtp_packets() {
        let key = [0u8; 32];
        assert!(matches!(
            decrypt_packet(&[0u8; MIN_PACKET_LEN - 1], &key),
            Err(RealtimePacketError::TooShort)
        ));
        assert!(matches!(
            decrypt_packet(&[0u8; MIN_PACKET_LEN], &key),
            Err(RealtimePacketError::InvalidRtpVersion)
        ));
    }
}
