use std::net::SocketAddr;

use anyhow::Context;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::{net::UdpSocket, task::JoinHandle};
use tracing::{debug, info, warn};

use crate::{
    audio::AudioEngine,
    codec,
    config::AirplayConfig,
    decoder,
    playout::{
        ingress::{IngressReceiver, IngressResult, IngressSender, packet_ingress},
        packet::{StreamProtocol, TimedPacket},
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
    /// Transitional AP1 decode worker.
    pub worker: JoinHandle<()>,
}

pub async fn spawn_rtp_receivers(
    config: AirplayConfig,
    state: AppState,
    audio_engine: AudioEngine,
) -> anyhow::Result<RtpReceiverHandles> {
    // Create a shared bounded ingress for the audio path.
    let (tx, rx) = packet_ingress();
    let ingress_tx = tx;

    let audio_net = bind_audio_network(config.audio_port, state.clone(), ingress_tx).await?;
    let control = bind_channel(RtpChannel::Control, config.control_port, state.clone()).await?;
    let timing = bind_channel(RtpChannel::Timing, config.timing_port, state.clone()).await?;

    let worker = spawn_ap1_decode_worker(rx, state, audio_engine);

    Ok(RtpReceiverHandles {
        network: vec![audio_net, control, timing],
        worker,
    })
}

/// UDP receive loop: parses RTP, decrypts AES-CBC, extends sequence,
/// builds a [`TimedPacket`], and non-blocking `try_send`s it into the
/// bounded ingress.  No decoding or PCM enqueue happens here.
async fn bind_audio_network(
    port: u16,
    state: AppState,
    ingress: IngressSender,
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

                    // Record diagnostics for recording (still done in worker,
                    // but we can also track at network level). The worker will
                    // record the full RTP diagnostics.
                    let pkt = TimedPacket::new(
                        StreamProtocol::ClassicAp1,
                        seq_result.extended_sequence,
                        rtp.sequence_number as u32,
                        rtp.timestamp,
                        rtp.ssrc,
                        None, // format determined by decoder in worker
                        Bytes::from(decrypted),
                        std::time::Instant::now(),
                        retransmitted,
                        epoch,
                    );

                    match ingress.try_send(pkt) {
                        IngressResult::Accepted => {
                            if first_packet {
                                info!("AP1 ingress: first packet accepted");
                                first_packet = false;
                            }
                        }
                        IngressResult::Full => {
                            state.set_diagnostic("ap1_ingress_full_drops", {
                                let d = ingress.diagnostics();
                                d.full_drops.to_string()
                            });
                            warn!("AP1 ingress full — packet dropped");
                        }
                        IngressResult::Closed => {
                            state.set_diagnostic("ap1_ingress_closed_drops", {
                                let d = ingress.diagnostics();
                                d.closed_drops.to_string()
                            });
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

/// Transitional AP1 decode worker: owns the ingress receiver, ALAC decoder,
/// transition-epoch resets, waiting-for-title policy, and AudioEngine
/// conversion/enqueue.
fn spawn_ap1_decode_worker(
    mut rx: IngressReceiver,
    state: AppState,
    audio_engine: AudioEngine,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut audio_decoder: Option<codec::AudioDecoder> = None;
        let mut decoder_epoch = state.track_transition_epoch();

        while let Some(pkt) = rx.recv().await {
            // Epoch transition → reset decoder.
            let current_epoch = state.track_transition_epoch();
            if current_epoch != decoder_epoch {
                audio_decoder = None;
                decoder_epoch = current_epoch;
                info!(
                    epoch = decoder_epoch,
                    "RTP audio decoder reset for track transition"
                );
            }

            // Skip stale packets from before the transition.
            if pkt.transition_epoch != current_epoch {
                debug!(
                    seq = pkt.extended_sequence,
                    "stale RTP packet drained after track transition"
                );
                continue;
            }

            if state.is_waiting_for_track_title() {
                debug!("RTP audio packet drained while waiting for new title");
                continue;
            }

            // Lazy-init ALAC decoder.
            if audio_decoder.is_none() {
                let cookie = state.alac_magic_cookie.read().clone();
                if let Some(ref cookie) = cookie {
                    let sample_size = state.alac_sample_size.read().unwrap_or(16);
                    let channels = state.alac_channels.read().unwrap_or(2);
                    let rate = state.alac_sample_rate.read().unwrap_or(44_100);
                    let frames_per_packet = state.frames_per_packet.read().unwrap_or(352) as usize;
                    match codec::AudioDecoder::new_alac(
                        sample_size,
                        channels,
                        rate,
                        frames_per_packet,
                        cookie,
                    ) {
                        Ok(d) => {
                            audio_decoder = Some(d);
                            info!(sample_size, channels, rate, "ALAC decoder initialized");
                        }
                        Err(e) => {
                            warn!(%e, "ALAC decoder init failed");
                            continue;
                        }
                    }
                }
            }

            // Decode and enqueue.
            if let Some(ref mut dec) = audio_decoder {
                match dec.decode(&pkt.payload) {
                    Ok(decoded) => {
                        if !decoded.samples.is_empty() {
                            let (enqueued, total_samples) = audio_engine
                                .enqueue_interleaved_for_output(
                                    &decoded.samples,
                                    decoded.sample_rate,
                                    decoded.channels,
                                );
                            if enqueued < total_samples {
                                debug!(
                                    "audio ring buffer full, dropped {} samples",
                                    total_samples - enqueued
                                );
                            }
                        }
                        // Record RTP diagnostics.
                        state.record_rtp_packet(
                            RtpChannel::Audio,
                            RtpPacket {
                                version: 2,
                                marker: false,
                                payload_type: if pkt.retransmitted { 0x56 } else { 0x60 },
                                sequence_number: pkt.raw_sequence as u16,
                                timestamp: pkt.rtp_timestamp,
                                ssrc: pkt.ssrc,
                                payload_len: pkt.payload.len(),
                            },
                        );
                    }
                    Err(e) => {
                        warn!(%e, "ALAC decode failed");
                    }
                }
            }

            // Periodically update ingress depth diagnostics.
            let diag = rx.diagnostics();
            if diag.full_drops > 0 {
                state.set_diagnostic("ap1_ingress_full_drops", diag.full_drops.to_string());
            }
            if diag.max_depth > 0 {
                state.set_diagnostic("ap1_ingress_max_depth", diag.max_depth.to_string());
            }
        }
        info!("AP1 decode worker exiting");
    })
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
}
