use bytes::Bytes;
use std::time::Instant;

/// Protocol origin of a timed audio packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamProtocol {
    /// Classic AirPlay 1 RTP over UDP (payload types 0x60 / 0x56).
    ClassicAp1,
    /// AirPlay 2 buffered audio over TCP (ChaCha20-Poly1305 blocks).
    AirPlay2Buffered,
}

/// A decoded-and-timestamped audio packet ready for the playout scheduler.
///
/// Carries the decrypted compressed payload; decoding is deferred to a
/// transitional per-stream worker.
#[derive(Clone, Debug)]
pub struct TimedPacket {
    /// Which protocol produced this packet.
    pub protocol: StreamProtocol,
    /// 64-bit extended sequence number (gap-resistant, monotonic).
    pub extended_sequence: u64,
    /// Raw wire sequence number (16-bit for AP1, 23-bit for AP2).
    pub raw_sequence: u32,
    /// RTP / block timestamp (units depend on protocol).
    pub rtp_timestamp: u32,
    /// Synchronisation source identifier.
    pub ssrc: u32,
    /// Detected audio format, when known at ingress time.
    pub format: Option<crate::codec::AudioFormat>,
    /// Compressed (still-encoded) audio payload.
    pub payload: Bytes,
    /// Wall-clock instant the packet was received.
    pub received_at: Instant,
    /// True when the packet is a retransmission (AP1 payload type 0x56).
    pub retransmitted: bool,
    /// Track-transition epoch at the moment of reception.
    pub transition_epoch: u64,
}

// Instant prevents a derived Serialize; we intentionally skip serde for it.
impl TimedPacket {
    /// Construct a new timed packet with all fields explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: StreamProtocol,
        extended_sequence: u64,
        raw_sequence: u32,
        rtp_timestamp: u32,
        ssrc: u32,
        format: Option<crate::codec::AudioFormat>,
        payload: Bytes,
        received_at: Instant,
        retransmitted: bool,
        transition_epoch: u64,
    ) -> Self {
        Self {
            protocol,
            extended_sequence,
            raw_sequence,
            rtp_timestamp,
            ssrc,
            format,
            payload,
            received_at,
            retransmitted,
            transition_epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::AudioFormat;

    #[test]
    fn construct_timed_packet() {
        let now = Instant::now();
        let pkt = TimedPacket::new(
            StreamProtocol::ClassicAp1,
            42,
            42,
            12345,
            0x01020304,
            None,
            Bytes::from_static(&[1, 2, 3]),
            now,
            false,
            0,
        );
        assert_eq!(pkt.protocol, StreamProtocol::ClassicAp1);
        assert_eq!(pkt.extended_sequence, 42);
        assert_eq!(pkt.raw_sequence, 42);
        assert_eq!(pkt.rtp_timestamp, 12345);
        assert_eq!(pkt.ssrc, 0x01020304);
        assert!(pkt.format.is_none());
        assert_eq!(&pkt.payload[..], &[1, 2, 3]);
        assert!(!pkt.retransmitted);
        assert_eq!(pkt.transition_epoch, 0);
    }

    #[test]
    fn construct_ap2_packet_with_format() {
        let now = Instant::now();
        let pkt = TimedPacket::new(
            StreamProtocol::AirPlay2Buffered,
            100,
            100,
            99999,
            0x1500_0000,
            Some(AudioFormat::Alac48000S24Stereo),
            Bytes::from_static(&[0xAA; 512]),
            now,
            false,
            1,
        );
        assert_eq!(pkt.protocol, StreamProtocol::AirPlay2Buffered);
        assert_eq!(pkt.format, Some(AudioFormat::Alac48000S24Stereo));
        assert_eq!(pkt.payload.len(), 512);
        assert_eq!(pkt.transition_epoch, 1);
    }

    #[test]
    fn retransmitted_flag() {
        let pkt = TimedPacket::new(
            StreamProtocol::ClassicAp1,
            5,
            5,
            0,
            0,
            None,
            Bytes::new(),
            Instant::now(),
            true,
            0,
        );
        assert!(pkt.retransmitted);
    }
}
