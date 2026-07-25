//! Bounded packet ingress for common playout pipeline.
//!
//! Provides a single-producer, single-consumer [`tokio::sync::mpsc`] channel
//! with two submission modes:
//!
//! * **AP1 (try-send):** non-blocking `try_send` — never awaits, returns
//!   `Accepted`/`Full`/`Closed` immediately. Suitable for UDP receive loops.
//! * **AP2 (async send):** `send().await` that applies TCP backpressure
//!   when the channel is full. Suitable for per-connection TCP loops.
//!
//! Atomic counters track accepted packets, full-channel drops, closed-channel
//! drops, and the maximum observed channel depth, so diagnostics can be
//! reported without mutex contention.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::mpsc;

use super::packet::TimedPacket;

/// Default channel capacity (packets).
pub const DEFAULT_PACKET_CAPACITY: usize = 256;

/// Result of a non-blocking (AP1) submission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressResult {
    /// Packet was accepted into the channel.
    Accepted,
    /// Channel is at capacity; packet was dropped.
    Full,
    /// Channel receiver has been closed; packet was dropped.
    Closed,
}

/// Atomic diagnostic counters shared between sender and receiver.
#[derive(Debug)]
struct IngressCounters {
    accepted: AtomicU64,
    full_drops: AtomicU64,
    closed_drops: AtomicU64,
    /// Maximum number of packets observed in-flight (in the channel) at any
    /// point after a successful send.
    max_depth: AtomicU64,
    /// Current number of packets residing in the channel.
    inflight: AtomicU64,
}

impl IngressCounters {
    fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            full_drops: AtomicU64::new(0),
            closed_drops: AtomicU64::new(0),
            max_depth: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
        }
    }
}

/// The sending half of a bounded packet ingress.
///
/// Cloneable (cheap `Arc` interior). Use [`IngressSender::try_send`] for AP1
/// and [`IngressSender::send`] for AP2.
#[derive(Clone, Debug)]
pub struct IngressSender {
    tx: mpsc::Sender<TimedPacket>,
    counters: Arc<IngressCounters>,
}

/// The receiving half of a bounded packet ingress.
///
/// **Single-consumer:** this type is not `Clone`. Exactly one worker task
/// should own it.
#[derive(Debug)]
pub struct IngressReceiver {
    rx: mpsc::Receiver<TimedPacket>,
    counters: Arc<IngressCounters>,
}

/// Create a new bounded ingress channel with [`DEFAULT_PACKET_CAPACITY`].
pub fn packet_ingress() -> (IngressSender, IngressReceiver) {
    packet_ingress_with_capacity(DEFAULT_PACKET_CAPACITY)
}

/// Create a new bounded ingress channel with a custom capacity.
pub fn packet_ingress_with_capacity(capacity: usize) -> (IngressSender, IngressReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let counters = Arc::new(IngressCounters::new());
    let sender = IngressSender {
        tx,
        counters: Arc::clone(&counters),
    };
    let receiver = IngressReceiver { rx, counters };
    (sender, receiver)
}

impl IngressSender {
    /// Non-blocking submission for AP1 UDP receive loops.
    ///
    /// Never awaits. Returns [`IngressResult::Full`] when the channel is at
    /// capacity so the caller can record a drop and move on.
    pub fn try_send(&self, packet: TimedPacket) -> IngressResult {
        match self.tx.try_send(packet) {
            Ok(()) => {
                self.record_accepted();
                IngressResult::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.counters.full_drops.fetch_add(1, Ordering::Relaxed);
                IngressResult::Full
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.closed_drops.fetch_add(1, Ordering::Relaxed);
                IngressResult::Closed
            }
        }
    }

    /// Async submission for AP2 TCP receive loops.
    ///
    /// Applies backpressure: `send().await` will block until channel capacity
    /// is available. Only returns `Closed` when the receiver has been dropped.
    pub async fn send(&self, packet: TimedPacket) -> IngressResult {
        match self.tx.send(packet).await {
            Ok(()) => {
                self.record_accepted();
                IngressResult::Accepted
            }
            Err(_) => {
                self.counters.closed_drops.fetch_add(1, Ordering::Relaxed);
                IngressResult::Closed
            }
        }
    }

    /// Snapshot current diagnostic counters.
    pub fn diagnostics(&self) -> IngressDiagnostics {
        IngressDiagnostics {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            full_drops: self.counters.full_drops.load(Ordering::Relaxed),
            closed_drops: self.counters.closed_drops.load(Ordering::Relaxed),
            max_depth: self.counters.max_depth.load(Ordering::Relaxed),
            current_inflight: self.counters.inflight.load(Ordering::Relaxed),
        }
    }

    fn record_accepted(&self) {
        let prev = self.counters.inflight.fetch_add(1, Ordering::Relaxed) + 1;
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
        let _ = self.counters.max_depth.fetch_max(prev, Ordering::Relaxed);
    }
}

impl IngressReceiver {
    /// Receive the next packet, or `None` when all senders have been dropped.
    ///
    /// Decrements the in-flight counter on receipt.
    pub async fn recv(&mut self) -> Option<TimedPacket> {
        let packet = self.rx.recv().await?;
        self.counters.inflight.fetch_sub(1, Ordering::Relaxed);
        Some(packet)
    }

    /// Snapshot current diagnostic counters.
    pub fn diagnostics(&self) -> IngressDiagnostics {
        IngressDiagnostics {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            full_drops: self.counters.full_drops.load(Ordering::Relaxed),
            closed_drops: self.counters.closed_drops.load(Ordering::Relaxed),
            max_depth: self.counters.max_depth.load(Ordering::Relaxed),
            current_inflight: self.counters.inflight.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of ingress counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct IngressDiagnostics {
    pub accepted: u64,
    pub full_drops: u64,
    pub closed_drops: u64,
    pub max_depth: u64,
    pub current_inflight: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playout::packet::StreamProtocol;
    use bytes::Bytes;
    use std::time::Instant;

    fn dummy_packet(seq: u64) -> TimedPacket {
        TimedPacket::new(
            StreamProtocol::ClassicAp1,
            seq,
            seq as u32,
            0,
            0,
            None,
            Bytes::from_static(&[0; 16]),
            Instant::now(),
            false,
            0,
        )
    }

    #[tokio::test]
    async fn ap1_try_send_accepted() {
        let (tx, mut rx) = packet_ingress_with_capacity(4);
        assert_eq!(tx.try_send(dummy_packet(1)), IngressResult::Accepted);
        assert_eq!(tx.try_send(dummy_packet(2)), IngressResult::Accepted);
        let diag = tx.diagnostics();
        assert_eq!(diag.accepted, 2);
        assert_eq!(diag.full_drops, 0);
        assert_eq!(diag.max_depth, 2); // second send pushed depth to 2

        let pkt = rx.recv().await.unwrap();
        assert_eq!(pkt.extended_sequence, 1);
        assert_eq!(rx.diagnostics().current_inflight, 1);
    }

    #[tokio::test]
    async fn ap1_full_is_nonblocking() {
        let (tx, _rx) = packet_ingress_with_capacity(2);
        // _rx not being received from → channel fills up.
        assert_eq!(tx.try_send(dummy_packet(1)), IngressResult::Accepted);
        assert_eq!(tx.try_send(dummy_packet(2)), IngressResult::Accepted);
        // Third should be Full, not block.
        let start = Instant::now();
        assert_eq!(tx.try_send(dummy_packet(3)), IngressResult::Full);
        assert!(start.elapsed().as_millis() < 10, "try_send must not block");

        let diag = tx.diagnostics();
        assert_eq!(diag.accepted, 2);
        assert_eq!(diag.full_drops, 1);
    }

    #[tokio::test]
    async fn ap1_closed_after_receiver_drop() {
        let (tx, rx) = packet_ingress_with_capacity(2);
        drop(rx);
        assert_eq!(tx.try_send(dummy_packet(1)), IngressResult::Closed);
        assert_eq!(tx.diagnostics().closed_drops, 1);
    }

    #[tokio::test]
    async fn ap2_send_awaits_backpressure() {
        let (tx, mut rx) = packet_ingress_with_capacity(2);

        // Fill the channel.
        tx.send(dummy_packet(1)).await;
        tx.send(dummy_packet(2)).await;

        // Spawn a task that will free space after a short delay.
        let tx2 = tx.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            // Drain one packet to make room.
            let _ = rx.recv().await;
            // Send should now succeed.
            let result = tx2.send(dummy_packet(3)).await;
            assert_eq!(result, IngressResult::Accepted);
        });

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ap2_closed_when_receiver_dropped() {
        let (tx, rx) = packet_ingress_with_capacity(4);
        drop(rx);
        let result = tx.send(dummy_packet(1)).await;
        assert_eq!(result, IngressResult::Closed);
    }

    #[tokio::test]
    async fn memory_is_bounded() {
        // Channel capacity limits the number of buffered packets regardless
        // of how fast the sender is.
        let (tx, mut rx) = packet_ingress_with_capacity(4);

        // Send 4 packets quickly.
        for i in 0..4 {
            tx.send(dummy_packet(i)).await;
        }

        let diag = tx.diagnostics();
        assert_eq!(diag.accepted, 4);
        assert_eq!(diag.max_depth, 4); // all still in channel
        assert_eq!(diag.current_inflight, 4);

        // Drain them.
        for i in 0..4 {
            let pkt = rx.recv().await.unwrap();
            assert_eq!(pkt.extended_sequence, i as u64);
        }
        assert_eq!(rx.diagnostics().current_inflight, 0);
    }

    #[tokio::test]
    async fn max_depth_tracks_peak() {
        let (tx, mut rx) = packet_ingress_with_capacity(8);
        // Send 5.
        for i in 0..5 {
            tx.send(dummy_packet(i)).await;
        }
        assert_eq!(tx.diagnostics().max_depth, 5);

        // Drain 3.
        for _ in 0..3 {
            rx.recv().await;
        }
        // Send 4 more — peak should be max(2, 6) = 6.
        for i in 0..4 {
            tx.send(dummy_packet(100 + i)).await;
        }
        assert_eq!(tx.diagnostics().max_depth, 6);
    }

    #[test]
    fn default_capacity_is_documented_value() {
        assert_eq!(DEFAULT_PACKET_CAPACITY, 256);
    }
}
