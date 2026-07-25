//! Pure watermark state machine and generic playout scheduler for the
//! audio playout pipeline.
//!
//! [`WatermarkController`] tracks the playout lifecycle —
//! priming, steady-state playback, rebuffering, pause/resume, and stop —
//! and emits discrete output-gate and flush actions.  It contains no
//! decoder, jitter-buffer, or I/O logic; the caller feeds it the
//! current FIFO fill level (in milliseconds) via [`observe_fifo`] and
//! applies the returned actions.
//!
//! [`SchedulerCore`] wraps the watermark controller, a
//! [`JitterBuffer`], a generic [`PacketDecoder`], and a generic
//! [`PcmSink`] into a complete playout pipeline with strict
//! ordering and backpressure semantics.
//!
//! [`observe_fifo`]: WatermarkController::observe_fifo
//! [`JitterBuffer`]: super::jitter::JitterBuffer

use crate::audio::AudioEngine;
use crate::config::AudioConfig;
use anyhow;
use std::time::Instant;

use super::jitter::{InsertResult, JitterBuffer, JitterDiagnostics, TakeExpectedResult};
use super::packet::TimedPacket;

// ── Playout state ──────────────────────────────────────────────────────

/// High-level state of the audio playout pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlayoutState {
    /// No transport active; output is silent and the FIFO is empty.
    Stopped,
    /// Transport is active but the output gate is off while the FIFO
    /// fills to the start watermark.
    Priming,
    /// Normal playback: the output gate is on and the FIFO level is
    /// above the low watermark.
    Playing,
    /// The FIFO has dropped below the low watermark; the output gate
    /// was turned off without a flush so buffered audio is preserved
    /// while the pipeline recovers.
    Rebuffering,
    /// Transport is active but the output gate is off (user pause).
    /// The FIFO is preserved — no flush occurs on pause.
    Paused,
}

impl PlayoutState {
    /// Whether the transport is logically active (audio may be flowing).
    pub fn is_transport_active(self) -> bool {
        matches!(self, Self::Priming | Self::Playing | Self::Rebuffering)
    }
}

// ── Scheduler configuration ────────────────────────────────────────────

/// Watermark and jitter-buffer parameters for the playout scheduler.
///
/// Constructed from [`AudioConfig`] with sensible jitter defaults.
/// After construction, invariants `low ≤ target ≤ start` and
/// `jitter_capacity_packets > 0` are guaranteed.
#[derive(Clone, Debug, PartialEq)]
pub struct SchedulerConfig {
    /// FIFO level (ms) that triggers the output gate to open.
    pub start_watermark_ms: u32,
    /// FIFO level (ms) below which the output gate is closed to avoid
    /// audible underruns.
    pub low_watermark_ms: u32,
    /// Desired steady-state FIFO level (ms).
    pub target_watermark_ms: u32,
    /// Maximum number of packets the jitter buffer can hold.
    pub jitter_capacity_packets: usize,
    /// Maximum reorder tolerance in milliseconds.
    pub reorder_grace_ms: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            start_watermark_ms: 80,
            low_watermark_ms: 40,
            target_watermark_ms: 80,
            jitter_capacity_packets: 512,
            reorder_grace_ms: 30,
        }
    }
}

impl SchedulerConfig {
    /// Create a [`SchedulerConfig`] from an [`AudioConfig`], filling in
    /// jitter defaults and normalising watermark ordering.
    pub fn from_audio_config(audio: &AudioConfig) -> Self {
        let fifo_ms = audio.pcm_fifo_ms.max(1);
        let mut cfg = Self {
            start_watermark_ms: audio.start_watermark_ms.min(fifo_ms),
            low_watermark_ms: audio.low_watermark_ms.min(fifo_ms),
            target_watermark_ms: audio.target_watermark_ms.min(fifo_ms),
            ..Default::default()
        };
        cfg.normalize();
        cfg
    }

    /// Enforce `low ≤ target ≤ start` and `jitter_capacity_packets > 0`.
    pub fn normalize(&mut self) {
        self.jitter_capacity_packets = self.jitter_capacity_packets.max(1);
        // Order: low ≤ target ≤ start.
        self.target_watermark_ms = self.target_watermark_ms.max(self.low_watermark_ms);
        self.start_watermark_ms = self.start_watermark_ms.max(self.target_watermark_ms);
    }
}

// ── Watermark actions ──────────────────────────────────────────────────

/// A discrete action emitted by the watermark controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatermarkAction {
    /// Open (`true`) or close (`false`) the output gate.
    Gate(bool),
    /// Flush the audio FIFO (discard all currently buffered samples).
    Flush,
}

// ── WatermarkController ────────────────────────────────────────────────

/// Pure state machine that tracks playout state and emits gate/flush
/// actions based on watermark thresholds.
///
/// # Lifecycle
///
/// ```text
///   start ──→ Priming ──(fifo ≥ start)──→ Playing
///                 ↑                           │
///                 │                    (fifo < low)
///                 │                           ↓
///              (flush on                  Rebuffering
///            active transport)               │
///                 ↑                    (fifo ≥ start)
///                 │                           ↓
///                 └───────────────────── Playing
///
///   pause ──→ Paused  (from any active state)
///   resume ──→ Priming (may gate-on immediately)
///   stop ───→ Stopped
/// ```
#[derive(Clone, Debug)]
pub struct WatermarkController {
    state: PlayoutState,
    config: SchedulerConfig,
}

impl WatermarkController {
    /// Create a new controller in the [`Stopped`](PlayoutState::Stopped) state.
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            state: PlayoutState::Stopped,
            config,
        }
    }

    /// Return the current playout state.
    pub fn state(&self) -> PlayoutState {
        self.state
    }

    /// Return a reference to the scheduler configuration.
    #[allow(dead_code)]
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    // ── lifecycle commands ─────────────────────────────────────────

    /// Start the transport.
    ///
    /// Enters [`Priming`](PlayoutState::Priming), gates off, and
    /// requests a flush so the pipeline starts from a clean FIFO.
    pub fn start(&mut self) -> Vec<WatermarkAction> {
        self.state = PlayoutState::Priming;
        vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
    }

    /// Pause the transport.
    ///
    /// Gates off **without** flushing — buffered audio is preserved so
    /// that [`resume`](Self::resume) can pick up where it left off.
    pub fn pause(&mut self) -> Vec<WatermarkAction> {
        self.state = PlayoutState::Paused;
        vec![WatermarkAction::Gate(false)]
    }

    /// Resume from pause.
    ///
    /// Enters [`Priming`](PlayoutState::Priming) preserving the FIFO.
    /// If the FIFO is already at or above the start watermark the gate
    /// is enabled immediately and the state advances to [`Playing`].
    pub fn resume(&mut self, current_queued_ms: u64) -> Vec<WatermarkAction> {
        debug_assert_eq!(
            self.state,
            PlayoutState::Paused,
            "resume is only valid from Paused"
        );
        self.state = PlayoutState::Priming;
        if current_queued_ms >= self.config.start_watermark_ms as u64 {
            self.state = PlayoutState::Playing;
            vec![WatermarkAction::Gate(true)]
        } else {
            vec![]
        }
    }

    /// Stop the transport.
    ///
    /// Enters [`Stopped`](PlayoutState::Stopped), gates off, and
    /// flushes the FIFO.
    pub fn stop(&mut self) -> Vec<WatermarkAction> {
        self.state = PlayoutState::Stopped;
        vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
    }

    /// Flush the audio FIFO.
    ///
    /// If the transport is active ([`Priming`], [`Playing`], or
    /// [`Rebuffering`]) the state resets to [`Priming`] so the
    /// pipeline re-primes after the flush.  If the transport is
    /// inactive ([`Stopped`] or [`Paused`]) the state is preserved.
    ///
    /// [`Priming`]: PlayoutState::Priming
    /// [`Playing`]: PlayoutState::Playing
    /// [`Rebuffering`]: PlayoutState::Rebuffering
    /// [`Stopped`]: PlayoutState::Stopped
    /// [`Paused`]: PlayoutState::Paused
    pub fn flush(&mut self) -> Vec<WatermarkAction> {
        if self.state.is_transport_active() {
            self.state = PlayoutState::Priming;
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        } else {
            // Stopped / Paused — keep state, just flush.
            vec![WatermarkAction::Flush]
        }
    }

    // ── watermark observation ──────────────────────────────────────

    /// Observe the current FIFO fill level and return the appropriate
    /// action.
    ///
    /// * In [`Priming`]: enables the gate when `queued_ms ≥ start`.
    /// * In [`Playing`]: gates off (without flush) when
    ///   `queued_ms < low`, entering [`Rebuffering`].
    /// * In [`Rebuffering`]: re-enables the gate when
    ///   `queued_ms ≥ start`.
    /// * In [`Stopped`] or [`Paused`]: always returns `None`.
    ///
    /// [`Priming`]: PlayoutState::Priming
    /// [`Playing`]: PlayoutState::Playing
    /// [`Rebuffering`]: PlayoutState::Rebuffering
    /// [`Stopped`]: PlayoutState::Stopped
    /// [`Paused`]: PlayoutState::Paused
    pub fn observe_fifo(&mut self, queued_ms: u64) -> Option<WatermarkAction> {
        match self.state {
            PlayoutState::Priming => {
                if queued_ms >= self.config.start_watermark_ms as u64 {
                    self.state = PlayoutState::Playing;
                    Some(WatermarkAction::Gate(true))
                } else {
                    None
                }
            }
            PlayoutState::Playing => {
                if queued_ms < self.config.low_watermark_ms as u64 {
                    self.state = PlayoutState::Rebuffering;
                    Some(WatermarkAction::Gate(false))
                } else {
                    None
                }
            }
            PlayoutState::Rebuffering => {
                if queued_ms >= self.config.start_watermark_ms as u64 {
                    self.state = PlayoutState::Playing;
                    Some(WatermarkAction::Gate(true))
                } else {
                    None
                }
            }
            PlayoutState::Stopped | PlayoutState::Paused => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Decoded audio and traits
// ═══════════════════════════════════════════════════════════════════════

/// A block of decoded interleaved f32 PCM samples.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedAudio {
    /// Interleaved f32 samples (channel 0, channel 1, …).
    pub samples: Vec<f32>,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Number of channels.
    pub channels: u16,
}

impl DecodedAudio {
    /// Number of complete frames (`samples.len() / channels`).
    pub fn frames(&self) -> usize {
        let ch = self.channels.max(1) as usize;
        self.samples.len() / ch
    }
}

/// Trait for decoding compressed audio packets into PCM.
///
/// Implementations may be stateful (e.g. Symphonia codec wrappers).
pub trait PacketDecoder {
    /// Reset the decoder to its initial state (e.g. after a resync).
    fn reset(&mut self);

    /// Decode a compressed packet into interleaved f32 PCM.
    fn decode(&mut self, packet: &TimedPacket) -> anyhow::Result<DecodedAudio>;

    /// Generate a concealment (PLC) block for a missing packet.
    ///
    /// `expected_sequence` is the missing packet's sequence number.
    /// `last_packet` is the most recently successfully decoded packet,
    /// if any, for context (e.g. fade-out/fade-in hints).
    fn conceal_missing(
        &mut self,
        expected_sequence: u64,
        last_packet: Option<&TimedPacket>,
    ) -> anyhow::Result<DecodedAudio>;
}

/// Result of writing a decoded block to a PCM sink.
///
/// The key contract: the sink either accepts **all** requested frames
/// or **zero** — it never partially accepts a block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmWriteResult {
    /// Number of complete frames presented.
    pub requested_frames: usize,
    /// Number of complete frames accepted (all or zero).
    pub accepted_frames: usize,
    /// Number of complete frames rejected (zero or all).
    pub rejected_frames: usize,
}

impl PcmWriteResult {
    /// Create a result where all requested frames were accepted.
    pub fn all_accepted(requested_frames: usize) -> Self {
        Self {
            requested_frames,
            accepted_frames: requested_frames,
            rejected_frames: 0,
        }
    }

    /// Create a result where all requested frames were rejected.
    pub fn all_rejected(requested_frames: usize) -> Self {
        Self {
            requested_frames,
            accepted_frames: 0,
            rejected_frames: requested_frames,
        }
    }

    /// Whether the block was fully accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted_frames == self.requested_frames && self.rejected_frames == 0
    }
}

/// Trait for a PCM audio sink (output FIFO).
///
/// Implementations must provide atomic whole-block enqueue: either all
/// requested frames are accepted or zero.
pub trait PcmSink {
    /// Current queued duration in milliseconds.
    fn queued_ms(&self) -> u64;

    /// Enable or disable the output gate (mute without flushing).
    fn set_output_gate(&mut self, enabled: bool);

    /// Request the sink to flush all currently buffered samples.
    fn request_flush(&mut self);

    /// Enqueue a decoded audio block.
    ///
    /// When `unchecked` is true the sink may bypass the output gate
    /// (used during Priming and Rebuffering so the FIFO can fill).
    /// When `unchecked` is false (Playing state), the sink must check
    /// the gate and reject the block if the gate is closed.
    ///
    /// Returns [`PcmWriteResult`] where `accepted_frames` is either
    /// all of `decoded.frames()` or zero.
    fn enqueue(&mut self, decoded: &DecodedAudio, unchecked: bool) -> PcmWriteResult;
}

// ═══════════════════════════════════════════════════════════════════════
// AudioEngineSink — production PcmSink adapter
// ═══════════════════════════════════════════════════════════════════════

/// Production [`PcmSink`] that wraps an [`AudioEngine`].
///
/// Uses [`AudioEngine::try_enqueue_output_frames_all_or_nothing`]
/// to atomically accept or reject an entire block under a single
/// producer-lock interval.  Conversion from decoded sample
/// rate/channels to the output format is performed via
/// [`AudioEngine::convert_interleaved_for_output`].
pub struct AudioEngineSink {
    engine: AudioEngine,
}

impl AudioEngineSink {
    /// Create a new sink wrapping the given [`AudioEngine`].
    pub fn new(engine: AudioEngine) -> Self {
        Self { engine }
    }

    /// Return a reference to the inner [`AudioEngine`].
    pub fn engine(&self) -> &AudioEngine {
        &self.engine
    }
}

impl PcmSink for AudioEngineSink {
    fn queued_ms(&self) -> u64 {
        self.engine.status().queued_ms
    }

    fn set_output_gate(&mut self, enabled: bool) {
        self.engine.set_output_gate(enabled);
    }

    fn request_flush(&mut self) {
        self.engine.request_flush();
    }

    fn enqueue(&mut self, decoded: &DecodedAudio, unchecked: bool) -> PcmWriteResult {
        let requested_frames = decoded.frames();
        if requested_frames == 0 {
            return PcmWriteResult::all_accepted(0);
        }

        // Convert to the output format first.
        let converted = self.engine.convert_interleaved_for_output(
            &decoded.samples,
            decoded.sample_rate,
            decoded.channels,
        );

        // Atomic all-or-nothing enqueue under a single producer-lock
        // interval.  Capacity rejection is scheduler backpressure and
        // does not increment overflow/loss counters.
        let (_requested, accepted) = self
            .engine
            .try_enqueue_output_frames_all_or_nothing(&converted, unchecked);

        if accepted == _requested {
            PcmWriteResult::all_accepted(requested_frames)
        } else {
            PcmWriteResult::all_rejected(requested_frames)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Scheduler diagnostics
// ═══════════════════════════════════════════════════════════════════════

/// Point-in-time snapshot of scheduler diagnostic counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct SchedulerDiagnostics {
    /// Packets accepted by the jitter buffer.
    pub insert_accepted: u64,
    /// Packets that filled a previously-missing jitter slot.
    pub insert_filled: u64,
    /// Packets rejected as duplicates.
    pub insert_duplicate: u64,
    /// Packets rejected as too old.
    pub insert_too_old: u64,
    /// Resyncs triggered (jitter ResyncRequired or other resync cause).
    pub resync_count: u64,
    /// Blocks successfully decoded.
    pub decoded_blocks: u64,
    /// Decode failures (packet consumed but decoding errored).
    pub decode_errors: u64,
    /// Concealment blocks produced for missing packets.
    pub concealed_missing: u64,
    /// Number of times the sink rejected a pending block (backpressure).
    pub fifo_backpressure_events: u64,
    /// Total frames in backpressure-rejected blocks.
    pub fifo_backpressure_frames: u64,
    /// Actual playout-state changes (start, pause, resume, stop, flush,
    /// watermark observation, active resync).  Idempotent same-state
    /// calls do not increment.
    pub state_transitions: u64,
}

/// Runtime status snapshot of the scheduler.
#[derive(Clone, Debug)]
pub struct SchedulerStatus {
    /// Current playout state.
    pub state: PlayoutState,
    /// Jitter buffer diagnostics.
    pub jitter: JitterDiagnostics,
    /// Scheduler-level diagnostics.
    pub diag: SchedulerDiagnostics,
    /// Current queued duration in the output sink (ms).
    pub queued_ms: u64,
    /// Whether a decoded/concealed block is currently pending (waiting
    /// for sink capacity).
    pub has_pending_block: bool,
    /// Number of frames in the pending block (if any).
    pub pending_block_frames: usize,
    /// Next expected sequence number.
    pub expected_sequence: u64,
}

// ═══════════════════════════════════════════════════════════════════════
// SchedulerCore — generic playout scheduler
// ═══════════════════════════════════════════════════════════════════════

/// Generic playout scheduler parameterised over a [`PacketDecoder`] and
/// a [`PcmSink`].
///
/// Owns the watermark state machine, jitter buffer, decoder, sink, and
/// all ancillary state.  The caller drives the scheduler by calling
/// [`insert_packet`] when a new packet arrives and [`process_ready`]
/// periodically to move decoded audio into the sink.
///
/// [`insert_packet`]: SchedulerCore::insert_packet
/// [`process_ready`]: SchedulerCore::process_ready
pub struct SchedulerCore<D: PacketDecoder, S: PcmSink> {
    config: SchedulerConfig,
    watermark: WatermarkController,
    jitter: JitterBuffer,
    decoder: D,
    sink: S,

    /// Decoded block that was rejected by the sink and must be retried
    /// before any further packets are decoded.
    pending: Option<DecodedAudio>,
    /// Sequence number of the pending block (for diagnostics).
    pending_sequence: Option<u64>,
    /// The most recently successfully decoded packet (not concealed).
    last_decoded_packet: Option<TimedPacket>,

    diag: SchedulerDiagnostics,
}

impl<D: PacketDecoder, S: PcmSink> SchedulerCore<D, S> {
    /// Create a new scheduler.
    ///
    /// The scheduler starts in [`Stopped`](PlayoutState::Stopped).
    pub fn new(config: SchedulerConfig, decoder: D, sink: S) -> Self {
        let jitter = JitterBuffer::new(config.jitter_capacity_packets);
        let watermark = WatermarkController::new(config.clone());
        Self {
            config,
            watermark,
            jitter,
            decoder,
            sink,
            pending: None,
            pending_sequence: None,
            last_decoded_packet: None,
            diag: SchedulerDiagnostics::default(),
        }
    }

    /// Start the transport.  Resets stream state and decoder, gates
    /// off, and flushes the sink.
    pub fn start(&mut self) {
        let old_state = self.watermark.state();
        let actions = self.watermark.start();
        self.record_state_transition(old_state);
        self.apply_actions(&actions);
        self.decoder.reset();
        self.jitter.reset();
        self.pending = None;
        self.pending_sequence = None;
        self.last_decoded_packet = None;
    }

    /// Pause the transport.  The output gate is closed but the jitter
    /// buffer and sink FIFO are preserved.
    pub fn pause(&mut self) {
        let old_state = self.watermark.state();
        let actions = self.watermark.pause();
        self.record_state_transition(old_state);
        self.apply_actions(&actions);
    }

    /// Resume from pause.  Uses the current sink queued duration to
    /// decide whether the gate can open immediately.
    pub fn resume(&mut self) {
        let old_state = self.watermark.state();
        let queued_ms = self.sink.queued_ms();
        let actions = self.watermark.resume(queued_ms);
        self.record_state_transition(old_state);
        self.apply_actions(&actions);
    }

    /// Stop the transport.  Gates off, flushes the sink, resets the
    /// decoder, jitter buffer, and all pending state.
    pub fn stop(&mut self) {
        let old_state = self.watermark.state();
        let actions = self.watermark.stop();
        self.record_state_transition(old_state);
        self.apply_actions(&actions);
        self.decoder.reset();
        self.jitter.reset();
        self.pending = None;
        self.pending_sequence = None;
        self.last_decoded_packet = None;
    }

    /// Flush the audio FIFO and reset jitter+decoder+pending state.
    /// If the transport is active the watermark resets to Priming.
    pub fn flush(&mut self) {
        let old_state = self.watermark.state();
        let actions = self.watermark.flush();
        self.record_state_transition(old_state);
        self.apply_actions(&actions);
        self.jitter.reset();
        self.decoder.reset();
        self.pending = None;
        self.pending_sequence = None;
        self.last_decoded_packet = None;
    }

    /// Insert a packet into the jitter buffer.
    ///
    /// Returns the jitter [`InsertResult`] and updates diagnostics.
    /// If the result is [`InsertResult::ResyncRequired`], the scheduler
    /// automatically performs a resync: the jitter buffer, decoder,
    /// pending block, and last-decoded-packet are reset; active
    /// flush/gate actions are applied; and the triggering packet is
    /// re-inserted as the fresh seed.  The returned result in that case
    /// is the result of the re-insertion (typically [`Accepted`]).
    ///
    /// [`Accepted`]: InsertResult::Accepted
    pub fn insert_packet(&mut self, packet: TimedPacket) -> InsertResult {
        // Clone the packet so we can re-insert it if a resync is needed
        // (the jitter buffer drops the packet on ResyncRequired).
        let pkt_clone = packet.clone();
        let result = self.jitter.insert(packet);
        match result {
            InsertResult::Accepted => {
                self.diag.insert_accepted += 1;
                result
            }
            InsertResult::FilledMissing => {
                self.diag.insert_filled += 1;
                result
            }
            InsertResult::Duplicate => {
                self.diag.insert_duplicate += 1;
                result
            }
            InsertResult::TooOld => {
                self.diag.insert_too_old += 1;
                result
            }
            InsertResult::ResyncRequired => {
                // Reset jitter, decoder, pending state.
                self.jitter.reset();
                self.decoder.reset();
                self.pending = None;
                self.pending_sequence = None;
                self.last_decoded_packet = None;
                self.diag.resync_count += 1;

                // Apply resync through the watermark controller.
                // For active states, WatermarkController::flush()
                // emits Gate(false),Flush in order — gate before
                // flush — and retains Priming.  Do not reconstruct
                // the controller.
                //
                // For Paused/Stopped the state is preserved and we
                // do NOT flush the PCM sink merely because an
                // unprocessed jitter window resynced; only the
                // jitter/decoder/pending reset above is needed.
                let state = self.watermark.state();
                if state.is_transport_active() {
                    let actions = self.watermark.flush();
                    self.record_state_transition(state);
                    self.apply_actions(&actions);
                }

                // Re-insert the triggering packet as a fresh seed.
                let re_result = self.jitter.insert(pkt_clone);
                match re_result {
                    InsertResult::Accepted => self.diag.insert_accepted += 1,
                    InsertResult::FilledMissing => self.diag.insert_filled += 1,
                    InsertResult::Duplicate => self.diag.insert_duplicate += 1,
                    InsertResult::TooOld => self.diag.insert_too_old += 1,
                    InsertResult::ResyncRequired => {
                        // Should not happen after a reset, but handle gracefully.
                    }
                }
                re_result
            }
        }
    }

    /// Process ready packets: decode the next expected packet, enqueue
    /// it into the sink, and observe watermark state.
    ///
    /// Only processes when the state is [`Priming`], [`Playing`], or
    /// [`Rebuffering`].  Returns the number of blocks successfully
    /// enqueued in this call (0 or 1 — one block per call for
    /// deterministic backpressure).
    ///
    /// `now` is the current time, used to decide whether a missing
    /// packet has exceeded the reorder grace period.
    pub fn process_ready(&mut self, now: Instant) -> usize {
        let state = self.watermark.state();
        if !state.is_transport_active() {
            return 0;
        }

        // ── Retry pending block first ──
        if let Some(ref decoded) = self.pending {
            let unchecked = matches!(state, PlayoutState::Priming | PlayoutState::Rebuffering);
            let result = self.sink.enqueue(decoded, unchecked);
            if result.is_accepted() {
                self.pending = None;
                self.pending_sequence = None;
                // After successful enqueue, observe watermark.
                self.observe_and_apply();
                return 1;
            }
            // Still rejected — no additional backpressure event (already
            // counted when the block was first rejected).
            return 0;
        }

        // ── Look at the next expected slot ──
        loop {
            let _expected_seq = self.jitter.expected_sequence();

            match self.jitter.peek_expected() {
                super::jitter::PeekExpectedResult::Packet(pkt) => {
                    // Clone the packet data so we can consume the slot.
                    let pkt_clone = pkt.clone();
                    let seq = pkt_clone.extended_sequence;

                    // Take (consume) the slot.
                    match self.jitter.take_expected() {
                        TakeExpectedResult::Packet(_) => {}
                        _ => unreachable!("peek gave Packet but take did not"),
                    }

                    // Decode.
                    match self.decoder.decode(&pkt_clone) {
                        Ok(decoded) => {
                            self.diag.decoded_blocks += 1;
                            self.last_decoded_packet = Some(pkt_clone);

                            let unchecked =
                                matches!(state, PlayoutState::Priming | PlayoutState::Rebuffering);
                            let frames = decoded.frames();
                            let result = self.sink.enqueue(&decoded, unchecked);
                            if result.is_accepted() {
                                // Enqueue succeeded — observe watermark.
                                self.observe_and_apply();
                                return 1;
                            }
                            // Rejected — store as pending, count one backpressure.
                            self.diag.fifo_backpressure_events += 1;
                            self.diag.fifo_backpressure_frames += frames as u64;
                            self.pending = Some(decoded);
                            self.pending_sequence = Some(seq);
                            return 0;
                        }
                        Err(_) => {
                            self.diag.decode_errors += 1;
                            // Bad packet consumed; continue to next slot.
                            continue;
                        }
                    }
                }

                super::jitter::PeekExpectedResult::Missing {
                    first_noticed,
                    resend_attempts: _,
                } => {
                    let reorder_grace =
                        std::time::Duration::from_millis(self.config.reorder_grace_ms as u64);
                    let age = now.saturating_duration_since(first_noticed);

                    if age < reorder_grace {
                        // Still within reorder grace — wait.
                        return 0;
                    }

                    // Grace expired — take the missing slot and conceal.
                    let seq = self.jitter.expected_sequence();
                    match self.jitter.take_expected() {
                        TakeExpectedResult::Missing { .. } => {}
                        _ => unreachable!("peek gave Missing but take did not"),
                    }

                    match self
                        .decoder
                        .conceal_missing(seq, self.last_decoded_packet.as_ref())
                    {
                        Ok(decoded) => {
                            self.diag.concealed_missing += 1;

                            let unchecked =
                                matches!(state, PlayoutState::Priming | PlayoutState::Rebuffering);
                            let frames = decoded.frames();
                            let result = self.sink.enqueue(&decoded, unchecked);
                            if result.is_accepted() {
                                self.observe_and_apply();
                                return 1;
                            }
                            // Rejected — store as pending, count one backpressure.
                            self.diag.fifo_backpressure_events += 1;
                            self.diag.fifo_backpressure_frames += frames as u64;
                            self.pending = Some(decoded);
                            self.pending_sequence = Some(seq);
                            return 0;
                        }
                        Err(_) => {
                            // Concealment itself can fail (unlikely but
                            // possible); treat like a decode error.
                            self.diag.decode_errors += 1;
                            continue;
                        }
                    }
                }

                super::jitter::PeekExpectedResult::Empty => {
                    return 0;
                }
            }
        }
    }

    /// Observe the current sink FIFO level and apply any resulting
    /// watermark actions.
    pub fn observe_fifo(&mut self) {
        self.observe_and_apply();
    }

    /// Snapshot of current scheduler status.
    pub fn status(&self) -> SchedulerStatus {
        SchedulerStatus {
            state: self.watermark.state(),
            jitter: self.jitter.diagnostics(),
            diag: self.diag,
            queued_ms: self.sink.queued_ms(),
            has_pending_block: self.pending.is_some(),
            pending_block_frames: self.pending.as_ref().map(|d| d.frames()).unwrap_or(0),
            expected_sequence: self.jitter.expected_sequence(),
        }
    }

    /// Return a reference to the decoder (for tests).
    #[allow(dead_code)]
    pub fn decoder(&self) -> &D {
        &self.decoder
    }

    /// Return a mutable reference to the decoder (for tests).
    #[allow(dead_code)]
    pub fn decoder_mut(&mut self) -> &mut D {
        &mut self.decoder
    }

    /// Return a reference to the sink (for tests).
    #[allow(dead_code)]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Return a mutable reference to the sink (for tests).
    #[allow(dead_code)]
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Return the current playout state.
    pub fn state(&self) -> PlayoutState {
        self.watermark.state()
    }

    /// Return a reference to the scheduler configuration.
    #[allow(dead_code)]
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Return the jitter buffer's expected sequence.
    #[allow(dead_code)]
    pub fn expected_sequence(&self) -> u64 {
        self.jitter.expected_sequence()
    }

    // ── internals ─────────────────────────────────────────────────

    /// Record a state transition if the playout state actually changed.
    fn record_state_transition(&mut self, old: PlayoutState) {
        let new = self.watermark.state();
        if old != new {
            self.diag.state_transitions += 1;
        }
    }

    /// Apply watermark actions to the sink and handle resync if needed.
    fn apply_actions(&mut self, actions: &[WatermarkAction]) {
        for action in actions {
            match *action {
                WatermarkAction::Gate(enabled) => self.sink.set_output_gate(enabled),
                WatermarkAction::Flush => self.sink.request_flush(),
            }
        }
    }

    /// Observe the current sink FIFO level via the watermark controller
    /// and apply any resulting actions.
    fn observe_and_apply(&mut self) {
        let old_state = self.watermark.state();
        let queued_ms = self.sink.queued_ms();
        if let Some(action) = self.watermark.observe_fifo(queued_ms) {
            self.apply_actions(&[action]);
        }
        self.record_state_transition(old_state);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AudioBackendName, AudioHostName};

    fn test_config() -> SchedulerConfig {
        SchedulerConfig {
            start_watermark_ms: 80,
            low_watermark_ms: 40,
            target_watermark_ms: 60,
            jitter_capacity_packets: 512,
            reorder_grace_ms: 30,
        }
    }

    // ── SchedulerConfig ────────────────────────────────────────────

    #[test]
    fn config_defaults_are_sensible() {
        let cfg = SchedulerConfig::default();
        assert_eq!(cfg.jitter_capacity_packets, 512);
        assert_eq!(cfg.reorder_grace_ms, 30);
        // After Default the user must call normalize(); the raw values
        // may be out of order until then.
        assert!(cfg.start_watermark_ms >= cfg.low_watermark_ms);
    }

    #[test]
    fn config_normalize_enforces_ordering() {
        let mut cfg = SchedulerConfig {
            start_watermark_ms: 10,
            low_watermark_ms: 100,
            target_watermark_ms: 50,
            ..Default::default()
        };
        cfg.normalize();
        assert!(cfg.low_watermark_ms <= cfg.target_watermark_ms);
        assert!(cfg.target_watermark_ms <= cfg.start_watermark_ms);
    }

    #[test]
    fn config_normalize_nonzero_capacity() {
        let mut cfg = SchedulerConfig {
            jitter_capacity_packets: 0,
            ..Default::default()
        };
        cfg.normalize();
        assert!(cfg.jitter_capacity_packets > 0);
    }

    #[test]
    fn config_from_audio_config() {
        let audio = AudioConfig {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 150,
            start_watermark_ms: 90,
            low_watermark_ms: 30,
            target_watermark_ms: 70,
        };
        let cfg = SchedulerConfig::from_audio_config(&audio);
        assert_eq!(cfg.start_watermark_ms, 90);
        assert_eq!(cfg.low_watermark_ms, 30);
        assert_eq!(cfg.target_watermark_ms, 70);
        assert_eq!(cfg.jitter_capacity_packets, 512);
        assert_eq!(cfg.reorder_grace_ms, 30);
    }

    #[test]
    fn config_from_audio_config_clamps_to_fifo_capacity() {
        let audio = AudioConfig {
            backend: AudioBackendName::Cpal,
            host: AudioHostName::Default,
            device: None,
            pcm_fifo_ms: 50,
            start_watermark_ms: 500,
            low_watermark_ms: 300,
            target_watermark_ms: 400,
        };
        let cfg = SchedulerConfig::from_audio_config(&audio);
        assert_eq!(cfg.low_watermark_ms, 50);
        assert_eq!(cfg.target_watermark_ms, 50);
        assert_eq!(cfg.start_watermark_ms, 50);
    }

    #[test]
    fn config_normalize_already_valid_is_idempotent() {
        let cfg = test_config();
        let mut cfg2 = cfg.clone();
        cfg2.normalize();
        assert_eq!(cfg, cfg2);
    }

    // ── Initial state ──────────────────────────────────────────────

    #[test]
    fn new_controller_is_stopped() {
        let ctrl = WatermarkController::new(test_config());
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
    }

    // ── start ──────────────────────────────────────────────────────

    #[test]
    fn start_from_stopped_enters_priming_gates_off_and_flushes() {
        let mut ctrl = WatermarkController::new(test_config());
        let actions = ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn start_from_paused_enters_priming_gates_off_and_flushes() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start(); // Stopped → Priming
        // Simulate: priming completes, then user pauses.
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
        ctrl.pause();
        assert_eq!(ctrl.state(), PlayoutState::Paused);

        // Restart from pause.
        let actions = ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    // ── pause ──────────────────────────────────────────────────────

    #[test]
    fn pause_gates_off_without_flush() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        // Complete priming.
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        let actions = ctrl.pause();
        assert_eq!(ctrl.state(), PlayoutState::Paused);
        assert_eq!(actions, vec![WatermarkAction::Gate(false)]);
    }

    #[test]
    fn pause_from_priming_is_valid() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        let actions = ctrl.pause();
        assert_eq!(ctrl.state(), PlayoutState::Paused);
        assert_eq!(actions, vec![WatermarkAction::Gate(false)]);
    }

    #[test]
    fn pause_from_rebuffering_is_valid() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        // Drain below low to enter Rebuffering.
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        let actions = ctrl.pause();
        assert_eq!(ctrl.state(), PlayoutState::Paused);
        assert_eq!(actions, vec![WatermarkAction::Gate(false)]);
    }

    // ── resume ─────────────────────────────────────────────────────

    #[test]
    fn resume_enters_priming_preserves_fifo() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();

        // Resume with FIFO below start — no immediate gate-on.
        let actions = ctrl.resume(30);
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert!(actions.is_empty());
    }

    #[test]
    fn resume_enables_immediately_when_already_at_start() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();

        // FIFO is still at start level → gate on immediately.
        let actions = ctrl.resume(80);
        assert_eq!(ctrl.state(), PlayoutState::Playing);
        assert_eq!(actions, vec![WatermarkAction::Gate(true)]);
    }

    #[test]
    fn resume_above_start_enables_immediately() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();

        let actions = ctrl.resume(120);
        assert_eq!(ctrl.state(), PlayoutState::Playing);
        assert_eq!(actions, vec![WatermarkAction::Gate(true)]);
    }

    #[test]
    fn resume_below_start_then_observe_fifo_enables() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();

        // Resume with low FIFO.
        assert!(ctrl.resume(20).is_empty());
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        // Still below start — no action.
        assert_eq!(ctrl.observe_fifo(70), None);
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        // Cross start threshold.
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    // ── stop ───────────────────────────────────────────────────────

    #[test]
    fn stop_from_playing_gates_off_and_flushes() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        let actions = ctrl.stop();
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn stop_from_priming_gates_off_and_flushes() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        let actions = ctrl.stop();
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn stop_from_rebuffering_gates_off_and_flushes() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        let actions = ctrl.stop();
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn stop_from_paused_gates_off_and_flushes() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();

        let actions = ctrl.stop();
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    // ── flush ──────────────────────────────────────────────────────

    #[test]
    fn flush_on_active_transport_resets_to_priming() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        let actions = ctrl.flush();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn flush_on_priming_stays_priming() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        let actions = ctrl.flush();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn flush_on_rebuffering_resets_to_priming() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        let actions = ctrl.flush();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );
    }

    #[test]
    fn flush_on_stopped_preserves_stopped() {
        let mut ctrl = WatermarkController::new(test_config());
        assert_eq!(ctrl.state(), PlayoutState::Stopped);

        let actions = ctrl.flush();
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert_eq!(actions, vec![WatermarkAction::Flush]);
    }

    #[test]
    fn flush_on_paused_preserves_paused() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();
        assert_eq!(ctrl.state(), PlayoutState::Paused);

        let actions = ctrl.flush();
        assert_eq!(ctrl.state(), PlayoutState::Paused);
        assert_eq!(actions, vec![WatermarkAction::Flush]);
    }

    // ── observe_fifo ───────────────────────────────────────────────

    #[test]
    fn observe_fifo_in_stopped_always_none() {
        let mut ctrl = WatermarkController::new(test_config());
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert_eq!(ctrl.observe_fifo(0), None);
        assert_eq!(ctrl.observe_fifo(80), None);
        assert_eq!(ctrl.observe_fifo(1000), None);
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
    }

    #[test]
    fn observe_fifo_in_paused_always_none() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        ctrl.pause();

        assert_eq!(ctrl.observe_fifo(0), None);
        assert_eq!(ctrl.observe_fifo(80), None);
        assert_eq!(ctrl.observe_fifo(1000), None);
        assert_eq!(ctrl.state(), PlayoutState::Paused);
    }

    #[test]
    fn priming_enables_at_start_watermark() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        // One packet below watermark — still priming.
        assert_eq!(ctrl.observe_fifo(79), None);
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        // Exactly at start — gate on, transition to Playing.
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    #[test]
    fn priming_enables_above_start_watermark() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();

        // Well above start.
        assert_eq!(ctrl.observe_fifo(200), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    #[test]
    fn playing_above_low_is_noop() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // Still above low — no action.
        assert_eq!(ctrl.observe_fifo(50), None);
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        assert_eq!(ctrl.observe_fifo(40), None);
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    #[test]
    fn playing_below_low_enters_rebuffering_and_gates_off() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // Drop below low watermark.
        assert_eq!(ctrl.observe_fifo(39), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);
    }

    #[test]
    fn playing_at_zero_enters_rebuffering() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));

        assert_eq!(ctrl.observe_fifo(0), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);
    }

    #[test]
    fn rebuffering_below_start_is_noop() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        // Still below start — no action.
        assert_eq!(ctrl.observe_fifo(50), None);
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        assert_eq!(ctrl.observe_fifo(79), None);
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);
    }

    #[test]
    fn rebuffering_re_enables_at_start_watermark() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        // Recover to start watermark.
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    #[test]
    fn rebuffering_re_enables_above_start() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        // Overshoot recovery.
        assert_eq!(ctrl.observe_fifo(150), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    // ── One-packet-below-watermark tests ───────────────────────────

    #[test]
    fn priming_one_ms_below_start_no_enable() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        // start = 80, queued = 79 → still Priming.
        assert_eq!(ctrl.observe_fifo(79), None);
        assert_eq!(ctrl.state(), PlayoutState::Priming);
    }

    #[test]
    fn playing_one_ms_above_low_no_rebuffer() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        // low = 40, queued = 40 → still Playing (not below low).
        assert_eq!(ctrl.observe_fifo(40), None);
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    #[test]
    fn playing_exactly_at_low_is_noop() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        // Exactly at low — no rebuffer (must be strictly below).
        assert_eq!(ctrl.observe_fifo(40), None);
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    #[test]
    fn rebuffering_one_ms_below_start_no_enable() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        // start = 80, queued = 79 → still Rebuffering.
        assert_eq!(ctrl.observe_fifo(79), None);
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);
    }

    // ── Full lifecycle scenario ────────────────────────────────────

    #[test]
    fn full_lifecycle_start_play_rebuffer_recover_pause_resume_stop() {
        let mut ctrl = WatermarkController::new(test_config());

        // 1. Start.
        let actions = ctrl.start();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert!(actions.contains(&WatermarkAction::Gate(false)));
        assert!(actions.contains(&WatermarkAction::Flush));

        // 2. Prime (FIFO fills).
        assert_eq!(ctrl.observe_fifo(60), None);
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // 3. Playing — no action while above low.
        assert_eq!(ctrl.observe_fifo(50), None);
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // 4. Rebuffer (drain below low).
        assert_eq!(ctrl.observe_fifo(30), Some(WatermarkAction::Gate(false)));
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);

        // 5. Recover.
        assert_eq!(ctrl.observe_fifo(70), None);
        assert_eq!(ctrl.state(), PlayoutState::Rebuffering);
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // 6. Pause.
        let actions = ctrl.pause();
        assert_eq!(ctrl.state(), PlayoutState::Paused);
        assert_eq!(actions, vec![WatermarkAction::Gate(false)]);

        // 7. Observe does nothing in Paused.
        assert_eq!(ctrl.observe_fifo(80), None);
        assert_eq!(ctrl.state(), PlayoutState::Paused);

        // 8. Resume with low FIFO.
        let actions = ctrl.resume(20);
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert!(actions.is_empty());

        // 9. Observe re-primes.
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // 10. Stop.
        let actions = ctrl.stop();
        assert_eq!(ctrl.state(), PlayoutState::Stopped);
        assert!(actions.contains(&WatermarkAction::Gate(false)));
        assert!(actions.contains(&WatermarkAction::Flush));
    }

    // ── Flush-then-reprime scenario ────────────────────────────────

    #[test]
    fn flush_during_playback_then_reprime() {
        let mut ctrl = WatermarkController::new(test_config());
        ctrl.start();
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // Flush resets to Priming and gates off.
        let actions = ctrl.flush();
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(
            actions,
            vec![WatermarkAction::Gate(false), WatermarkAction::Flush]
        );

        // Must re-prime.
        assert_eq!(ctrl.observe_fifo(50), None);
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert_eq!(ctrl.observe_fifo(80), Some(WatermarkAction::Gate(true)));
        assert_eq!(ctrl.state(), PlayoutState::Playing);
    }

    /// Apply controller actions to a real AudioEngine and verify the
    /// flush boundary preserves only post-flush priming samples.
    #[test]
    fn active_flush_gates_real_audio_engine_until_reprimed() {
        use crate::audio::AudioEngine;

        fn apply(engine: &AudioEngine, actions: &[WatermarkAction]) {
            for action in actions {
                match *action {
                    WatermarkAction::Gate(enabled) => engine.set_output_gate(enabled),
                    WatermarkAction::Flush => engine.request_flush(),
                }
            }
        }

        let mut ctrl = WatermarkController::new(test_config());
        let (engine, mut consumer) = AudioEngine::new(32_768);
        engine.set_output_format(48_000, 2);

        // Start gates output and establishes a clean flush boundary.
        apply(&engine, &ctrl.start());
        let mut callback = vec![1.0f32; 480];
        assert_eq!(consumer.fill_output(&mut callback), 0);
        assert!(callback.iter().all(|&sample| sample == 0.0));

        // Prime to 80 ms and enable output.
        let start_samples = 48_000usize * 2 * 80 / 1000;
        let priming = vec![0.25f32; start_samples];
        assert_eq!(
            engine.enqueue_output_samples_unchecked(&priming),
            start_samples
        );
        let action = ctrl
            .observe_fifo(engine.status().queued_ms)
            .expect("start watermark should open the gate");
        apply(&engine, &[action]);
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        // Consume one callback, leaving old playback samples in the FIFO.
        callback.fill(0.0);
        assert_eq!(consumer.fill_output(&mut callback), callback.len());
        assert!(callback.iter().all(|&sample| (sample - 0.25).abs() < 0.001));

        // Active flush must gate off before publishing the flush boundary.
        apply(&engine, &ctrl.flush());
        assert_eq!(ctrl.state(), PlayoutState::Priming);
        assert!(!engine.is_playback_enabled());

        // Samples queued after the flush request are the new priming epoch.
        let post_flush_samples = 48_000usize * 2 * 20 / 1000;
        let post_flush = vec![0.75f32; post_flush_samples];
        assert_eq!(
            engine.enqueue_output_samples_unchecked(&post_flush),
            post_flush_samples
        );

        // Callback applies the boundary, discards old samples, preserves the
        // post-flush samples, and remains silent because the gate is closed.
        callback.fill(1.0);
        assert_eq!(consumer.fill_output(&mut callback), 0);
        assert!(callback.iter().all(|&sample| sample == 0.0));
        assert_eq!(engine.status().queued_samples, post_flush_samples);
        assert_eq!(ctrl.observe_fifo(engine.status().queued_ms), None);
        assert_eq!(ctrl.state(), PlayoutState::Priming);

        // Add enough new-epoch audio to reach the start watermark.
        let additional_samples = start_samples - post_flush_samples;
        let additional = vec![0.75f32; additional_samples];
        assert_eq!(
            engine.enqueue_output_samples_unchecked(&additional),
            additional_samples
        );
        let action = ctrl
            .observe_fifo(engine.status().queued_ms)
            .expect("reprimed FIFO should reopen the gate");
        apply(&engine, &[action]);
        assert!(engine.is_playback_enabled());
        assert_eq!(ctrl.state(), PlayoutState::Playing);

        callback.fill(0.0);
        assert_eq!(consumer.fill_output(&mut callback), callback.len());
        assert!(callback.iter().all(|&sample| (sample - 0.75).abs() < 0.001));
    }

    // ── PlayoutState::is_transport_active ──────────────────────────

    #[test]
    fn transport_active_is_true_for_priming_playing_rebuffering() {
        assert!(PlayoutState::Priming.is_transport_active());
        assert!(PlayoutState::Playing.is_transport_active());
        assert!(PlayoutState::Rebuffering.is_transport_active());
    }

    #[test]
    fn transport_active_is_false_for_stopped_and_paused() {
        assert!(!PlayoutState::Stopped.is_transport_active());
        assert!(!PlayoutState::Paused.is_transport_active());
    }

    // ═══════════════════════════════════════════════════════════════
    // Deterministic fake decoder and sink for SchedulerCore tests
    // ═══════════════════════════════════════════════════════════════

    /// Fake decoder that returns predictable samples based on the
    /// packet's extended sequence number.  Each decoded block has
    /// exactly `frames_per_packet` frames, with all samples set to
    /// `seq as f32`.
    struct FakeDecoder {
        frames_per_packet: usize,
        sample_rate: u32,
        channels: u16,
        /// If set, the next `decode` call will return an error.
        next_decode_error: bool,
        /// If set, the next `conceal_missing` call will return an error.
        next_conceal_error: bool,
        decode_count: usize,
        conceal_count: usize,
        reset_count: usize,
        last_concealed_seq: Option<u64>,
    }

    impl FakeDecoder {
        fn new(frames_per_packet: usize, sample_rate: u32, channels: u16) -> Self {
            Self {
                frames_per_packet,
                sample_rate,
                channels,
                next_decode_error: false,
                next_conceal_error: false,
                decode_count: 0,
                conceal_count: 0,
                reset_count: 0,
                last_concealed_seq: None,
            }
        }
    }

    impl PacketDecoder for FakeDecoder {
        fn reset(&mut self) {
            self.reset_count += 1;
        }

        fn decode(&mut self, packet: &TimedPacket) -> anyhow::Result<DecodedAudio> {
            if self.next_decode_error {
                self.next_decode_error = false;
                self.decode_count += 1;
                anyhow::bail!("fake decode error for seq {}", packet.extended_sequence);
            }
            self.decode_count += 1;
            let seq = packet.extended_sequence;
            let sample_count = self.frames_per_packet * self.channels as usize;
            Ok(DecodedAudio {
                samples: vec![seq as f32; sample_count],
                sample_rate: self.sample_rate,
                channels: self.channels,
            })
        }

        fn conceal_missing(
            &mut self,
            expected_sequence: u64,
            _last_packet: Option<&TimedPacket>,
        ) -> anyhow::Result<DecodedAudio> {
            if self.next_conceal_error {
                self.next_conceal_error = false;
                self.conceal_count += 1;
                anyhow::bail!("fake conceal error for seq {}", expected_sequence);
            }
            self.conceal_count += 1;
            self.last_concealed_seq = Some(expected_sequence);
            let sample_count = self.frames_per_packet * self.channels as usize;
            // Concealed samples are negative to distinguish from real.
            Ok(DecodedAudio {
                samples: vec![-(expected_sequence as f32); sample_count],
                sample_rate: self.sample_rate,
                channels: self.channels,
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeSinkAction {
        Gate(bool),
        Flush,
    }

    /// Fake sink that stores enqueued blocks in a Vec for inspection.
    /// Can be configured to reject the next enqueue.
    struct FakeSink {
        blocks: Vec<DecodedAudio>,
        queued_ms: u64,
        gate: bool,
        flush_count: usize,
        /// If true, reject the next enqueue call.
        next_reject: bool,
        actions: Vec<FakeSinkAction>,
    }

    impl FakeSink {
        fn new() -> Self {
            Self {
                blocks: Vec::new(),
                queued_ms: 0,
                gate: false,
                flush_count: 0,
                next_reject: false,
                actions: Vec::new(),
            }
        }

        fn total_frames(&self) -> usize {
            self.blocks.iter().map(|b| b.frames()).sum()
        }
    }

    impl PcmSink for FakeSink {
        fn queued_ms(&self) -> u64 {
            self.queued_ms
        }

        fn set_output_gate(&mut self, enabled: bool) {
            self.actions.push(FakeSinkAction::Gate(enabled));
            self.gate = enabled;
        }

        fn request_flush(&mut self) {
            self.actions.push(FakeSinkAction::Flush);
            self.flush_count += 1;
            self.blocks.clear();
            self.queued_ms = 0;
        }

        fn enqueue(&mut self, decoded: &DecodedAudio, _unchecked: bool) -> PcmWriteResult {
            let frames = decoded.frames();
            if self.next_reject {
                self.next_reject = false;
                return PcmWriteResult::all_rejected(frames);
            }
            self.blocks.push(decoded.clone());
            // Simulate queued_ms: each frame is ~1 ms at 1000 Hz for tests.
            self.queued_ms += frames as u64;
            PcmWriteResult::all_accepted(frames)
        }
    }

    /// Helper: build a TimedPacket with the given sequence and payload.
    fn seq_packet(seq: u64) -> TimedPacket {
        TimedPacket::new(
            super::super::packet::StreamProtocol::ClassicAp1,
            seq,
            (seq & 0xFFFF) as u32,
            0,
            0x01020304,
            None,
            bytes::Bytes::from_static(&[0; 16]),
            Instant::now(),
            false,
            0,
        )
    }

    /// Test config with small watermarks for fast priming.
    fn sched_test_config() -> SchedulerConfig {
        SchedulerConfig {
            start_watermark_ms: 3,
            low_watermark_ms: 1,
            target_watermark_ms: 2,
            jitter_capacity_packets: 16,
            reorder_grace_ms: 100,
        }
    }

    // ── Reordered output: 10, 12, 11 → 10, 11, 12 ─────────────

    #[test]
    fn reordered_packets_output_in_sequence_order() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1); // 1 frame = 1 ms
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Insert 10, 12, 11 out of order.
        assert_eq!(sched.insert_packet(seq_packet(10)), InsertResult::Accepted);
        assert_eq!(sched.insert_packet(seq_packet(12)), InsertResult::Accepted);
        assert_eq!(
            sched.insert_packet(seq_packet(11)),
            InsertResult::FilledMissing
        );

        let now = Instant::now();

        // Process seq 10.
        let n = sched.process_ready(now);
        assert_eq!(n, 1);
        assert_eq!(sched.sink().blocks.len(), 1);
        assert_eq!(sched.sink().blocks[0].samples[0], 10.0);

        // Process seq 11 (filled missing, should be available now).
        let n = sched.process_ready(now);
        assert_eq!(n, 1);
        assert_eq!(sched.sink().blocks.len(), 2);
        assert_eq!(sched.sink().blocks[1].samples[0], 11.0);

        // Process seq 12.
        let n = sched.process_ready(now);
        assert_eq!(n, 1);
        assert_eq!(sched.sink().blocks.len(), 3);
        assert_eq!(sched.sink().blocks[2].samples[0], 12.0);

        // Output order: 10, 11, 12.
        let seqs: Vec<f32> = sched.sink().blocks.iter().map(|b| b.samples[0]).collect();
        assert_eq!(seqs, vec![10.0, 11.0, 12.0]);
    }

    // ── Missing packet waits then conceals ─────────────────────

    #[test]
    fn missing_waits_before_grace_then_conceals() {
        let mut cfg = sched_test_config();
        cfg.reorder_grace_ms = 200; // 200 ms grace
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Insert 10 and 12 (skipping 11 creates a Missing slot).
        let t0 = Instant::now();
        assert_eq!(sched.insert_packet(seq_packet(10)), InsertResult::Accepted);
        assert_eq!(sched.insert_packet(seq_packet(12)), InsertResult::Accepted);

        // Process seq 10.
        assert_eq!(sched.process_ready(t0), 1);

        // At t0, seq 11 is Missing with first_noticed ≈ now.  Within grace
        // period: process_ready should return 0 (waiting).
        let t_early = t0;
        assert_eq!(sched.process_ready(t_early), 0);
        assert_eq!(sched.sink().blocks.len(), 1); // Only seq 10

        // After grace expires: should conceal seq 11.
        let t_late = t0 + std::time::Duration::from_millis(250);
        let n = sched.process_ready(t_late);
        assert_eq!(n, 1);
        assert_eq!(sched.sink().blocks.len(), 2);
        // Concealed sample is negative.
        assert!(sched.sink().blocks[1].samples[0] < 0.0);
        assert_eq!(sched.sink().blocks[1].samples[0], -11.0);

        // Now seq 12 should be available.
        assert_eq!(sched.process_ready(t_late), 1);
        assert_eq!(sched.sink().blocks.len(), 3);
        assert_eq!(sched.sink().blocks[2].samples[0], 12.0);
    }

    // ── One packet remains Priming below watermark ──────────────

    #[test]
    fn one_packet_stays_priming_below_watermark() {
        let cfg = sched_test_config(); // start_watermark_ms = 3
        let decoder = FakeDecoder::new(1, 1000, 1); // 1 ms per frame
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();
        assert_eq!(sched.state(), PlayoutState::Priming);

        // Insert and process one packet (1 ms < 3 ms start watermark).
        sched.insert_packet(seq_packet(0));
        let n = sched.process_ready(Instant::now());
        assert_eq!(n, 1);
        assert_eq!(sched.state(), PlayoutState::Priming); // Still priming.
    }

    // ── Enough packets enable Playing ──────────────────────────

    #[test]
    fn enough_packets_enable_playing() {
        let cfg = sched_test_config(); // start_watermark_ms = 3
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Insert 5 packets (seq 0..4 = 5 ms > 3 ms start).
        for seq in 0..5 {
            sched.insert_packet(seq_packet(seq));
        }

        let now = Instant::now();
        let mut total = 0;
        for _ in 0..5 {
            total += sched.process_ready(now);
        }
        assert_eq!(total, 5);
        // Should have transitioned to Playing after 3 ms.
        assert_eq!(sched.state(), PlayoutState::Playing);
    }

    // ── Playing below low enters Rebuffering ────────────────────

    #[test]
    fn playing_below_low_enters_rebuffering() {
        let mut cfg = sched_test_config();
        cfg.start_watermark_ms = 3;
        cfg.low_watermark_ms = 2;
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Prime to 3 ms.
        for seq in 0..3 {
            sched.insert_packet(seq_packet(seq));
        }
        let now = Instant::now();
        for _ in 0..3 {
            sched.process_ready(now);
        }
        assert_eq!(sched.state(), PlayoutState::Playing);

        // Drain sink to simulate FIFO consumption below low watermark.
        sched.sink_mut().queued_ms = 1;

        // Observe the low watermark: should enter Rebuffering.
        sched.observe_fifo();
        assert_eq!(sched.state(), PlayoutState::Rebuffering);
    }

    // ── Pause prevents processing and resume continues ──────────

    #[test]
    fn pause_prevents_processing_and_resume_continues() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Insert some packets.
        for seq in 0..5 {
            sched.insert_packet(seq_packet(seq));
        }

        let now = Instant::now();
        // Process one to get some data in.
        sched.process_ready(now);

        // Pause.
        sched.pause();
        assert_eq!(sched.state(), PlayoutState::Paused);

        // Processing should do nothing while paused.
        let n = sched.process_ready(now);
        assert_eq!(n, 0);

        // Resume.
        sched.resume();
        // Should be Priming (since queued_ms may be below start).
        assert!(matches!(
            sched.state(),
            PlayoutState::Priming | PlayoutState::Playing
        ));

        // Processing resumes.
        let n = sched.process_ready(now);
        assert!(n > 0);
    }

    // ── Stop/flush clear stale jitter/pending ───────────────────

    #[test]
    fn stop_clears_stale_jitter_and_pending() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();
        sched.insert_packet(seq_packet(10));
        sched.insert_packet(seq_packet(11));
        sched.process_ready(Instant::now());

        // Verify data is in jitter.
        assert!(sched.expected_sequence() > 0);

        // Stop.
        sched.stop();
        assert_eq!(sched.state(), PlayoutState::Stopped);
        // Jitter should be reset (expected_sequence goes to 0).
        assert_eq!(sched.expected_sequence(), 0);
        // Decoder was reset by start (1) + stop (1) = 2.
        assert_eq!(sched.decoder().reset_count, 2);
    }

    #[test]
    fn flush_clears_stale_jitter_and_pending() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();
        sched.insert_packet(seq_packet(100));
        sched.process_ready(Instant::now());

        sched.flush();
        assert_eq!(sched.state(), PlayoutState::Priming);
        assert_eq!(sched.expected_sequence(), 0);
        // Decoder reset by start (1) + flush (1) = 2.
        assert_eq!(sched.decoder().reset_count, 2);
        assert!(sched.sink().flush_count > 0);
    }

    // ── Resync reinserts trigger ────────────────────────────────

    #[test]
    fn resync_reinserts_triggering_packet() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Seed with seq 0 to establish a window.
        assert_eq!(sched.insert_packet(seq_packet(0)), InsertResult::Accepted);

        // Insert a packet far ahead (beyond capacity 16) to trigger resync.
        let far_pkt = seq_packet(100);
        let result = sched.insert_packet(far_pkt);
        // Should be Accepted after resync (re-inserted as fresh seed).
        assert!(matches!(result, InsertResult::Accepted));

        // Resync count should be 1.
        let status = sched.status();
        assert_eq!(status.diag.resync_count, 1);

        // The new window should start at 100.
        assert_eq!(sched.expected_sequence(), 100);
    }

    // ── Sink rejection retains pending, later retry succeeds ────

    #[test]
    fn sink_rejection_retains_pending_and_retries_before_next_packet() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let mut sink = FakeSink::new();
        sink.next_reject = true; // Reject the first enqueue.
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();
        sched.insert_packet(seq_packet(0));

        // First process_ready: decode succeeds but sink rejects.
        let n = sched.process_ready(Instant::now());
        assert_eq!(n, 0); // Blocked.
        let status = sched.status();
        assert!(status.has_pending_block);
        assert_eq!(status.diag.fifo_backpressure_events, 1);

        // Next process_ready: retries the pending block, now sink accepts.
        let n = sched.process_ready(Instant::now());
        assert_eq!(n, 1);
        assert!(!sched.status().has_pending_block);

        // Now insert and process the next packet — it should work.
        sched.insert_packet(seq_packet(1));
        let n = sched.process_ready(Instant::now());
        assert_eq!(n, 1);
        assert_eq!(sched.sink().blocks.len(), 2);
    }

    // ── Decoder error consumes bad packet but continues ──────────

    #[test]
    fn decoder_error_consumes_bad_packet_and_continues() {
        let cfg = sched_test_config();
        let mut decoder = FakeDecoder::new(1, 1000, 1);
        decoder.next_decode_error = true; // First decode will fail.
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Insert seq 0 (bad), seq 1 (good).
        sched.insert_packet(seq_packet(0));
        sched.insert_packet(seq_packet(1));

        let now = Instant::now();

        // First process: seq 0 fails to decode, consumed, loop continues to seq 1.
        let n = sched.process_ready(now);
        assert_eq!(n, 1); // seq 1 was successfully processed.
        assert_eq!(sched.status().diag.decode_errors, 1);
        assert_eq!(sched.status().diag.decoded_blocks, 1);
        assert_eq!(sched.sink().blocks[0].samples[0], 1.0); // seq 1's data.
    }

    // ── Diagnostics are exact ───────────────────────────────────

    #[test]
    fn diagnostics_track_insert_and_decode_counts() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();

        // Insert 3 packets.
        sched.insert_packet(seq_packet(0));
        sched.insert_packet(seq_packet(1));
        sched.insert_packet(seq_packet(1)); // Duplicate.

        let status = sched.status();
        assert_eq!(status.diag.insert_accepted, 2);
        assert_eq!(status.diag.insert_duplicate, 1);

        // Process them.
        let now = Instant::now();
        sched.process_ready(now);
        sched.process_ready(now);

        let status = sched.status();
        assert_eq!(status.diag.decoded_blocks, 2);
    }

    // ── State transition counting ──────────────────────────────

    #[test]
    fn state_transitions_count_start_stop_exactly() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        // Stopped → Priming (1).
        sched.start();
        assert_eq!(sched.status().diag.state_transitions, 1);

        // Priming → Stopped (2).
        sched.stop();
        assert_eq!(sched.status().diag.state_transitions, 2);
    }

    #[test]
    fn state_transitions_count_pause_resume() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start(); // Stopped → Priming (1).

        // Pause from Priming: Priming → Paused (2).
        sched.pause();
        assert_eq!(sched.status().diag.state_transitions, 2);

        // Resume: Paused → Priming (3).
        sched.resume();
        assert_eq!(sched.status().diag.state_transitions, 3);
    }

    #[test]
    fn state_transitions_count_flush() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start(); // Stopped → Priming (1).

        // Flush from Priming → Priming: no transition (idempotent).
        sched.flush();
        assert_eq!(sched.status().diag.state_transitions, 1);

        // Prime to Playing — insert distinct sequences.
        for seq in 0..5 {
            sched.insert_packet(seq_packet(seq));
        }
        for _ in 0..5 {
            sched.process_ready(Instant::now());
        }

        // Should be Playing now.
        assert_eq!(sched.state(), PlayoutState::Playing);

        // Playing → Priming via flush (3).
        sched.flush();
        assert_eq!(sched.status().diag.state_transitions, 3);
    }

    #[test]
    fn state_transitions_watermark_observation_increments() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        // Initial start.
        sched.start(); // Stopped → Priming (1).
        assert_eq!(sched.status().diag.state_transitions, 1);

        // Insert enough to reach start watermark.
        for seq in 0..5 {
            sched.insert_packet(seq_packet(seq));
        }
        let now = Instant::now();
        for _ in 0..3 {
            sched.process_ready(now);
        }
        // After 3 ms of queued data ≥ start_watermark_ms=3: Priming → Playing (2).
        assert_eq!(sched.state(), PlayoutState::Playing);
        assert_eq!(sched.status().diag.state_transitions, 2);

        // Drain sink below low watermark to trigger Rebuffering.
        sched.sink_mut().queued_ms = 0;
        sched.observe_fifo();
        // Playing → Rebuffering (3).
        assert_eq!(sched.state(), PlayoutState::Rebuffering);
        assert_eq!(sched.status().diag.state_transitions, 3);

        // Restore sink to trigger re-enable.
        sched.sink_mut().queued_ms = 5;
        sched.observe_fifo();
        // Rebuffering → Playing (4).
        assert_eq!(sched.state(), PlayoutState::Playing);
        assert_eq!(sched.status().diag.state_transitions, 4);
    }

    #[test]
    fn state_transitions_idempotent_same_state_no_increment() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        // Stopped → Priming (1).
        sched.start();
        assert_eq!(sched.status().diag.state_transitions, 1);

        // Second start: Priming → Priming → no increment.
        sched.start();
        assert_eq!(sched.status().diag.state_transitions, 1);

        // Stop: Priming → Stopped (2).
        sched.stop();
        assert_eq!(sched.status().diag.state_transitions, 2);

        // Second stop: Stopped → Stopped → no increment.
        sched.stop();
        assert_eq!(sched.status().diag.state_transitions, 2);

        // Flush from Stopped: Stopped → Stopped → no increment.
        sched.flush();
        assert_eq!(sched.status().diag.state_transitions, 2);
    }

    // ── Resync action order ─────────────────────────────────────

    #[test]
    fn active_resync_applies_gate_before_flush_and_retains_priming() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();
        sched.sink_mut().actions.clear();

        // Insert a seed packet, then one far beyond capacity to trigger resync.
        sched.insert_packet(seq_packet(0));
        let far = seq_packet(100);
        let result = sched.insert_packet(far);

        // The resync should be accepted (re-inserted as seed).
        assert!(matches!(result, InsertResult::Accepted));

        // After active resync the watermark should be Priming.
        assert_eq!(sched.state(), PlayoutState::Priming);

        // The exact action order is gate-off before flush.
        assert_eq!(
            sched.sink().actions,
            vec![FakeSinkAction::Gate(false), FakeSinkAction::Flush]
        );
        assert!(!sched.sink().gate);
    }

    #[test]
    fn paused_resync_preserves_state_and_does_not_flush_sink() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        sched.start();
        sched.insert_packet(seq_packet(0));
        sched.pause(); // Paused.
        assert_eq!(sched.state(), PlayoutState::Paused);

        let flush_before = sched.sink().flush_count;
        sched.sink_mut().actions.clear();

        // Trigger resync while paused.
        let far = seq_packet(100);
        let result = sched.insert_packet(far);

        // Should be accepted (re-inserted).
        assert!(matches!(result, InsertResult::Accepted));

        // State must remain Paused — resync does not alter inactive state.
        assert_eq!(sched.state(), PlayoutState::Paused);

        // No sink action should have occurred.
        assert_eq!(sched.sink().flush_count, flush_before);
        assert!(sched.sink().actions.is_empty());
    }

    #[test]
    fn stopped_resync_preserves_state_and_does_not_flush_sink() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(cfg, decoder, sink);

        // Stopped by default. Seed the jitter window, then jump beyond it.
        assert_eq!(sched.state(), PlayoutState::Stopped);
        sched.insert_packet(seq_packet(0));
        let flush_before = sched.sink().flush_count;
        sched.sink_mut().actions.clear();

        // Trigger resync while stopped; the sink must not be touched.
        let far = seq_packet(100);
        let result = sched.insert_packet(far);
        assert!(matches!(result, InsertResult::Accepted));

        assert_eq!(sched.state(), PlayoutState::Stopped);
        assert_eq!(sched.sink().flush_count, flush_before);
    }

    // ═══════════════════════════════════════════════════════════════
    // AudioEngineSink production tests
    // ═══════════════════════════════════════════════════════════════

    /// Create a real AudioEngine + consumer pair for tests.
    fn make_engine() -> (AudioEngine, crate::audio::AudioConsumer) {
        use crate::audio::AudioEngine;
        AudioEngine::new(32_768)
    }

    #[test]
    fn audio_engine_sink_accepts_whole_block_with_resampling() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);

        // Decoded audio at 44.1 kHz stereo → resampled to 48 kHz stereo.
        // 1024 frames of 44.1 kHz → ~1115 frames after resampling,
        // which fits comfortably in the 32k sample buffer.
        let decoded = DecodedAudio {
            samples: vec![0.5f32; 1024 * 2], // 1024 stereo frames
            sample_rate: 44_100,
            channels: 2,
        };

        let mut sink = AudioEngineSink::new(engine);
        let result = sink.enqueue(&decoded, true); // unchecked
        assert!(result.is_accepted());
        assert_eq!(result.requested_frames, 1024);
        assert_eq!(result.accepted_frames, 1024);
        let queued = sink.engine().status().queued_frames;
        assert!(queued > 1024, "44.1→48 kHz conversion should add frames");
        assert!(queued < 1120, "unexpected converted frame count: {queued}");
    }

    #[test]
    fn audio_engine_sink_rejects_whole_block_when_capacity_insufficient() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);

        // Fill the buffer almost completely.
        let capacity_frames = engine.status().capacity_frames;
        let fill_samples = (capacity_frames.saturating_sub(2)) * 2;
        let fill_data = vec![0.1f32; fill_samples];
        let (_, accepted) = engine.try_enqueue_output_frames_all_or_nothing(&fill_data, true);
        let _ = accepted;

        // Now try to enqueue a large block that exceeds remaining capacity.
        let decoded = DecodedAudio {
            samples: vec![0.5f32; 8 * 2], // 8 stereo frames
            sample_rate: 48_000,
            channels: 2,
        };

        let before = engine.status().queued_frames;
        let mut sink = AudioEngineSink::new(engine);
        let result = sink.enqueue(&decoded, true);
        assert!(!result.is_accepted());
        assert_eq!(result.accepted_frames, 0);
        assert_eq!(result.rejected_frames, result.requested_frames);
        assert_eq!(sink.engine().status().queued_frames, before);
    }

    #[test]
    fn audio_engine_sink_checked_gate_rejects() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);
        engine.set_output_gate(false); // gate closed

        let decoded = DecodedAudio {
            samples: vec![0.5f32; 100 * 2],
            sample_rate: 48_000,
            channels: 2,
        };

        let mut sink = AudioEngineSink::new(engine);
        // checked enqueue (unchecked = false) → gate closed → reject.
        let result = sink.enqueue(&decoded, false);
        assert!(!result.is_accepted());
        assert_eq!(result.accepted_frames, 0);
        assert_eq!(result.rejected_frames, 100);
    }

    #[test]
    fn audio_engine_sink_unchecked_bypasses_gate() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);
        engine.set_output_gate(false); // gate closed

        let decoded = DecodedAudio {
            samples: vec![0.5f32; 100 * 2],
            sample_rate: 48_000,
            channels: 2,
        };

        let mut sink = AudioEngineSink::new(engine);
        // unchecked enqueue bypasses the gate.
        let result = sink.enqueue(&decoded, true);
        assert!(result.is_accepted());
        assert_eq!(result.accepted_frames, 100);
    }

    #[test]
    fn audio_engine_sink_empty_block_is_accepted() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);

        let decoded = DecodedAudio {
            samples: vec![],
            sample_rate: 48_000,
            channels: 2,
        };

        let mut sink = AudioEngineSink::new(engine);
        let result = sink.enqueue(&decoded, false);
        assert!(result.is_accepted());
        assert_eq!(result.accepted_frames, 0);
    }

    // ── Atomic all-or-nothing: concurrent-producer tests ─────────

    #[test]
    fn try_enqueue_all_or_nothing_no_partial_write_on_capacity() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);

        let cap = engine.status().capacity_frames;

        // Fill to near capacity.
        let fill_frames = cap.saturating_sub(1);
        let fill_data = vec![0.2f32; fill_frames * 2];
        let (req, acc) = engine.try_enqueue_output_frames_all_or_nothing(&fill_data, true);
        assert_eq!(req, fill_frames);
        assert_eq!(acc, fill_frames);

        // Now request more frames than available.
        let excess = vec![0.5f32; 10 * 2]; // 10 frames, more than 1 remaining
        let (req, acc) = engine.try_enqueue_output_frames_all_or_nothing(&excess, true);
        assert_eq!(req, 10);
        assert_eq!(acc, 0); // Rejected wholesale — no partial write.

        // Overflow counter must NOT have been incremented.
        assert_eq!(engine.status().producer_overflow_samples, 0);
    }

    #[test]
    fn try_enqueue_all_or_nothing_trailing_samples_rejected() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);

        // 5 complete frames + 1 trailing sample → incomplete block.
        let data = vec![0.3f32; 5 * 2 + 1]; // 5 frames + 1 sample
        let (req, acc) = engine.try_enqueue_output_frames_all_or_nothing(&data, true);
        assert_eq!(req, 5);
        assert_eq!(acc, 0); // Trailing sample prevents all-or-nothing.

        // No overflow.
        assert_eq!(engine.status().producer_overflow_samples, 0);
    }
}
