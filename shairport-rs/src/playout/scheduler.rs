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
use crate::audio::drift::{DriftController, DriftDiagnostics};
use crate::config::AudioConfig;
use anyhow;
use std::time::Instant;

use super::jitter::{InsertResult, JitterBuffer, JitterDiagnostics, TakeExpectedResult};
use super::packet::TimedPacket;
use tracing::{debug, info, warn};

/// Playback rate carried by AP2 timing control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaybackRate {
    Paused,
    Normal,
}

/// Mapping between an AP2 RTP timeline and the sender's PTP network clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ap2TimelineAnchor {
    pub timeline_id: u64,
    pub network_time_ns: u64,
    pub rtp_timestamp: u32,
    pub sample_rate: u32,
    pub rate: PlaybackRate,
}

/// Temporary local presentation timeline installed after a hard drift
/// discontinuity. A later sender SETRATEANCHORTIME replaces it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Ap2RecoveryAnchor {
    local_time_ns: u64,
    rtp_timestamp: u32,
    sample_rate: u32,
}

/// Clock interface used by the scheduler. Local nanoseconds and values
/// returned by `network_to_local_ns` must use the same monotonic epoch.
pub trait NetworkClock: Send + Sync {
    fn is_locked(&self) -> bool;
    fn master_clock_id(&self) -> Option<u64>;
    fn network_to_local_ns(&self, network_ns: u64) -> Option<u64>;
    fn local_now_ns(&self) -> u64;
    fn uncertainty_ns(&self) -> u64;
}

/// Immutable, non-secret stream parameters required by the AP2 scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ap2StreamRuntime {
    pub stream_id: u32,
    pub stream_connection_id: Option<u64>,
    pub audio_format: crate::codec::AudioFormat,
    pub sample_rate: u32,
    pub frames_per_packet: u32,
}

/// A half-open AP2 buffered-audio flush range. Sequence numbers are the
/// 23-bit values carried on the wire; `from_* == None` denotes an immediate
/// flush from the current playout position. The `until_*` packet is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ap2FlushRange {
    pub from_sequence: Option<u32>,
    pub from_rtp_timestamp: Option<u32>,
    pub until_sequence: u32,
    pub until_rtp_timestamp: u32,
}

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
            start_watermark_ms: 250,
            low_watermark_ms: 100,
            target_watermark_ms: 200,
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
        self.observe_fifo_with_release(queued_ms, true)
    }

    /// Observe FIFO state while allowing an external timing authority to
    /// prevent Priming/Rebuffering from opening the output gate.
    pub fn observe_fifo_with_release(
        &mut self,
        queued_ms: u64,
        release_allowed: bool,
    ) -> Option<WatermarkAction> {
        match self.state {
            PlayoutState::Priming => {
                if release_allowed && queued_ms >= self.config.start_watermark_ms as u64 {
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
                if release_allowed && queued_ms >= self.config.start_watermark_ms as u64 {
                    self.state = PlayoutState::Playing;
                    Some(WatermarkAction::Gate(true))
                } else {
                    None
                }
            }
            PlayoutState::Stopped | PlayoutState::Paused => None,
        }
    }

    /// Return to Priming and close the gate without discarding buffered data.
    pub fn reprime(&mut self) -> Vec<WatermarkAction> {
        self.state = PlayoutState::Priming;
        vec![WatermarkAction::Gate(false)]
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

    /// Exact queued duration in nanoseconds when the sink can provide it.
    ///
    /// Test and legacy sinks may use the millisecond fallback. Production
    /// sinks should derive this from their actual queued frame count.
    fn queued_duration_ns(&self) -> u64 {
        self.queued_ms().saturating_mul(1_000_000)
    }

    /// Whether a previously requested flush still awaits callback
    /// acknowledgement.
    fn flush_pending(&self) -> bool {
        false
    }

    /// Enable or disable the output gate (mute without flushing).
    fn set_output_gate(&mut self, enabled: bool);

    /// Request the sink to flush all currently buffered samples.
    fn request_flush(&mut self);

    /// Apply a drift correction ratio in parts per million.
    ///
    /// A positive value speeds up the output to compensate for a DAC
    /// that is consuming faster than the sender (FIFO draining).
    /// A negative value slows it down (FIFO filling).
    ///
    /// The default implementation is a no-op — only sinks that support
    /// drift correction override this method.
    fn set_drift_correction_ppm(&mut self, _ppm: f64) {}

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
    pending_conversion: Option<PreparedConversion>,
}

struct PreparedConversion {
    source_ptr: usize,
    source_len: usize,
    sample_rate: u32,
    channels: u16,
    source_frames: usize,
    samples: Vec<f32>,
}

impl AudioEngineSink {
    /// Create a new sink wrapping the given [`AudioEngine`].
    pub fn new(engine: AudioEngine) -> Self {
        Self {
            engine,
            pending_conversion: None,
        }
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

    fn queued_duration_ns(&self) -> u64 {
        let status = self.engine.status();
        (status.queued_frames as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(status.output_sample_rate.max(1) as u128)
            .unwrap_or(0)
            .min(u64::MAX as u128) as u64
    }

    fn flush_pending(&self) -> bool {
        self.engine.is_flush_pending()
    }

    fn set_output_gate(&mut self, enabled: bool) {
        self.engine.set_output_gate(enabled);
    }

    fn request_flush(&mut self) {
        self.pending_conversion = None;
        self.engine.request_flush();
    }

    fn set_drift_correction_ppm(&mut self, ppm: f64) {
        self.engine.set_drift_correction_ppm(ppm);
    }

    fn enqueue(&mut self, decoded: &DecodedAudio, unchecked: bool) -> PcmWriteResult {
        let requested_frames = decoded.frames();
        if requested_frames == 0 {
            return PcmWriteResult::all_accepted(0);
        }

        let source_ptr = decoded.samples.as_ptr() as usize;
        let prepared = self.pending_conversion.take().filter(|prepared| {
            prepared.source_ptr == source_ptr
                && prepared.source_len == decoded.samples.len()
                && prepared.sample_rate == decoded.sample_rate
                && prepared.channels == decoded.channels
        });
        let prepared = prepared.unwrap_or_else(|| PreparedConversion {
            source_ptr,
            source_len: decoded.samples.len(),
            sample_rate: decoded.sample_rate,
            channels: decoded.channels,
            source_frames: requested_frames,
            samples: self.engine.convert_interleaved_for_output(
                &decoded.samples,
                decoded.sample_rate,
                decoded.channels,
            ),
        });

        // Atomic all-or-nothing enqueue under a single producer-lock
        // interval.  Capacity rejection is scheduler backpressure and
        // does not increment overflow/loss counters.
        let (_requested, accepted) = self
            .engine
            .try_enqueue_output_frames_all_or_nothing(&prepared.samples, unchecked);

        if accepted == _requested {
            PcmWriteResult::all_accepted(prepared.source_frames)
        } else {
            self.pending_conversion = Some(prepared);
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
    /// AP2 packets discarded because their presentation deadline passed.
    pub late_packet_drops: u64,
    /// Discontinuous late-packet runs recovered with one PCM flush/re-prime.
    pub late_catchup_events: u64,
    /// Ticks where a primed AP2 pipeline remained gated by timing.
    pub timing_gate_holds: u64,
    /// PTP lock-loss events that forced playback back to Priming.
    pub clock_lock_losses: u64,
    /// Buffered AP2 packets discarded by FLUSHBUFFERED ranges.
    pub buffered_flush_drops: u64,
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
    /// Drift correction diagnostics (None when not active).
    pub drift: Option<DriftDiagnostics>,
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
    /// Active AP2 stream parameters. This contains no key material.
    ap2_stream: Option<Ap2StreamRuntime>,
    ap2_recording: bool,
    playback_rate: PlaybackRate,
    timeline: Option<Ap2TimelineAnchor>,
    recovery_anchor: Option<Ap2RecoveryAnchor>,
    pending_hard_reanchor: bool,
    network_clock: Option<Arc<dyn NetworkClock>>,
    first_buffered_rtp_timestamp: Option<u32>,
    pending_rtp_timestamp: Option<u32>,
    /// RTP timestamp and sender-timeline frame span of the last AP2 packet
    /// accepted by the sink. The span comes from stream negotiation rather
    /// than decoder/resampler output shape.
    last_enqueued_ap2: Option<(u32, usize)>,
    /// After a paused AP2 stream receives a fresh resume anchor, discard
    /// already-buffered packets older than this RTP timestamp before seeding
    /// a new jitter window.
    resume_rtp_floor: Option<u32>,
    ap2_flush_ranges: Vec<Ap2FlushRange>,
    /// True while stale AP2 packets are being discarded up to the first
    /// packet whose presentation deadline is still viable.
    late_catchup_active: bool,
    late_catchup_dropped: u64,

    /// Bounded PI controller for AP2 clock drift correction.
    /// Only active during AP2 buffered playback with PTP lock.
    drift_controller: DriftController,
    /// Cached diagnostics from the drift controller (updated on each tick).
    drift_diag: Option<DriftDiagnostics>,
    /// Smoothed commanded ppm value sent to the sink/resampler.
    /// Low-pass filtered to avoid audible transients.
    smoothed_ppm: f64,
    /// Last correction actually applied to the sink. Kept separately from
    /// the smoothed controller output so insignificant changes do not restart
    /// the resampler's ratio ramp for every scheduler event.
    applied_drift_ppm: f64,
    /// Last observed PTP master clock ID — used to detect master changes
    /// and reset the drift controller.
    last_ptp_master_id: Option<u64>,
    /// Timestamp of the last drift controller update (for time-based integral).
    last_drift_update: Option<std::time::Instant>,

    /// Cooldown timers for rate-limited diagnostics logging (seconds
    /// between repeated messages of each category).
    last_timing_gate_warn: Option<std::time::Instant>,
    last_clock_loss_warn: Option<std::time::Instant>,
    last_resync_warn: Option<std::time::Instant>,
    last_late_drop_warn: Option<std::time::Instant>,
    last_drift_resync_warn: Option<std::time::Instant>,

    diag: SchedulerDiagnostics,
}

impl<D: PacketDecoder, S: PcmSink> SchedulerCore<D, S> {
    /// Create a new scheduler.
    ///
    /// The scheduler starts in [`Stopped`](PlayoutState::Stopped).
    pub fn new(config: SchedulerConfig, decoder: D, sink: S) -> Self {
        let jitter = JitterBuffer::new(config.jitter_capacity_packets);
        let watermark = WatermarkController::new(config.clone());
        let drift_controller = DriftController::new(config.target_watermark_ms as u64);
        Self {
            config,
            watermark,
            jitter,
            decoder,
            sink,
            pending: None,
            pending_sequence: None,
            last_decoded_packet: None,
            ap2_stream: None,
            ap2_recording: false,
            playback_rate: PlaybackRate::Paused,
            timeline: None,
            recovery_anchor: None,
            pending_hard_reanchor: false,
            network_clock: None,
            first_buffered_rtp_timestamp: None,
            pending_rtp_timestamp: None,
            last_enqueued_ap2: None,
            resume_rtp_floor: None,
            ap2_flush_ranges: Vec::new(),
            late_catchup_active: false,
            late_catchup_dropped: 0,
            drift_controller,
            drift_diag: None,
            smoothed_ppm: 0.0,
            applied_drift_ppm: 0.0,
            last_ptp_master_id: None,
            last_drift_update: None,
            last_timing_gate_warn: None,
            last_clock_loss_warn: None,
            last_resync_warn: None,
            last_late_drop_warn: None,
            last_drift_resync_warn: None,
            diag: SchedulerDiagnostics::default(),
        }
    }

    /// Attach the network clock used for AP2 deadline scheduling.
    pub fn set_network_clock(&mut self, clock: Arc<dyn NetworkClock>) {
        self.network_clock = Some(clock);
    }

    fn reset_drift_state(&mut self, disable: bool) {
        if disable {
            self.drift_controller.disable();
        } else {
            self.drift_controller.reset();
        }
        self.smoothed_ppm = 0.0;
        self.applied_drift_ppm = 0.0;
        self.last_drift_update = None;
        self.last_enqueued_ap2 = None;
        self.sink.set_drift_correction_ppm(0.0);
        self.drift_diag = self
            .ap2_stream
            .is_some()
            .then(|| self.drift_controller.diagnostics());
    }

    /// Install AP2 stream parameters without starting transport or opening
    /// the output gate.
    pub fn configure_ap2_stream(&mut self, runtime: Ap2StreamRuntime) {
        if self.ap2_stream != Some(runtime) {
            self.stop();
            self.ap2_stream = Some(runtime);
            self.ap2_recording = false;
            self.timeline = None;
            self.recovery_anchor = None;
            self.pending_hard_reanchor = false;
            self.playback_rate = PlaybackRate::Paused;
            self.reset_drift_state(true);
        }
    }

    /// Make RECORD authoritative for AP2 pipeline preparation. This resets
    /// stale compressed, decoder, pending PCM, and sink state and enters
    /// Priming with output gated.
    pub fn record_ap2(&mut self) {
        if self.ap2_stream.is_some() {
            self.start();
            self.ap2_recording = true;
            self.timeline = None;
            self.playback_rate = PlaybackRate::Paused;
            self.reset_drift_state(true);
        }
    }

    /// Remove the AP2 stream configuration and all associated pipeline state.
    pub fn clear_ap2_stream(&mut self) {
        self.stop();
        self.ap2_stream = None;
        self.ap2_recording = false;
        self.timeline = None;
        self.playback_rate = PlaybackRate::Paused;
        self.ap2_flush_ranges.clear();
        self.reset_drift_state(true);
    }

    /// Install an AP2 timeline. Replacing an existing timeline ID gates and
    /// flushes stale compressed/decoded/PCM data before re-priming.
    pub fn set_timeline(&mut self, anchor: Ap2TimelineAnchor) {
        let resuming_from_pause =
            self.playback_rate == PlaybackRate::Paused && anchor.rate == PlaybackRate::Normal;
        if self
            .timeline
            .is_some_and(|current| current.timeline_id != anchor.timeline_id)
        {
            self.start();
        }
        self.timeline = Some(anchor);
        self.recovery_anchor = None;
        self.pending_hard_reanchor = false;

        // A complete rate=1 anchor after a pause defines a fresh presentation
        // point. The sender may have advanced by hundreds of milliseconds
        // while our gated PCM FIFO and jitter window still contain pre-pause
        // audio. Comparing that stale tail with the new anchor produces a
        // false drift discontinuity and makes resume fail. Flush the stale
        // pipeline and ignore queued ingress packets older than the anchor;
        // the first packet at/after the floor seeds a clean jitter window.
        if resuming_from_pause {
            self.sink.request_flush();
            self.jitter.reset();
            self.decoder.reset();
            self.pending = None;
            self.pending_sequence = None;
            self.pending_rtp_timestamp = None;
            self.last_decoded_packet = None;
            self.first_buffered_rtp_timestamp = None;
            self.last_enqueued_ap2 = None;
            self.resume_rtp_floor = Some(anchor.rtp_timestamp);
            self.late_catchup_active = false;
            self.late_catchup_dropped = 0;
        }

        self.reset_drift_state(false);
        self.set_playback_rate(anchor.rate);
    }

    pub fn set_playback_rate(&mut self, rate: PlaybackRate) {
        self.playback_rate = rate;
        match rate {
            PlaybackRate::Paused => self.pause(),
            PlaybackRate::Normal if self.ap2_recording => {
                let old_state = self.watermark.state();
                let actions = self.watermark.reprime();
                self.record_state_transition(old_state);
                self.apply_actions(&actions);
            }
            PlaybackRate::Normal => {}
        }
    }

    pub fn clear_timeline(&mut self) {
        self.timeline = None;
        self.recovery_anchor = None;
        self.pending_hard_reanchor = false;
        self.playback_rate = PlaybackRate::Paused;
        self.first_buffered_rtp_timestamp = None;
        let old_state = self.watermark.state();
        let actions = self.watermark.reprime();
        self.record_state_transition(old_state);
        self.apply_actions(&actions);
        self.reset_drift_state(true);
    }

    /// Register a scheduler-owned FLUSHBUFFERED range. Immediate flushes
    /// discard already-decoded PCM and pending decoder output; deferred
    /// ranges preserve current output and are enforced as packets reach the
    /// head of the jitter buffer.
    pub fn flush_buffered(&mut self, range: Ap2FlushRange) {
        self.set_playback_rate(PlaybackRate::Paused);
        self.reset_drift_state(false);
        if range.from_sequence.is_none() {
            self.sink.request_flush();
            self.pending = None;
            self.pending_sequence = None;
            self.pending_rtp_timestamp = None;
            self.last_decoded_packet = None;
            self.first_buffered_rtp_timestamp = None;
        }
        self.ap2_flush_ranges.push(range);
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
        self.pending_rtp_timestamp = None;
        self.last_decoded_packet = None;
        self.first_buffered_rtp_timestamp = None;
        self.last_enqueued_ap2 = None;
        self.recovery_anchor = None;
        self.pending_hard_reanchor = false;
        self.resume_rtp_floor = None;
        self.ap2_flush_ranges.clear();
        self.late_catchup_active = false;
        self.late_catchup_dropped = 0;
        self.reset_drift_state(true);
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
        self.pending_rtp_timestamp = None;
        self.last_decoded_packet = None;
        self.first_buffered_rtp_timestamp = None;
        self.last_enqueued_ap2 = None;
        self.recovery_anchor = None;
        self.pending_hard_reanchor = false;
        self.resume_rtp_floor = None;
        self.ap2_flush_ranges.clear();
        self.late_catchup_active = false;
        self.late_catchup_dropped = 0;
        self.reset_drift_state(true);
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
        self.pending_rtp_timestamp = None;
        self.last_decoded_packet = None;
        self.first_buffered_rtp_timestamp = None;
        self.last_enqueued_ap2 = None;
        self.late_catchup_active = false;
        self.late_catchup_dropped = 0;
        self.reset_drift_state(false);
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
        if packet.protocol.is_airplay2_audio() {
            self.maybe_install_hard_recovery_anchor(packet.rtp_timestamp);
        }

        if packet.protocol == super::packet::StreamProtocol::AirPlay2Buffered
            && let Some(floor) = self.resume_rtp_floor
        {
            let relative = packet.rtp_timestamp.wrapping_sub(floor) as i32;
            if relative < 0 {
                self.diag.buffered_flush_drops = self.diag.buffered_flush_drops.saturating_add(1);
                self.diag.insert_too_old = self.diag.insert_too_old.saturating_add(1);
                return InsertResult::TooOld;
            }
            self.resume_rtp_floor = None;
        }

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
                self.pending_rtp_timestamp = None;
                self.last_decoded_packet = None;
                self.first_buffered_rtp_timestamp = None;
                self.last_enqueued_ap2 = None;
                self.reset_drift_state(false);
                self.diag.resync_count += 1;
                if self.cooldown_warn("resync", 5) {
                    warn!(
                        resyncs = self.diag.resync_count,
                        state = ?self.watermark.state(),
                        "playout resync triggered — jitter window overflow"
                    );
                }

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
        if let Some(rtp_timestamp) = self.pending_rtp_timestamp {
            self.maybe_install_hard_recovery_anchor(rtp_timestamp);
        }
        if let Some(ref decoded) = self.pending {
            let unchecked = matches!(state, PlayoutState::Priming | PlayoutState::Rebuffering);
            let result = self.sink.enqueue(decoded, unchecked);
            if result.is_accepted() {
                let accepted_frames = decoded.frames();
                let accepted_rtp = self.pending_rtp_timestamp;
                if self.first_buffered_rtp_timestamp.is_none() {
                    self.first_buffered_rtp_timestamp = accepted_rtp;
                }
                if let Some(rtp) = accepted_rtp {
                    let timeline_frames = self
                        .ap2_stream
                        .map(|stream| stream.frames_per_packet as usize)
                        .unwrap_or(accepted_frames);
                    self.last_enqueued_ap2 = Some((rtp, timeline_frames));
                    self.finish_late_catchup(rtp);
                }
                self.pending = None;
                self.pending_sequence = None;
                self.pending_rtp_timestamp = None;
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
                    let packet_rtp = pkt_clone.rtp_timestamp;
                    let packet_is_ap2 = pkt_clone.protocol.is_airplay2_audio();
                    let packet_is_buffered =
                        pkt_clone.protocol == super::packet::StreamProtocol::AirPlay2Buffered;
                    if packet_is_ap2 {
                        self.maybe_install_hard_recovery_anchor(packet_rtp);
                    }

                    if packet_is_buffered && self.packet_is_in_flush_range(&pkt_clone) {
                        match self.jitter.take_expected() {
                            TakeExpectedResult::Packet(_) => {}
                            _ => unreachable!("peek gave Packet but take did not"),
                        }
                        self.diag.buffered_flush_drops += 1;
                        continue;
                    }

                    if packet_is_ap2 && self.packet_is_too_late(packet_rtp) {
                        let catchup_started = !self.late_catchup_active;
                        if catchup_started {
                            self.begin_late_catchup();
                        }
                        match self.jitter.take_expected() {
                            TakeExpectedResult::Packet(_) => {}
                            _ => unreachable!("peek gave Packet but take did not"),
                        }
                        self.diag.late_packet_drops += 1;
                        self.late_catchup_dropped = self.late_catchup_dropped.saturating_add(1);
                        if catchup_started && self.cooldown_warn("late_drop", 5) {
                            warn!(
                                drops = self.diag.late_packet_drops,
                                raw_sequence = pkt_clone.raw_sequence,
                                rtp_timestamp = packet_rtp,
                                "AP2 late-packet catch-up started — stale PCM flushed once"
                            );
                        }
                        continue;
                    }

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

                            let unchecked = matches!(
                                self.watermark.state(),
                                PlayoutState::Priming | PlayoutState::Rebuffering
                            );
                            let frames = decoded.frames();
                            let result = self.sink.enqueue(&decoded, unchecked);
                            if result.is_accepted() {
                                if packet_is_ap2 && self.first_buffered_rtp_timestamp.is_none() {
                                    self.first_buffered_rtp_timestamp = Some(packet_rtp);
                                }
                                if packet_is_ap2 {
                                    let timeline_frames = self
                                        .ap2_stream
                                        .map(|stream| stream.frames_per_packet as usize)
                                        .unwrap_or(frames);
                                    self.last_enqueued_ap2 = Some((packet_rtp, timeline_frames));
                                    self.finish_late_catchup(packet_rtp);
                                }
                                // Enqueue succeeded — observe watermark.
                                self.observe_and_apply();
                                return 1;
                            }
                            // Rejected — store as pending, count one backpressure.
                            self.diag.fifo_backpressure_events += 1;
                            self.diag.fifo_backpressure_frames += frames as u64;
                            self.pending = Some(decoded);
                            self.pending_sequence = Some(seq);
                            self.pending_rtp_timestamp = packet_is_ap2.then_some(packet_rtp);
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

                            let unchecked = matches!(
                                self.watermark.state(),
                                PlayoutState::Priming | PlayoutState::Rebuffering
                            );
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
                            self.pending_rtp_timestamp = None;
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
            drift: self.drift_diag,
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
            info!(
                ?old,
                ?new,
                transitions = self.diag.state_transitions,
                "playout state transition"
            );
        }
    }

    /// Enter one discontinuous catch-up epoch. Stale compressed packets stay
    /// in the jitter buffer so they can be discarded in sequence, but stale
    /// PCM and decoder history are cleared exactly once. This prevents the
    /// first current packet from being appended behind old queued audio.
    fn begin_late_catchup(&mut self) {
        let old_state = self.watermark.state();
        let actions = self.watermark.flush();
        self.apply_actions(&actions);
        self.record_state_transition(old_state);
        self.decoder.reset();
        self.pending = None;
        self.pending_sequence = None;
        self.pending_rtp_timestamp = None;
        self.last_decoded_packet = None;
        self.first_buffered_rtp_timestamp = None;
        self.last_enqueued_ap2 = None;
        self.reset_drift_state(false);
        self.late_catchup_active = true;
        self.late_catchup_dropped = 0;
        self.diag.late_catchup_events = self.diag.late_catchup_events.saturating_add(1);
    }

    fn finish_late_catchup(&mut self, viable_rtp_timestamp: u32) {
        if !self.late_catchup_active {
            return;
        }
        info!(
            event = self.diag.late_catchup_events,
            dropped = self.late_catchup_dropped,
            viable_rtp_timestamp,
            "AP2 late-packet catch-up completed; pipeline re-priming"
        );
        self.late_catchup_active = false;
        self.late_catchup_dropped = 0;
    }

    /// Returns `true` if a category-throttled warning should be emitted
    /// (at most once per `cooldown_secs`).  The category string selects
    /// the cooldown timer field.
    fn cooldown_warn(&mut self, category: &str, cooldown_secs: u64) -> bool {
        let cooldown = std::time::Duration::from_secs(cooldown_secs);
        let now = std::time::Instant::now();
        let timer = match category {
            "timing_gate" => &mut self.last_timing_gate_warn,
            "clock_loss" => &mut self.last_clock_loss_warn,
            "resync" => &mut self.last_resync_warn,
            "late_drop" => &mut self.last_late_drop_warn,
            "drift_resync" => &mut self.last_drift_resync_warn,
            _ => return true,
        };
        let should_log = timer
            .map(|t| now.saturating_duration_since(t) >= cooldown)
            .unwrap_or(true);
        if should_log {
            *timer = Some(now);
        }
        should_log
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
        let timing_release_allowed = if self.ap2_stream.is_some() && self.ap2_recording {
            self.ap2_timing_release_allowed()
        } else {
            true
        };
        let release_allowed = timing_release_allowed && !self.sink.flush_pending();

        if old_state == PlayoutState::Playing
            && self.ap2_stream.is_some()
            && self.ap2_recording
            && !timing_release_allowed
        {
            let actions = self.watermark.reprime();
            self.apply_actions(&actions);
            self.diag.clock_lock_losses += 1;
            if self.cooldown_warn("clock_loss", 5) {
                warn!(
                    losses = self.diag.clock_lock_losses,
                    "AP2 clock lock lost — playback re-primed"
                );
            }
        } else if let Some(action) = self
            .watermark
            .observe_fifo_with_release(queued_ms, release_allowed)
        {
            self.apply_actions(&[action]);
        } else if matches!(
            self.watermark.state(),
            PlayoutState::Priming | PlayoutState::Rebuffering
        ) && queued_ms >= self.config.start_watermark_ms as u64
            && !timing_release_allowed
        {
            self.diag.timing_gate_holds += 1;
            if self.cooldown_warn("timing_gate", 5) {
                warn!(
                    holds = self.diag.timing_gate_holds,
                    queued_ms, "AP2 timing gate holding — network/RTP anchor not yet eligible"
                );
            }
        }
        self.record_state_transition(old_state);
    }

    fn ap2_timing_release_allowed(&self) -> bool {
        if self.playback_rate != PlaybackRate::Normal {
            return false;
        }
        let Some(clock) = &self.network_clock else {
            return false;
        };
        if !clock.is_locked() || clock.master_clock_id().is_none() {
            return false;
        }
        let Some(first_rtp) = self.first_buffered_rtp_timestamp else {
            return false;
        };
        let Some(deadline) = self.packet_deadline_ns(first_rtp) else {
            return false;
        };
        clock.local_now_ns() >= deadline
    }

    fn packet_is_too_late(&self, rtp_timestamp: u32) -> bool {
        let Some(clock) = &self.network_clock else {
            return false;
        };
        if !clock.is_locked() {
            return false;
        }
        let Some(deadline) = self.packet_deadline_ns(rtp_timestamp) else {
            return false;
        };
        let tolerance = clock.uncertainty_ns().saturating_add(20_000_000);
        clock.local_now_ns() > deadline.saturating_add(tolerance)
    }

    fn packet_is_in_flush_range(&mut self, packet: &TimedPacket) -> bool {
        const AP2_SEQUENCE_MASK: u32 = 0x7f_ffff;
        const AP2_SEQUENCE_HALF: u32 = 0x40_0000;

        fn compare_23(a: u32, b: u32) -> i32 {
            let delta = a.wrapping_sub(b) & AP2_SEQUENCE_MASK;
            if delta >= AP2_SEQUENCE_HALF {
                delta as i32 - 0x80_0000
            } else {
                delta as i32
            }
        }

        let sequence = packet.raw_sequence & AP2_SEQUENCE_MASK;
        let mut discard = false;
        self.ap2_flush_ranges.retain(|range| {
            let until = range.until_sequence & AP2_SEQUENCE_MASK;
            let at_or_after_until = compare_23(sequence, until) >= 0;
            if at_or_after_until {
                return false;
            }
            let at_or_after_from = range
                .from_sequence
                .is_none_or(|from| compare_23(sequence, from & AP2_SEQUENCE_MASK) >= 0);
            if at_or_after_from {
                discard = true;
            }
            true
        });
        discard
    }

    /// Update the AP2 drift controller and apply the commanded correction
    /// to the sink.
    ///
    /// Should be called once per scheduler tick during active AP2 playback.
    fn update_drift(&mut self) {
        const DRIFT_UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
        const DRIFT_APPLY_DEADBAND_PPM: f64 = 0.5;

        let Some(clock) = self.network_clock.as_ref().cloned() else {
            self.reset_drift_state(true);
            return;
        };
        let master_id = clock.master_clock_id();
        let master_changed = self
            .last_ptp_master_id
            .is_some_and(|previous| Some(previous) != master_id);
        self.last_ptp_master_id = master_id;

        if master_changed {
            self.reset_drift_state(true);
            if self.watermark.state() == PlayoutState::Playing {
                let old_state = self.watermark.state();
                let actions = self.watermark.reprime();
                self.apply_actions(&actions);
                self.record_state_transition(old_state);
            }
            self.drift_diag = Some(self.drift_controller.diagnostics());
            return;
        }

        let active = self.ap2_stream.is_some()
            && self.ap2_recording
            && self.playback_rate == PlaybackRate::Normal
            && self.timeline.is_some()
            && self.watermark.state() == PlayoutState::Playing
            && clock.is_locked()
            && master_id.is_some();
        if !active {
            self.reset_drift_state(true);
            return;
        }

        let (tail_rtp, tail_frames) = match self.last_enqueued_ap2 {
            Some(value) => value,
            None => {
                self.reset_drift_state(true);
                return;
            }
        };
        let stream = self.ap2_stream.expect("active AP2 stream checked");
        let Some(tail_start_ns) = self.packet_deadline_ns(tail_rtp) else {
            self.reset_drift_state(true);
            return;
        };

        if !self.drift_controller.is_enabled() {
            self.drift_controller.enable();
        }
        let now = std::time::Instant::now();
        let elapsed = self
            .last_drift_update
            .map(|last| now.saturating_duration_since(last).as_secs_f64())
            .unwrap_or(0.0);
        if self.last_drift_update.is_some() && elapsed < DRIFT_UPDATE_INTERVAL.as_secs_f64() {
            return;
        }
        self.last_drift_update = Some(now);

        let fifo_queued_ms = self.sink.queued_ms();
        let tail_duration_ns = (tail_frames as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(stream.sample_rate.max(1) as u128)
            .unwrap_or(0)
            .min(u64::MAX as u128) as u64;
        let scheduled_tail_ns = tail_start_ns.saturating_add(tail_duration_ns);
        let fifo_queued_duration_ns = self.sink.queued_duration_ns();
        let predicted_tail_ns = clock.local_now_ns().saturating_add(fifo_queued_duration_ns);
        let timing_error_ns = (scheduled_tail_ns as i128 - predicted_tail_ns as i128)
            .clamp(-(u64::MAX as i128), u64::MAX as i128) as f64;
        debug!(
            tail_rtp,
            timeline_frames = tail_frames,
            fifo_queued_ms,
            fifo_queued_duration_ns,
            scheduled_tail_ns,
            predicted_tail_ns,
            timing_error_ns,
            "AP2 drift timeline sample"
        );

        match self
            .drift_controller
            .update(fifo_queued_ms, timing_error_ns, true, elapsed)
        {
            Some(raw_ppm) => {
                const SMOOTH_TIME_CONSTANT_SECONDS: f64 = 1.0;
                let alpha = 1.0 - (-elapsed / SMOOTH_TIME_CONSTANT_SECONDS).exp();
                self.smoothed_ppm += (raw_ppm - self.smoothed_ppm) * alpha;
                if (self.smoothed_ppm - self.applied_drift_ppm).abs() >= DRIFT_APPLY_DEADBAND_PPM {
                    self.applied_drift_ppm = self.smoothed_ppm;
                    self.sink.set_drift_correction_ppm(self.applied_drift_ppm);
                }
            }
            None => {
                let hard_resyncs = self.drift_controller.diagnostics().hard_resync_count;
                if self.cooldown_warn("drift_resync", 5) {
                    warn!(
                        hard_resyncs,
                        fifo_queued_ms,
                        timing_error_ns,
                        "AP2 drift discontinuity triggered a hard playout resync"
                    );
                }
                let old_state = self.watermark.state();
                let actions = self.watermark.flush();
                self.apply_actions(&actions);
                self.record_state_transition(old_state);
                self.sink.set_drift_correction_ppm(0.0);
                self.smoothed_ppm = 0.0;
                self.applied_drift_ppm = 0.0;
                self.decoder.reset();
                self.jitter.reset();
                self.pending = None;
                self.pending_sequence = None;
                self.pending_rtp_timestamp = None;
                self.last_decoded_packet = None;
                self.first_buffered_rtp_timestamp = None;
                self.last_enqueued_ap2 = None;
                self.diag.resync_count += 1;
                self.recovery_anchor = None;
                self.pending_hard_reanchor = true;
            }
        }

        let mut diagnostics = self.drift_controller.diagnostics();
        diagnostics.correction_ppm = self.applied_drift_ppm;
        self.drift_diag = Some(diagnostics);
    }

    fn packet_deadline_ns(&self, rtp_timestamp: u32) -> Option<u64> {
        if let Some(anchor) = self.recovery_anchor {
            let frame_delta = rtp_timestamp.wrapping_sub(anchor.rtp_timestamp) as i32 as i64;
            let offset_ns =
                (frame_delta as i128 * 1_000_000_000i128) / anchor.sample_rate.max(1) as i128;
            return (anchor.local_time_ns as i128)
                .checked_add(offset_ns)?
                .try_into()
                .ok();
        }

        let anchor = self.timeline?;
        let clock = self.network_clock.as_ref()?;
        let frame_delta = rtp_timestamp.wrapping_sub(anchor.rtp_timestamp) as i32 as i64;
        let offset_ns =
            (frame_delta as i128 * 1_000_000_000i128) / anchor.sample_rate.max(1) as i128;
        let network_ns: u64 = (anchor.network_time_ns as i128)
            .checked_add(offset_ns)?
            .try_into()
            .ok()?;
        clock.network_to_local_ns(network_ns)
    }

    fn maybe_install_hard_recovery_anchor(&mut self, rtp_timestamp: u32) {
        if !self.pending_hard_reanchor {
            return;
        }
        let Some(clock) = &self.network_clock else {
            return;
        };
        if !clock.is_locked() || clock.master_clock_id().is_none() {
            return;
        }
        let sample_rate = self
            .ap2_stream
            .map(|stream| stream.sample_rate)
            .unwrap_or(44_100)
            .max(1);
        let start_delay_ns = (self.config.start_watermark_ms as u64).saturating_mul(1_000_000);
        let local_time_ns = clock.local_now_ns().saturating_add(start_delay_ns);
        self.recovery_anchor = Some(Ap2RecoveryAnchor {
            local_time_ns,
            rtp_timestamp,
            sample_rate,
        });
        self.pending_hard_reanchor = false;
        info!(
            rtp_timestamp,
            sample_rate,
            start_delay_ms = self.config.start_watermark_ms,
            "AP2 hard-resync recovery anchor installed"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Playout service — async task that drives SchedulerCore
// ═══════════════════════════════════════════════════════════════════════

use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use super::ingress::{IngressReceiver, IngressSender, packet_ingress};

/// Commands sent to the playout service task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlayoutCommand {
    /// Configure immutable AP2 stream parameters without starting output.
    ConfigureStream(Ap2StreamRuntime),
    /// Prepare the configured AP2 stream for playback, gated in Priming.
    Record,
    /// Clear the configured AP2 stream and all buffered state.
    ClearStream,
    /// Install or replace the AP2 network/RTP timeline.
    SetTimeline(Ap2TimelineAnchor),
    /// Change AP2 playback rate without discarding the configured stream.
    SetPlaybackRate(PlaybackRate),
    /// Remove the active AP2 timeline and close the output gate.
    ClearTimeline,
    /// Apply a bounded AP2 buffered-audio flush.
    FlushBuffered(Ap2FlushRange),
    /// Start the transport (enters Priming, gates off, flushes).
    Start,
    /// Pause the transport (gates off, preserves FIFO).
    Pause,
    /// Resume from pause.
    Resume,
    /// Flush the FIFO and restart priming.
    Flush,
    /// Stop the transport (gates off, flushes, resets decoder).
    Stop,
    /// Gracefully shut down the service task.
    Shutdown,
}

/// Cloneable handle to a running playout service.
///
/// `PlayoutHandle` is cheap to clone and safe to share across threads.
/// All packet insertion and command methods are non-blocking or
/// properly async.
#[derive(Clone, Debug)]
pub struct PlayoutHandle {
    /// Bounded ingress for packet submission.
    ingress: IngressSender,
    /// Unbounded command channel.
    cmd_tx: mpsc::UnboundedSender<PlayoutCommand>,
    /// Shared latest scheduler status.
    status: Arc<RwLock<SchedulerStatus>>,
    jitter_capacity_packets: usize,
    start_watermark_ms: u32,
}

impl PlayoutHandle {
    /// Non-blocking packet submission for AP1 (UDP receive loops).
    ///
    /// Returns [`IngressResult::Accepted`], [`Full`], or [`Closed`].
    /// Never blocks — suitable for synchronous UDP socket loops.
    ///
    /// [`Full`]: super::ingress::IngressResult::Full
    /// [`Closed`]: super::ingress::IngressResult::Closed
    pub fn try_send_ap1(&self, packet: TimedPacket) -> super::ingress::IngressResult {
        self.ingress.try_send(packet)
    }

    /// Async packet submission for AP2 (TCP backpressure).
    ///
    /// Awaits until the bounded channel has capacity.  Returns
    /// [`IngressResult::Closed`] when the receiver has been dropped so
    /// the caller can observe shutdown.
    ///
    /// [`IngressResult::Closed`]: super::ingress::IngressResult::Closed
    pub async fn send_ap2(&self, packet: TimedPacket) -> super::ingress::IngressResult {
        self.ingress.send(packet).await
    }

    /// Send a command to the service task.
    fn send_cmd(&self, cmd: PlayoutCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Start the transport.
    pub fn start(&self) {
        self.send_cmd(PlayoutCommand::Start);
    }

    /// Configure an AP2 stream without starting output.
    pub fn configure_stream(&self, runtime: Ap2StreamRuntime) {
        self.send_cmd(PlayoutCommand::ConfigureStream(runtime));
    }

    /// Prepare the configured AP2 stream for timed playback.
    pub fn record(&self) {
        self.send_cmd(PlayoutCommand::Record);
    }

    /// Clear AP2 stream configuration and buffered state.
    pub fn clear_stream(&self) {
        self.send_cmd(PlayoutCommand::ClearStream);
    }

    pub fn set_timeline(&self, anchor: Ap2TimelineAnchor) {
        self.send_cmd(PlayoutCommand::SetTimeline(anchor));
    }

    pub fn set_playback_rate(&self, rate: PlaybackRate) {
        self.send_cmd(PlayoutCommand::SetPlaybackRate(rate));
    }

    pub fn clear_timeline(&self) {
        self.send_cmd(PlayoutCommand::ClearTimeline);
    }

    /// Queue a scheduler-owned AP2 buffered flush. Returns false if the
    /// playout task has already stopped and cannot accept the request.
    pub fn flush_buffered(&self, range: Ap2FlushRange) -> bool {
        self.cmd_tx
            .send(PlayoutCommand::FlushBuffered(range))
            .is_ok()
    }

    /// Pause the transport.
    pub fn pause(&self) {
        self.send_cmd(PlayoutCommand::Pause);
    }

    /// Resume from pause.
    pub fn resume(&self) {
        self.send_cmd(PlayoutCommand::Resume);
    }

    /// Flush the audio FIFO and re-prime.
    pub fn flush(&self) {
        self.send_cmd(PlayoutCommand::Flush);
    }

    /// Stop the transport.
    pub fn stop(&self) {
        self.send_cmd(PlayoutCommand::Stop);
    }

    /// Request graceful shutdown of the service task.
    pub fn shutdown(&self) {
        self.send_cmd(PlayoutCommand::Shutdown);
    }

    /// Snapshot the latest scheduler status.
    pub fn status(&self) -> SchedulerStatus {
        self.status.read().clone()
    }

    /// Snapshot the ingress diagnostic counters (accepted, full drops,
    /// closed drops, max depth, current inflight).
    pub fn ingress_diagnostics(&self) -> super::ingress::IngressDiagnostics {
        self.ingress.diagnostics()
    }

    /// Total compressed-packet capacity across ingress and jitter stages.
    pub fn buffered_packet_capacity(&self) -> usize {
        self.ingress
            .capacity_packets()
            .saturating_add(self.jitter_capacity_packets)
    }

    /// Scheduler priming latency expressed in source audio frames.
    pub fn start_latency_frames(&self, sample_rate: u32) -> u32 {
        ((sample_rate as u64)
            .saturating_mul(self.start_watermark_ms as u64)
            .saturating_add(999)
            / 1_000)
            .min(u32::MAX as u64) as u32
    }

    /// Return a test-only channel that receives every command sent to
    /// the service, plus the ingress receiver so tests can observe
    /// packet submission.
    ///
    /// The returned [`PlayoutHandle`] **does not** spawn a service task;
    /// it is backed by an unbounded channel whose receiver is returned
    /// alongside.  Tests use this to assert exact command sequences.
    #[cfg(test)]
    pub fn command_channel_for_tests(
        capacity: usize,
    ) -> (
        PlayoutHandle,
        tokio::sync::mpsc::UnboundedReceiver<PlayoutCommand>,
        super::ingress::IngressReceiver,
    ) {
        let (ingress_tx, ingress_rx) = super::ingress::packet_ingress_with_capacity(capacity);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let status = Arc::new(RwLock::new(SchedulerStatus {
            state: PlayoutState::Stopped,
            jitter: JitterDiagnostics::default(),
            diag: SchedulerDiagnostics::default(),
            queued_ms: 0,
            has_pending_block: false,
            pending_block_frames: 0,
            expected_sequence: 0,
            drift: None,
        }));
        let handle = PlayoutHandle {
            ingress: ingress_tx,
            cmd_tx,
            status,
            jitter_capacity_packets: SchedulerConfig::default().jitter_capacity_packets,
            start_watermark_ms: SchedulerConfig::default().start_watermark_ms,
        };
        (handle, cmd_rx, ingress_rx)
    }
}

/// Spawn a playout service that owns and drives a [`SchedulerCore`].
///
/// Production entry point.  Takes an [`AudioEngine`] and wraps it in
/// an [`AudioEngineSink`] internally.  Returns a cloneable
/// [`PlayoutHandle`] and the task's [`JoinHandle<()>`].
///
/// The handle provides packet submission and lifecycle commands; the
/// task serializes all decoder access, packet insertion, and PCM
/// production.
///
/// The task ticks every 2 ms (with [`MissedTickBehavior::Skip`]).  On
/// each packet arrival or tick it calls `process_ready` repeatedly
/// (bounded at 64 blocks), then `observe_fifo`, and publishes the
/// latest status.
///
/// When all [`IngressSender`] clones are dropped the task continues to
/// service commands and ticks until either a [`PlayoutCommand::Shutdown`]
/// is received or the command channel closes.
pub fn spawn_playout_service<D>(
    config: SchedulerConfig,
    decoder: D,
    audio_engine: AudioEngine,
) -> (PlayoutHandle, JoinHandle<()>)
where
    D: PacketDecoder + Send + 'static,
{
    let sink = AudioEngineSink::new(audio_engine);
    spawn_playout_service_with_sink(config, decoder, sink)
}

/// Spawn production playout with a clock that can release AP2 output against
/// the sender's network timeline.
pub fn spawn_playout_service_with_clock<D>(
    config: SchedulerConfig,
    decoder: D,
    audio_engine: AudioEngine,
    clock: Arc<dyn NetworkClock>,
) -> (PlayoutHandle, JoinHandle<()>)
where
    D: PacketDecoder + Send + 'static,
{
    let sink = AudioEngineSink::new(audio_engine);
    spawn_playout_service_with_sink_and_clock(config, decoder, sink, Some(clock))
}

/// Internal helper: spawn the playout service with an explicit
/// [`PcmSink`].  Used by production via [`spawn_playout_service`]
/// and by tests that substitute a fake sink.
fn spawn_playout_service_with_sink<D, S>(
    config: SchedulerConfig,
    decoder: D,
    sink: S,
) -> (PlayoutHandle, JoinHandle<()>)
where
    D: PacketDecoder + Send + 'static,
    S: PcmSink + Send + 'static,
{
    spawn_playout_service_with_sink_and_clock(config, decoder, sink, None)
}

fn spawn_playout_service_with_sink_and_clock<D, S>(
    config: SchedulerConfig,
    decoder: D,
    sink: S,
    clock: Option<Arc<dyn NetworkClock>>,
) -> (PlayoutHandle, JoinHandle<()>)
where
    D: PacketDecoder + Send + 'static,
    S: PcmSink + Send + 'static,
{
    let (ingress_tx, ingress_rx) = packet_ingress();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PlayoutCommand>();

    // Build the core once and snapshot its initial status (reflects
    // any prequeued data in the sink).
    let mut core = SchedulerCore::new(config.clone(), decoder, sink);
    if let Some(clock) = clock {
        core.set_network_clock(clock);
    }
    let initial_status = core.status();

    let status = Arc::new(RwLock::new(initial_status));

    let handle = PlayoutHandle {
        ingress: ingress_tx,
        cmd_tx,
        status: Arc::clone(&status),
        jitter_capacity_packets: config.jitter_capacity_packets,
        start_watermark_ms: config.start_watermark_ms,
    };

    let join_handle = tokio::spawn(playout_task(core, ingress_rx, cmd_rx, status));

    (handle, join_handle)
}

/// The main async task that owns and drives the scheduler.
async fn playout_task<D, S>(
    mut core: SchedulerCore<D, S>,
    mut ingress_rx: IngressReceiver,
    mut cmd_rx: mpsc::UnboundedReceiver<PlayoutCommand>,
    status: Arc<RwLock<SchedulerStatus>>,
) where
    D: PacketDecoder + Send + 'static,
    S: PcmSink + Send + 'static,
{
    let mut ticker = tokio::time::interval(Duration::from_millis(2));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Whether all ingress senders have been dropped.
    let mut ingress_closed = false;

    loop {
        // Process any pending commands first, then wait for either a
        // packet, a command, or the next tick.
        let tick_fut = ticker.tick();

        // ── jitter-buffer flow control ───────────────────────────
        //
        // When the jitter buffer has no free slot for another sequential
        // packet (total_occupied ≥ capacity), a new packet would be
        // inserted beyond the active window and trigger
        // InsertResult::ResyncRequired — resetting the entire pipeline.
        //
        // This condition arises during AP2 TCP bursts when the PCM sink
        // is backpressured: playout_task *must* stop consuming from the
        // bounded ingress channel so the existing sender-side
        // send().await can propagate TCP backpressure.  While throttled,
        // only commands and timer ticks are serviced — ticks drive
        // process_ready, which drains the jitter buffer as the PCM sink
        // frees capacity.
        //
        // The check is re-evaluated each loop iteration after
        // drive_scheduler has had a chance to drain, so polling
        // resumes as soon as a slot opens.
        let jitter_full = core.jitter.total_occupied() >= core.jitter.capacity();

        tokio::select! {
            biased;

            // ── commands (highest priority) ──────────────────────
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PlayoutCommand::Shutdown) | None => break,
                    Some(cmd) => {
                        apply_command(&mut core, cmd);
                        *status.write() = core.status();
                        continue; // re-loop to drain any queued commands
                    }
                }
            }

            // ── packets (throttled when jitter buffer is full) ───
            packet = ingress_rx.recv(), if !ingress_closed && !jitter_full => {
                match packet {
                    Some(pkt) => {
                        core.insert_packet(pkt);
                    }
                    None => {
                        // All senders dropped — stop polling the ingress.
                        ingress_closed = true;
                    }
                }
                // Fall through to tick processing below.
            }

            // ── tick ─────────────────────────────────────────────
            _ = tick_fut => {}
        }

        // After any event (packet or tick), drive the scheduler.
        drive_scheduler(&mut core, &status);
    }
}

/// Apply a single command to the scheduler core.
fn apply_command<D: PacketDecoder, S: PcmSink>(
    core: &mut SchedulerCore<D, S>,
    cmd: PlayoutCommand,
) {
    match cmd {
        PlayoutCommand::ConfigureStream(runtime) => core.configure_ap2_stream(runtime),
        PlayoutCommand::Record => core.record_ap2(),
        PlayoutCommand::ClearStream => core.clear_ap2_stream(),
        PlayoutCommand::SetTimeline(anchor) => core.set_timeline(anchor),
        PlayoutCommand::SetPlaybackRate(rate) => core.set_playback_rate(rate),
        PlayoutCommand::ClearTimeline => core.clear_timeline(),
        PlayoutCommand::FlushBuffered(range) => core.flush_buffered(range),
        PlayoutCommand::Start => core.start(),
        PlayoutCommand::Pause => core.pause(),
        PlayoutCommand::Resume => core.resume(),
        PlayoutCommand::Flush => core.flush(),
        PlayoutCommand::Stop => core.stop(),
        PlayoutCommand::Shutdown => {} // handled at the select level
    }
}

/// Drive `process_ready` (up to 64 blocks), then `observe_fifo`, then
/// publish the latest status.
fn drive_scheduler<D: PacketDecoder, S: PcmSink>(
    core: &mut SchedulerCore<D, S>,
    status: &Arc<RwLock<SchedulerStatus>>,
) {
    for _ in 0..64 {
        if core.process_ready(std::time::Instant::now()) == 0 {
            break;
        }
    }
    core.observe_fifo();
    core.update_drift();
    *status.write() = core.status();
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
        /// Optional shared log: each successful decode pushes the
        /// packet's extended sequence number (used by reorder tests).
        decode_log: Option<std::sync::Arc<std::sync::Mutex<Vec<u64>>>>,
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
                decode_log: None,
            }
        }

        fn with_decode_log(mut self, log: std::sync::Arc<std::sync::Mutex<Vec<u64>>>) -> Self {
            self.decode_log = Some(log);
            self
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
            if let Some(ref log) = self.decode_log {
                log.lock().unwrap().push(seq);
            }
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
        correction_ppm: f64,
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
                correction_ppm: 0.0,
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

        fn set_drift_correction_ppm(&mut self, ppm: f64) {
            self.correction_ppm = ppm;
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

    fn ap2_packet(seq: u64, rtp_timestamp: u32) -> TimedPacket {
        TimedPacket::new(
            super::super::packet::StreamProtocol::AirPlay2Buffered,
            seq,
            seq as u32,
            rtp_timestamp,
            0x1500_0000,
            Some(crate::codec::AudioFormat::Alac44100S16Stereo),
            bytes::Bytes::from_static(&[0; 16]),
            Instant::now(),
            false,
            0,
        )
    }

    #[derive(Clone)]
    struct FakeNetworkClock {
        state: Arc<std::sync::Mutex<FakeNetworkClockState>>,
    }

    #[derive(Clone, Copy)]
    struct FakeNetworkClockState {
        locked: bool,
        master_clock_id: Option<u64>,
        now_ns: u64,
        offset_ns: i64,
        uncertainty_ns: u64,
    }

    impl FakeNetworkClock {
        fn new(locked: bool, now_ns: u64) -> Self {
            Self {
                state: Arc::new(std::sync::Mutex::new(FakeNetworkClockState {
                    locked,
                    master_clock_id: locked.then_some(0x1234),
                    now_ns,
                    offset_ns: 0,
                    uncertainty_ns: 1_000_000,
                })),
            }
        }

        fn set_now(&self, now_ns: u64) {
            self.state.lock().unwrap().now_ns = now_ns;
        }

        fn set_locked(&self, locked: bool) {
            let mut state = self.state.lock().unwrap();
            state.locked = locked;
            state.master_clock_id = locked.then_some(0x1234);
        }

        fn set_master_clock_id(&self, master_clock_id: u64) {
            let mut state = self.state.lock().unwrap();
            state.locked = true;
            state.master_clock_id = Some(master_clock_id);
        }
    }

    impl NetworkClock for FakeNetworkClock {
        fn is_locked(&self) -> bool {
            self.state.lock().unwrap().locked
        }

        fn master_clock_id(&self) -> Option<u64> {
            self.state.lock().unwrap().master_clock_id
        }

        fn network_to_local_ns(&self, network_ns: u64) -> Option<u64> {
            let state = self.state.lock().unwrap();
            if !state.locked {
                return None;
            }
            Some(if state.offset_ns >= 0 {
                network_ns.saturating_add(state.offset_ns as u64)
            } else {
                network_ns.saturating_sub(state.offset_ns.unsigned_abs())
            })
        }

        fn local_now_ns(&self) -> u64 {
            self.state.lock().unwrap().now_ns
        }

        fn uncertainty_ns(&self) -> u64 {
            self.state.lock().unwrap().uncertainty_ns
        }
    }

    fn ap2_runtime(sample_rate: u32) -> Ap2StreamRuntime {
        Ap2StreamRuntime {
            stream_id: 7,
            stream_connection_id: Some(9),
            audio_format: crate::codec::AudioFormat::Alac44100S16Stereo,
            sample_rate,
            frames_per_packet: 1,
        }
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

    #[test]
    fn ap2_record_primes_but_waits_for_anchor_deadline() {
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let clock = FakeNetworkClock::new(true, 900_000_000);
        let mut sched = SchedulerCore::new(sched_test_config(), decoder, sink);
        sched.set_network_clock(Arc::new(clock.clone()));
        sched.configure_ap2_stream(ap2_runtime(1000));
        sched.record_ap2();
        sched.set_timeline(Ap2TimelineAnchor {
            timeline_id: 1,
            network_time_ns: 1_000_000_000,
            rtp_timestamp: 10,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });

        for (seq, rtp) in [(10, 10), (11, 11), (12, 12)] {
            assert_eq!(
                sched.insert_packet(ap2_packet(seq, rtp)),
                InsertResult::Accepted
            );
            assert_eq!(sched.process_ready(Instant::now()), 1);
        }
        assert_eq!(sched.status().queued_ms, 3);
        assert_eq!(sched.status().state, PlayoutState::Priming);
        assert!(!sched.sink().gate);

        clock.set_now(999_999_999);
        sched.observe_fifo();
        assert_eq!(sched.status().state, PlayoutState::Priming);
        assert!(!sched.sink().gate);

        clock.set_now(1_000_000_000);
        sched.observe_fifo();
        assert_eq!(sched.status().state, PlayoutState::Playing);
        assert!(sched.sink().gate);
    }

    #[test]
    fn ap2_ptp_lock_loss_closes_gate_and_reprimes() {
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let clock = FakeNetworkClock::new(true, 1_000_000_000);
        let mut sched = SchedulerCore::new(sched_test_config(), decoder, sink);
        sched.set_network_clock(Arc::new(clock.clone()));
        sched.configure_ap2_stream(ap2_runtime(1000));
        sched.record_ap2();
        sched.set_timeline(Ap2TimelineAnchor {
            timeline_id: 1,
            network_time_ns: 1_000_000_000,
            rtp_timestamp: 10,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });
        for (seq, rtp) in [(10, 10), (11, 11), (12, 12)] {
            sched.insert_packet(ap2_packet(seq, rtp));
            sched.process_ready(Instant::now());
        }
        assert_eq!(sched.status().state, PlayoutState::Playing);

        clock.set_locked(false);
        sched.observe_fifo();
        assert_eq!(sched.status().state, PlayoutState::Priming);
        assert!(!sched.sink().gate);
        assert_eq!(sched.status().diag.clock_lock_losses, 1);
    }

    fn playing_ap2_scheduler() -> (SchedulerCore<FakeDecoder, FakeSink>, FakeNetworkClock) {
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let clock = FakeNetworkClock::new(true, 1_000_000_000);
        let mut scheduler = SchedulerCore::new(sched_test_config(), decoder, sink);
        scheduler.set_network_clock(Arc::new(clock.clone()));
        scheduler.configure_ap2_stream(ap2_runtime(1000));
        scheduler.record_ap2();
        scheduler.set_timeline(Ap2TimelineAnchor {
            timeline_id: 1,
            network_time_ns: 1_000_000_000,
            rtp_timestamp: 10,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });
        for (sequence, timestamp) in [(10, 10), (11, 11), (12, 12)] {
            scheduler.insert_packet(ap2_packet(sequence, timestamp));
            scheduler.process_ready(Instant::now());
        }
        assert_eq!(scheduler.state(), PlayoutState::Playing);
        (scheduler, clock)
    }

    #[test]
    fn ap2_drift_controller_uses_fifo_and_timeline_tail_error() {
        let (mut scheduler, _clock) = playing_ap2_scheduler();
        scheduler.last_drift_update = Some(Instant::now() - Duration::from_secs(1));
        scheduler.update_drift();

        let diagnostics = scheduler.status().drift.expect("drift diagnostics");
        assert!(diagnostics.enabled);
        assert_eq!(diagnostics.fifo_error_ms, -1.0);
        assert!(diagnostics.timing_error_ns.abs() < 1.0);
        assert!(diagnostics.correction_ppm < 0.0);
        assert_eq!(scheduler.sink().correction_ppm, diagnostics.correction_ppm);

        scheduler.stop();
        assert_eq!(scheduler.sink().correction_ppm, 0.0);
        assert!(!scheduler.status().drift.unwrap().enabled);
    }

    #[test]
    fn ap2_drift_resets_and_reprimes_on_ptp_master_change() {
        let (mut scheduler, clock) = playing_ap2_scheduler();
        scheduler.last_drift_update = Some(Instant::now() - Duration::from_secs(1));
        scheduler.update_drift();
        assert_ne!(scheduler.sink().correction_ppm, 0.0);

        clock.set_master_clock_id(0x5678);
        scheduler.update_drift();
        assert_eq!(scheduler.state(), PlayoutState::Priming);
        assert_eq!(scheduler.sink().correction_ppm, 0.0);
        assert!(!scheduler.status().drift.unwrap().enabled);
    }

    #[test]
    fn ap2_large_timeline_error_hard_resyncs_complete_pipeline() {
        let (mut scheduler, clock) = playing_ap2_scheduler();
        scheduler.update_drift();
        let flushes_before = scheduler.sink().flush_count;

        clock.set_now(1_200_000_000);
        scheduler.last_drift_update = Some(Instant::now() - Duration::from_millis(200));
        scheduler.update_drift();

        let diagnostics = scheduler.status().drift.expect("drift diagnostics");
        assert_eq!(diagnostics.hard_resync_count, 1);
        assert_eq!(scheduler.state(), PlayoutState::Priming);
        assert_eq!(scheduler.sink().correction_ppm, 0.0);
        assert!(scheduler.sink().flush_count > flushes_before);
        assert_eq!(scheduler.status().diag.resync_count, 1);
        assert_eq!(scheduler.expected_sequence(), 0);
        assert!(scheduler.last_enqueued_ap2.is_none());
        assert!(scheduler.pending_hard_reanchor);
        assert!(scheduler.recovery_anchor.is_none());

        for (sequence, timestamp) in [(20, 20), (21, 21), (22, 22)] {
            assert_eq!(
                scheduler.insert_packet(ap2_packet(sequence, timestamp)),
                InsertResult::Accepted
            );
            assert_eq!(scheduler.process_ready(Instant::now()), 1);
        }

        let recovery = scheduler
            .recovery_anchor
            .expect("first packet after a hard resync must install a recovery anchor");
        assert_eq!(recovery.rtp_timestamp, 20);
        assert_eq!(recovery.local_time_ns, 1_203_000_000);
        assert!(!scheduler.pending_hard_reanchor);
        assert_eq!(scheduler.state(), PlayoutState::Priming);

        clock.set_now(recovery.local_time_ns);
        scheduler.observe_fifo();
        assert_eq!(scheduler.state(), PlayoutState::Playing);

        scheduler.last_drift_update = Some(Instant::now() - Duration::from_millis(200));
        scheduler.update_drift();
        assert_eq!(
            scheduler
                .status()
                .drift
                .expect("drift diagnostics")
                .hard_resync_count,
            1,
            "the recovery timeline must not immediately trigger another hard resync"
        );
    }

    #[test]
    fn sender_timeline_replaces_hard_resync_recovery_anchor() {
        let (mut scheduler, clock) = playing_ap2_scheduler();
        clock.set_now(1_200_000_000);
        scheduler.last_drift_update = Some(Instant::now() - Duration::from_millis(200));
        scheduler.update_drift();
        scheduler.insert_packet(ap2_packet(20, 20));
        assert!(scheduler.recovery_anchor.is_some());

        scheduler.set_timeline(Ap2TimelineAnchor {
            timeline_id: 2,
            network_time_ns: 1_300_000_000,
            rtp_timestamp: 30,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });

        assert!(scheduler.recovery_anchor.is_none());
        assert!(!scheduler.pending_hard_reanchor);
        assert_eq!(scheduler.timeline.unwrap().timeline_id, 2);
    }

    #[test]
    fn ap2_resume_anchor_discards_stale_pause_audio_without_hard_resync() {
        let (mut scheduler, clock) = playing_ap2_scheduler();
        scheduler.set_playback_rate(PlaybackRate::Paused);
        assert_eq!(scheduler.state(), PlayoutState::Paused);
        let flushes_before = scheduler.sink().flush_count;

        scheduler.set_timeline(Ap2TimelineAnchor {
            timeline_id: 1,
            network_time_ns: 1_000_000_000,
            rtp_timestamp: 100,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });

        assert_eq!(scheduler.state(), PlayoutState::Priming);
        assert!(scheduler.sink().flush_count > flushes_before);
        assert_eq!(scheduler.status().queued_ms, 0);
        assert_eq!(
            scheduler.insert_packet(ap2_packet(99, 99)),
            InsertResult::TooOld
        );
        assert_eq!(scheduler.status().diag.buffered_flush_drops, 1);

        for (sequence, timestamp) in [(100, 100), (101, 101), (102, 102)] {
            assert_eq!(
                scheduler.insert_packet(ap2_packet(sequence, timestamp)),
                InsertResult::Accepted
            );
            assert_eq!(scheduler.process_ready(Instant::now()), 1);
        }
        clock.set_now(1_000_000_000);
        scheduler.observe_fifo();
        assert_eq!(scheduler.state(), PlayoutState::Playing);

        scheduler.last_drift_update = Some(Instant::now() - Duration::from_millis(200));
        scheduler.update_drift();
        assert_eq!(scheduler.status().diag.resync_count, 0);
        assert_eq!(
            scheduler
                .status()
                .drift
                .expect("drift diagnostics")
                .hard_resync_count,
            0
        );
    }

    #[test]
    fn ap2_drift_updates_are_cadence_limited() {
        let (mut scheduler, clock) = playing_ap2_scheduler();
        scheduler.last_drift_update = Some(Instant::now() - Duration::from_millis(200));
        scheduler.update_drift();
        let applied_before = scheduler.sink().correction_ppm;
        let diagnostics_before = scheduler.status().drift.expect("drift diagnostics");

        // A scheduler event immediately after the prior update must not
        // restart the sink's resampler ramp.
        clock.set_now(1_050_000_000);
        scheduler.update_drift();

        assert_eq!(scheduler.sink().correction_ppm, applied_before);
        assert_eq!(
            scheduler.status().drift.expect("drift diagnostics"),
            diagnostics_before
        );
        assert_eq!(scheduler.status().diag.resync_count, 0);
    }

    #[test]
    fn ap2_drops_packet_beyond_deadline_tolerance() {
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let clock = FakeNetworkClock::new(true, 100_000_000);
        let mut sched = SchedulerCore::new(sched_test_config(), decoder, sink);
        sched.set_network_clock(Arc::new(clock));
        sched.configure_ap2_stream(ap2_runtime(1000));
        sched.record_ap2();
        sched.set_timeline(Ap2TimelineAnchor {
            timeline_id: 1,
            network_time_ns: 0,
            rtp_timestamp: 10,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });
        sched.insert_packet(ap2_packet(10, 10));

        assert_eq!(sched.process_ready(Instant::now()), 0);
        assert_eq!(sched.status().diag.late_packet_drops, 1);
        assert_eq!(sched.status().diag.late_catchup_events, 1);
        assert_eq!(sched.state(), PlayoutState::Priming);
        assert_eq!(sched.decoder().decode_count, 0);
    }

    #[test]
    fn ap2_bulk_late_catchup_flushes_old_pcm_once_and_reanchors_tail() {
        let (mut scheduler, clock) = playing_ap2_scheduler();
        let flushes_before = scheduler.sink().flush_count;
        assert_eq!(scheduler.status().queued_ms, 3);

        // At 1.050 s, RTP 13/14 are expired beyond the 21 ms tolerance,
        // while RTP 40 and later are still viable.
        clock.set_now(1_050_000_000);
        for (sequence, timestamp) in [(13, 13), (14, 14), (15, 40), (16, 41), (17, 42)] {
            assert_eq!(
                scheduler.insert_packet(ap2_packet(sequence, timestamp)),
                InsertResult::Accepted
            );
        }

        assert_eq!(scheduler.process_ready(Instant::now()), 1);
        assert_eq!(scheduler.status().diag.late_packet_drops, 2);
        assert_eq!(scheduler.status().diag.late_catchup_events, 1);
        assert_eq!(scheduler.sink().flush_count, flushes_before + 1);
        assert_eq!(scheduler.status().queued_ms, 1);
        assert_eq!(scheduler.last_enqueued_ap2, Some((40, 1)));

        assert_eq!(scheduler.process_ready(Instant::now()), 1);
        assert_eq!(scheduler.process_ready(Instant::now()), 1);
        assert_eq!(scheduler.state(), PlayoutState::Playing);
        assert_eq!(scheduler.status().queued_ms, 3);
        assert_eq!(scheduler.sink().flush_count, flushes_before + 1);
        assert_eq!(scheduler.last_enqueued_ap2, Some((42, 1)));

        scheduler.last_drift_update = Some(Instant::now() - Duration::from_millis(200));
        scheduler.update_drift();
        assert_eq!(scheduler.status().diag.resync_count, 0);
        assert_eq!(
            scheduler
                .status()
                .drift
                .expect("drift diagnostics")
                .hard_resync_count,
            0
        );
    }

    #[test]
    fn ap2_deadline_extends_rtp_across_wraparound() {
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let clock = FakeNetworkClock::new(true, 0);
        let mut sched = SchedulerCore::new(sched_test_config(), decoder, sink);
        sched.set_network_clock(Arc::new(clock));
        sched.timeline = Some(Ap2TimelineAnchor {
            timeline_id: 1,
            network_time_ns: 1_000_000_000,
            rtp_timestamp: u32::MAX - 10,
            sample_rate: 1000,
            rate: PlaybackRate::Normal,
        });

        assert_eq!(sched.packet_deadline_ns(5), Some(1_016_000_000));
    }

    #[test]
    fn reported_start_latency_uses_configured_watermark() {
        let (handle, _cmd_rx, _ingress_rx) = PlayoutHandle::command_channel_for_tests(8);
        let watermark_ms = SchedulerConfig::default().start_watermark_ms as u64;
        let expected_44k = ((44_100_u64 * watermark_ms) + 999) / 1_000;
        let expected_48k = ((48_000_u64 * watermark_ms) + 999) / 1_000;
        assert_eq!(handle.start_latency_frames(44_100), expected_44k as u32);
        assert_eq!(handle.start_latency_frames(48_000), expected_48k as u32);
    }

    #[test]
    fn ap2_immediate_flush_drops_through_boundary_and_retains_endpoint() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let decoder = FakeDecoder::new(1, 1000, 1).with_decode_log(Arc::clone(&log));
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(sched_test_config(), decoder, sink);
        sched.configure_ap2_stream(ap2_runtime(1000));
        sched.record_ap2();
        sched.flush_buffered(Ap2FlushRange {
            from_sequence: None,
            from_rtp_timestamp: None,
            until_sequence: 12,
            until_rtp_timestamp: 102,
        });
        sched.resume();

        for (seq, timestamp) in [(10, 100), (11, 101), (12, 102)] {
            assert_eq!(
                sched.insert_packet(ap2_packet(seq, timestamp)),
                InsertResult::Accepted
            );
        }
        assert_eq!(sched.process_ready(Instant::now()), 1);
        assert_eq!(&*log.lock().unwrap(), &[12]);
        assert_eq!(sched.status().diag.buffered_flush_drops, 2);
    }

    #[test]
    fn ap2_deferred_flush_preserves_pcm_and_discards_only_half_open_range() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let decoder = FakeDecoder::new(1, 1000, 1).with_decode_log(Arc::clone(&log));
        let sink = FakeSink::new();
        let mut sched = SchedulerCore::new(sched_test_config(), decoder, sink);
        sched.configure_ap2_stream(ap2_runtime(1000));
        sched.record_ap2();
        let flushes_before = sched.sink().flush_count;
        sched.flush_buffered(Ap2FlushRange {
            from_sequence: Some(11),
            from_rtp_timestamp: Some(101),
            until_sequence: 13,
            until_rtp_timestamp: 103,
        });
        assert_eq!(sched.sink().flush_count, flushes_before);
        sched.resume();

        for (seq, timestamp) in [(10, 100), (11, 101), (12, 102), (13, 103)] {
            assert_eq!(
                sched.insert_packet(ap2_packet(seq, timestamp)),
                InsertResult::Accepted
            );
        }
        assert_eq!(sched.process_ready(Instant::now()), 1);
        assert_eq!(sched.process_ready(Instant::now()), 1);
        assert_eq!(&*log.lock().unwrap(), &[10, 13]);
        assert_eq!(sched.status().diag.buffered_flush_drops, 2);
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
    fn audio_engine_sink_reuses_prepared_resampler_output_after_backpressure() {
        let (engine, mut consumer) = make_engine();
        engine.set_output_format(48_000, 2);
        engine.set_output_gate(true);

        let capacity_samples = engine.status().capacity_samples;
        let fill = vec![0.1f32; capacity_samples - 2];
        let (_, accepted) = engine.try_enqueue_output_frames_all_or_nothing(&fill, true);
        assert_eq!(accepted * 2, fill.len());

        let mut decoded = DecodedAudio {
            samples: vec![0.5f32; 1024 * 2],
            sample_rate: 44_100,
            channels: 2,
        };
        let mut sink = AudioEngineSink::new(engine);
        assert!(!sink.enqueue(&decoded, true).is_accepted());
        assert!(sink.pending_conversion.is_some());

        // Drain the original fill, then mutate the source. A retry must use
        // the already-prepared non-zero resampler output rather than advance
        // the stateful resampler over this block for a second time.
        let mut drain = vec![0.0; capacity_samples];
        consumer.fill_output(&mut drain);
        decoded.samples.fill(0.0);
        assert!(sink.enqueue(&decoded, true).is_accepted());
        assert!(sink.pending_conversion.is_none());

        let queued_samples = sink.engine().status().queued_samples;
        let mut retried_output = vec![0.0; queued_samples];
        consumer.fill_output(&mut retried_output);
        assert!(
            retried_output.iter().any(|sample| sample.abs() > 0.01),
            "retry unexpectedly resampled the mutated source block"
        );
    }

    #[test]
    fn audio_engine_sink_reports_sub_millisecond_queue_duration_exactly() {
        let (engine, _consumer) = make_engine();
        engine.set_output_format(48_000, 2);
        let decoded = DecodedAudio {
            samples: vec![0.25, -0.25],
            sample_rate: 48_000,
            channels: 2,
        };
        let mut sink = AudioEngineSink::new(engine);
        assert!(sink.enqueue(&decoded, true).is_accepted());
        assert_eq!(sink.queued_ms(), 0);
        assert_eq!(sink.queued_duration_ns(), 20_833);
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

    // ═══════════════════════════════════════════════════════════════
    // Playout-service async tests
    // ═══════════════════════════════════════════════════════════════

    /// A `Send` but `!Sync` decoder to verify that the service task
    /// does not require `Sync` — only exclusive `Send` ownership.
    struct NonSyncDecoder {
        _marker: std::cell::Cell<()>,
    }

    impl NonSyncDecoder {
        fn new() -> Self {
            Self {
                _marker: std::cell::Cell::new(()),
            }
        }
    }

    impl PacketDecoder for NonSyncDecoder {
        fn reset(&mut self) {}
        fn decode(&mut self, _packet: &TimedPacket) -> anyhow::Result<DecodedAudio> {
            Ok(DecodedAudio {
                samples: vec![0.0f32; 2],
                sample_rate: 44100,
                channels: 2,
            })
        }
        fn conceal_missing(
            &mut self,
            _expected_sequence: u64,
            _last_packet: Option<&TimedPacket>,
        ) -> anyhow::Result<DecodedAudio> {
            Ok(DecodedAudio {
                samples: vec![0.0f32; 2],
                sample_rate: 44100,
                channels: 2,
            })
        }
    }

    // Cell<()> is Send but not Sync — verifies the service only needs Send.

    /// Helper: spawn a real service and return the handle + a oneshot
    /// for the task result.
    async fn spawn_test_service() -> (PlayoutHandle, tokio::sync::oneshot::Receiver<()>) {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();

        let (handle, join_handle) = spawn_playout_service_with_sink(cfg, decoder, sink);

        // Wrap the JoinHandle into a oneshot for convenient test
        // checking.
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = join_handle.await;
            let _ = tx.send(());
        });

        // Give the service a tick to settle.
        tokio::time::sleep(Duration::from_millis(5)).await;
        (handle, rx)
    }

    // ── command lifecycle / status ───────────────────────────────

    #[tokio::test]
    async fn service_command_lifecycle() {
        let (handle, _rx) = spawn_test_service().await;

        // Initial state: Stopped.
        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Stopped);

        // Start → Priming.
        handle.start();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Priming);

        // Stop → Stopped.
        handle.stop();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Stopped);

        // Start again, then pause.
        handle.start();
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.pause();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Paused);

        // Resume.
        handle.resume();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = handle.status();
        assert!(matches!(
            s.state,
            PlayoutState::Priming | PlayoutState::Playing
        ));

        // Flush.
        handle.flush();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Priming);

        // Stop and shutdown.
        handle.stop();
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.shutdown();

        // Task should exit.
        let _ = _rx.await;
    }

    // ── AP1 try_send bounded / nonblocking ───────────────────────

    #[tokio::test]
    async fn ap1_try_send_bounded_nonblocking() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();

        // Create with a very small internal channel capacity.
        // We'll replace the default ingress with a custom one.
        let (ingress_tx, ingress_rx) = crate::playout::ingress::packet_ingress_with_capacity(2);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let status = Arc::new(RwLock::new(SchedulerStatus {
            state: PlayoutState::Stopped,
            jitter: Default::default(),
            diag: SchedulerDiagnostics::default(),
            queued_ms: 0,
            has_pending_block: false,
            pending_block_frames: 0,
            expected_sequence: 0,
            drift: None,
        }));

        let handle = PlayoutHandle {
            ingress: ingress_tx,
            cmd_tx,
            status: Arc::clone(&status),
            jitter_capacity_packets: cfg.jitter_capacity_packets,
            start_watermark_ms: cfg.start_watermark_ms,
        };

        let join_handle = {
            let core = SchedulerCore::new(cfg, decoder, sink);
            tokio::spawn(playout_task(core, ingress_rx, cmd_rx, status))
        };

        // Fill the 2-slot channel.
        let pkt = seq_packet(0);
        assert_eq!(
            handle.try_send_ap1(pkt.clone()),
            crate::playout::ingress::IngressResult::Accepted
        );
        assert_eq!(
            handle.try_send_ap1(pkt.clone()),
            crate::playout::ingress::IngressResult::Accepted
        );
        // Third send: channel is full.
        assert_eq!(
            handle.try_send_ap1(pkt.clone()),
            crate::playout::ingress::IngressResult::Full
        );

        // Let the service drain the channel.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Now there should be room again.
        let result = handle.try_send_ap1(pkt);
        assert_eq!(result, crate::playout::ingress::IngressResult::Accepted);

        handle.shutdown();
        let _ = join_handle.await;
    }

    // ── AP2 send backpressure ────────────────────────────────────

    #[tokio::test]
    async fn ap2_send_backpressure() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();

        let (ingress_tx, ingress_rx) = crate::playout::ingress::packet_ingress_with_capacity(1);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let status = Arc::new(RwLock::new(SchedulerStatus {
            state: PlayoutState::Stopped,
            jitter: Default::default(),
            diag: SchedulerDiagnostics::default(),
            queued_ms: 0,
            has_pending_block: false,
            pending_block_frames: 0,
            expected_sequence: 0,
            drift: None,
        }));

        let handle = PlayoutHandle {
            ingress: ingress_tx,
            cmd_tx,
            status: Arc::clone(&status),
            jitter_capacity_packets: cfg.jitter_capacity_packets,
            start_watermark_ms: cfg.start_watermark_ms,
        };

        // Fill the 1-slot channel before spawning the service so the
        // service hasn't started draining yet.
        let pkt = seq_packet(0);
        assert_eq!(
            handle.ingress.try_send(pkt.clone()),
            crate::playout::ingress::IngressResult::Accepted
        );

        // Spawn a task that tries to send — it should block because the
        // channel is full and the service hasn't been spawned yet.
        let handle2 = handle.clone();
        let pkt2 = seq_packet(1);
        let send_task = tokio::spawn(async move { handle2.send_ap2(pkt2).await });

        // The send should not complete within 10 ms.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !send_task.is_finished(),
            "send_ap2 should block when channel is full"
        );

        // Now spawn the service which will drain the channel.
        let join_handle = {
            let core = SchedulerCore::new(cfg, decoder, sink);
            tokio::spawn(playout_task(core, ingress_rx, cmd_rx, status))
        };

        // The send should now complete (service drains the slot).
        let result = tokio::time::timeout(Duration::from_secs(2), send_task).await;
        assert!(
            result.is_ok(),
            "send_ap2 should complete after service drains the channel"
        );
        let ingress_result = result.unwrap().unwrap();
        assert_eq!(
            ingress_result,
            crate::playout::ingress::IngressResult::Accepted
        );

        handle.shutdown();
        let _ = join_handle.await;
    }

    #[tokio::test]
    async fn ap2_send_returns_closed_when_receiver_dropped() {
        let (tx, rx) = crate::playout::ingress::packet_ingress_with_capacity(4);
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let status = Arc::new(RwLock::new(SchedulerStatus {
            state: PlayoutState::Stopped,
            jitter: Default::default(),
            diag: SchedulerDiagnostics::default(),
            queued_ms: 0,
            has_pending_block: false,
            pending_block_frames: 0,
            expected_sequence: 0,
            drift: None,
        }));
        let handle = PlayoutHandle {
            ingress: tx,
            cmd_tx,
            status,
            jitter_capacity_packets: SchedulerConfig::default().jitter_capacity_packets,
            start_watermark_ms: SchedulerConfig::default().start_watermark_ms,
        };

        // Drop the receiver so the channel is closed.
        drop(rx);

        let result = handle.send_ap2(seq_packet(0)).await;
        assert_eq!(result, crate::playout::ingress::IngressResult::Closed);
    }

    // ── Reordered packets decoded by service ─────────────────────

    #[tokio::test]
    async fn reordered_packets_decoded_in_order() {
        use std::sync::{Arc, Mutex};

        let cfg = sched_test_config();
        let decode_log = Arc::new(Mutex::new(Vec::new()));
        let decoder = FakeDecoder::new(1, 1000, 1).with_decode_log(Arc::clone(&decode_log));
        let mut sink = FakeSink::new();
        // Disable gate so we can observe the decoded output immediately.
        sink.gate = true;

        let (ingress_tx, ingress_rx) = crate::playout::ingress::packet_ingress_with_capacity(16);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let status = Arc::new(RwLock::new(SchedulerStatus {
            state: PlayoutState::Stopped,
            jitter: Default::default(),
            diag: SchedulerDiagnostics::default(),
            queued_ms: 0,
            has_pending_block: false,
            pending_block_frames: 0,
            expected_sequence: 0,
            drift: None,
        }));

        let handle = PlayoutHandle {
            ingress: ingress_tx,
            cmd_tx,
            status: Arc::clone(&status),
            jitter_capacity_packets: cfg.jitter_capacity_packets,
            start_watermark_ms: cfg.start_watermark_ms,
        };

        let join_handle = {
            let core = SchedulerCore::new(cfg.clone(), decoder, sink);
            tokio::spawn(playout_task(core, ingress_rx, cmd_rx, Arc::clone(&status)))
        };

        // Start the transport.
        handle.start();
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Insert packets 10, 12, 11 out of order.
        handle.try_send_ap1(seq_packet(10));
        handle.try_send_ap1(seq_packet(12));
        handle.try_send_ap1(seq_packet(11));

        // Give the service time to process.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify exact decode order: 10, 11, 12.
        {
            let log = decode_log.lock().unwrap();
            assert_eq!(
                *log,
                vec![10, 11, 12],
                "reordered packets must decode in sequence order"
            );
        } // drop MutexGuard before awaiting

        handle.shutdown();
        let _ = join_handle.await;
    }

    // ── Shutdown exits ───────────────────────────────────────────

    #[tokio::test]
    async fn shutdown_exits_service() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();
        let (handle, join_handle) = spawn_playout_service_with_sink(cfg, decoder, sink);

        // Verify the task is running (status is accessible).
        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Stopped);

        handle.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(2), join_handle).await;
        assert!(result.is_ok(), "service task should exit after shutdown");
    }

    // ── Non-Sync decoder is accepted ─────────────────────────────

    #[tokio::test]
    async fn non_sync_decoder_accepted_by_service() {
        let cfg = sched_test_config();
        let decoder = NonSyncDecoder::new();
        let sink = FakeSink::new();
        let (handle, join_handle) = spawn_playout_service_with_sink(cfg, decoder, sink);

        let s = handle.status();
        assert_eq!(s.state, PlayoutState::Stopped);

        handle.shutdown();
        let _ = join_handle.await;
    }

    // ── All ingress senders close, service continues command handling ─

    /// Verify the task remains alive and responsive to commands after
    /// every ingress sender is dropped, and only exits on Shutdown.
    #[tokio::test]
    async fn service_continues_after_ingress_senders_close() {
        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = FakeSink::new();

        // Construct channels directly so we can drop the ingress
        // sender independently of the command channel.
        let (ingress_tx, ingress_rx) = packet_ingress();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PlayoutCommand>();

        // Build the core once and snapshot initial status.
        let core = SchedulerCore::new(cfg, decoder, sink);
        let initial_status = core.status();
        let status = Arc::new(RwLock::new(initial_status));

        let join_handle = tokio::spawn(playout_task(core, ingress_rx, cmd_rx, status.clone()));

        // Drop the only ingress sender — task must stay alive.
        drop(ingress_tx);
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Send Start through cmd_tx — task must process it.
        let _ = cmd_tx.send(PlayoutCommand::Start);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = status.read().clone();
        assert_eq!(
            s.state,
            PlayoutState::Priming,
            "task must transition to Priming after Start even with no ingress senders"
        );

        // Send Stop — task must process it.
        let _ = cmd_tx.send(PlayoutCommand::Stop);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s = status.read().clone();
        assert_eq!(
            s.state,
            PlayoutState::Stopped,
            "task must transition to Stopped after Stop even with no ingress senders"
        );

        // Task must still be alive (not exited).
        assert!(
            !join_handle.is_finished(),
            "task must remain alive after ingress senders close"
        );

        // Shutdown must exit the task cleanly.
        let _ = cmd_tx.send(PlayoutCommand::Shutdown);
        let result = tokio::time::timeout(Duration::from_secs(2), join_handle).await;
        assert!(result.is_ok(), "service task should exit after Shutdown");
    }

    // ── Initial status from prequeued AudioEngine data ──────────

    #[tokio::test]
    async fn initial_status_reflects_prequeued_audio_engine_data() {
        use crate::audio::AudioEngine;

        let cfg = sched_test_config();
        let decoder = FakeDecoder::new(352, 44100, 2);

        // Create an AudioEngine with some prequeued data.
        let (engine, _consumer) = AudioEngine::new(32_768);
        engine.set_output_format(44100, 2);
        let prequeued = vec![0.25f32; 44100 * 2 / 10]; // 100 ms of stereo 44.1 kHz
        let (_, accepted) = engine.try_enqueue_output_frames_all_or_nothing(&prequeued, true);
        assert!(accepted > 0, "prequeued data must be accepted");

        let (handle, join_handle) = spawn_playout_service(cfg, decoder, engine);

        // Initial status must reflect the prequeued ms.
        let s = handle.status();
        assert!(
            s.queued_ms > 0,
            "initial queued_ms must reflect prequeued AudioEngine data, got {}",
            s.queued_ms
        );
        assert_eq!(s.state, PlayoutState::Stopped);

        handle.shutdown();
        let _ = join_handle.await;
    }

    // ═══════════════════════════════════════════════════════════════
    // Jitter-buffer flow-control regression tests
    // ═══════════════════════════════════════════════════════════════

    /// A sink with a fixed frame capacity that rejects enqueues once
    /// `queued_frames >= capacity`.  Supports `consume_frames(n)` to
    /// simulate PCM drain.
    ///
    /// INVARIANT: `queued_frames` never exceeds `capacity_frames`.
    struct CapacityBoundedSink {
        queued_frames: usize,
        capacity_frames: usize,
        gate: bool,
        flush_count: usize,
        actions: Vec<FakeSinkAction>,
    }

    impl CapacityBoundedSink {
        fn with_capacity(frames: usize) -> Self {
            Self {
                queued_frames: 0,
                capacity_frames: frames,
                gate: false,
                flush_count: 0,
                actions: Vec::new(),
            }
        }

        /// Simulate the PCM sink draining `n` frames.
        fn consume_frames(&mut self, n: usize) {
            self.queued_frames = self.queued_frames.saturating_sub(n);
        }
    }

    impl PcmSink for CapacityBoundedSink {
        fn queued_ms(&self) -> u64 {
            // At 1000 Hz, each frame ≈ 1 ms (matching FakeDecoder).
            self.queued_frames as u64
        }

        fn set_output_gate(&mut self, enabled: bool) {
            self.actions.push(FakeSinkAction::Gate(enabled));
            self.gate = enabled;
        }

        fn request_flush(&mut self) {
            self.actions.push(FakeSinkAction::Flush);
            self.flush_count += 1;
            self.queued_frames = 0;
        }

        fn enqueue(&mut self, decoded: &DecodedAudio, _unchecked: bool) -> PcmWriteResult {
            let frames = decoded.frames();
            if frames == 0 {
                return PcmWriteResult::all_accepted(0);
            }
            let new_total = self.queued_frames.saturating_add(frames);
            if new_total > self.capacity_frames {
                return PcmWriteResult::all_rejected(frames);
            }
            self.queued_frames = new_total;
            PcmWriteResult::all_accepted(frames)
        }
    }

    /// Helper: spawn a service with a small jitter capacity and a
    /// frame-bounded sink for flow-control tests, returning the handle
    /// plus a shared reference to the sink so the test can release frames.
    fn spawn_flow_control_service(
        jitter_capacity: usize,
        sink_capacity_frames: usize,
    ) -> (
        PlayoutHandle,
        tokio::sync::oneshot::Receiver<()>,
        Arc<std::sync::Mutex<CapacityBoundedSink>>,
    ) {
        let cfg = SchedulerConfig {
            start_watermark_ms: 3,
            low_watermark_ms: 1,
            target_watermark_ms: 2,
            jitter_capacity_packets: jitter_capacity,
            reorder_grace_ms: 100,
        };
        let decoder = FakeDecoder::new(1, 1000, 1);
        let sink = CapacityBoundedSink::with_capacity(sink_capacity_frames);
        let sink_shared = Arc::new(std::sync::Mutex::new(sink));

        // We use spawn_playout_service_with_sink which takes ownership.
        // To get shared access we use the same pattern as existing tests:
        // build the channels manually and wrap the sink in an Arc<Mutex<>>.
        let (ingress_tx, ingress_rx) = packet_ingress();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PlayoutCommand>();

        let sink_for_core = /* clone the Arc */ {
            // We need a PcmSink that delegates through the Arc<Mutex>.
            // Since PcmSink takes &mut self, we wrap it.
            struct ArcSink(Arc<std::sync::Mutex<CapacityBoundedSink>>);
            impl PcmSink for ArcSink {
                fn queued_ms(&self) -> u64 {
                    self.0.lock().unwrap().queued_ms()
                }
                fn set_output_gate(&mut self, enabled: bool) {
                    self.0.lock().unwrap().set_output_gate(enabled);
                }
                fn request_flush(&mut self) {
                    self.0.lock().unwrap().request_flush();
                }
                fn enqueue(&mut self, decoded: &DecodedAudio, unchecked: bool) -> PcmWriteResult {
                    self.0.lock().unwrap().enqueue(decoded, unchecked)
                }
            }
            ArcSink(Arc::clone(&sink_shared))
        };

        let core = SchedulerCore::new(cfg, decoder, sink_for_core);
        let initial_status = core.status();
        let status = Arc::new(RwLock::new(initial_status));

        let handle = PlayoutHandle {
            ingress: ingress_tx,
            cmd_tx,
            status: Arc::clone(&status),
            jitter_capacity_packets: jitter_capacity,
            start_watermark_ms: 3,
        };

        let join_handle = tokio::spawn(playout_task(core, ingress_rx, cmd_rx, status));

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = join_handle.await;
            let _ = tx.send(());
        });

        (handle, rx, sink_shared)
    }

    /// Sequential burst at AP2 line rate, exceeding combined ingress +
    /// jitter capacity with a backpressured sink.  The flow-control
    /// guard must prevent ResyncRequired and preserve packet order.
    #[tokio::test]
    async fn burst_with_backpressure_no_resync() {
        // Small jitter (8) so we can overflow it with a modest burst.
        // Sink accepts only 3 frames, then rejects.
        let (handle, mut _rx, sink) = spawn_flow_control_service(8, 3);

        // Start → Priming.
        handle.start();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let initial_resyncs = handle.status().diag.resync_count;
        let initial_inserted = handle.status().diag.insert_accepted;

        // Send a sequential burst of 20 packets (far exceeding jitter=8).
        let packets: Vec<_> = (0u64..20).map(seq_packet).collect();
        for pkt in &packets {
            // Use send_ap2 (async, backpressure-aware) so the test
            // doesn't drop packets on a full ingress channel.
            let result = handle.send_ap2(pkt.clone()).await;
            assert_eq!(
                result,
                crate::playout::ingress::IngressResult::Accepted,
                "send_ap2 must accept packet seq {}",
                pkt.extended_sequence
            );
        }

        // Let the service process for a bit — with flow control, the
        // burst should drain through the jitter buffer without resyncing.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let after_burst = handle.status();

        // The flow-control guard must prevent ResyncRequired.
        assert_eq!(
            after_burst.diag.resync_count, initial_resyncs,
            "no resyncs should occur during a normal sequential burst, \
             even with a full sink — flow control must throttle ingress \
             instead of letting the jitter window overflow"
        );

        // At least one packet must have been inserted (the seed).
        assert!(
            after_burst.diag.insert_accepted > initial_inserted,
            "packets must be inserted into jitter"
        );

        // Now drain the sink in steps, freeing jitter slots so flow
        // control can resume ingress polling and move remaining packets
        // through the pipeline.
        let mut prev_inserted = after_burst.diag.insert_accepted;
        for step in 0..8 {
            {
                let mut s = sink.lock().unwrap();
                s.consume_frames(10); // drain well below capacity
            }
            tokio::time::sleep(Duration::from_millis(30)).await;

            let s = handle.status();
            assert_eq!(
                s.diag.resync_count, initial_resyncs,
                "no resync after drain step {}",
                step
            );
            assert!(
                s.diag.insert_accepted >= prev_inserted,
                "insert_accepted must not regress (step {})",
                step
            );
            prev_inserted = s.diag.insert_accepted;

            if prev_inserted >= 20 {
                break;
            }
        }

        // All 20 packets should have been inserted.
        assert!(
            prev_inserted >= 20,
            "all 20 packets must eventually be inserted, got {} after {} drain steps",
            prev_inserted,
            8
        );

        handle.shutdown();
        // Wait for task to finish.
        let _ = _rx.await;
    }

    /// A far-ahead sequential gap (beyond the active window) must still
    /// trigger ResyncRequired — the flow-control guard only prevents
    /// ingestion when the jitter buffer is *full from sequential traffic*,
    /// not when a genuine discontinuity arrives.
    #[tokio::test]
    async fn far_ahead_discontinuity_triggers_resync() {
        let (handle, mut _rx, _sink) = spawn_flow_control_service(8, 100);

        // Start → Priming.
        handle.start();
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Insert initial sequential packets to seed the jitter window.
        for seq in 0u64..4 {
            let result = handle.send_ap2(seq_packet(seq)).await;
            assert_eq!(result, crate::playout::ingress::IngressResult::Accepted);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let initial_accepted = handle.status().diag.insert_accepted;

        // Send a packet far beyond the active window (seq 1000, jitter
        // capacity is 8, so the window is [expected, expected+8)).
        // This is a genuine discontinuity and MUST trigger ResyncRequired.
        let result = handle.send_ap2(seq_packet(1000)).await;
        assert_eq!(result, crate::playout::ingress::IngressResult::Accepted);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let after = handle.status();

        // A resync must have occurred.
        assert!(
            after.diag.resync_count > 0,
            "a far-ahead discontinuity must trigger ResyncRequired"
        );

        // The resync resets the jitter, so the total inserted should be
        // only the initial packets + the resync re-insertion.
        // After resync, the far-ahead packet becomes the new seed.
        // So insert_accepted might be at most initial_accepted + 2
        // (the resync re-inserts the far-ahead packet).
        assert!(
            after.diag.insert_accepted > initial_accepted,
            "the far-ahead packet must be inserted (possibly after resync)"
        );

        // Verify the pipeline is back in a valid state.
        assert!(
            matches!(after.state, PlayoutState::Priming | PlayoutState::Playing),
            "after resync the pipeline must be in a valid active state, got {:?}",
            after.state
        );

        handle.shutdown();
        let _ = _rx.await;
    }

    /// Sequential burst into a full sink with gradually released
    /// capacity: prove that flow control unblocks and remaining packets
    /// are delivered in order without resyncs.
    #[tokio::test]
    async fn burst_recovers_after_sink_drains() {
        let (handle, mut _rx, sink) = spawn_flow_control_service(8, 2);

        handle.start();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let initial_resyncs = handle.status().diag.resync_count;

        // Send 12 sequential packets (more than jitter=8).
        for seq in 0u64..12 {
            let result = handle.send_ap2(seq_packet(seq)).await;
            assert_eq!(result, crate::playout::ingress::IngressResult::Accepted);
        }

        // Wait a bit — flow control should throttle after jitter fills.
        tokio::time::sleep(Duration::from_millis(30)).await;

        // No resyncs so far.
        assert_eq!(
            handle.status().diag.resync_count,
            initial_resyncs,
            "no resync during burst with full sink"
        );

        // Gradually drain the sink in steps.
        let mut total_accepted_before = 0u64;
        for step in 0..5 {
            {
                let mut s = sink.lock().unwrap();
                s.consume_frames(3);
            }
            tokio::time::sleep(Duration::from_millis(30)).await;

            let s = handle.status();
            assert_eq!(
                s.diag.resync_count, initial_resyncs,
                "no resync after drain step {}",
                step
            );
            // insert_accepted should increase monotonically.
            assert!(
                s.diag.insert_accepted >= total_accepted_before,
                "insert_accepted must not regress (step {})",
                step
            );
            total_accepted_before = s.diag.insert_accepted;
        }

        // Eventually all packets are processed.
        let final_status = handle.status();
        assert!(
            final_status.diag.insert_accepted >= 12,
            "all 12 packets eventually inserted, got {}",
            final_status.diag.insert_accepted
        );

        handle.shutdown();
        let _ = _rx.await;
    }
}
