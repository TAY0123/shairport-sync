//! Pure watermark state machine for the audio playout pipeline.
//!
//! [`WatermarkController`] tracks the playout lifecycle —
//! priming, steady-state playback, rebuffering, pause/resume, and stop —
//! and emits discrete output-gate and flush actions.  It contains no
//! decoder, jitter-buffer, or I/O logic; the caller feeds it the
//! current FIFO fill level (in milliseconds) via [`observe_fifo`] and
//! applies the returned actions.
//!
//! [`observe_fifo`]: WatermarkController::observe_fifo

use crate::config::AudioConfig;

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
}
