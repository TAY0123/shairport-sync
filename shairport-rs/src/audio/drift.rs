//! Bounded PI control for AirPlay 2 sender-clock versus local-DAC drift.
//!
//! The controller combines PCM FIFO error with a smaller presentation-timeline
//! error term. Its output is an output/input resampling-ratio adjustment in
//! parts per million. Positive correction produces more output frames per
//! source frame, increasing queued duration; negative correction produces
//! fewer frames.

/// Normal correction is intentionally limited to ±300 ppm.
const DEFAULT_MAX_CORRECTION_PPM: f64 = 300.0;
/// A timeline discontinuity this large is not clock drift and needs a resync.
const HARD_RESYNC_THRESHOLD_NS: f64 = 100_000_000.0;
/// Proportional FIFO gain in ppm per millisecond.
const DEFAULT_FIFO_KP: f64 = 2.0;
/// Integral gain in ppm per millisecond-second.
const DEFAULT_KI: f64 = 0.05;
/// Presentation error gain in ppm per millisecond.
const DEFAULT_TIMING_KP: f64 = 0.25;
/// Prevent the timing term from reacting aggressively to ordinary jitter.
const TIMING_ERROR_CLAMP_MS: f64 = 20.0;

/// Point-in-time drift-controller diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DriftDiagnostics {
    pub correction_ppm: f64,
    /// `target_fifo_ms - actual_fifo_ms`; positive means the FIFO is low.
    pub fifo_error_ms: f64,
    /// Scheduled PCM-tail time minus predicted local PCM-tail time.
    pub timing_error_ns: f64,
    pub saturated: bool,
    pub saturation_count: u64,
    pub hard_resync_count: u64,
    pub enabled: bool,
}

/// Deterministic bounded PI controller.
///
/// The caller supplies elapsed time, so behavior does not depend on scheduler
/// tick frequency and tests do not depend on wall-clock sleeps.
#[derive(Clone, Debug)]
pub struct DriftController {
    target_fifo_ms: u64,
    max_correction_ppm: f64,
    fifo_kp: f64,
    timing_kp: f64,
    ki: f64,
    integral_ppm: f64,
    correction_ppm: f64,
    fifo_error_ms: f64,
    timing_error_ns: f64,
    saturation_count: u64,
    hard_resync_count: u64,
    enabled: bool,
}

impl DriftController {
    pub fn new(target_fifo_ms: u64) -> Self {
        Self {
            target_fifo_ms,
            max_correction_ppm: DEFAULT_MAX_CORRECTION_PPM,
            fifo_kp: DEFAULT_FIFO_KP,
            timing_kp: DEFAULT_TIMING_KP,
            ki: DEFAULT_KI,
            integral_ppm: 0.0,
            correction_ppm: 0.0,
            fifo_error_ms: 0.0,
            timing_error_ns: 0.0,
            saturation_count: 0,
            hard_resync_count: 0,
            enabled: false,
        }
    }

    #[cfg(test)]
    fn with_params(
        target_fifo_ms: u64,
        max_correction_ppm: f64,
        fifo_kp: f64,
        timing_kp: f64,
        ki: f64,
    ) -> Self {
        Self {
            max_correction_ppm,
            fifo_kp,
            timing_kp,
            ki,
            ..Self::new(target_fifo_ms)
        }
    }

    pub fn enable(&mut self) {
        if !self.enabled {
            self.enabled = true;
            self.reset_state();
        }
    }

    pub fn disable(&mut self) {
        self.enabled = false;
        self.reset_state();
    }

    /// Reset control history while preserving cumulative event counters.
    pub fn reset(&mut self) {
        self.reset_state();
    }

    fn reset_state(&mut self) {
        self.integral_ppm = 0.0;
        self.correction_ppm = 0.0;
        self.fifo_error_ms = 0.0;
        self.timing_error_ns = 0.0;
    }

    /// Return `None` when a discontinuity requires a hard scheduler resync.
    pub fn update(
        &mut self,
        fifo_queued_ms: u64,
        timing_error_ns: f64,
        clock_locked: bool,
        elapsed_seconds: f64,
    ) -> Option<f64> {
        if !self.enabled || !clock_locked {
            self.reset_state();
            return Some(0.0);
        }

        self.fifo_error_ms = self.target_fifo_ms as f64 - fifo_queued_ms as f64;
        self.timing_error_ns = timing_error_ns;

        if !timing_error_ns.is_finite() || timing_error_ns.abs() > HARD_RESYNC_THRESHOLD_NS {
            self.hard_resync_count = self.hard_resync_count.saturating_add(1);
            self.reset_state();
            return None;
        }

        let timing_error_ms =
            (timing_error_ns / 1_000_000.0).clamp(-TIMING_ERROR_CLAMP_MS, TIMING_ERROR_CLAMP_MS);
        let dt = elapsed_seconds.clamp(0.0, 1.0);
        let combined_error_ms = self.fifo_error_ms + timing_error_ms * 0.25;
        self.integral_ppm += combined_error_ms * dt * self.ki;
        self.integral_ppm = self
            .integral_ppm
            .clamp(-self.max_correction_ppm, self.max_correction_ppm);

        let raw = self.fifo_error_ms * self.fifo_kp
            + timing_error_ms * self.timing_kp
            + self.integral_ppm;
        let correction = raw.clamp(-self.max_correction_ppm, self.max_correction_ppm);
        if (raw - correction).abs() > f64::EPSILON {
            self.saturation_count = self.saturation_count.saturating_add(1);
        }
        self.correction_ppm = correction;
        Some(correction)
    }

    pub fn diagnostics(&self) -> DriftDiagnostics {
        DriftDiagnostics {
            correction_ppm: self.correction_ppm,
            fifo_error_ms: self.fifo_error_ms,
            timing_error_ns: self.timing_error_ns,
            saturated: self.correction_ppm.abs() >= self.max_correction_ppm - 1e-6,
            saturation_count: self.saturation_count,
            hard_resync_count: self.hard_resync_count,
            enabled: self.enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> DriftController {
        DriftController::with_params(80, 300.0, 2.0, 0.25, 0.05)
    }

    #[test]
    fn disabled_or_unlocked_returns_zero() {
        let mut controller = controller();
        assert_eq!(controller.update(60, 0.0, true, 0.01), Some(0.0));
        controller.enable();
        assert_eq!(controller.update(60, 0.0, false, 0.01), Some(0.0));
    }

    #[test]
    fn fifo_error_has_correct_direction() {
        let mut controller = controller();
        controller.enable();
        assert!(controller.update(60, 0.0, true, 0.01).unwrap() > 0.0);
        controller.reset();
        assert!(controller.update(100, 0.0, true, 0.01).unwrap() < 0.0);
    }

    #[test]
    fn timeline_error_contributes_in_correct_direction() {
        let mut controller = controller();
        controller.enable();
        assert!(controller.update(80, 10_000_000.0, true, 0.01).unwrap() > 0.0);
        controller.reset();
        assert!(controller.update(80, -10_000_000.0, true, 0.01).unwrap() < 0.0);
    }

    #[test]
    fn integral_is_elapsed_time_based() {
        let mut fast_ticks = controller();
        let mut slow_ticks = controller();
        fast_ticks.enable();
        slow_ticks.enable();
        for _ in 0..100 {
            fast_ticks.update(70, 0.0, true, 0.01);
        }
        for _ in 0..10 {
            slow_ticks.update(70, 0.0, true, 0.1);
        }
        let a = fast_ticks.diagnostics().correction_ppm;
        let b = slow_ticks.diagnostics().correction_ppm;
        assert!((a - b).abs() < 1e-9, "{a} != {b}");
    }

    #[test]
    fn correction_is_clamped_and_saturation_counted() {
        let mut controller = DriftController::with_params(80, 50.0, 10.0, 1.0, 1.0);
        controller.enable();
        assert_eq!(controller.update(0, 0.0, true, 1.0), Some(50.0));
        let diagnostics = controller.diagnostics();
        assert!(diagnostics.saturated);
        assert_eq!(diagnostics.saturation_count, 1);
    }

    #[test]
    fn large_timeline_discontinuity_requests_hard_resync() {
        let mut controller = controller();
        controller.enable();
        assert_eq!(controller.update(80, 150_000_000.0, true, 0.01), None);
        let diagnostics = controller.diagnostics();
        assert_eq!(diagnostics.hard_resync_count, 1);
        assert_eq!(diagnostics.correction_ppm, 0.0);
    }

    #[test]
    fn reset_and_disable_zero_control_state_but_keep_counters() {
        let mut controller = DriftController::with_params(80, 10.0, 10.0, 1.0, 1.0);
        controller.enable();
        controller.update(0, 0.0, true, 1.0);
        controller.reset();
        assert_eq!(controller.diagnostics().correction_ppm, 0.0);
        assert_eq!(controller.diagnostics().saturation_count, 1);
        controller.disable();
        assert!(!controller.diagnostics().enabled);
    }

    #[test]
    fn sustained_small_error_remains_bounded() {
        let mut controller = controller();
        controller.enable();
        for _ in 0..36_000 {
            let ppm = controller.update(79, 0.0, true, 0.1).unwrap();
            assert!(ppm.abs() <= 300.0);
        }
    }

    #[test]
    fn six_hour_closed_loop_fifo_stays_bounded_for_clock_drift_in_both_directions() {
        const TARGET_MS: f64 = 80.0;
        const DT_SECONDS: f64 = 0.1;
        const SIX_HOURS_IN_TICKS: usize = 6 * 60 * 60 * 10;

        for sender_drift_ppm in [-150.0, 150.0] {
            let mut controller = controller();
            controller.enable();
            let mut queued_ms = TARGET_MS;
            let mut minimum_ms = queued_ms;
            let mut maximum_ms = queued_ms;

            for _ in 0..SIX_HOURS_IN_TICKS {
                let observed_ms = queued_ms.max(0.0).floor() as u64;
                let correction_ppm = controller
                    .update(observed_ms, 0.0, true, DT_SECONDS)
                    .expect("ordinary clock drift must not request a hard resync");

                // One ppm sustained for one second changes FIFO duration by
                // one microsecond, or 0.001 ms. Sender and resampler rates
                // therefore add in this closed-loop queue model.
                queued_ms += (sender_drift_ppm + correction_ppm) * DT_SECONDS / 1_000.0;
                minimum_ms = minimum_ms.min(queued_ms);
                maximum_ms = maximum_ms.max(queued_ms);
            }

            let diagnostics = controller.diagnostics();
            assert_eq!(diagnostics.hard_resync_count, 0);
            assert_eq!(diagnostics.saturation_count, 0);
            assert!(
                minimum_ms >= 60.0 && maximum_ms <= 100.0,
                "{sender_drift_ppm} ppm escaped FIFO bounds: {minimum_ms}..{maximum_ms} ms"
            );
            assert!(
                (queued_ms - TARGET_MS).abs() <= 1.1,
                "{sender_drift_ppm} ppm did not settle near target: {queued_ms} ms"
            );
            assert!(
                (diagnostics.correction_ppm + sender_drift_ppm).abs() <= 0.1,
                "controller did not cancel {sender_drift_ppm} ppm: {} ppm",
                diagnostics.correction_ppm
            );
        }
    }
}
