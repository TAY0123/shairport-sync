//! AirPlay 2 session-phase state machine.
//!
//! Tracks the logical lifecycle of an AP2 session from idle through pairing,
//! stream setup, playback, and teardown.  The [`Ap2SessionPhase`] enum
//! captures each distinct phase; [`validate_transition`] enforces valid
//! ordering without side-effects.
//!
//! # Phase diagram
//!
//! ```text
//! Idle ──▶ Paired ──▶ Configured ──▶ StreamSetup ──▶ Recording
//!                                                    │
//!                                          ┌─────────┼─────────┐
//!                                          ▼         ▼         ▼
//!                                        Paused   Flushed   Teardown
//!                                          │         │         │
//!                                          └────┬────┘         │
//!                                               ▼              │
//!                                          Recording ◀─────────┘
//!                                          (via SETRATEANCHORTIME rate=1)
//!                                          or Idle (session TEARDOWN)
//! ```
//!
//! All transitions are validated as pure functions — the caller decides
//! whether to apply the transition to its own state.

use std::fmt;

/// Logical phase of an AirPlay 2 session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ap2SessionPhase {
    /// No session established.
    Idle,
    /// Pair-verify completed; shared secret and ciphers active.
    Paired,
    /// Configuration received (`/configure`, `/fp-setup`, `/audioMode`).
    Configured,
    /// At least one SETUP has been processed (stream ports open).
    StreamSetup,
    /// RECORD or SETRATEANCHORTIME with rate=1 — audio is playing.
    Recording,
    /// PAUSE — audio paused but session alive.
    Paused,
    /// FLUSHBUFFERED — audio flushed and paused.
    Flushed,
    /// TEARDOWN (session) — session fully torn down.
    Teardown,
}

impl Ap2SessionPhase {
    /// Human-readable label for the phase.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Paired => "paired",
            Self::Configured => "configured",
            Self::StreamSetup => "stream-setup",
            Self::Recording => "recording",
            Self::Paused => "paused",
            Self::Flushed => "flushed",
            Self::Teardown => "teardown",
        }
    }
}

impl fmt::Display for Ap2SessionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when a requested phase transition is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionError {
    pub from: Ap2SessionPhase,
    pub to: Ap2SessionPhase,
    pub reason: &'static str,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid transition from {} to {}: {}",
            self.from.name(),
            self.to.name(),
            self.reason
        )
    }
}

/// Validate a session-phase transition.
///
/// Returns `Ok(())` if the transition is legal; otherwise returns a
/// [`TransitionError`] describing why.
///
/// # Allowed transitions
///
/// | From          | To             | Trigger                          |
/// |---------------|----------------|----------------------------------|
/// | Idle          | Paired         | pair-verify success              |
/// | Paired        | Configured     | /configure, /fp-setup, /audioMode|
/// | Paired        | Idle           | TEARDOWN (session)               |
/// | Configured    | StreamSetup    | SETUP (first stream)             |
/// | Configured    | Idle           | TEARDOWN (session)               |
/// | StreamSetup   | Recording      | RECORD, SETRATEANCHORTIME rate=1 |
/// | StreamSetup   | Idle           | TEARDOWN (session)               |
/// | Recording     | Paused         | PAUSE                            |
/// | Recording     | Flushed        | FLUSHBUFFERED                    |
/// | Recording     | Idle           | TEARDOWN (session)               |
/// | Paused        | Recording      | SETRATEANCHORTIME rate=1         |
/// | Paused        | Flushed        | FLUSHBUFFERED                    |
/// | Paused        | Idle           | TEARDOWN (session)               |
/// | Flushed       | Recording      | SETRATEANCHORTIME rate=1         |
/// | Flushed       | Paused         | PAUSE (redundant, allowed)       |
/// | Flushed       | Idle           | TEARDOWN (session)               |
/// | Teardown      | Idle           | (reset)                          |
/// | Idle          | StreamSetup    | SETUP (unpaired initial)         |
/// | Paired        | StreamSetup    | SETUP (additional stream add)    |
/// | Configured    | StreamSetup    | SETUP (additional stream add)    |
/// | Recording     | StreamSetup    | SETUP (additional stream add)    |
/// | Paused        | StreamSetup    | SETUP (additional stream add)    |
/// | Flushed       | StreamSetup    | SETUP (additional stream add)    |
///
/// Notes:
/// - Additional StreamSetup (subsequent SETUP) is only valid from active
///   phases: Paired, Configured, StreamSetup, Recording, Paused, Flushed.
///   It is **not** valid from Idle (that path is the distinct "initial"
///   SETUP) or Teardown.
/// - Teardown may **only** transition to Idle; it may not transition
///   directly to StreamSetup or any other phase.
/// - Stream teardown (TEARDOWN with body) stays in the current phase — it
///   only closes a single stream listener and does **not** transition the
///   session.
/// - PAUSE during Flushed is allowed (redundant, equivalent).
/// - Idempotent transitions (same → same) are always allowed.
pub fn validate_transition(
    from: Ap2SessionPhase,
    to: Ap2SessionPhase,
) -> Result<(), TransitionError> {
    if from == to {
        return Ok(());
    }

    let allowed = match (from, to) {
        // Idle — only way out is pairing or direct SETUP (unpaired AP2 path)
        (Ap2SessionPhase::Idle, Ap2SessionPhase::Paired) => true,
        (Ap2SessionPhase::Idle, Ap2SessionPhase::StreamSetup) => true,

        // Paired
        (Ap2SessionPhase::Paired, Ap2SessionPhase::Configured) => true,
        (Ap2SessionPhase::Paired, Ap2SessionPhase::StreamSetup) => true,
        (Ap2SessionPhase::Paired, Ap2SessionPhase::Idle) => true,

        // Configured
        (Ap2SessionPhase::Configured, Ap2SessionPhase::StreamSetup) => true,
        (Ap2SessionPhase::Configured, Ap2SessionPhase::Idle) => true,

        // StreamSetup — into recording or back to idle
        (Ap2SessionPhase::StreamSetup, Ap2SessionPhase::Recording) => true,
        (Ap2SessionPhase::StreamSetup, Ap2SessionPhase::Idle) => true,

        // Recording — pause, flush, or teardown
        (Ap2SessionPhase::Recording, Ap2SessionPhase::Paused) => true,
        (Ap2SessionPhase::Recording, Ap2SessionPhase::Flushed) => true,
        (Ap2SessionPhase::Recording, Ap2SessionPhase::Idle) => true,

        // Paused — resume, flush, or teardown
        (Ap2SessionPhase::Paused, Ap2SessionPhase::Recording) => true,
        (Ap2SessionPhase::Paused, Ap2SessionPhase::Flushed) => true,
        (Ap2SessionPhase::Paused, Ap2SessionPhase::Idle) => true,

        // Flushed — resume, pause (redundant), or teardown
        (Ap2SessionPhase::Flushed, Ap2SessionPhase::Recording) => true,
        (Ap2SessionPhase::Flushed, Ap2SessionPhase::Paused) => true,
        (Ap2SessionPhase::Flushed, Ap2SessionPhase::Idle) => true,

        // Teardown — only back to idle
        (Ap2SessionPhase::Teardown, Ap2SessionPhase::Idle) => true,

        // Additional StreamSetup from active phases not already covered above.
        (Ap2SessionPhase::Recording, Ap2SessionPhase::StreamSetup) => true,
        (Ap2SessionPhase::Paused, Ap2SessionPhase::StreamSetup) => true,
        (Ap2SessionPhase::Flushed, Ap2SessionPhase::StreamSetup) => true,

        _ => false,
    };

    if allowed {
        Ok(())
    } else {
        Err(TransitionError {
            from,
            to,
            reason: "transition not in the allowed set for this phase pair",
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_phase_always_allowed() {
        for phase in [
            Ap2SessionPhase::Idle,
            Ap2SessionPhase::Paired,
            Ap2SessionPhase::Configured,
            Ap2SessionPhase::StreamSetup,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Paused,
            Ap2SessionPhase::Flushed,
            Ap2SessionPhase::Teardown,
        ] {
            assert!(
                validate_transition(phase, phase).is_ok(),
                "same-phase transition {phase} → {phase} should be allowed"
            );
        }
    }

    #[test]
    fn happy_path_lifecycle() {
        let seq = [
            Ap2SessionPhase::Idle,
            Ap2SessionPhase::Paired,
            Ap2SessionPhase::Configured,
            Ap2SessionPhase::StreamSetup,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Paused,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Flushed,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Idle,
        ];
        for w in seq.windows(2) {
            let (from, to) = (w[0], w[1]);
            assert!(
                validate_transition(from, to).is_ok(),
                "transition {from} → {to} should be allowed"
            );
        }
    }

    #[test]
    fn idle_direct_to_streamsetup() {
        // Unpaired AP2 client might SETUP directly
        assert!(validate_transition(Ap2SessionPhase::Idle, Ap2SessionPhase::StreamSetup).is_ok());
    }

    #[test]
    fn recording_direct_to_idle() {
        assert!(validate_transition(Ap2SessionPhase::Recording, Ap2SessionPhase::Idle).is_ok());
    }

    #[test]
    fn paused_to_flushed() {
        assert!(validate_transition(Ap2SessionPhase::Paused, Ap2SessionPhase::Flushed).is_ok());
    }

    #[test]
    fn flushed_to_paused() {
        assert!(validate_transition(Ap2SessionPhase::Flushed, Ap2SessionPhase::Paused).is_ok());
    }

    #[test]
    fn teardown_to_idle() {
        assert!(validate_transition(Ap2SessionPhase::Teardown, Ap2SessionPhase::Idle).is_ok());
    }

    #[test]
    fn additional_setup_from_any_active_phase() {
        for from in [
            Ap2SessionPhase::Paired,
            Ap2SessionPhase::Configured,
            Ap2SessionPhase::StreamSetup,
            Ap2SessionPhase::Recording,
            Ap2SessionPhase::Paused,
            Ap2SessionPhase::Flushed,
        ] {
            assert!(
                validate_transition(from, Ap2SessionPhase::StreamSetup).is_ok(),
                "SETUP (additional stream) from {from} should be allowed"
            );
        }
    }

    // ── Invalid transitions ─────────────────────────────────────────────

    #[test]
    fn idle_to_recording_invalid() {
        let err =
            validate_transition(Ap2SessionPhase::Idle, Ap2SessionPhase::Recording).unwrap_err();
        assert_eq!(err.from, Ap2SessionPhase::Idle);
        assert_eq!(err.to, Ap2SessionPhase::Recording);
    }

    #[test]
    fn idle_to_paused_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Idle, Ap2SessionPhase::Paused).is_err());
    }

    #[test]
    fn paired_to_recording_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Paired, Ap2SessionPhase::Recording).is_err());
    }

    #[test]
    fn recording_to_configured_invalid() {
        assert!(
            validate_transition(Ap2SessionPhase::Recording, Ap2SessionPhase::Configured).is_err()
        );
    }

    #[test]
    fn teardown_to_recording_invalid() {
        assert!(
            validate_transition(Ap2SessionPhase::Teardown, Ap2SessionPhase::Recording).is_err()
        );
    }

    #[test]
    fn teardown_to_paused_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Teardown, Ap2SessionPhase::Paused).is_err());
    }

    #[test]
    fn teardown_to_streamsetup_invalid() {
        // Regression: the catch-all `(_, StreamSetup) => true` used to allow
        // this illegal transition.  Teardown must only go to Idle.
        let err = validate_transition(Ap2SessionPhase::Teardown, Ap2SessionPhase::StreamSetup)
            .unwrap_err();
        assert_eq!(err.from, Ap2SessionPhase::Teardown);
        assert_eq!(err.to, Ap2SessionPhase::StreamSetup);
    }

    #[test]
    fn paused_to_configured_invalid() {
        assert!(validate_transition(Ap2SessionPhase::Paused, Ap2SessionPhase::Configured).is_err());
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn phase_display() {
        assert_eq!(Ap2SessionPhase::Idle.to_string(), "idle");
        assert_eq!(Ap2SessionPhase::Recording.to_string(), "recording");
        assert_eq!(Ap2SessionPhase::Teardown.to_string(), "teardown");
    }

    #[test]
    fn transition_error_display() {
        let err = TransitionError {
            from: Ap2SessionPhase::Idle,
            to: Ap2SessionPhase::Recording,
            reason: "must set up a stream first",
        };
        let s = err.to_string();
        assert!(s.contains("idle"));
        assert!(s.contains("recording"));
        assert!(s.contains("must set up a stream first"));
    }
}
