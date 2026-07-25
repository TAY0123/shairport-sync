use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

const DEFAULT_LATENCY_FRAMES: u32 = 11025; // ~250ms at 44100Hz
const DEFAULT_SAMPLE_RATE: u32 = 44100;

/// Snapshot of player transport control state.
///
/// Queue‑related fields (`buffered_frames`, `total_frames_played`, `underruns`,
/// `late_frames_dropped`, `timestamp_offset`) are preserved for API compatibility
/// but always report zero / `None` — the `Player` is now control‑only and does
/// not accumulate an audio‑frame queue.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlayerStatus {
    pub buffered_frames: usize,
    pub total_frames_played: u64,
    pub underruns: u64,
    pub late_frames_dropped: u64,
    pub playing: bool,
    pub timestamp_offset: Option<u32>,
    pub latency_frames: u32,
    /// Current stream sample rate set via `set_sample_rate`.
    /// Defaults to 44_100 so serde deserialization of older snapshots succeeds.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,
}

const fn default_sample_rate() -> u32 {
    DEFAULT_SAMPLE_RATE
}

/// Pure transport‑control state — start, stop, flush, sample‑rate.
///
/// This type does **not** hold an audio‑frame queue.  The decoded‑PCM pipeline
/// goes directly from the RTP path into [`AudioEngine`](crate::audio::AudioEngine);
/// the `Player` is kept only so RTSP commands (SETUP / PLAY / PAUSE / STOP /
/// TEARDOWN) can observe and mutate playback‑control state.
pub struct Player {
    playing: bool,
    latency_frames: u32,
    sample_rate: u32,
}

impl Player {
    pub fn new() -> Self {
        Self {
            playing: false,
            latency_frames: DEFAULT_LATENCY_FRAMES,
            sample_rate: DEFAULT_SAMPLE_RATE,
        }
    }

    /// Start or resume playback.
    ///
    /// `latency_frames` of 0 selects the default (~250 ms at 44.1 kHz).
    pub fn start(&mut self, latency_frames: u32) {
        self.playing = true;
        self.latency_frames = if latency_frames > 0 {
            latency_frames
        } else {
            DEFAULT_LATENCY_FRAMES
        };
        info!(latency = self.latency_frames, "player started");
    }

    /// Stop playback and reset transport state.
    pub fn stop(&mut self) {
        self.playing = false;
        // Reset to defaults so a subsequent start without explicit sample-rate
        // does not carry over a stale stream setting.
        self.sample_rate = DEFAULT_SAMPLE_RATE;
        self.latency_frames = DEFAULT_LATENCY_FRAMES;
        info!("player stopped");
    }

    /// Flush without changing playback state.
    ///
    /// Since there is no audio‑frame queue, this is a no‑op other than logging
    /// (the method is still called by RTSP FLUSHBUFFERED / pause handling).
    pub fn flush(&mut self) {
        debug!("player flushed (control-only)");
    }

    /// Set the sample rate for the current stream.
    ///
    /// Zero selects the default 44.1 kHz; nonzero rates are preserved.
    pub fn set_sample_rate(&mut self, rate: u32) {
        self.sample_rate = if rate > 0 { rate } else { DEFAULT_SAMPLE_RATE };
    }

    /// Snapshot transport‑control state.
    ///
    /// Queue‑related fields are always reported as zero / `None`.
    pub fn status(&self) -> PlayerStatus {
        PlayerStatus {
            buffered_frames: 0,
            total_frames_played: 0,
            underruns: 0,
            late_frames_dropped: 0,
            playing: self.playing,
            timestamp_offset: None,
            latency_frames: self.latency_frames,
            sample_rate: self.sample_rate,
        }
    }
}

/// Thread‑safe, cloneable handle to a shared [`Player`].
///
/// Cloned instances share the same underlying transport state, which is
/// protected by a `parking_lot::Mutex`.
#[derive(Clone)]
pub struct SharedPlayer {
    inner: Arc<Mutex<Player>>,
}

impl SharedPlayer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Player::new())),
        }
    }

    pub fn start(&self, latency_frames: u32) {
        self.inner.lock().start(latency_frames);
    }

    pub fn stop(&self) {
        self.inner.lock().stop();
    }

    pub fn flush(&self) {
        self.inner.lock().flush();
    }

    pub fn set_sample_rate(&self, rate: u32) {
        self.inner.lock().set_sample_rate(rate);
    }

    pub fn status(&self) -> PlayerStatus {
        self.inner.lock().status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Control-state transition tests
    // ---------------------------------------------------------------------------

    #[test]
    fn player_starts_and_stops() {
        let mut p = Player::new();
        assert!(!p.playing);
        p.start(11025);
        assert!(p.playing);
        assert_eq!(p.status().latency_frames, 11025);
        p.stop();
        assert!(!p.playing);
    }

    #[test]
    fn latency_defaults_when_zero() {
        let mut p = Player::new();
        p.start(0);
        assert!(p.playing);
        assert_eq!(p.status().latency_frames, DEFAULT_LATENCY_FRAMES);
    }

    #[test]
    fn latency_defaults_when_explicit() {
        let mut p = Player::new();
        p.start(88200);
        assert_eq!(p.status().latency_frames, 88200);
    }

    #[test]
    fn sample_rate_defaults_only_when_zero() {
        let mut p = Player::new();
        p.set_sample_rate(0);
        assert_eq!(p.status().sample_rate, DEFAULT_SAMPLE_RATE);
        p.set_sample_rate(u32::MAX);
        assert_eq!(p.status().sample_rate, u32::MAX);
        p.set_sample_rate(48_000);
        assert_eq!(p.status().sample_rate, 48_000);
    }

    #[test]
    fn sample_rate_reported_in_status() {
        let mut p = Player::new();
        p.set_sample_rate(88_200);
        assert_eq!(p.status().sample_rate, 88_200);
        // serde default: the field has #[serde(default)] so it survives
        // deserialization even when absent.
        let json = serde_json::to_string(&p.status()).unwrap();
        let round_tripped: PlayerStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.sample_rate, 88_200);
    }

    #[test]
    fn flush_preserves_playing_state() {
        let mut p = Player::new();
        p.start(11025);
        assert!(p.playing);
        p.flush();
        assert!(p.playing, "flush must not stop playback");
        // And it's idempotent — no panic.
        p.flush();
    }

    #[test]
    fn stop_resets_transport_state() {
        let mut p = Player::new();
        p.set_sample_rate(96_000);
        p.start(22050);
        assert!(p.playing);
        p.stop();
        assert!(!p.playing);
        // stop should restore defaults so a stale stream setting does not leak.
        assert_eq!(p.status().sample_rate, DEFAULT_SAMPLE_RATE);
        assert_eq!(p.status().latency_frames, DEFAULT_LATENCY_FRAMES);
    }

    #[test]
    fn queue_metrics_are_permanently_zero() {
        let mut p = Player::new();
        p.start(11025);
        let s = p.status();
        assert_eq!(s.buffered_frames, 0);
        assert_eq!(s.total_frames_played, 0);
        assert_eq!(s.underruns, 0);
        assert_eq!(s.late_frames_dropped, 0);
        assert!(s.timestamp_offset.is_none());

        // Still zero after start/stop cycle.
        p.stop();
        let s = p.status();
        assert_eq!(s.buffered_frames, 0);
        assert_eq!(s.total_frames_played, 0);
        assert_eq!(s.underruns, 0);
        assert_eq!(s.late_frames_dropped, 0);
    }

    #[test]
    fn shared_player_delegates_to_inner() {
        let sp = SharedPlayer::new();
        sp.set_sample_rate(48_000);
        sp.start(22050);
        let s = sp.status();
        assert!(s.playing);
        assert_eq!(s.latency_frames, 22050);
        assert_eq!(s.sample_rate, 48_000);
        sp.flush();
        assert!(sp.status().playing, "flush preserves playing");
        sp.stop();
        assert!(!sp.status().playing);
    }

    #[test]
    fn player_status_serde_defaults_sample_rate() {
        // Simulate a JSON snapshot that is missing the new `sample_rate` field.
        let old_json = r#"{
            "buffered_frames":0,
            "total_frames_played":0,
            "underruns":0,
            "late_frames_dropped":0,
            "playing":true,
            "timestamp_offset":null,
            "latency_frames":11025
        }"#;
        let status: PlayerStatus = serde_json::from_str(old_json).unwrap();
        assert_eq!(status.sample_rate, DEFAULT_SAMPLE_RATE);
        assert!(status.playing);
    }
}
