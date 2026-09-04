use std::time::{Duration, SystemTime};

use anyhow::Context;
use playwire::{Capabilities, Event, MediaControls, PlaybackState, PlayerConfig, Track};
use sha1::{Digest, Sha1};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::{
    api::ApiContext,
    config::SystemMediaConfig,
    state::{AppState, PlayerState, StateSnapshot},
};

const POSITION_PUBLISH_INTERVAL: Duration = Duration::from_secs(1);
const PLATFORM_PUMP_INTERVAL: Duration = Duration::from_millis(50);
const EVENT_QUEUE_CAPACITY: usize = 32;

/// Bridges shairport-rs state and transport controls to the host OS media UI.
///
/// The OS callback only queues an event. All state mutation and DACP work stays
/// on the application async loop, which also keeps macOS MediaPlayer calls on
/// the main thread.
pub struct SystemMediaIntegration {
    controls: MediaControls,
    platform: platform::PlatformHost,
    state: AppState,
    context: ApiContext,
    state_rx: broadcast::Receiver<StateSnapshot>,
    event_rx: mpsc::Receiver<Event>,
    last_published: Option<PlaybackState>,
    last_progress_updated_at: Option<SystemTime>,
}

impl SystemMediaIntegration {
    pub fn start(
        config: &SystemMediaConfig,
        state: AppState,
        context: ApiContext,
    ) -> anyhow::Result<Option<Self>> {
        if !config.enabled {
            info!("system media integration disabled by configuration");
            state.set_diagnostic("system_media", "disabled");
            return Ok(None);
        }

        let platform = platform::PlatformHost::new().context("platform media host setup failed")?;
        let mut player_config = PlayerConfig::new(config.bus_name.clone())
            .desktop_entry(config.desktop_entry.clone())
            .track_id_prefix("/org/shairport_rs/MediaPlayer2/Track")
            .supported_uri_schemes(Vec::new())
            .supported_mime_types(Vec::new());
        player_config.identity = config.identity.clone();
        platform.configure_player(&mut player_config);

        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let mut controls = MediaControls::new(player_config, move |event| {
            // Media-key callbacks must never block an OS callback thread. A
            // short bounded queue is ample for human input while preventing a
            // pathological local client from growing memory without bound.
            let _ = event_tx.try_send(event);
        })
        .context("OS media controls registration failed")?;

        let initial_snapshot = state.snapshot();
        let initial = playback_state_from_snapshot(&initial_snapshot, false);
        controls
            .set_state(&initial)
            .context("initial OS media state publication failed")?;

        state.set_diagnostic("system_media", platform.backend_name());
        info!(
            backend = platform.backend_name(),
            "system media integration started"
        );

        Ok(Some(Self {
            controls,
            platform,
            state_rx: state.subscribe(),
            state,
            context,
            event_rx,
            last_published: Some(initial),
            last_progress_updated_at: initial_snapshot.track.progress_updated_at,
        }))
    }

    /// Run forever while the receiver is alive.
    ///
    /// This future is deliberately driven by the top-level `main` future rather
    /// than `tokio::spawn`: macOS requires its Now Playing objects and main run
    /// loop to be serviced from the process main thread.
    pub async fn run(&mut self) {
        let mut position_tick = tokio::time::interval(POSITION_PUBLISH_INTERVAL);
        position_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut platform_tick = tokio::time::interval(PLATFORM_PUMP_INTERVAL);
        platform_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                received = self.state_rx.recv() => {
                    match received {
                        Ok(snapshot) => self.publish(snapshot, false),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            self.publish(self.state.snapshot(), false);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            warn!("system media state channel closed");
                            return;
                        }
                    }
                }
                event = self.event_rx.recv() => {
                    match event {
                        Some(event) => self.handle_event(event).await,
                        None => {
                            warn!("system media event channel closed");
                            return;
                        }
                    }
                }
                _ = position_tick.tick() => {
                    if self.state.snapshot().player_state == PlayerState::Playing {
                        self.publish(self.state.snapshot(), true);
                    }
                }
                _ = platform_tick.tick() => self.platform.pump(),
            }
        }
    }

    fn publish(&mut self, snapshot: StateSnapshot, estimate_position: bool) {
        let progress_updated_at = snapshot.track.progress_updated_at;
        let mut playback = playback_state_from_snapshot(&snapshot, estimate_position);

        // AppState broadcasts for diagnostics/RTP counters too. Between sender
        // progress anchors those updates must not overwrite our 1 Hz estimated
        // position with the older base value and make the shell scrubber jump
        // backwards. A changed progress_updated_at is an explicit sender anchor
        // and is therefore allowed to move in either direction.
        if !estimate_position
            && progress_updated_at == self.last_progress_updated_at
            && let Some(last) = self.last_published.as_ref()
            && last.track == playback.track
            && playback.position < last.position
        {
            playback.position = last.position;
        }

        if self.last_published.as_ref() == Some(&playback) {
            self.last_progress_updated_at = progress_updated_at;
            return;
        }
        if let Err(err) = self.controls.set_state(&playback) {
            // Do not write the error back into AppState here: that would emit a
            // new state snapshot and create a feedback loop if an OS backend is
            // persistently unavailable after successful registration.
            warn!(%err, "failed to publish system media state");
            return;
        }
        self.last_published = Some(playback);
        self.last_progress_updated_at = progress_updated_at;
    }

    async fn handle_event(&self, event: Event) {
        let command = match event {
            Event::Play => Some("play"),
            Event::Pause => Some("pause"),
            Event::PlayPause => Some("playpause"),
            Event::Stop => Some("stop"),
            Event::Next => Some("next"),
            Event::Previous => Some("previous"),
            Event::SetVolume(volume) => {
                self.context.set_system_volume_linear(volume);
                debug!(volume, "system media volume applied");
                return;
            }
            // Shairport is a receiver, not the source timeline owner. Seeking,
            // shuffle/repeat, URI opening and shell lifecycle requests cannot be
            // applied faithfully, so they are deliberately rejected/ignored.
            Event::SeekTo(_)
            | Event::SeekBy(_)
            | Event::SetShuffle(_)
            | Event::SetRepeat(_)
            | Event::OpenUri(_)
            | Event::Raise
            | Event::Quit => {
                debug!(?event, "unsupported system media command ignored");
                return;
            }
            _ => {
                debug!(?event, "unknown system media command ignored");
                return;
            }
        };

        if let Some(command) = command {
            let result = self.context.dispatch_system_media_command(command).await;
            debug!(
                command,
                accepted = result.accepted,
                message = %result.message,
                "system media transport command handled"
            );
        }
    }
}

fn playback_state_from_snapshot(
    snapshot: &StateSnapshot,
    estimate_position: bool,
) -> PlaybackState {
    let has_loaded_track = snapshot.active && snapshot.player_state != PlayerState::Stopped;
    let track = has_loaded_track.then(|| Track {
        id: stable_track_id(snapshot),
        title: snapshot
            .track
            .title
            .clone()
            .or_else(|| snapshot.track.client_name.clone())
            .unwrap_or_else(|| "AirPlay".to_string()),
        artists: snapshot.track.artist.clone().into_iter().collect(),
        album: snapshot.track.album.clone().unwrap_or_default(),
        artwork_url: snapshot.track.artwork_url.clone().unwrap_or_default(),
        url: String::new(),
    });

    PlaybackState {
        track,
        playing: snapshot.player_state == PlayerState::Playing,
        position: Duration::from_millis(position_ms(snapshot, estimate_position)),
        duration: snapshot.track.duration_ms.map(Duration::from_millis),
        volume: db_to_linear(snapshot.volume.local_db),
        capabilities: Capabilities {
            can_go_next: has_source_navigation(snapshot),
            can_go_previous: has_source_navigation(snapshot),
            can_seek: false,
        },
        ..PlaybackState::default()
    }
}

fn has_source_navigation(snapshot: &StateSnapshot) -> bool {
    snapshot.remote_control.dacp_id.is_some() && snapshot.remote_control.active_remote.is_some()
}

fn position_ms(snapshot: &StateSnapshot, estimate: bool) -> u64 {
    let base = snapshot.track.progress_ms.unwrap_or(0);
    if !estimate || snapshot.player_state != PlayerState::Playing {
        return base.min(snapshot.track.duration_ms.unwrap_or(u64::MAX));
    }
    let elapsed = snapshot
        .track
        .progress_updated_at
        .and_then(|updated| SystemTime::now().duration_since(updated).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0);
    base.saturating_add(elapsed)
        .min(snapshot.track.duration_ms.unwrap_or(u64::MAX))
}

fn stable_track_id(snapshot: &StateSnapshot) -> String {
    let mut hash = Sha1::new();
    for value in [
        snapshot.track.title.as_deref().unwrap_or(""),
        snapshot.track.artist.as_deref().unwrap_or(""),
        snapshot.track.album.as_deref().unwrap_or(""),
        snapshot.track.client_name.as_deref().unwrap_or(""),
    ] {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    hash.update(snapshot.track.duration_ms.unwrap_or(0).to_be_bytes());
    let digest = hash.finalize();
    digest[..10]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn db_to_linear(db: f64) -> f64 {
    if !db.is_finite() || db <= -144.0 {
        0.0
    } else {
        10.0f64.powf(db.clamp(-144.0, 0.0) / 20.0)
    }
}

pub(crate) fn linear_to_db(volume: f64) -> f64 {
    if !volume.is_finite() || volume <= 0.0 {
        -144.0
    } else {
        (20.0 * volume.clamp(f64::MIN_POSITIVE, 1.0).log10()).clamp(-144.0, 0.0)
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use anyhow::Context;
    use playwire::PlayerConfig;
    use windows::{
        Win32::{
            Foundation::{HWND, RPC_E_CHANGED_MODE},
            System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
            UI::WindowsAndMessaging::{
                CreateWindowExW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
                TranslateMessage, WINDOW_EX_STYLE, WS_OVERLAPPED,
            },
        },
        core::w,
    };

    pub struct PlatformHost {
        hwnd: HWND,
        winrt_initialized: bool,
    }

    impl PlatformHost {
        pub fn new() -> anyhow::Result<Self> {
            let winrt_initialized = match unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
                Ok(()) => true,
                // Another library may already have initialized the main thread
                // as STA. That is still a valid COM/WinRT apartment for SMTC;
                // only skip our matching RoUninitialize in this case.
                Err(err) if err.code() == RPC_E_CHANGED_MODE => false,
                Err(err) => return Err(err).context("RoInitialize failed"),
            };
            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("STATIC"),
                    w!("Shairport RS Media Controls"),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    None,
                    None,
                )
            }
            .context("failed to create hidden SMTC window")?;
            Ok(Self {
                hwnd,
                winrt_initialized,
            })
        }

        pub fn configure_player(&self, config: &mut PlayerConfig) {
            config.hwnd = Some(self.hwnd.0 as usize as u64);
        }

        pub fn pump(&self) {
            unsafe {
                let mut message = MSG::default();
                while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        }

        pub fn backend_name(&self) -> &'static str {
            "windows-smtc"
        }
    }

    impl Drop for PlatformHost {
        fn drop(&mut self) {
            unsafe {
                let _ = DestroyWindow(self.hwnd);
                if self.winrt_initialized {
                    RoUninitialize();
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use anyhow::anyhow;
    use objc2::{MainThreadMarker, rc::Retained};
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
    use objc2_foundation::{NSDate, NSRunLoop};
    use playwire::PlayerConfig;

    pub struct PlatformHost {
        _application: Retained<NSApplication>,
        run_loop: Retained<NSRunLoop>,
    }

    impl PlatformHost {
        pub fn new() -> anyhow::Result<Self> {
            let mtm = MainThreadMarker::new().ok_or_else(|| {
                anyhow!("macOS system media integration must start on the main thread")
            })?;
            let application = NSApplication::sharedApplication(mtm);
            application.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
            application.finishLaunching();
            Ok(Self {
                _application: application,
                run_loop: NSRunLoop::mainRunLoop(),
            })
        }

        pub fn configure_player(&self, _config: &mut PlayerConfig) {}

        pub fn pump(&self) {
            // Tokio owns the process main thread instead of NSApplication::run.
            // Give AppKit/MediaPlayer a short turn of the main run loop so remote
            // command callbacks are delivered while remaining a headless app.
            let deadline = NSDate::dateWithTimeIntervalSinceNow(0.001);
            self.run_loop.runUntilDate(&deadline);
        }

        pub fn backend_name(&self) -> &'static str {
            "macos-now-playing"
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    use playwire::PlayerConfig;

    pub struct PlatformHost;

    impl PlatformHost {
        pub fn new() -> anyhow::Result<Self> {
            Ok(Self)
        }

        pub fn configure_player(&self, _config: &mut PlayerConfig) {}

        pub fn pump(&self) {}

        pub fn backend_name(&self) -> &'static str {
            "linux-mpris"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn stopped_receiver_clears_os_track() {
        let snapshot = AppState::new(Config::default()).snapshot();
        let media = playback_state_from_snapshot(&snapshot, false);
        assert!(media.track.is_none());
        assert!(!media.playing);
        assert!(!media.capabilities.can_seek);
    }

    #[test]
    fn active_metadata_maps_to_os_media_snapshot() {
        let state = AppState::new(Config::default());
        state.set_active(true);
        state.set_player_state(PlayerState::Playing);
        state.set_track_metadata(
            Some("Song".into()),
            Some("Artist".into()),
            Some("Album".into()),
        );
        state.set_duration_ms(12_000);
        state.set_progress_ms(3_000);
        let media = playback_state_from_snapshot(&state.snapshot(), false);
        let track = media.track.expect("track");
        assert_eq!(track.title, "Song");
        assert_eq!(track.artists, vec!["Artist"]);
        assert_eq!(track.album, "Album");
        assert_eq!(media.position, Duration::from_secs(3));
        assert_eq!(media.duration, Some(Duration::from_secs(12)));
        assert!(media.playing);
        assert!(!media.capabilities.can_seek);
    }

    #[test]
    fn system_volume_conversions_cover_mute_and_unity() {
        assert_eq!(db_to_linear(-144.0), 0.0);
        assert!((db_to_linear(0.0) - 1.0).abs() < f64::EPSILON);
        assert_eq!(linear_to_db(0.0), -144.0);
        assert!((linear_to_db(1.0) - 0.0).abs() < f64::EPSILON);
        assert!((linear_to_db(0.5) + 6.020_599_913).abs() < 1e-6);
    }

    #[test]
    fn navigation_capability_requires_dacp_session() {
        let state = AppState::new(Config::default());
        state.set_active(true);
        state.set_player_state(PlayerState::Playing);
        let media = playback_state_from_snapshot(&state.snapshot(), false);
        assert!(!media.capabilities.can_go_next);
        assert!(!media.capabilities.can_go_previous);
    }
}
