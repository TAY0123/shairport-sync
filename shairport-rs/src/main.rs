#![allow(dead_code)]

mod airplay;
mod api;
mod audio;
mod codec;
mod config;
mod decoder;
mod mdns;
mod player;
mod playout;
mod ptp;
mod state;
mod system_media;
mod web;

use std::{future::IntoFuture, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use axum::Router;
use clap::Parser;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::{
    airplay::{ap2::capability::Ap2CapabilityPolicy, playout_decoder::AirPlayPacketDecoder},
    api::ApiContext,
    config::{Config, ConfigOverrides, PtpBackendName},
    mdns::{MdnsAdvertiser, MdnsBackend},
    playout::scheduler::SchedulerConfig,
    state::AppState,
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(short, long, env = "SHAIRPORT_RS_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, env = "SHAIRPORT_RS_DEBUG")]
    debug: bool,

    #[command(flatten)]
    config_overrides: ConfigOverrides,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Create logs directory
    let log_dir = std::path::Path::new("logs");
    if !log_dir.exists() {
        std::fs::create_dir_all(log_dir).context("failed to create logs directory")?;
    }

    // Datetime-stamped log file
    let now = chrono::Local::now();
    let log_path = log_dir.join(now.format("%Y%m%d-%H%M%S.log").to_string());
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open log file {}", log_path.display()))?;

    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        if args.debug {
            "shairport_rs=debug,tower_http=debug".to_string()
        } else {
            "info".to_string()
        }
    });
    let filter = tracing_subscriber::EnvFilter::new(env_filter);

    // Console layer (stdout with colors)
    let console_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    // File layer (non-blocking, no ANSI)
    let (file_writer, _guard) = tracing_appender::non_blocking(log_file);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer);

    use tracing_subscriber::layer::SubscriberExt;
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer);
    tracing::subscriber::set_global_default(subscriber).expect("failed to set tracing subscriber");

    info!(log = %log_path.display(), "log file created");

    if args.debug {
        info!("debug logging enabled");
    }

    let config = Config::load(args.config.as_deref(), &args.config_overrides)?;
    let app_state = AppState::new(config.clone());

    let audio_manager = audio::AudioManager::new(config.audio.clone());
    let (audio_engine, audio_output, audio_controller, initial_output_result) =
        audio_manager.create_engine_and_supervised_output();
    if let Err(err) = initial_output_result {
        warn!(%err, "audio output stream not started; supervisor will keep retrying");
        app_state.set_diagnostic("audio_output_error", err.to_string());
    }
    let player = player::SharedPlayer::new();
    let dacp = airplay::dacp::DacpController::new(app_state.clone());
    app_state.update_audio_devices(audio_manager.list_devices());

    // Create the shared playout service immediately after AudioEngine.
    // It owns the decoder, ingress channel, and watermark state machine,
    // and is the single authority for audio lifecycle commands.
    let scheduler_config = SchedulerConfig::from_audio_config(&config.audio);
    let decoder = AirPlayPacketDecoder::new(app_state.clone());
    let (playout_handle, playout_task) = playout::scheduler::spawn_playout_service_with_clock(
        scheduler_config,
        decoder,
        audio_engine.clone(),
        std::sync::Arc::new(app_state.ptp_servo.clone()),
    );

    // Device loss / output-format changes invalidate queued PCM and drift
    // assumptions. Ask the scheduler to flush and re-prime before the
    // supervisor starts the replacement CPAL stream.
    let recovery_playout = playout_handle.clone();
    audio_controller.set_recovery_hook(move || recovery_playout.flush());

    // Periodically surface the counters that distinguish real PCM starvation
    // from AP2/PTP scheduling resets. These are intentionally INFO-level only
    // while a stream is active/paused so long Windows runs remain diagnosable
    // without requiring debug packet logging.
    let playout_diagnostics_handle = {
        let diag_playout = playout_handle.clone();
        let diag_engine = audio_engine.clone();
        let diag_state = app_state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the immediate first tick; report after one full interval.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let scheduler = diag_playout.status();
                let ingress = diag_playout.ingress_diagnostics();
                let audio = diag_engine.status();
                let snapshot = diag_state.snapshot();
                if !snapshot.active
                    && matches!(scheduler.state, playout::scheduler::PlayoutState::Stopped)
                {
                    continue;
                }

                let drift = scheduler.drift.unwrap_or_default();
                info!(
                    state = ?scheduler.state,
                    source_format = snapshot.audio.source_format.as_deref().unwrap_or("unknown"),
                    fifo_queued_ms = audio.queued_ms,
                    fifo_capacity_ms = audio.capacity_ms,
                    scheduler_queued_ms = scheduler.queued_ms,
                    callback_underrun_frames = audio.callback_underrun_frames,
                    producer_overflow_frames = audio.producer_overflow_frames,
                    fifo_backpressure_events = scheduler.diag.fifo_backpressure_events,
                    resyncs = scheduler.diag.resync_count,
                    jitter_resync_required = scheduler.jitter.resync_required,
                    timing_gate_holds = scheduler.diag.timing_gate_holds,
                    clock_lock_losses = scheduler.diag.clock_lock_losses,
                    late_packet_drops = scheduler.diag.late_packet_drops,
                    ingress_inflight = ingress.current_inflight,
                    ingress_max_depth = ingress.max_depth,
                    ingress_full_drops = ingress.full_drops,
                    drift_correction_ppm = drift.correction_ppm,
                    drift_timing_error_ns = drift.timing_error_ns,
                    drift_hard_resyncs = drift.hard_resync_count,
                    ptp_quality = ?snapshot.ptp.sync_quality,
                    ptp_offset_ns = ?snapshot.ptp.offset_ns,
                    "playout health"
                );
            }
        })
    };

    let mut ptp_running = false;
    let ptp_handle = if config.airplay.enabled
        && config.airplay.airplay2_enabled
        && config.ptp.enabled
    {
        match config.ptp.backend {
            PtpBackendName::Embedded => {
                match ptp::spawn_ptp_service(config.ptp.clone(), app_state.clone()).await {
                    Ok(handle) => {
                        ptp_running = true;
                        Some(handle)
                    }
                    Err(err) => {
                        warn!(%err, "embedded PTP service not started");
                        app_state.set_diagnostic("ptp_error", err.to_string());
                        None
                    }
                }
            }
            PtpBackendName::Nqptp => {
                info!("external nqptp configured; no shared-memory clock adapter implemented yet");
                app_state.set_diagnostic("ptp_backend", "nqptp".to_string());
                app_state.set_diagnostic(
                    "ap2_unavailable_reason",
                    "nqptp-adapter-not-implemented".to_string(),
                );
                // nqptp requires a shared-memory clock adapter that is not
                // yet implemented.  Until it exists, PTP is not available,
                // which means _airplay._tcp will be suppressed and AP2
                // stream/timing requests will be rejected.
                ptp_running = false;
                None
            }
            PtpBackendName::Off => None,
        }
    } else {
        None
    };

    // Build the capability policy once so mDNS and RTSP /info agree.
    let ap2_policy = Ap2CapabilityPolicy::from_config(&config, ptp_running);

    let rtsp_handle = if config.airplay.enabled {
        Some(
            airplay::rtsp::spawn_rtsp_server(
                config.airplay.clone(),
                app_state.clone(),
                audio_engine.clone(),
                player.clone(),
                dacp.clone(),
                playout_handle.clone(),
                ap2_policy,
            )
            .await?,
        )
    } else {
        None
    };
    let rtp_handles = if config.airplay.enabled {
        Some(
            airplay::rtp::spawn_rtp_receivers(
                config.airplay.clone(),
                app_state.clone(),
                playout_handle.clone(),
            )
            .await?,
        )
    } else {
        None
    };

    // AP2 audio listeners are session-owned and opened during RTSP stream SETUP.
    // The static buffered audio receiver on config.audio_port is removed;
    // sessions negotiate their own ports dynamically.

    let mdns_backend = MdnsBackend::from_config(&config.mdns);
    let mdns_advertiser = MdnsAdvertiser::new(mdns_backend, config.mdns.clone());
    let services = airplay::txt_records::airplay_services(&config, ptp_running);
    let service_types: Vec<String> = services
        .iter()
        .map(|s| s.service_type.trim_end_matches(".local.").to_string())
        .collect();
    if let Err(err) = mdns_advertiser.publish(services).await {
        warn!(%err, "mDNS publication failed");
        app_state.set_mdns_error(err.to_string());
    } else {
        let backend = mdns_advertiser
            .active_backend_name()
            .unwrap_or_else(|| config.mdns.backend.to_string());
        app_state.set_mdns_running(backend, service_types.clone());
    }

    // External Bonjour/Avahi publishers are long-lived subprocesses. Network
    // interface churn and sleep/wake can terminate them while RTSP :7000 keeps
    // listening, leaving iOS unable to rediscover the receiver. Supervise and
    // republish all services when any publisher exits.
    let mdns_supervisor_handle = {
        let advertiser = mdns_advertiser.clone();
        let state = app_state.clone();
        let service_types = service_types.clone();
        let configured_backend = config.mdns.backend.to_string();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            let mut restart_count = 0_u64;
            loop {
                ticker.tick().await;
                match advertiser.supervise_once().await {
                    Ok(true) => {
                        restart_count = restart_count.saturating_add(1);
                        let backend = advertiser
                            .active_backend_name()
                            .unwrap_or_else(|| configured_backend.clone());
                        state.set_mdns_running(backend, service_types.clone());
                        state.set_diagnostic("mdns_publisher_restarts", restart_count.to_string());
                    }
                    Ok(false) => {}
                    Err(err) => {
                        warn!(%err, "mDNS publisher restart failed; will retry");
                        state.set_mdns_error(err.to_string());
                    }
                }
            }
        })
    };

    let api_context = ApiContext::new(
        app_state.clone(),
        audio_manager,
        audio_engine,
        mdns_advertiser,
        dacp,
    )
    .with_audio_output(audio_controller)
    .with_playout(playout_handle.clone());

    let mut system_media = match system_media::SystemMediaIntegration::start(
        &config.system_media,
        app_state.clone(),
        api_context.clone(),
    ) {
        Ok(integration) => integration,
        Err(err) => {
            warn!(%err, "system media integration unavailable; continuing without it");
            app_state.set_diagnostic("system_media_error", err.to_string());
            None
        }
    };

    let router = Router::new()
        .merge(api::router(api_context))
        .merge(web::router())
        .layer(TraceLayer::new_for_http());

    let bind: SocketAddr = config
        .server
        .bind
        .parse()
        .with_context(|| format!("invalid server bind address {}", config.server.bind))?;
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "shairport-rs listening");

    let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = server_shutdown_rx.await;
        })
        .into_future();
    tokio::pin!(server);

    let server_finished = if let Some(integration) = system_media.as_mut() {
        tokio::select! {
            result = &mut server => {
                result?;
                true
            }
            _ = shutdown_signal() => false,
            _ = integration.run() => {
                warn!("system media integration loop stopped unexpectedly");
                false
            }
        }
    } else {
        tokio::select! {
            result = &mut server => {
                result?;
                true
            }
            _ = shutdown_signal() => false,
        }
    };

    if !server_finished {
        let _ = server_shutdown_tx.send(());
        server.await?;
    }

    if let Some(handle) = ptp_handle {
        handle.abort();
    }
    if let Some(handle) = rtsp_handle {
        handle.abort();
    }
    if let Some(rtp_handles) = rtp_handles {
        for handle in rtp_handles.network {
            handle.abort();
        }
    }
    mdns_supervisor_handle.abort();
    playout_diagnostics_handle.abort();

    // Graceful shutdown: tell the playout service to stop, then await
    // the task with a bounded timeout.  Do not abort it first.
    playout_handle.shutdown();
    let mut playout_task = playout_task;
    match tokio::time::timeout(std::time::Duration::from_secs(2), &mut playout_task).await {
        Ok(Ok(())) => info!("playout service stopped cleanly"),
        Ok(Err(err)) if err.is_cancelled() => info!("playout service task cancelled"),
        Ok(Err(err)) => warn!(%err, "playout service task panicked"),
        Err(_elapsed) => {
            warn!("playout service shutdown timed out after 2 s; aborting task");
            playout_task.abort();
            let _ = playout_task.await;
        }
    }

    audio_output.shutdown();
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn config_override_arguments_have_unique_ids_and_parse() {
        Args::command().debug_assert();

        let args = Args::try_parse_from([
            "shairport-rs",
            "--mdns-backend",
            "dns-sd",
            "--audio-host",
            "wasapi",
            "--airplay2-enabled",
            "true",
            "--system-media-enabled",
            "false",
        ])
        .unwrap();

        assert!(args.config.is_none());
    }
}
