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
mod web;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use axum::Router;
use clap::Parser;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::{
    airplay::playout_decoder::AirPlayPacketDecoder,
    api::ApiContext,
    config::{Config, PtpBackendName},
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

    let config = Config::load(args.config.as_deref())?;
    let app_state = AppState::new(config.clone());

    let audio_manager = audio::AudioManager::new(config.audio.clone());
    let (audio_engine, audio_output) = match audio_manager.create_engine_and_output() {
        (engine, Ok(output)) => (engine, Some(output)),
        (engine, Err(err)) => {
            warn!(%err, "audio output stream not started");
            app_state.set_diagnostic("audio_output_error", err.to_string());
            (engine, None)
        }
    };
    let player = player::SharedPlayer::new();
    let dacp = airplay::dacp::DacpController::new(app_state.clone());
    app_state.update_audio_devices(audio_manager.list_devices());

    // Create the shared playout service immediately after AudioEngine.
    // It owns the decoder, ingress channel, and watermark state machine,
    // and is the single authority for audio lifecycle commands.
    let scheduler_config = SchedulerConfig::from_audio_config(&config.audio);
    let decoder = AirPlayPacketDecoder::new(app_state.clone());
    let (playout_handle, playout_task) =
        playout::scheduler::spawn_playout_service(scheduler_config, decoder, audio_engine.clone());

    let ptp_handle =
        if config.airplay.enabled && config.airplay.airplay2_enabled && config.ptp.enabled {
            match config.ptp.backend {
                PtpBackendName::Embedded => {
                    match ptp::spawn_ptp_service(config.ptp.clone(), app_state.clone()).await {
                        Ok(handle) => Some(handle),
                        Err(err) => {
                            warn!(%err, "embedded PTP service not started");
                            app_state.set_diagnostic("ptp_error", err.to_string());
                            None
                        }
                    }
                }
                PtpBackendName::Nqptp => {
                    info!("external nqptp configured; embedded PTP socket bind skipped");
                    app_state.set_diagnostic("ptp_backend", "nqptp".to_string());
                    None
                }
                PtpBackendName::Off => None,
            }
        } else {
            None
        };

    let rtsp_handle = if config.airplay.enabled {
        Some(
            airplay::rtsp::spawn_rtsp_server(
                config.airplay.clone(),
                app_state.clone(),
                audio_engine.clone(),
                player.clone(),
                dacp.clone(),
                playout_handle.clone(),
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
    let services = airplay::txt_records::airplay_services(&config);
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
        app_state.set_mdns_running(backend, service_types);
    }

    let api_context = ApiContext::new(
        app_state.clone(),
        audio_manager,
        audio_engine,
        mdns_advertiser,
        dacp,
    );
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

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

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

    drop(audio_output);
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
