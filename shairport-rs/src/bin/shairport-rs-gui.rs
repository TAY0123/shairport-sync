#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("shairport-rs-gui is available on Windows only");
}

#[cfg(target_os = "windows")]
mod windows_gui {
    use serde::Deserialize;
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::{TcpStream, ToSocketAddrs},
        path::PathBuf,
        process::Command,
        sync::OnceLock,
        time::Duration,
    };
    use windows_reactor::*;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DEFAULT_ENDPOINT: &str = "127.0.0.1:36890";

    static GUI_CONFIG: OnceLock<GuiConfig> = OnceLock::new();

    #[derive(Clone, Debug)]
    struct GuiConfig {
        endpoint: String,
        config_path: Option<PathBuf>,
        debug: bool,
        auto_start: bool,
    }

    #[derive(Clone, Debug, Default, Deserialize)]
    struct Snapshot {
        active: bool,
        player_state: String,
        track: TrackSnapshot,
        audio: AudioSnapshot,
        diagnostics: BTreeMap<String, String>,
    }

    #[derive(Clone, Debug, Default, Deserialize)]
    struct TrackSnapshot {
        title: Option<String>,
        artist: Option<String>,
        client_name: Option<String>,
    }

    #[derive(Clone, Debug, Default, Deserialize)]
    struct AudioSnapshot {
        source_format: Option<String>,
        output_format: Option<String>,
        selected_device: Option<String>,
    }

    #[derive(Clone, Debug)]
    enum Message {
        Refresh,
        Tick,
        StartReceiver,
        RemoteCommand(&'static str),
    }

    struct ReceiverGui {
        snapshot: Result<Snapshot, String>,
        last_action: String,
    }

    impl Component for ReceiverGui {
        type Input = ();
        type Message = Message;

        fn create(_input: &(), context: &ComponentContext<Self>) -> Self {
            schedule_refresh(context);
            let config = GUI_CONFIG.get().expect("GUI config initialized");
            let mut last_action = String::new();
            if config.auto_start && fetch_snapshot(&config.endpoint).is_err() {
                last_action = match start_backend(config) {
                    Ok(()) => "Receiver started in the background".to_string(),
                    Err(err) => format!("Receiver start failed: {err}"),
                };
            }
            Self {
                snapshot: fetch_snapshot(&config.endpoint),
                last_action,
            }
        }

        fn update(&mut self, message: Message, context: &ComponentContext<Self>) {
            let config = GUI_CONFIG.get().expect("GUI config initialized");
            match message {
                Message::Refresh => {}
                Message::Tick => schedule_refresh(context),
                Message::StartReceiver => {
                    self.last_action = match start_backend(config) {
                        Ok(()) => "Receiver started in the background".to_string(),
                        Err(err) => format!("Receiver start failed: {err}"),
                    };
                }
                Message::RemoteCommand(command) => {
                    self.last_action = run_command(&config.endpoint, command);
                }
            }
            self.snapshot = fetch_snapshot(&config.endpoint);
        }

        fn view(&self, _input: &(), context: &mut ViewContext<Self>) -> View {
            context.window_title("Shairport RS");
            let config = GUI_CONFIG.get().expect("GUI config initialized");
            let online = self.snapshot.is_ok();

            let (status, client, track, source_format, output_format, ptp, remote) =
                status_strings(&self.snapshot);
            let mr_caps = match &self.snapshot {
                Ok(snapshot) => match snapshot.diagnostics.get("ap2_mr_supported_command_count") {
                    Some(count) => format!(
                        "MediaRemote sender capabilities: {count} commands — {}",
                        snapshot
                            .diagnostics
                            .get("ap2_mr_supported_commands")
                            .map(String::as_str)
                            .unwrap_or("summary unavailable")
                    ),
                    None => "MediaRemote sender capabilities: not received".to_string(),
                },
                Err(_) => "MediaRemote sender capabilities: unavailable".to_string(),
            };

            StackPanel::new().spacing(12.0).children((
                TextBlock::new().text("Shairport RS").font_size(30.0),
                TextBlock::new().text(status).font_size(18.0),
                TextBlock::new().text(format!("AirPlay client: {client}")),
                TextBlock::new().text(format!("Now playing: {track}")),
                TextBlock::new().text(format!("Source format: {source_format}")),
                TextBlock::new().text(format!("Output: {output_format}")),
                TextBlock::new().text(format!("PTP: {ptp}")),
                TextBlock::new().text(format!("Remote control: {remote}")),
                TextBlock::new().text(mr_caps),
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(8.0)
                    .children((
                        Button::new()
                            .is_enabled(online)
                            .on_click(context.message(Message::RemoteCommand("previous")))
                            .content("Previous"),
                        Button::new()
                            .is_enabled(online)
                            .on_click(context.message(Message::RemoteCommand("play")))
                            .content("Play"),
                        Button::new()
                            .is_enabled(online)
                            .on_click(context.message(Message::RemoteCommand("pause")))
                            .content("Pause"),
                        Button::new()
                            .is_enabled(online)
                            .on_click(context.message(Message::RemoteCommand("next")))
                            .content("Next"),
                        Button::new()
                            .is_enabled(online)
                            .on_click(context.message(Message::RemoteCommand("stop")))
                            .content("Stop"),
                    )),
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(8.0)
                    .children((
                        Button::new()
                            .on_click(context.message(Message::Refresh))
                            .content("Refresh"),
                        Button::new()
                            .is_enabled(!online)
                            .on_click(context.message(Message::StartReceiver))
                            .content("Start receiver"),
                    )),
                TextBlock::new().text(format!("API: {}", config.endpoint)),
                TextBlock::new().text(self.last_action.clone()),
            ))
        }
    }

    fn schedule_refresh(context: &ComponentContext<ReceiverGui>) {
        let _ = context.spawn_background(|cancel| {
            for _ in 0..10 {
                if cancel.is_cancelled() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Message::Tick
        });
    }

    fn status_strings(
        snapshot: &Result<Snapshot, String>,
    ) -> (String, String, String, String, String, String, String) {
        match snapshot {
            Ok(snapshot) => {
                let status = if snapshot.active {
                    format!("Receiver online — {}", snapshot.player_state)
                } else {
                    "Receiver online — idle".to_string()
                };
                let client = snapshot
                    .track
                    .client_name
                    .clone()
                    .unwrap_or_else(|| "No AirPlay client".to_string());
                let title = snapshot
                    .track
                    .title
                    .clone()
                    .unwrap_or_else(|| "No track metadata".to_string());
                let artist = snapshot.track.artist.clone().unwrap_or_default();
                let track = if artist.is_empty() {
                    title
                } else {
                    format!("{title} — {artist}")
                };
                let source = snapshot
                    .audio
                    .source_format
                    .clone()
                    .unwrap_or_else(|| "—".to_string());
                let output = snapshot
                    .audio
                    .output_format
                    .clone()
                    .or_else(|| snapshot.audio.selected_device.clone())
                    .unwrap_or_else(|| "—".to_string());
                let ptp = match snapshot.diagnostics.get("ptp_locked").map(String::as_str) {
                    Some("yes") | Some("true") => "Locked",
                    Some(value) => value,
                    None => "Unknown",
                }
                .to_string();
                let delivery = snapshot
                    .diagnostics
                    .get("remote_control_delivery")
                    .map(String::as_str)
                    .unwrap_or("none");
                let dacp = snapshot
                    .diagnostics
                    .get("remote_control_dacp_headers")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                let mrp = snapshot
                    .diagnostics
                    .get("remote_control_mrp_connected")
                    .map(String::as_str)
                    .unwrap_or("false");
                let remote = format!("delivery={delivery} · DACP={dacp} · MRP={mrp}");
                (status, client, track, source, output, ptp, remote)
            }
            Err(err) => (
                "Receiver offline".to_string(),
                "—".to_string(),
                "—".to_string(),
                "—".to_string(),
                "—".to_string(),
                "Unknown".to_string(),
                format!("API unavailable: {err}"),
            ),
        }
    }

    fn run_command(endpoint: &str, command: &'static str) -> String {
        match http_request(endpoint, "POST", &format!("/api/v1/remote/{command}")) {
            Ok(body) => serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.get("message")?.as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{command} accepted")),
            Err(err) => format!("{command} failed: {err}"),
        }
    }

    fn fetch_snapshot(endpoint: &str) -> Result<Snapshot, String> {
        let body = http_request(endpoint, "GET", "/api/v1/state")?;
        serde_json::from_str(&body).map_err(|err| format!("invalid state response: {err}"))
    }

    fn http_request(endpoint: &str, method: &str, path: &str) -> Result<String, String> {
        let mut addresses = endpoint
            .to_socket_addrs()
            .map_err(|err| format!("invalid API address {endpoint}: {err}"))?;
        let address = addresses
            .next()
            .ok_or_else(|| format!("API address {endpoint} did not resolve"))?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(350))
            .map_err(|err| err.to_string())?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(750)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(750)));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|err| err.to_string())?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|err| err.to_string())?;
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| "malformed HTTP response".to_string())?;
        let status = headers.lines().next().unwrap_or_default();
        if !status.contains(" 200 ") {
            return Err(status.to_string());
        }
        Ok(body.to_string())
    }

    fn start_backend(config: &GuiConfig) -> Result<(), String> {
        if fetch_snapshot(&config.endpoint).is_ok() {
            return Ok(());
        }
        let current = std::env::current_exe().map_err(|err| err.to_string())?;
        let backend = current.with_file_name("shairport-rs.exe");
        if !backend.exists() {
            return Err(format!("{} not found", backend.display()));
        }

        let mut command = Command::new(backend);
        if let Some(path) = &config.config_path {
            command.arg("--config").arg(path);
        }
        if config.debug {
            command.arg("--debug");
        }
        if config.endpoint != DEFAULT_ENDPOINT {
            command.arg("--server-bind").arg(&config.endpoint);
        }

        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
        command.spawn().map_err(|err| err.to_string())?;

        for _ in 0..20 {
            if fetch_snapshot(&config.endpoint).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!("receiver did not open API {}", config.endpoint))
    }

    fn parse_args() -> GuiConfig {
        let mut endpoint = DEFAULT_ENDPOINT.to_string();
        let mut config_path = None;
        let mut debug = false;
        let mut auto_start = true;
        let mut args = std::env::args_os().skip(1);
        while let Some(arg) = args.next() {
            match arg.to_string_lossy().as_ref() {
                "--api" => {
                    if let Some(value) = args.next() {
                        endpoint = value.to_string_lossy().into_owned();
                    }
                }
                "--config" => {
                    config_path = args.next().map(PathBuf::from);
                }
                "--debug" => debug = true,
                "--no-start-backend" => auto_start = false,
                _ => {}
            }
        }
        GuiConfig {
            endpoint,
            config_path,
            debug,
            auto_start,
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let config = parse_args();
        let _ = GUI_CONFIG.set(config);
        App::run_component::<ReceiverGui>(())?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_gui::run()
}
