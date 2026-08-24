use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::Context;
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use tracing::{debug, info, trace, warn};
use zeroize::Zeroizing;

static NEXT_RTSP_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

use crate::{
    airplay::pairing::{PairingCompletion, PairingEndpoint, PairingService, PairingSession},
    airplay::sdp::parse_sdp,
    airplay::session_crypto::SessionCrypto,
    airplay::{
        ap2::capability::Ap2CapabilityPolicy,
        ap2::contract::{Ap2StreamType, Ap2TimingProtocol},
        ap2::data::DataStreamListener,
        ap2::event::EventListener,
        ap2::session::{
            Ap2Configuration, Ap2SessionPhase, Ap2SessionState, Ap2Stream, Ap2StreamConfig,
            Ap2StreamState, Ap2TeardownTarget, TimingPeerListFormat, TransitionError,
            parse_initial_timing_peer, parse_timing_peer_list, validate_add_stream_phase,
            validate_transition,
        },
        buffered_audio::{BufferedStreamContext, advertised_audio_buffer_size},
        crypto::{IdentityKey, PairCipher},
        dacp::{DacpController, dacp_command_for_alias, is_navigation_alias},
        realtime_audio::RealtimeStreamContext,
        transcript::TranscriptRecorder,
    },
    audio::AudioEngine,
    codec::AudioFormat,
    config::AirplayConfig,
    decoder,
    player::SharedPlayer,
    playout::scheduler::{
        Ap2FlushRange, Ap2StreamRuntime, Ap2TimelineAnchor, PlaybackRate, PlayoutHandle,
    },
    ptp,
    state::{AppState, PlayerState},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RtspRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RtspResponse {
    pub code: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub async fn spawn_rtsp_server(
    config: AirplayConfig,
    state: AppState,
    audio_engine: AudioEngine,
    player: SharedPlayer,
    dacp: DacpController,
    playout: PlayoutHandle,
    ap2_policy: Ap2CapabilityPolicy,
) -> anyhow::Result<JoinHandle<()>> {
    let bind: SocketAddr = config
        .bind
        .parse()
        .with_context(|| format!("invalid AirPlay bind address {}", config.bind))?;
    let listener = bind_rtsp_listener(bind)
        .await
        .with_context(|| format!("failed to bind AirPlay RTSP listener {bind}"))?;
    let identity_key = IdentityKey::load_or_generate(
        config.identity_key_path.as_ref().map(std::path::Path::new),
        &config.device_id,
    );
    let pairing = Arc::new(PairingService::new(
        identity_key,
        config.device_id.clone(),
        config.pin.clone(),
        config
            .pairing_db_path
            .as_ref()
            .map(std::path::PathBuf::from),
    ));
    let transcript = config
        .transcript_path
        .as_deref()
        .map(std::path::Path::new)
        .map(TranscriptRecorder::create)
        .transpose()
        .with_context(|| "failed to create AP2 transcript")?
        .map(Arc::new);
    if let Some(path) = config.transcript_path.as_deref() {
        info!(path, "privacy-safe AP2 transcript enabled");
    }

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    let config = config.clone();
                    let pairing = pairing.clone();
                    let audio_engine = audio_engine.clone();
                    let player = player.clone();
                    let dacp = dacp.clone();
                    let playout = playout.clone();
                    let ap2_policy = ap2_policy;
                    let transcript = transcript.clone();
                    let transcript_connection = transcript
                        .as_ref()
                        .map(|recorder| recorder.allocate_connection());
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(
                            stream,
                            peer,
                            config,
                            state,
                            pairing,
                            audio_engine,
                            player,
                            dacp,
                            playout,
                            ap2_policy,
                            transcript,
                            transcript_connection,
                        )
                        .await
                        {
                            warn!(%peer, %err, "RTSP connection failed");
                        }
                    });
                }
                Err(err) => warn!(%err, "RTSP accept failed"),
            }
        }
    }))
}

async fn bind_rtsp_listener(bind: SocketAddr) -> anyhow::Result<TcpListener> {
    if bind.ip().is_ipv4() && bind.ip().is_unspecified() {
        let dual_stack_bind = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, bind.port()));
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        socket.bind(&dual_stack_bind.into())?;
        socket.listen(128)?;
        socket.set_nonblocking(true)?;
        let listener: std::net::TcpListener = socket.into();
        return TcpListener::from_std(listener).context("failed to create Tokio RTSP listener");
    }

    TcpListener::bind(bind).await.map_err(Into::into)
}

fn build_ap2_update_info_event(
    config: &AirplayConfig,
    peer_addr: Option<SocketAddr>,
    group_uuid: Option<&str>,
    group_contains_group_leader: Option<bool>,
    initial_volume_db: f64,
    ap2_policy: &Ap2CapabilityPolicy,
) -> anyhow::Result<Vec<u8>> {
    let info_body = get_info_body_with_group(
        config,
        peer_addr,
        group_uuid,
        group_contains_group_leader.unwrap_or(false),
        initial_volume_db,
        ap2_policy,
    );
    let info_value: Value =
        plist::from_bytes(&info_body).context("failed to parse generated /info plist")?;
    debug_ap2_info_payload("AP2 updateInfo value built", &info_value, group_uuid);
    let mut update_info = Dictionary::new();
    update_info.insert("type".to_string(), Value::String("updateInfo".to_string()));
    update_info.insert("value".to_string(), info_value);

    let mut body = Vec::new();
    plist::to_writer_binary(&mut body, &Value::Dictionary(update_info))
        .context("failed to serialize AP2 updateInfo plist")?;

    Ok(body)
}

fn spawn_ap2_control_receiver(bind_addr: SocketAddr) -> anyhow::Result<(u16, JoinHandle<()>)> {
    let std_socket = match bind_addr {
        SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?,
        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(false)?;
            socket
        }
    };
    std_socket.set_reuse_address(true)?;
    std_socket.bind(&bind_addr.into())?;
    std_socket.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(std_socket.into())?;
    let port = udp.local_addr()?.port();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut packet_number: u64 = 0;
        loop {
            match udp.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    if len < 28 {
                        debug!(%peer, len, "AP2 control: packet too short");
                        continue;
                    }
                    packet_number += 1;
                    let flags = buf[0];
                    let msg_type = buf[1];
                    match msg_type {
                        0xD7 => {
                            // Type 215: Anchoring announcement
                            let frame_1 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                            let remote_time = u64::from_be_bytes([
                                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14],
                                buf[15],
                            ]);
                            let frame_2 = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
                            let clock_id = u64::from_be_bytes([
                                buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26],
                                buf[27],
                            ]);
                            let latency = frame_2.wrapping_sub(frame_1);
                            debug!(
                                %peer,
                                packet_number,
                                clock_id = format!("{clock_id:016x}"),
                                frame_1,
                                frame_2,
                                latency,
                                remote_time,
                                "AP2 control: anchoring announcement received"
                            );
                        }
                        0xD6 => {
                            // Type 214: Encrypted audio/sync packet
                            debug!(
                                %peer,
                                packet_number,
                                len,
                                "AP2 control: encrypted sync packet received"
                            );
                        }
                        0xCE => {
                            // Type 206: Feedback
                            debug!(%peer, packet_number, len, "AP2 control: feedback packet");
                        }
                        0xCF => {
                            // Type 207: Timing sync
                            debug!(%peer, packet_number, len, "AP2 control: timing sync packet");
                        }
                        _ => {
                            debug!(
                                %peer,
                                packet_number,
                                msg_type = format!("0x{msg_type:02X}"),
                                len,
                                flags = format!("0x{flags:02X}"),
                                "AP2 control: unknown packet type"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(%e, "AP2 control receiver socket error");
                    break;
                }
            }
        }
    });
    info!(port, "AP2 control receiver started");
    Ok((port, handle))
}

fn receiver_timing_addresses(primary: IpAddr) -> Vec<String> {
    let mut addresses = Vec::new();
    push_unique_ip(&mut addresses, primary);
    for ip in local_non_loopback_interface_addresses() {
        push_unique_ip(&mut addresses, ip);
    }
    addresses
}

fn receiver_primary_ip(socket_ip: Option<IpAddr>, override_ip: Option<&str>) -> IpAddr {
    if let Some(override_ip) = override_ip {
        match override_ip.parse::<IpAddr>() {
            Ok(ip) if !ip.is_unspecified() => return ip,
            Ok(ip) => warn!(%ip, "ignoring AP2 bind IP override because it is not usable"),
            Err(e) => warn!(%override_ip, %e, "ignoring invalid AP2 bind IP override"),
        }
    }

    if let Some(ip) = socket_ip
        && !ip.is_unspecified()
    {
        return ip;
    }

    let interface_ips = local_non_loopback_interface_addresses();
    interface_ips
        .into_iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| local_non_loopback_interface_addresses().into_iter().next())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn event_bind_addr(local_addr: Option<SocketAddr>, primary_ip: IpAddr) -> SocketAddr {
    match local_addr {
        Some(SocketAddr::V4(addr))
            if IpAddr::V4(*addr.ip()) == primary_ip
                && !addr.ip().is_unspecified()
                && !addr.ip().is_loopback() =>
        {
            SocketAddr::from((*addr.ip(), 0))
        }
        Some(SocketAddr::V6(addr))
            if IpAddr::V6(*addr.ip()) == primary_ip
                && !addr.ip().is_unspecified()
                && !addr.ip().is_loopback() =>
        {
            SocketAddr::from(std::net::SocketAddrV6::new(
                *addr.ip(),
                0,
                0,
                addr.scope_id(),
            ))
        }
        _ => SocketAddr::new(primary_ip, 0),
    }
}

fn push_unique_ip(addresses: &mut Vec<String>, ip: IpAddr) {
    if ip.is_unspecified() {
        return;
    }
    let address = ip.to_string();
    if !addresses.iter().any(|candidate| candidate == &address) {
        addresses.push(address);
    }
}

#[cfg(unix)]
fn local_non_loopback_interface_addresses() -> Vec<IpAddr> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    let mut ips = Vec::new();

    // SAFETY: getifaddrs initializes a linked list owned by libc. We only read
    // sockaddr fields while the list is alive and always release it with
    // freeifaddrs before returning.
    unsafe {
        if libc::getifaddrs(&mut addrs) != 0 {
            return ips;
        }

        let mut cursor = addrs;
        while !cursor.is_null() {
            let ifa = &*cursor;
            let flags = ifa.ifa_flags as libc::c_uint;
            let is_up = flags & libc::IFF_UP as libc::c_uint != 0;
            let is_loopback = flags & libc::IFF_LOOPBACK as libc::c_uint != 0;
            if !ifa.ifa_addr.is_null() && !ifa.ifa_netmask.is_null() && is_up && !is_loopback {
                let family = (*ifa.ifa_addr).sa_family as libc::c_int;
                match family {
                    libc::AF_INET => {
                        let sockaddr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes()));
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            ips.push(ip);
                        }
                    }
                    libc::AF_INET6 => {
                        let sockaddr = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(sockaddr.sin6_addr.s6_addr));
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            ips.push(ip);
                        }
                    }
                    _ => {}
                }
            }
            cursor = ifa.ifa_next;
        }

        libc::freeifaddrs(addrs);
    }

    ips
}

#[cfg(not(unix))]
fn local_non_loopback_interface_addresses() -> Vec<IpAddr> {
    Vec::new()
}

/// Bundles the set of shared services / configuration that almost every RTSP
/// handler needs.  This keeps function signatures under the clippy
/// `too_many_arguments` limit (7) without burying the ownership / cleanup
/// logic inside an opaque mega-struct.
struct ConnectionServices<'a> {
    config: &'a AirplayConfig,
    state: &'a AppState,
    pairing: &'a PairingService,
    audio_engine: &'a AudioEngine,
    playout: &'a PlayoutHandle,
    player: &'a SharedPlayer,
    dacp: &'a DacpController,
    ap2_policy: &'a Ap2CapabilityPolicy,
}

/// Entry point for a per-peer RTSP connection.  This function receives owned
/// values and creates the borrowed [`ConnectionServices`] context; it has 8
/// parameters by design (the spawned-task boundary requires ownership transfer).
/// All downstream functions use the slimmer context struct.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: AirplayConfig,
    state: AppState,
    pairing: Arc<PairingService>,
    audio_engine: AudioEngine,
    player: SharedPlayer,
    dacp: DacpController,
    playout: PlayoutHandle,
    ap2_policy: Ap2CapabilityPolicy,
    transcript: Option<Arc<TranscriptRecorder>>,
    transcript_connection: Option<u64>,
) -> anyhow::Result<()> {
    debug!(%peer, "RTSP connection opened");
    let mut session = RtspSession::default();
    session.connection_id = NEXT_RTSP_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    session.local_addr = stream.local_addr().ok();
    session.peer_addr = Some(peer);
    session.transcript = transcript;
    session.transcript_connection = transcript_connection;

    let services = ConnectionServices {
        config: &config,
        state: &state,
        pairing: &pairing,
        audio_engine: &audio_engine,
        playout: &playout,
        player: &player,
        dacp: &dacp,
        ap2_policy: &ap2_policy,
    };

    // Run the inner request/response loop.  Every exit from this inner
    // function — whether clean EOF, read error, write error, or encryption
    // error — flows through the idempotent cleanup block below, matching
    // the pthread cleanup handler in shairport-sync C.
    let result = process_rtsp_requests(stream, peer, &services, &mut session).await;

    // --- Idempotent per-connection cleanup (safe to call regardless of
    //     how the inner function exited).  TEARDOWN already performs an
    //     equivalent cleanup, so this is a safety-net for EOF/error exits. ---
    perform_connection_cleanup(
        &state,
        &audio_engine,
        &player,
        &dacp,
        &playout,
        &mut session,
    );

    match &result {
        Ok(()) => debug!(%peer, "RTSP connection closed cleanly"),
        Err(e) => warn!(%peer, %e, "RTSP connection closed with error (cleanup performed)"),
    }

    result
}

/// Maximum plaintext buffer size for an RTSP control connection.
///
/// Metadata and artwork requests can be substantially larger than ordinary
/// RTSP control messages. This 16 MiB bound permits those requests while
/// preventing unbounded accumulation from a never-ending message.
const MAX_PLAINTEXT_CONTROL_BUF: usize = 16 * 1024 * 1024;

/// Maximum encrypted buffer size for an RTSP control connection.
///
/// Each encrypted block carries at most `MAX_BLOCK + 2 + 16 = 1042` bytes,
/// so this buffer holds ~62 blocks.  Encrypted frames that never
/// complete will exhaust this buffer and the connection is dropped.
const MAX_ENCRYPTED_CONTROL_BUF: usize = 65536;

/// Decrypt one or more blocks from `encrypted_buf` and append decrypted
/// plaintext into `plaintext_buf`.  Returns the number of encrypted bytes
/// consumed (may be zero for incomplete frames).
///
/// # Errors
///
/// Returns [`CipherError::BlockTooLarge`] if a length prefix exceeds
/// [`MAX_BLOCK`], or [`CipherError::AuthFailed`] if authentication fails.
/// Neither error advances the cipher counter.
fn append_control_plaintext(plaintext_buf: &mut Vec<u8>, plaintext: &[u8]) -> anyhow::Result<()> {
    let new_len = plaintext_buf
        .len()
        .checked_add(plaintext.len())
        .ok_or_else(|| anyhow::anyhow!("plaintext control buffer length overflow"))?;
    if new_len > MAX_PLAINTEXT_CONTROL_BUF {
        return Err(anyhow::anyhow!("plaintext control buffer limit exceeded"));
    }
    plaintext_buf.extend_from_slice(plaintext);
    Ok(())
}

fn append_encrypted_control(encrypted_buf: &mut Vec<u8>, encrypted: &[u8]) -> anyhow::Result<()> {
    let new_len = encrypted_buf
        .len()
        .checked_add(encrypted.len())
        .ok_or_else(|| anyhow::anyhow!("encrypted control buffer length overflow"))?;
    if new_len > MAX_ENCRYPTED_CONTROL_BUF {
        return Err(anyhow::anyhow!("encrypted control buffer limit exceeded"));
    }
    encrypted_buf.extend_from_slice(encrypted);
    Ok(())
}

fn decrypt_control_blocks(
    cipher: &mut PairCipher,
    encrypted_buf: &[u8],
    plaintext_buf: &mut Vec<u8>,
) -> anyhow::Result<usize> {
    let (plaintext, consumed) = cipher
        .decrypt_blocks(encrypted_buf)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    append_control_plaintext(plaintext_buf, &plaintext)?;
    Ok(consumed)
}

/// Move bytes that followed a terminal plaintext pairing request into the
/// newly activated encrypted stream. This must run only on the exact
/// plaintext-to-encrypted transition; residual bytes from an already-encrypted
/// request are already plaintext and must never be decrypted twice.
fn handoff_coalesced_encrypted_control(
    cipher_was_active: bool,
    cipher: Option<&mut PairCipher>,
    plaintext_buf: &mut Vec<u8>,
    encrypted_buf: &mut Vec<u8>,
) -> anyhow::Result<()> {
    if cipher_was_active || plaintext_buf.is_empty() {
        return Ok(());
    }
    let Some(cipher) = cipher else {
        return Ok(());
    };

    let residual = std::mem::take(plaintext_buf);
    append_encrypted_control(encrypted_buf, &residual)?;
    let consumed = decrypt_control_blocks(cipher, encrypted_buf, plaintext_buf)?;
    if consumed > 0 {
        encrypted_buf.drain(..consumed);
    }
    Ok(())
}

/// Inner request/response loop extracted from [`handle_connection`] so that
/// every exit path (EOF, read/write error, encryption failure) returns to a
/// single point where per-connection cleanup is guaranteed.
async fn process_rtsp_requests(
    mut stream: TcpStream,
    peer: SocketAddr,
    svc: &ConnectionServices<'_>,
    session: &mut RtspSession,
) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(8192);
    let mut encrypted_buf = Vec::with_capacity(8192);
    loop {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            debug!(%peer, "RTSP connection closed by client (read EOF)");
            return Ok(());
        }
        trace!(%peer, bytes_read = read, "RTSP raw read");

        if let Some(ref mut cipher) = session.control_cipher {
            append_encrypted_control(&mut encrypted_buf, &chunk[..read]).map_err(|e| {
                warn!(%peer, %e, "encrypted control buffer rejected");
                e
            })?;
            match decrypt_control_blocks(cipher, &encrypted_buf, &mut buf) {
                Ok(consumed) => {
                    trace!(
                        %peer,
                        encrypted_read = read,
                        encrypted_pending = encrypted_buf.len(),
                        encrypted_consumed = consumed,
                        "RTSP control stream decrypted"
                    );
                    if consumed > 0 {
                        encrypted_buf.drain(..consumed);
                    }
                }
                Err(e) => {
                    warn!(
                        %peer,
                        %e,
                        encrypted_pending = encrypted_buf.len(),
                        "RTSP control stream decryption failed"
                    );
                    return Err(anyhow::anyhow!(e.to_string()));
                }
            }
        } else {
            append_control_plaintext(&mut buf, &chunk[..read]).map_err(|e| {
                warn!(%peer, %e, "plaintext control buffer rejected");
                e
            })?;
        }

        while let Some((request, consumed)) = parse_request(&buf) {
            log_request(peer, &request);

            // Capture cipher state BEFORE routing: a terminal pairing
            // request may install the control cipher, but its own
            // response must still be sent as plaintext.
            let cipher_was_active = session.control_cipher.is_some();
            let encrypt_response = cipher_was_active;

            let response = route_request(svc, session, &request);

            log_response(peer, &request, &response);
            if let (Some(recorder), Some(connection)) =
                (session.transcript.as_ref(), session.transcript_connection)
                && let Err(error) = recorder.record_exchange(connection, &request, &response)
            {
                warn!(%error, "AP2 transcript write failed");
            }
            let wire = response.to_bytes();
            let wire_len = if encrypt_response {
                let Some(ref mut cipher) = session.control_cipher else {
                    return Err(anyhow::anyhow!(
                        "control cipher disappeared before response write"
                    ));
                };
                let prepared = cipher.prepare_encryption(&wire).map_err(|error| {
                    warn!(%peer, %error, "RTSP control stream encryption failed");
                    anyhow::anyhow!(error.to_string())
                })?;
                let encrypted_len = prepared.ciphertext().len();
                trace!(
                    %peer,
                    plaintext_len = wire.len(),
                    encrypted_len,
                    "RTSP control stream encrypted"
                );
                stream.write_all(prepared.ciphertext()).await?;
                prepared.commit();
                encrypted_len
            } else {
                stream.write_all(&wire).await?;
                wire.len()
            };
            trace!(%peer, wire_len, encrypted = encrypt_response, "RTSP response wire");
            buf.drain(..consumed);

            // A terminal plaintext pairing request may activate encryption.
            // Only in that exact transition are residual bytes ciphertext.
            if !cipher_was_active && session.control_cipher.is_some() && !buf.is_empty() {
                debug!(
                    %peer,
                    residual_len = buf.len(),
                    "coalesced transition: decrypting bytes after terminal pairing request"
                );
                handoff_coalesced_encrypted_control(
                    cipher_was_active,
                    session.control_cipher.as_mut(),
                    &mut buf,
                    &mut encrypted_buf,
                )?;
            }
        }
        // If we have residual data but no complete message, log at trace
        if !buf.is_empty() {
            trace!(%peer, pending = buf.len(), "RTSP incomplete frame waiting for more data");
        }
        if !encrypted_buf.is_empty() {
            trace!(%peer, encrypted_pending = encrypted_buf.len(), "RTSP encrypted frame waiting for more data");
        }
    }
}

/// Idempotent per-connection cleanup.  Safe to call multiple times (TEARDOWN
/// may have already run an equivalent cleanup; subsequent calls are no-ops).
///
/// Only a connection that actually established / controlled the principal
/// playback session (marked via [`RtspSession::is_playback_owner`]) may clear
/// global playback state, crypto, and DACP.  Non-owner connections — e.g.
/// OPTIONS-only probes or ancillary AP2 control sockets that never issued a
/// successful ANNOUNCE / audio SETUP — only abort their own listener tasks.
///
/// Matches the pthread cleanup handler `rtsp_conversation_thread_cleanup_function`
/// in shairport-sync C but with explicit ownership gating.
fn perform_connection_cleanup(
    state: &AppState,
    _audio_engine: &AudioEngine,
    player: &SharedPlayer,
    dacp: &DacpController,
    playout: &PlayoutHandle,
    session: &mut RtspSession,
) {
    state.clear_ptp_master_if_owner(session.connection_id);
    let had_audio_stream = session.ap2.find_audio_stream().is_some();
    // Call begin_teardown + close idempotently.
    let _ = session.ap2.begin_teardown();

    if session.is_playback_owner {
        player.stop();
        if had_audio_stream {
            playout.clear_stream();
        } else {
            playout.stop();
        }
        state.set_active(false);
        state.set_player_state(PlayerState::Stopped);
        *state.session_crypto.write() = None;
        state.clear_ap1_remote_endpoints();
        session.ap1_remote_control_port = None;
        session.ap1_remote_timing_port = None;
        dacp.clear_session();
        session.is_playback_owner = false;
    }
    // Always clear this session's AP2 secrets and listeners,
    // regardless of playback ownership.
    session.fairplay = FairPlayState::NotStarted;
    session.abort_ap2_listeners();
    // close() now calls clear_sensitive() internally.
    let _ = session.ap2.close();
}

/// Activate a [`PairingCompletion`] on the session.
///
/// # Control encryption behaviour
///
/// | Completion         | Marks Paired | Installs `control_cipher` |
/// |--------------------|:------------:|:-------------------------:|
/// | `TransientSetup`   | ✓            | ✓ (SRP session key K)    |
/// | `FullSetup`        | ✓            | **no** — stays plaintext |
/// | `Verify`           | ✓            | ✓ (X25519 shared secret) |
///
/// **Transient** pair-setup has no subsequent pair-verify; the SRP session
/// key is therefore used directly for control encryption.
///
/// **Non-transient (Full)** pair-setup persists the client identity to the
/// database but deliberately does *not* activate control encryption.  The
/// next pair-verify exchange must happen in plaintext; only a successful
/// `Verify` completion installs the control `PairCipher`.
fn activate_pairing_completion(
    session: &mut RtspSession,
    completion: &PairingCompletion,
) -> Result<(), TransitionError> {
    // Validate lifecycle state before installing any new ciphers.
    session.ap2.mark_paired()?;
    match completion {
        PairingCompletion::TransientSetup { key, .. } => {
            session.control_cipher = Some(PairCipher::control_for_server(key));
        }
        PairingCompletion::FullSetup { .. } => {
            // Non-transient (full) pair-setup persists the client to the
            // pairing database and marks the session Paired, but does NOT
            // activate RTSP control encryption.  The next pair-verify
            // exchange is plaintext; only successful Verify installs the
            // control PairCipher (using the fresh X25519 shared secret,
            // not the SRP session key).
        }
        PairingCompletion::Verify { shared_secret } => {
            session.control_cipher = Some(PairCipher::control_for_server(shared_secret));
        }
    }
    Ok(())
}

fn route_request(
    svc: &ConnectionServices<'_>,
    session: &mut RtspSession,
    request: &RtspRequest,
) -> RtspResponse {
    // Unpack the services bundle so the rest of the function body stays
    // readable and unchanged.  The function signature is the part clippy
    // inspects for `too_many_arguments`.
    let config = svc.config;
    let state = svc.state;
    let pairing = svc.pairing;
    let audio_engine = svc.audio_engine;
    let playout = svc.playout;
    let player = svc.player;
    let dacp = svc.dacp;
    let ap2_policy = svc.ap2_policy;

    if let Some(client_name) = request.headers.get("X-Apple-Client-Name") {
        state.set_client_name(client_name.clone());
    }
    update_dacp_session_from_headers(dacp, session, request);

    // Log any request body at debug level for non-OPTIONS methods
    if request.method != "OPTIONS" && request.method != "GET_PARAMETER" {
        debug!(
            method = %request.method,
            uri = %request.uri,
            content_type = request.headers.get("Content-Type").map(|s| s.as_str()).unwrap_or(""),
            body_len = request.body.len(),
            "RTSP handler"
        );
    }

    let mut resp = match (request.method.as_str(), request.uri.as_str()) {
        ("OPTIONS", _) => {
            let public = if config.airplay2_enabled {
                "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, SETPEERS"
            } else {
                "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER"
            };
            response(200, "OK")
                .header("Public", public)
                .with_cseq(request)
        }
        ("GET", "/info") | ("GET", "info") => {
            let initial_volume_db = state.snapshot().volume.airplay_db;
            response(200, "OK")
                .header("Content-Type", "application/x-apple-binary-plist")
                .body(get_info_body(
                    config,
                    session.peer_addr,
                    initial_volume_db,
                    ap2_policy,
                ))
                .with_cseq(request)
        }
        ("ANNOUNCE", _) => {
            info!("AP1 ANNOUNCE received ({} bytes body)", request.body.len());
            // Clear any stale session crypto from a previous ANNOUNCE before
            // populating fresh key material.  This matches the C behaviour
            // where conn->stream.aeskey / aesiv are simply overwritten each
            // ANNOUNCE, and the player thread sees the latest values atomically.
            *state.session_crypto.write() = None;
            // Also clear ALAC state so the RTP decoder re-initialises on the
            // first packet of the new stream.
            *state.alac_magic_cookie.write() = None;
            *state.alac_sample_rate.write() = None;
            *state.alac_sample_size.write() = None;
            *state.alac_channels.write() = None;
            *state.frames_per_packet.write() = None;
            state
                .track_transition_epoch
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

            let sdp = String::from_utf8_lossy(&request.body);
            let parsed = parse_sdp(&sdp);
            state.set_source_format(parsed.source_format_description());
            let params = parsed.classic_params();

            // --- Classic AirPlay crypto: unwrap rsaaeskey with the well-known
            //     Shairport Sync / AirPort Express RSA private key, then pair
            //     it with aesiv into a SessionCrypto stored on the app state.
            //
            //     RSA-OAEP output MUST be exactly 16 bytes (matching rtsp.c);
            //     any other length is rejected rather than truncated.  Partial
            //     key/IV material returns RTSP 456 (Parameter Not Understood)
            //     and leaves the classic crypto slot cleared. ---
            let has_encryption = params.rsaaeskey.is_some();
            let mut crypto_err: Option<&'static str> = None;
            let mut aes_key: Option<[u8; 16]> = None;
            let mut aes_iv: Option<[u8; 16]> = None;

            if let Some(encrypted_key) = &params.rsaaeskey {
                match decoder::classic_rsa_oaep_decrypt(encrypted_key) {
                    Ok(aes_key_bytes) => {
                        if aes_key_bytes.len() == 16 {
                            let mut k = [0u8; 16];
                            k.copy_from_slice(&aes_key_bytes);
                            aes_key = Some(k);
                            info!("classic AirPlay AES session key derived");
                        } else {
                            warn!(
                                len = aes_key_bytes.len(),
                                "RSA-OAEP output not exactly 16 bytes"
                            );
                            crypto_err = Some("decrypted AES key has wrong length");
                        }
                    }
                    Err(e) => {
                        warn!(%e, "RSA-OAEP decryption of AES key failed with classic key");
                        crypto_err = Some("RSA-OAEP decryption failed");
                    }
                }
            }

            if let Some(iv) = &params.aesiv {
                if iv.len() == 16 {
                    let mut v = [0u8; 16];
                    v.copy_from_slice(iv);
                    aes_iv = Some(v);
                } else {
                    warn!(len = iv.len(), "aesiv is not 16 bytes");
                    crypto_err = Some("aesiv wrong length");
                }
            }

            // If the sender provides encryption material, all of it must be
            // valid.  A partial key (rsaaeskey without aesiv, or vice-versa)
            // is an error.  Unencrypted sessions (no rsaaeskey at all) are
            // also rejected because our classic RTP path requires AES-CBC;
            // accepting them would succeed the ANNOUNCE but silently drop
            // every audio packet.
            if crypto_err.is_none() && has_encryption && aes_key.is_none() {
                crypto_err = Some("rsaaeskey provided but decryption produced no valid key");
            }
            if crypto_err.is_none() && has_encryption && aes_iv.is_none() {
                crypto_err = Some("rsaaeskey provided but aesiv is missing or invalid");
            }
            if crypto_err.is_none() && !has_encryption {
                crypto_err = Some("unencrypted classic AirPlay sessions are not supported");
            }

            if let Some(err) = crypto_err {
                warn!(%err, "ANNOUNCE crypto rejected");
                return response(456, "Parameter Not Understood").with_cseq(request);
            }

            // Both key and IV are valid — store session crypto.
            if let (Some(key), Some(iv)) = (aes_key, aes_iv)
                && let Some(crypto) = SessionCrypto::new(&key, &iv)
            {
                *state.session_crypto.write() = Some(crypto);
                session.is_playback_owner = true;
                info!("classic AirPlay session crypto stored");
            }

            // --- ALAC format parameters ---
            if let Some(asc) = &params.alac_specific_config {
                state
                    .alac_magic_cookie
                    .write()
                    .clone_from(&Some(asc.clone()));
            }
            if let Some(rate) = params.alac_sample_rate {
                state.alac_sample_rate.write().clone_from(&Some(rate));
            }
            if let Some(bits) = params.alac_bit_depth {
                state.alac_sample_size.write().clone_from(&Some(bits));
            }
            if let Some(fpp) = params.frames_per_packet {
                state.frames_per_packet.write().clone_from(&Some(fpp));
            }
            state.alac_channels.write().clone_from(&Some(2));

            response(200, "OK").with_cseq(request)
        }
        ("POST", "/pair-setup") => {
            let mut reply =
                pairing.handle(&mut session.pairing, PairingEndpoint::Setup, &request.body);
            if let Some(ref completion) = reply.completion
                && let Err(e) = activate_pairing_completion(session, completion)
            {
                session.pairing.clear();
                reply.completion = None;
                warn!(%e, "pair-setup completion rejected by lifecycle");
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", format!("cannot mark paired: {e}"))
                    .with_cseq(request);
            }
            info!(
                status = reply.status_code,
                body_len = reply.body.len(),
                completed = reply.completion.is_some(),
                "pair-setup step"
            );
            response(reply.status_code, "OK")
                .header("Content-Type", "application/octet-stream")
                .body(reply.body)
                .with_cseq(request)
        }
        ("POST", "/pair-pin-start") => response(200, "OK").with_cseq(request),
        ("POST", "/pair-add") => {
            let reply = pairing.handle(&mut session.pairing, PairingEndpoint::Add, &request.body);
            response(reply.status_code, "OK")
                .header("Content-Type", "application/octet-stream")
                .body(reply.body)
                .with_cseq(request)
        }
        ("POST", "/pair-remove") => {
            let reply =
                pairing.handle(&mut session.pairing, PairingEndpoint::Remove, &request.body);
            response(reply.status_code, "OK")
                .header("Content-Type", "application/octet-stream")
                .body(reply.body)
                .with_cseq(request)
        }
        ("POST", "/pair-list") => {
            let reply = pairing.handle(&mut session.pairing, PairingEndpoint::List, &request.body);
            response(reply.status_code, "OK")
                .header("Content-Type", "application/octet-stream")
                .body(reply.body)
                .with_cseq(request)
        }
        ("POST", "/pair-verify") => {
            let mut reply =
                pairing.handle(&mut session.pairing, PairingEndpoint::Verify, &request.body);
            if let Some(ref completion) = reply.completion
                && let Err(e) = activate_pairing_completion(session, completion)
            {
                session.pairing.clear();
                reply.completion = None;
                warn!(%e, "pair-verify completion rejected by lifecycle");
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", format!("cannot mark paired: {e}"))
                    .with_cseq(request);
            }
            info!(
                status = reply.status_code,
                completed = reply.completion.is_some(),
                "pair-verify step"
            );
            response(reply.status_code, "OK")
                .header("Content-Type", "application/octet-stream")
                .body(reply.body)
                .with_cseq(request)
        }
        ("POST", "/fp-setup") => handle_fairplay_setup(session, request).with_cseq(request),
        ("POST", "/command") => {
            // Command endpoint receives encrypted plist commands
            apply_ap2_command(state, audio_engine, playout, player, dacp, request);
            info!("received /command ({} bytes)", request.body.len());
            response(200, "OK")
                .header("Content-Type", "application/octet-stream")
                .body(Vec::new())
                .with_cseq(request)
        }
        ("POST", "/feedback") => handle_feedback(session, request).with_cseq(request),
        ("POST", "/audioMode") => handle_audio_mode(state, session, request).with_cseq(request),
        ("POST", "/configure") => {
            handle_configure(config, state, session, pairing, request).with_cseq(request)
        }
        ("SETPEERS", _) => handle_setpeers(state, session, request, TimingPeerListFormat::Legacy)
            .with_cseq(request),
        ("SETPEERSX", _) => {
            handle_setpeers(state, session, request, TimingPeerListFormat::Extended)
                .with_cseq(request)
        }
        ("SETRATEANCHORTI", _) | ("SETRATEANCHORTIME", _) => {
            let Some(sample_rate) = session
                .ap2
                .find_audio_stream()
                .and_then(Ap2Stream::sample_rate)
            else {
                return response(455, "Method Not Valid in This State")
                    .header(
                        "X-Reason",
                        "AP2 audio stream must be configured before anchor",
                    )
                    .with_cseq(request);
            };
            let control = match parse_setrateanchortime(request, sample_rate) {
                Ok(control) => control,
                Err(reason) => {
                    warn!(reason, "SETRATEANCHORTIME rejected");
                    return response(400, "Bad Request")
                        .header("X-Reason", reason)
                        .with_cseq(request);
                }
            };
            if control.rate == PlaybackRate::Normal && !session.ap2.record_requested() {
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", "RECORD must be accepted before rate=1")
                    .with_cseq(request);
            }
            let transition = match control.rate {
                PlaybackRate::Normal => session.ap2.resume(),
                PlaybackRate::Paused => session.ap2.pause(),
            };
            if let Err(e) = transition {
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", format!("invalid phase for rate change: {e}"))
                    .with_cseq(request);
            }
            apply_setrateanchortime(state, playout, control);
            response(200, "OK").with_cseq(request)
        }
        ("GET_PARAMETER", _) => get_parameter_response(state, request),
        ("SET_PARAMETER", _) => {
            apply_set_parameter(
                state,
                audio_engine,
                playout,
                dacp,
                session.peer_addr,
                request,
            );
            response(200, "OK").with_cseq(request)
        }
        ("SETUP", _) => {
            // Detect AP2 SETUP from Content-Type
            let is_ap2 = request
                .headers
                .get("Content-Type")
                .map(|ct| ct.contains("application/x-apple-binary-plist"))
                .unwrap_or(false);

            if is_ap2 && config.airplay2_enabled {
                let response = handle_ap2_setup_with_transcript(
                    config,
                    state,
                    session,
                    request,
                    playout,
                    dacp,
                    ap2_policy,
                    session.transcript.clone(),
                    session.transcript_connection,
                )
                .with_cseq(request);
                if (200..300).contains(&response.code) {
                    session.session_id = Some("1".to_string());
                }
                response
            } else if is_ap2 {
                // AP2 plist but AP2 is disabled - respond with error
                warn!("AP2 SETUP received but airplay2_enabled is false");
                response(501, "Not Implemented").with_cseq(request)
            } else {
                // Classic AP1 SETUP
                info!(
                    "AP1 SETUP — requesting audio on ports {} {} {}",
                    config.audio_port, config.control_port, config.timing_port
                );
                let server_port = config.audio_port;
                let control_port = config.control_port;
                let timing_port = config.timing_port;

                // Parse remote control/timing ports from the Transport header.
                // If the client does not supply valid ports we MUST return 400
                // rather than advertise a transport that cannot support timing/resend.
                let Some(transport_val) = request
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("Transport"))
                    .map(|(_, value)| value)
                else {
                    warn!("AP1 SETUP missing Transport header");
                    return response(400, "Bad Request")
                        .header("X-Reason", "missing Transport header")
                        .with_cseq(request);
                };
                let params = match parse_ap1_transport_header(transport_val) {
                    Ok(params) => params,
                    Err(err) => {
                        warn!(%err, transport_val, "AP1 SETUP invalid Transport header");
                        return response(400, "Bad Request")
                            .header("X-Reason", format!("invalid transport: {err}"))
                            .with_cseq(request);
                    }
                };
                let Some(peer) = session.peer_addr else {
                    warn!("AP1 SETUP has no connection peer address");
                    return response(400, "Bad Request")
                        .header("X-Reason", "missing peer address")
                        .with_cseq(request);
                };
                info!(
                    remote_control = params.control_port,
                    remote_timing = params.timing_port,
                    "AP1 SETUP remote ports parsed"
                );
                state.set_ap1_remote_endpoints(peer.ip(), params.control_port, params.timing_port);
                session.ap1_remote_control_port = Some(params.control_port);
                session.ap1_remote_timing_port = Some(params.timing_port);
                session.session_id = Some("1".to_string());
                state.set_active(true);

                info!(server_port, control_port, timing_port, "AP1 SETUP");
                response(200, "OK")
                    .header("Session", "1")
                    .header(
                        "Transport",
                        format!(
                            "RTP/AVP/UDP;unicast;mode=record;server_port={};control_port={};timing_port={}",
                            server_port, control_port, timing_port
                        ),
                    )
                    .with_cseq(request)
            }
        }
        ("RECORD", _) => {
            if session.ap2.is_ap2_active() || session.control_cipher.is_some() {
                info!(
                    phase = %session.ap2.phase(),
                    timing_protocol = ?session.ap2.timing_protocol(),
                    remote_control_only = session.ap2.is_remote_control_only(),
                    "AP2 RECORD"
                );
                state.set_diagnostic("ap2_phase", "record");

                // Remote-control-only session: allow RECORD without streams.
                if session.ap2.is_remote_control_only() && !session.ap2.has_streams() {
                    info!("AP2 RECORD accepted for remote-control-only session (no audio)");
                    return response(200, "OK")
                        .header("Audio-Latency", "0")
                        .with_cseq(request);
                }

                // A real sender may RECORD directly after timing SETUP and
                // configure its type-103 stream only after RECORD succeeds.
                if !session.ap2.has_streams() {
                    if let Err(e) = session.ap2.prepare_recording() {
                        warn!(%e, "AP2 pre-stream RECORD rejected");
                        return response(455, "Method Not Valid in This State")
                            .header("X-Reason", format!("invalid phase for RECORD: {e}"))
                            .with_cseq(request);
                    }
                    state.set_diagnostic("ap2_phase", "record-awaiting-stream");
                    info!("AP2 RECORD accepted; awaiting stream SETUP");
                    return response(200, "OK")
                        .header("Audio-Latency", "0")
                        .with_cseq(request);
                }

                // Transition to Recording
                if let Err(e) = session.ap2.begin_recording() {
                    warn!(%e, "AP2 RECORD rejected — invalid phase transition");
                    return response(455, "Method Not Valid in This State")
                        .header("X-Reason", format!("invalid phase for RECORD: {e}"))
                        .with_cseq(request);
                }
                playout.record();
                state.set_active(true);
                state.set_player_state(PlayerState::Playing);
                state.set_diagnostic("ap2_play_enabled", "pending-anchor");
                let audio_latency = session
                    .ap2
                    .find_audio_stream()
                    .and_then(Ap2Stream::sample_rate)
                    .map(|sample_rate| playout.start_latency_frames(sample_rate))
                    .unwrap_or(0);

                return response(200, "OK")
                    .header("Audio-Latency", audio_latency.to_string())
                    .with_cseq(request);
            }

            let latency = request
                .headers
                .get("X-Apple-Latency")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(11025);
            let rate = state.alac_sample_rate.read().unwrap_or(44100);
            player.set_sample_rate(rate);
            player.start(latency);
            enable_audio_when_track_ready(state, playout);
            state.set_player_state(PlayerState::Playing);
            state.set_diagnostic("ap1_latency", latency.to_string());
            info!(latency, "AP1 RECORD");

            response(200, "OK")
                .header("Audio-Latency", latency.to_string())
                .header("Audio-Jack-Status", "connected; type=analog")
                .with_cseq(request)
        }
        ("FLUSH", _) => {
            player.flush();
            playout.pause();
            playout.flush();
            state.set_player_state(PlayerState::Paused);
            info!("AP1 FLUSH");
            response(200, "OK").with_cseq(request)
        }
        ("PAUSE", _) => {
            if session.ap2.is_ap2_active() {
                // Validate phase transition first — no side effects until OK.
                if let Err(e) = session.ap2.pause() {
                    warn!(%e, "PAUSE rejected — invalid phase transition");
                    return response(455, "Method Not Valid in This State")
                        .header("X-Reason", format!("invalid phase for PAUSE: {e}"))
                        .with_cseq(request);
                }
                // Only now apply playback side effects.
                playout.set_playback_rate(PlaybackRate::Paused);
                state.set_player_state(PlayerState::Paused);
            } else {
                pause_playback(state, playout, player);
            }
            info!("PAUSE");
            response(200, "OK").with_cseq(request)
        }
        ("FLUSHBUFFERED", _) => {
            let flush_range = match parse_flushbuffered(request) {
                Ok(range) => range,
                Err(reason) => {
                    warn!(reason, "FLUSHBUFFERED rejected: malformed range");
                    return response(400, "Bad Request")
                        .header("X-Reason", reason)
                        .with_cseq(request);
                }
            };
            if session.ap2.is_ap2_active() {
                // Validate phase transition first — no side effects until OK.
                if let Err(e) = session.ap2.pause() {
                    warn!(%e, "FLUSHBUFFERED rejected — invalid phase transition");
                    return response(455, "Method Not Valid in This State")
                        .header("X-Reason", format!("invalid phase for FLUSHBUFFERED: {e}"))
                        .with_cseq(request);
                }
            }
            if !playout.flush_buffered(flush_range) {
                return response(503, "Service Unavailable")
                    .header("X-Reason", "playout scheduler unavailable")
                    .with_cseq(request);
            }
            apply_flushbuffered_diagnostics(state, flush_range);
            response(200, "OK").with_cseq(request)
        }
        ("TEARDOWN", _) => {
            match Ap2TeardownTarget::from_teardown_body(&request.body) {
                None => {
                    // Malformed body with unknown stream type — return 400,
                    // never full-teardown.
                    warn!("TEARDOWN with malformed/unknown stream type — returning 400");
                    return response(400, "Bad Request")
                        .header(
                            "X-Reason",
                            "malformed or unknown stream type in TEARDOWN body",
                        )
                        .with_cseq(request);
                }
                Some(Ap2TeardownTarget::Stream(stream_type)) => {
                    // Stream teardown — remove only the matching stream.
                    // Data stream (type 130) teardown: abort listener, clear port/stream,
                    // but do NOT stop/flush audio or alter global player state.
                    let is_data_stream = stream_type == Ap2StreamType::DataStream;

                    if is_data_stream {
                        session.abort_ap2_stream_listener(Ap2StreamType::DataStream);
                        if let Some(stream) =
                            session.ap2.find_stream_by_type(Ap2StreamType::DataStream)
                        {
                            let stream_id = stream.stream_id;
                            session.ap2.remove_stream(stream_id);
                        }
                        info!(stream_type = ?stream_type, "AP2 data stream TEARDOWN");
                        return response(200, "OK").with_cseq(request);
                    }

                    // Stop global playback when the negotiated AP2 audio stream is removed.
                    let is_audio_stream = matches!(
                        stream_type,
                        Ap2StreamType::BufferedAudio | Ap2StreamType::RealtimeAudio
                    );
                    let is_last_audio = is_audio_stream
                        && session.ap2.find_audio_stream().is_some()
                        && session.ap2.stream_count() == 1;

                    if session.is_playback_owner && is_last_audio {
                        player.stop();
                        playout.clear_stream();
                        state.set_player_state(PlayerState::Stopped);
                    }
                    session.abort_ap2_stream_listener(stream_type);

                    // Remove the stream record.
                    if let Some(stream) = session.ap2.find_stream_by_type(stream_type) {
                        let stream_id = stream.stream_id;
                        session.ap2.remove_stream(stream_id);
                    }
                    if is_audio_stream {
                        session.fairplay = FairPlayState::NotStarted;
                    }

                    if session.is_playback_owner && is_last_audio {
                        player.flush();
                        state.clear_track_for_transition();
                        state.set_diagnostic("audio_waiting_for_track_title", "true");
                    }
                    info!(stream_type = ?stream_type, "AP2 stream TEARDOWN");
                    return response(200, "OK").with_cseq(request);
                }
                Some(Ap2TeardownTarget::Session) => {
                    // Session teardown — close everything.
                    // Use begin_teardown + close idempotently.
                    state.clear_ptp_master_if_owner(session.connection_id);
                    let _ = session.ap2.begin_teardown();

                    let had_audio_stream = session.ap2.find_audio_stream().is_some();
                    if session.is_playback_owner {
                        player.stop();
                        if had_audio_stream {
                            playout.clear_stream();
                        } else {
                            playout.stop();
                        }
                        state.set_active(false);
                        state.set_player_state(PlayerState::Stopped);
                        *state.session_crypto.write() = None;
                        state.clear_ap1_remote_endpoints();
                        session.ap1_remote_control_port = None;
                        session.ap1_remote_timing_port = None;
                        dacp.clear_session();
                        session.is_playback_owner = false;
                    }
                    session.abort_ap2_listeners();
                    session.fairplay = FairPlayState::NotStarted;
                    // close() now calls clear_sensitive() internally.
                    let _ = session.ap2.close();

                    info!("TEARDOWN");
                    response(200, "OK").with_cseq(request)
                }
            }
        }
        _ => {
            warn!(
                method = %request.method,
                uri = %request.uri,
                "unhandled RTSP method — responding 404"
            );
            response(404, "Not Found").with_cseq(request)
        }
    };

    // --- Apple-Challenge → Apple-Response (classic AirPlay authentication) ---
    if let Some(challenge_b64) = request.headers.get("Apple-Challenge")
        && let Some(apple_response) =
            build_apple_response(challenge_b64, session.local_addr, &config.device_id)
    {
        resp.headers
            .push(("Apple-Response".to_string(), apple_response));
    }

    resp
}

/// Result of parsing a classic SETUP Transport header.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ap1TransportParams {
    control_port: u16,
    timing_port: u16,
}

/// Parse the classic SETUP `Transport` header value.
///
/// Expected format:
///   `RTP/AVP/UDP;unicast;mode=record;control_port=6001;timing_port=6002`
///
/// Keys are matched case-insensitively.  Both `control_port` / `controlPort`
/// and `timing_port` / `timingPort` are accepted.  Zero, out-of-range, and
/// non-numeric port values are rejected.  Unrelated tokens (e.g. the RTP
/// profile, `unicast`, `mode=record`) are silently ignored.
fn parse_ap1_transport_header(value: &str) -> Result<Ap1TransportParams, String> {
    let mut control_port: Option<u16> = None;
    let mut timing_port: Option<u16> = None;

    for token in value.split(';') {
        let token = token.trim();
        if let Some((key, val)) = token.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let val = val.trim();
            match key.as_str() {
                "control_port" | "controlport" => {
                    if control_port.is_some() {
                        return Err("duplicate control_port parameter".into());
                    }
                    let port: u16 = val
                        .parse()
                        .map_err(|_| format!("invalid control_port value: {val}"))?;
                    if port == 0 {
                        return Err(format!("control_port must not be zero: {val}"));
                    }
                    control_port = Some(port);
                }
                "timing_port" | "timingport" => {
                    if timing_port.is_some() {
                        return Err("duplicate timing_port parameter".into());
                    }
                    let port: u16 = val
                        .parse()
                        .map_err(|_| format!("invalid timing_port value: {val}"))?;
                    if port == 0 {
                        return Err(format!("timing_port must not be zero: {val}"));
                    }
                    timing_port = Some(port);
                }
                _ => { /* tolerate unrelated key=value tokens */ }
            }
        }
        // Bare tokens (no '=') are tolerated
    }

    let control_port = control_port.ok_or_else(|| "missing control_port parameter".to_string())?;
    let timing_port = timing_port.ok_or_else(|| "missing timing_port parameter".to_string())?;

    Ok(Ap1TransportParams {
        control_port,
        timing_port,
    })
}

/// Build the `Apple-Response` header value from a base64-encoded challenge,
/// the local socket address, and the device MAC address string.
///
/// Format (matching shairport-sync C):
///   challenge(≤16) || local_ip(4/16) || ap1_prefix(6)  → padded to ≥32 bytes
///   → RSA PKCS1v1.5 sign (unprefixed) with classic key
///   → base64, strip trailing '='
fn build_apple_response(
    challenge_b64: &str,
    local_addr: Option<SocketAddr>,
    device_id: &str,
) -> Option<String> {
    use base64::Engine;

    let challenge = crate::decoder::tolerant_base64_decode(challenge_b64.trim()).ok()?;
    if challenge.len() > 16 {
        warn!(
            len = challenge.len(),
            "oversized Apple-Challenge (>16 bytes)"
        );
        return None;
    }

    // Parse device MAC into 6 bytes (ap1_prefix equivalent)
    let ap1_prefix = parse_mac_bytes(device_id)?;

    // Build the to-be-signed buffer
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&challenge);
    // Pad challenge to 16 bytes (C code doesn't pad explicitly, but the
    // destination buffer is zeroed; we append the IP directly after).
    match local_addr {
        Some(SocketAddr::V4(v4)) => {
            // IPv4: 4 bytes
            buf.extend_from_slice(&v4.ip().octets());
        }
        Some(SocketAddr::V6(v6)) => {
            // IPv6: 16 bytes
            buf.extend_from_slice(&v6.ip().octets());
        }
        None => {
            // Fallback: zero IPv4 address
            buf.extend_from_slice(&[0u8; 4]);
        }
    }
    buf.extend_from_slice(&ap1_prefix);

    // Pad to at least 0x20 (32) bytes
    while buf.len() < 32 {
        buf.push(0u8);
    }

    let sig = decoder::classic_rsa_pkcs1_sign(&buf).ok()?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(&sig);
    // Strip padding '=' chars (matching C behaviour)
    let trimmed = encoded.trim_end_matches('=').to_string();
    Some(trimmed)
}

/// Parse a MAC address string "xx:xx:xx:xx:xx:xx" into 6 bytes.
fn parse_mac_bytes(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn log_request(peer: SocketAddr, request: &RtspRequest) {
    debug!(
        %peer,
        method = %request.method,
        uri = %request.uri,
        cseq = request.headers.get("CSeq").map(String::as_str).unwrap_or(""),
        content_type = request
            .headers
            .get("Content-Type")
            .map(String::as_str)
            .unwrap_or(""),
        content_length = request.body.len(),
        "RTSP request"
    );
    trace!(
        %peer,
        headers = ?request.headers,
        body_len = request.body.len(),
        "RTSP request details"
    );
}

/// Record request framing progress without logging wire payload bytes.
fn log_raw_request(peer: SocketAddr, _raw: &[u8], consumed: usize) {
    if consumed > 0 {
        trace!(%peer, consumed, "RTSP raw request consumed");
    }
}

fn update_dacp_session_from_headers(
    dacp: &DacpController,
    session: &mut RtspSession,
    request: &RtspRequest,
) {
    let active_remote = header_value(request, "Active-Remote").map(str::to_string);
    let dacp_id = header_value(request, "DACP-ID").map(str::to_string);
    if active_remote.is_none() && dacp_id.is_none() {
        return;
    }
    if active_remote.is_some() {
        session
            .ap2
            .set_active_remote(active_remote.clone().unwrap());
    }
    if dacp_id.is_some() {
        session.ap2.set_dacp_id(dacp_id.clone().unwrap());
    }
    dacp.update_session(dacp_id, active_remote, session.peer_addr);
}

fn header_value<'a>(request: &'a RtspRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn log_response(peer: SocketAddr, request: &RtspRequest, response: &RtspResponse) {
    debug!(
        %peer,
        method = %request.method,
        uri = %request.uri,
        cseq = request.headers.get("CSeq").map(String::as_str).unwrap_or(""),
        status = response.code,
        reason = response.reason,
        content_length = response.body.len(),
        response_headers = ?response.headers,
        "RTSP response"
    );
    trace!(
        %peer,
        body_len = response.body.len(),
        "RTSP response details"
    );
}

const FAIRPLAY_REPLY_MODE_0: &[u8] = b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x00\x0f\x9f\x3f\x9e\x0a\x25\x21\xdb\xdf\x31\x2a\xb2\xbf\xb2\x9e\x8d\x23\x2b\x63\x76\xa8\xc8\x18\x70\x1d\x22\xae\x93\xd8\x27\x37\xfe\xaf\x9d\xb4\xfd\xf4\x1c\x2d\xba\x9d\x1f\x49\xca\xaa\xbf\x65\x91\xac\x1f\x7b\xc6\xf7\xe0\x66\x3d\x21\xaf\xe0\x15\x65\x95\x3e\xab\x81\xf4\x18\xce\xed\x09\x5a\xdb\x7c\x3d\x0e\x25\x49\x09\xa7\x98\x31\xd4\x9c\x39\x82\x97\x34\x34\xfa\xcb\x42\xc6\x3a\x1c\xd9\x11\xa6\xfe\x94\x1a\x8a\x6d\x4a\x74\x3b\x46\xc3\xa7\x64\x9e\x44\xc7\x89\x55\xe4\x9d\x81\x55\x00\x95\x49\xc4\xe2\xf7\xa3\xf6\xd5\xba";
const FAIRPLAY_REPLY_MODE_1: &[u8] = b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x01\xcf\x32\xa2\x57\x14\xb2\x52\x4f\x8a\xa0\xad\x7a\xf1\x64\xe3\x7b\xcf\x44\x24\xe2\x00\x04\x7e\xfc\x0a\xd6\x7a\xfc\xd9\x5d\xed\x1c\x27\x30\xbb\x59\x1b\x96\x2e\xd6\x3a\x9c\x4d\xed\x88\xba\x8f\xc7\x8d\xe6\x4d\x91\xcc\xfd\x5c\x7b\x56\xda\x88\xe3\x1f\x5c\xce\xaf\xc7\x43\x19\x95\xa0\x16\x65\xa5\x4e\x19\x39\xd2\x5b\x94\xdb\x64\xb9\xe4\x5d\x8d\x06\x3e\x1e\x6a\xf0\x7e\x96\x56\x16\x2b\x0e\xfa\x40\x42\x75\xea\x5a\x44\xd9\x59\x1c\x72\x56\xb9\xfb\xe6\x51\x38\x98\xb8\x02\x27\x72\x19\x88\x57\x16\x50\x94\x2a\xd9\x46\x68\x8a";
const FAIRPLAY_REPLY_MODE_2: &[u8] = b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x02\xc1\x69\xa3\x52\xee\xed\x35\xb1\x8c\xdd\x9c\x58\xd6\x4f\x16\xc1\x51\x9a\x89\xeb\x53\x17\xbd\x0d\x43\x36\xcd\x68\xf6\x38\xff\x9d\x01\x6a\x5b\x52\xb7\xfa\x92\x16\xb2\xb6\x54\x82\xc7\x84\x44\x11\x81\x21\xa2\xc7\xfe\xd8\x3d\xb7\x11\x9e\x91\x82\xaa\xd7\xd1\x8c\x70\x63\xe2\xa4\x57\x55\x59\x10\xaf\x9e\x0e\xfc\x76\x34\x7d\x16\x40\x43\x80\x7f\x58\x1e\xe4\xfb\xe4\x2c\xa9\xde\xdc\x1b\x5e\xb2\xa3\xaa\x3d\x2e\xcd\x59\xe7\xee\xe7\x0b\x36\x29\xf2\x2a\xfd\x16\x1d\x87\x73\x53\xdd\xb9\x9a\xdc\x8e\x07\x00\x6e\x56\xf8\x50\xce";
const FAIRPLAY_REPLY_MODE_3: &[u8] = b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x03\x90\x01\xe1\x72\x7e\x0f\x57\xf9\xf5\x88\x0d\xb1\x04\xa6\x25\x7a\x23\xf5\xcf\xff\x1a\xbb\xe1\xe9\x30\x45\x25\x1a\xfb\x97\xeb\x9f\xc0\x01\x1e\xbe\x0f\x3a\x81\xdf\x5b\x69\x1d\x76\xac\xb2\xf7\xa5\xc7\x08\xe3\xd3\x28\xf5\x6b\xb3\x9d\xbd\xe5\xf2\x9c\x8a\x17\xf4\x81\x48\x7e\x3a\xe8\x63\xc6\x78\x32\x54\x22\xe6\xf7\x8e\x16\x6d\x18\xaa\x7f\xd6\x36\x25\x8b\xce\x28\x72\x6f\x66\x1f\x73\x88\x93\xce\x44\x31\x1e\x4b\xe6\xc0\x53\x51\x93\xe5\xef\x72\xe8\x68\x62\x33\x72\x9c\x22\x7d\x82\x0c\x99\x94\x45\xd8\x92\x46\xc8\xc3\x59";
const FAIRPLAY_SETUP2_HEADER: &[u8] = b"\x46\x50\x4c\x59\x03\x01\x04\x00\x00\x00\x00\x14";

const FAIRPLAY_HEADER_LEN: usize = 12;
const FAIRPLAY_SETUP1_PAYLOAD_LEN: usize = 4;
const FAIRPLAY_SETUP2_SUFFIX_LEN: usize = 20;
const FAIRPLAY_MAX_REQUEST_LEN: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FairPlayState {
    #[default]
    NotStarted,
    AwaitingSetup2 {
        mode: u8,
    },
    Complete {
        mode: u8,
    },
}

impl FairPlayState {
    fn is_complete(self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FairPlayRequest<'a> {
    Setup1 { mode: u8 },
    Setup2 { suffix: &'a [u8] },
}

fn parse_fairplay_request(body: &[u8]) -> Result<FairPlayRequest<'_>, &'static str> {
    if body.len() < FAIRPLAY_HEADER_LEN || body.len() > FAIRPLAY_MAX_REQUEST_LEN {
        return Err("invalid FairPlay request length");
    }
    if &body[..4] != b"FPLY" {
        return Err("invalid FairPlay magic");
    }
    if body[4] != 3 || body[5] != 1 || body[7] != 0 {
        return Err("unsupported FairPlay version or message type");
    }
    let declared_len = u32::from_be_bytes(body[8..12].try_into().expect("fixed slice")) as usize;
    if declared_len != body.len() - FAIRPLAY_HEADER_LEN {
        return Err("FairPlay payload length mismatch");
    }
    match body[6] {
        1 if declared_len == FAIRPLAY_SETUP1_PAYLOAD_LEN => {
            let mode = body[14];
            if mode > 3 {
                return Err("unsupported FairPlay mode");
            }
            Ok(FairPlayRequest::Setup1 { mode })
        }
        1 => Err("invalid FairPlay setup1 payload length"),
        3 if declared_len >= FAIRPLAY_SETUP2_SUFFIX_LEN => Ok(FairPlayRequest::Setup2 {
            suffix: &body[body.len() - FAIRPLAY_SETUP2_SUFFIX_LEN..],
        }),
        3 => Err("invalid FairPlay setup2 payload length"),
        _ => Err("unsupported FairPlay setup sequence"),
    }
}

fn fairplay_setup_reply(state: &mut FairPlayState, body: &[u8]) -> Result<Vec<u8>, &'static str> {
    match parse_fairplay_request(body)? {
        FairPlayRequest::Setup1 { mode } => {
            if *state != FairPlayState::NotStarted {
                return Err("FairPlay setup1 received after negotiation started");
            }
            let reply = match mode {
                0 => FAIRPLAY_REPLY_MODE_0,
                1 => FAIRPLAY_REPLY_MODE_1,
                2 => FAIRPLAY_REPLY_MODE_2,
                3 => FAIRPLAY_REPLY_MODE_3,
                _ => unreachable!("mode validated by parser"),
            };
            *state = FairPlayState::AwaitingSetup2 { mode };
            Ok(reply.to_vec())
        }
        FairPlayRequest::Setup2 { suffix } => {
            let FairPlayState::AwaitingSetup2 { mode } = *state else {
                return Err("FairPlay setup2 received before setup1");
            };
            let mut reply =
                Vec::with_capacity(FAIRPLAY_SETUP2_HEADER.len() + FAIRPLAY_SETUP2_SUFFIX_LEN);
            reply.extend_from_slice(FAIRPLAY_SETUP2_HEADER);
            reply.extend_from_slice(suffix);
            *state = FairPlayState::Complete { mode };
            Ok(reply)
        }
    }
}

fn handle_fairplay_setup(session: &mut RtspSession, request: &RtspRequest) -> RtspResponse {
    if !session.ap2.is_ap2_active() {
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", "pairing must complete before FairPlay setup");
    }
    if header_value(request, "Content-Type") != Some("application/octet-stream") {
        return response(400, "Bad Request").header(
            "X-Reason",
            "FairPlay setup requires application/octet-stream",
        );
    }
    match fairplay_setup_reply(&mut session.fairplay, &request.body) {
        Ok(body) => response(200, "OK")
            .header("Content-Type", "application/octet-stream")
            .body(body),
        Err(reason) => {
            warn!(reason, "FairPlay setup rejected");
            response(400, "Bad Request").header("X-Reason", reason)
        }
    }
}

fn handle_configure(
    _config: &AirplayConfig,
    state: &AppState,
    session: &mut RtspSession,
    pairing: &PairingService,
    request: &RtspRequest,
) -> RtspResponse {
    if session.ap2.phase() == Ap2SessionPhase::Connected {
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", "pairing must complete before /configure");
    }
    let Ok(dict) = plist::from_bytes::<plist::Dictionary>(&request.body) else {
        return response(400, "Bad Request").header("X-Reason", "invalid configure plist");
    };

    let timing_protocol = match dict.get("timingProtocol") {
        None => None,
        Some(plist::Value::String(value)) => match Ap2TimingProtocol::from_str(value) {
            Some(protocol) => Some(protocol),
            None => {
                return response(400, "Bad Request").header("X-Reason", "unknown timingProtocol");
            }
        },
        Some(_) => {
            return response(400, "Bad Request")
                .header("X-Reason", "timingProtocol must be a string");
        }
    };

    let group_uuid_present = match dict.get("groupUUID") {
        None => false,
        Some(plist::Value::String(value)) if !value.is_empty() && value.len() <= 128 => true,
        Some(_) => {
            return response(400, "Bad Request")
                .header("X-Reason", "groupUUID must be a bounded nonempty string");
        }
    };

    let stream_category = match dict.get("streamCategory") {
        None => None,
        Some(plist::Value::String(value)) if !value.is_empty() && value.len() <= 64 => {
            Some(value.clone())
        }
        Some(_) => {
            return response(400, "Bad Request").header(
                "X-Reason",
                "streamCategory must be a bounded nonempty string",
            );
        }
    };

    let (enable_hk_access_control, access_control_level) = match dict.get("ConfigurationDictionary")
    {
        None => (None, None),
        Some(plist::Value::Dictionary(configuration)) => {
            let enabled = match configuration.get("Enable_HK_Access_Control") {
                None => None,
                Some(plist::Value::Boolean(value)) => Some(*value),
                Some(_) => {
                    return response(400, "Bad Request")
                        .header("X-Reason", "Enable_HK_Access_Control must be boolean");
                }
            };
            let level = match configuration.get("Access_Control_Level") {
                None => None,
                Some(value) => match plist_uint(value).and_then(|v| u32::try_from(v).ok()) {
                    Some(level) => Some(level),
                    None => {
                        return response(400, "Bad Request")
                            .header("X-Reason", "Access_Control_Level must be a u32");
                    }
                },
            };
            (enabled, level)
        }
        Some(_) => {
            return response(400, "Bad Request")
                .header("X-Reason", "ConfigurationDictionary must be a dictionary");
        }
    };

    let configuration = Ap2Configuration {
        timing_protocol,
        group_uuid_present,
        stream_category,
        enable_hk_access_control,
        access_control_level,
    };

    let mut response_dict = plist::Dictionary::new();
    if enable_hk_access_control == Some(true) {
        response_dict.insert(
            "Identifier".to_string(),
            plist::Value::String(pairing.device_id().to_string()),
        );
        response_dict.insert(
            "Enable_HK_Access_Control".to_string(),
            plist::Value::Boolean(true),
        );
        response_dict.insert(
            "PublicKey".to_string(),
            plist::Value::Data(pairing.identity_public_key().to_vec()),
        );
        response_dict.insert(
            "Device_Name".to_string(),
            plist::Value::String("Shairport RS".to_string()),
        );
        response_dict.insert(
            "Access_Control_Level".to_string(),
            plist_uint_value(access_control_level.unwrap_or(0) as u64),
        );
    }
    let mut body = Vec::new();
    if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(response_dict)).is_err() {
        return response(500, "Internal Server Error");
    }

    session.ap2.replace_configuration(configuration);
    state.set_diagnostic("ap2_configure", "validated");
    state.set_diagnostic(
        "ap2_configure_group_uuid_present",
        group_uuid_present.to_string(),
    );
    if let Some(protocol) = timing_protocol {
        state.set_diagnostic(
            "ap2_configure_timing_protocol",
            format!("{protocol:?}").to_ascii_lowercase(),
        );
    }
    if let Some(enabled) = enable_hk_access_control {
        state.set_diagnostic("ap2_configure_hk_access", enabled.to_string());
    }

    response(200, "OK")
        .header("Content-Type", "application/x-apple-binary-plist")
        .body(body)
}

fn handle_setpeers(
    state: &AppState,
    session: &mut RtspSession,
    request: &RtspRequest,
    format: TimingPeerListFormat,
) -> RtspResponse {
    if session.ap2.timing_protocol() != Ap2TimingProtocol::Ptp {
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", "SETPEERS requires a PTP timing session");
    }
    let receiver_id = session
        .receiver_ip_override
        .map(|address| address.to_string());
    let peers = match parse_timing_peer_list(&request.body, format, receiver_id.as_deref()) {
        Ok(peers) => peers,
        Err(error) => {
            warn!(%error, ?format, "timing peer list rejected");
            return response(400, "Bad Request").header("X-Reason", error.to_string());
        }
    };
    let sender_ip = session.peer_addr.map(|address| address.ip());
    if let Err(error) = session.ap2.replace_timing_peers(peers, sender_ip) {
        warn!(%error, ?format, "timing peer list rejected in current phase");
        return response(455, "Method Not Valid in This State").header(
            "X-Reason",
            format!("invalid phase for timing peers: {error}"),
        );
    }

    state.set_diagnostic(
        "ap2_timing_peer_count",
        session.ap2.timing_peers().len().to_string(),
    );
    if let Some(clock_id) = session.ap2.selected_master_clock_id() {
        state.select_ptp_master(session.connection_id, clock_id);
    }
    info!(
        ?format,
        peer_count = session.ap2.timing_peers().len(),
        selected_master = session
            .ap2
            .selected_master_clock_id()
            .map(|id| format!("{id:016x}")),
        "AP2 timing peers committed"
    );
    response(200, "OK")
}

#[derive(Default)]
struct RtspSession {
    connection_id: u64,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    receiver_ip_override: Option<IpAddr>,
    session_id: Option<String>,
    pairing: PairingSession,
    control_cipher: Option<PairCipher>,
    event_listener: Option<EventListener>,
    ap2_control_listener: Option<JoinHandle<()>>,
    buffered_audio_listener: Option<JoinHandle<()>>,
    realtime_audio_listener: Option<JoinHandle<()>>,
    data_listener: Option<DataStreamListener>,
    event_port: Option<u16>,
    ap2_control_port: Option<u16>,
    buffered_audio_port: Option<u16>,
    realtime_audio_port: Option<u16>,
    data_port: Option<u16>,
    /// AirPlay 2 per-connection session state (phase, timing, streams, keys).
    ap2: Ap2SessionState,
    /// AP1 remote control port parsed from classic SETUP Transport header.
    ap1_remote_control_port: Option<u16>,
    /// AP1 remote timing port parsed from classic SETUP Transport header.
    ap1_remote_timing_port: Option<u16>,
    /// true when this connection established (or currently controls) the
    /// principal playback session — i.e. it sent a successful classic
    /// ANNOUNCE with valid crypto, or a successful AP2 audio SETUP/RECORD.
    /// Only owner connections may clear global playback state on close.
    is_playback_owner: bool,
    /// Optional privacy-safe capture shared with event-channel workers.
    transcript: Option<Arc<TranscriptRecorder>>,
    transcript_connection: Option<u64>,
    fairplay: FairPlayState,
}

impl RtspSession {
    fn receiver_ip(&self) -> IpAddr {
        self.receiver_ip_override
            .unwrap_or_else(|| receiver_primary_ip(self.local_addr.map(|addr| addr.ip()), None))
    }

    fn receiver_bind_addr(&self) -> SocketAddr {
        event_bind_addr(self.local_addr, self.receiver_ip())
    }

    #[cfg(test)]
    fn install_test_event_port(&mut self, port: u16) {
        self.event_port = Some(port);
    }

    fn abort_ap2_listeners(&mut self) {
        if let Some(listener) = self.event_listener.take() {
            listener.abort();
        }
        if let Some(listener) = self.data_listener.take() {
            listener.abort();
        }
        for handle in [
            self.ap2_control_listener.take(),
            self.buffered_audio_listener.take(),
            self.realtime_audio_listener.take(),
        ]
        .into_iter()
        .flatten()
        {
            handle.abort();
        }
        self.event_port = None;
        self.ap2_control_port = None;
        self.buffered_audio_port = None;
        self.realtime_audio_port = None;
        self.data_port = None;
    }

    fn abort_ap2_stream_listener(&mut self, stream_type: Ap2StreamType) {
        match stream_type {
            Ap2StreamType::RealtimeAudio => {
                if let Some(handle) = self.realtime_audio_listener.take() {
                    handle.abort();
                }
                self.realtime_audio_port = None;
            }
            Ap2StreamType::BufferedAudio => {
                if let Some(handle) = self.buffered_audio_listener.take() {
                    handle.abort();
                }
                self.buffered_audio_port = None;
            }
            Ap2StreamType::DataStream => {
                if let Some(listener) = self.data_listener.take() {
                    listener.abort();
                }
                self.data_port = None;
            }
        }
    }

    fn ensure_ap2_control_socket(&mut self) -> anyhow::Result<u16> {
        if let Some(port) = self.ap2_control_port {
            return Ok(port);
        }
        let bind = self.receiver_bind_addr();
        let (port, handle) = spawn_ap2_control_receiver(bind)?;
        self.ap2_control_port = Some(port);
        self.ap2_control_listener = Some(handle);
        Ok(port)
    }

    fn ensure_buffered_audio_listener(
        &mut self,
        state: &AppState,
        playout: &PlayoutHandle,
        context: Arc<BufferedStreamContext>,
    ) -> anyhow::Result<u16> {
        if let Some(port) = self.buffered_audio_port {
            return Ok(port);
        }
        let bind = self.receiver_bind_addr();
        let std_socket = match bind {
            SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?,
            SocketAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
                socket.set_only_v6(false)?;
                socket
            }
        };
        std_socket.set_reuse_address(true)?;
        std_socket
            .bind(&bind.into())
            .with_context(|| format!("failed to bind buffered audio TCP on {bind}"))?;
        std_socket.listen(128)?;
        std_socket.set_nonblocking(true)?;
        let std_listener: std::net::TcpListener = std_socket.into();
        let port = std_listener.local_addr()?.port();
        let listener = TcpListener::from_std(std_listener)?;
        let handle = crate::airplay::buffered_audio::spawn_buffered_accept_loop(
            listener,
            state.clone(),
            playout.clone(),
            context,
        );
        self.buffered_audio_port = Some(port);
        self.buffered_audio_listener = Some(handle);
        Ok(port)
    }

    fn ensure_realtime_audio_listener(
        &mut self,
        state: &AppState,
        playout: &PlayoutHandle,
        context: Arc<RealtimeStreamContext>,
    ) -> anyhow::Result<u16> {
        if let Some(port) = self.realtime_audio_port {
            return Ok(port);
        }
        let bind = self.receiver_bind_addr();
        let (port, handle) = crate::airplay::realtime_audio::spawn_realtime_audio_receiver(
            bind,
            state.clone(),
            playout.clone(),
            context,
        )?;
        self.realtime_audio_port = Some(port);
        self.realtime_audio_listener = Some(handle);
        Ok(port)
    }
}

impl Drop for RtspSession {
    fn drop(&mut self) {
        self.abort_ap2_listeners();
    }
}

/// Handle an AP2 PTP audio stream SETUP (type 103 buffered or type 96 realtime).
///
/// Both stream types share strict FairPlay/key/format/lifecycle validation and
/// the same PTP-aware playout scheduler; only their ingress transport differs.
#[allow(clippy::too_many_arguments)]
fn handle_ap2_setup_audio_stream(
    stream_type: Ap2StreamType,
    config: &AirplayConfig,
    state: &AppState,
    session: &mut RtspSession,
    setup: &plist::Dictionary,
    streams: &[plist::Value],
    request: &RtspRequest,
    playout: &PlayoutHandle,
    dacp: &DacpController,
    ap2_policy: &Ap2CapabilityPolicy,
) -> RtspResponse {
    let _ = config; // used indirectly via state/playout
    let (expected_type, stream_label) = match stream_type {
        Ap2StreamType::BufferedAudio => (103u32, "buffered"),
        Ap2StreamType::RealtimeAudio => (96u32, "realtime"),
        Ap2StreamType::DataStream => unreachable!("data stream uses dedicated SETUP handler"),
    };
    state.set_diagnostic("ap2_phase", "stream-setup");
    if !session.fairplay.is_complete() {
        return response(455, "Method Not Valid in This State")
            .header(
                "X-Reason",
                format!("FairPlay setup must complete before type-{expected_type} SETUP"),
            )
            .with_cseq(request);
    }

    // ── Phase 1: validate every stream ───────────────────────────
    struct ValidatedStream {
        type_val: u32,
        audio_format: Option<u64>,
        format: Option<AudioFormat>,
        shk: Option<Zeroizing<Vec<u8>>>,
        sr: Option<u32>,
        spf: Option<u64>,
    }
    let mut validated: Vec<ValidatedStream> = Vec::with_capacity(streams.len());
    let mut any_invalid = streams.is_empty();

    for stream_val in streams {
        let plist::Value::Dictionary(stream) = stream_val else {
            any_invalid = true;
            validated.push(ValidatedStream {
                type_val: 0,
                audio_format: None,
                format: None,
                shk: None,
                sr: None,
                spf: None,
            });
            continue;
        };
        let type_val = stream
            .get("type")
            .and_then(plist_uint)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0);
        let audio_format_bits = stream.get("audioFormat").and_then(plist_uint);
        let format = audio_format_bits.and_then(AudioFormat::from_ap2_audio_format);
        let shk_data = match stream.get("shk") {
            Some(plist::Value::Data(d)) if d.len() == 32 => Some(Zeroizing::new(d.clone())),
            _ => None,
        };
        let declared_sr = stream
            .get("sr")
            .and_then(plist_uint)
            .and_then(|value| u32::try_from(value).ok());
        let sr = declared_sr.or_else(|| format.map(|value| value.sample_rate()));
        let spf = stream.get("spf").and_then(plist_uint);
        let stream_id_valid = match stream.get("streamID") {
            None => true,
            Some(value) => plist_uint(value)
                .and_then(|value| u32::try_from(value).ok())
                .is_some(),
        };
        let stream_connection_id_valid = match stream.get("streamConnectionID") {
            None => true,
            Some(value) => plist_opaque_u64(value).is_some(),
        };
        let compression_type_valid = match stream.get("ct") {
            None => true,
            Some(value) => plist_uint(value)
                .and_then(|value| u32::try_from(value).ok())
                .is_some(),
        };
        let latency_fields_valid = [
            "latency",
            "audioLatency",
            "latencyMin",
            "latencyMax",
            "latencyMs",
        ]
        .into_iter()
        .all(|key| {
            stream.get(key).is_none_or(|value| {
                plist_uint(value)
                    .and_then(|value| u32::try_from(value).ok())
                    .is_some()
            })
        });

        let mut valid = type_val == expected_type && ap2_policy.supports_stream_type(type_val);
        if valid {
            match format {
                Some(fmt) => {
                    valid = ap2_policy.is_format_playable(audio_format_bits.unwrap_or(0))
                        && fmt.is_playable();
                    if valid {
                        if let Some(sr_val) = declared_sr {
                            valid = sr_val == fmt.sample_rate();
                        }
                        if valid && let Some(spf_val) = spf {
                            valid = spf_val > 0 && u32::try_from(spf_val).is_ok();
                        }
                    }
                }
                None => {
                    valid = false;
                }
            }
            if shk_data.is_none() {
                valid = false;
            }
            if spf.is_none() {
                valid = false;
            }
            valid = valid
                && stream_id_valid
                && stream_connection_id_valid
                && compression_type_valid
                && latency_fields_valid;
        }

        let stream_connection_id_type: Option<&str> =
            stream.get("streamConnectionID").map(|value| match value {
                plist::Value::Integer(i) => {
                    if i.as_unsigned().is_some() {
                        "integer-unsigned"
                    } else {
                        "integer-signed"
                    }
                }
                _ => "non-integer",
            });

        if !valid {
            warn!(
                stream_type = type_val,
                audio_format = audio_format_bits,
                decoded_format = ?format,
                declared_sample_rate = declared_sr,
                effective_sample_rate = sr,
                frames_per_packet = spf,
                shk_len = stream
                    .get("shk")
                    .and_then(plist::Value::as_data)
                    .map(<[u8]>::len),
                stream_id_valid,
                stream_connection_id_valid,
                stream_connection_id_type,
                compression_type_valid,
                latency_fields_valid,
                expected_type,
                "AP2 audio stream failed pre-validation"
            );
        }
        any_invalid = any_invalid || !valid;
        validated.push(ValidatedStream {
            type_val,
            audio_format: audio_format_bits,
            format,
            shk: shk_data,
            sr,
            spf,
        });
    }

    // ── Phase 2: reject on any invalid stream ─────────────────────
    if any_invalid {
        warn!("AP2 stream SETUP rejected — one or more streams failed pre-validation");
        let mut response_dict = plist::Dictionary::new();
        let response_streams: Vec<plist::Value> = validated
            .into_iter()
            .map(|vs| {
                let mut sd = plist::Dictionary::new();
                sd.insert("type".to_string(), plist_uint_value(vs.type_val as u64));
                sd.insert("status".to_string(), plist_uint_value(1u64));
                plist::Value::Dictionary(sd)
            })
            .collect();
        response_dict.insert("streams".to_string(), plist::Value::Array(response_streams));
        state.set_diagnostic("ap2_stream_setup", "rejected-pre-validation");

        let mut body = Vec::new();
        if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(response_dict)).is_ok() {
            return response(400, "Bad Request")
                .header("Content-Type", "application/x-apple-binary-plist")
                .body(body);
        }
        return response(400, "Bad Request");
    }

    // ── Phase 3: exactly one stream per request ─────────
    if validated.len() != 1 {
        warn!(
            count = validated.len(),
            "AP2 stream SETUP rejected — exactly one stream expected"
        );
        return response(400, "Bad Request")
            .header("X-Reason", "exactly one stream per SETUP request")
            .with_cseq(request);
    }

    if let Err(e) = validate_add_stream_phase(session.ap2.phase()) {
        warn!(%e, "AP2 stream SETUP rejected — invalid lifecycle phase");
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", format!("invalid phase for stream SETUP: {e}"))
            .with_cseq(request);
    }

    let vs = &validated[0];
    let raw_stream = streams
        .iter()
        .find_map(|v| v.as_dictionary())
        .expect("validated stream present");

    let stream_id: u32 = raw_stream
        .get("streamID")
        .and_then(plist_uint)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or_else(|| session.ap2.allocate_stream_id());

    if session.ap2.find_stream(stream_id).is_some() {
        warn!(stream_id, "AP2 stream SETUP rejected — duplicate stream ID");
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", format!("duplicate stream ID: {stream_id}"))
            .with_cseq(request);
    }
    if session.ap2.find_audio_stream().is_some() {
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", "only one AP2 audio stream is supported")
            .with_cseq(request);
    }

    let shk = vs.shk.as_ref().expect("shk validated");
    let mut stream_key = Zeroizing::new([0u8; 32]);
    stream_key.copy_from_slice(&shk[..32]);
    let audio_format = vs.format.expect("audio format validated");
    let sample_rate = vs.sr.expect("sample rate validated");
    let frames_per_packet =
        u32::try_from(vs.spf.expect("frames per packet validated")).expect("spf range validated");
    let stream_connection_id = raw_stream
        .get("streamConnectionID")
        .and_then(plist_opaque_u64);
    enum AudioRuntime {
        Buffered(Arc<BufferedStreamContext>),
        Realtime(Arc<RealtimeStreamContext>),
    }
    let runtime = match stream_type {
        Ap2StreamType::BufferedAudio => {
            AudioRuntime::Buffered(Arc::new(BufferedStreamContext::new(
                *stream_key,
                audio_format,
                sample_rate,
                frames_per_packet,
                stream_id,
                stream_connection_id,
            )))
        }
        Ap2StreamType::RealtimeAudio => {
            AudioRuntime::Realtime(Arc::new(RealtimeStreamContext::new(
                *stream_key,
                audio_format,
                sample_rate,
                frames_per_packet,
                stream_id,
                stream_connection_id,
            )))
        }
        Ap2StreamType::DataStream => unreachable!("validated audio stream"),
    };

    let had_control = session.ap2_control_port.is_some();
    let had_audio_listener = match stream_type {
        Ap2StreamType::BufferedAudio => session.buffered_audio_port.is_some(),
        Ap2StreamType::RealtimeAudio => session.realtime_audio_port.is_some(),
        Ap2StreamType::DataStream => false,
    };
    let control_port = match session.ensure_ap2_control_socket() {
        Ok(port) => port,
        Err(e) => {
            warn!(%e, "failed to open AP2 control UDP socket");
            return response(503, "Service Unavailable");
        }
    };

    let data_port_result = match &runtime {
        AudioRuntime::Buffered(runtime) => {
            session.ensure_buffered_audio_listener(state, playout, Arc::clone(runtime))
        }
        AudioRuntime::Realtime(runtime) => {
            session.ensure_realtime_audio_listener(state, playout, Arc::clone(runtime))
        }
    };
    let data_port = match data_port_result {
        Ok(port) => port,
        Err(e) => {
            warn!(%e, expected_type, "failed to open AP2 audio stream socket");
            if !had_control {
                if let Some(handle) = session.ap2_control_listener.take() {
                    handle.abort();
                }
                session.ap2_control_port = None;
            }
            return response(503, "Service Unavailable");
        }
    };

    let stream_config = match runtime {
        AudioRuntime::Buffered(runtime) => Ap2StreamConfig::BufferedAudio { runtime },
        AudioRuntime::Realtime(runtime) => Ap2StreamConfig::RealtimeAudio { runtime },
    };
    let ap2_stream = Ap2Stream {
        stream_id,
        stream_connection_id,
        stream_type,
        config: stream_config,
        data_port,
        state: Ap2StreamState::Configured,
    };

    let mut stream_dict = plist::Dictionary::new();
    stream_dict.insert("type".to_string(), plist_uint_value(expected_type as u64));
    stream_dict.insert("controlPort".to_string(), plist_uint_value(control_port));
    stream_dict.insert("dataPort".to_string(), plist_uint_value(data_port));
    if stream_type == Ap2StreamType::BufferedAudio {
        stream_dict.insert(
            "audioBufferSize".to_string(),
            plist_uint_value(advertised_audio_buffer_size(
                playout.buffered_packet_capacity(),
            )),
        );
    }

    let mut response_dict = plist::Dictionary::new();
    response_dict.insert(
        "streams".to_string(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_dict)]),
    );
    let mut body = Vec::new();
    if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(response_dict.clone())).is_err()
    {
        if !had_audio_listener {
            session.abort_ap2_stream_listener(stream_type);
        }
        if !had_control {
            if let Some(handle) = session.ap2_control_listener.take() {
                handle.abort();
            }
            session.ap2_control_port = None;
        }
        return response(500, "Internal Server Error");
    }

    if let Err(e) = session.ap2.add_stream(ap2_stream) {
        warn!(%e, "AP2 stream SETUP rejected — cannot add stream");
        if !had_audio_listener {
            session.abort_ap2_stream_listener(stream_type);
        }
        if !had_control {
            if let Some(handle) = session.ap2_control_listener.take() {
                handle.abort();
            }
            session.ap2_control_port = None;
        }
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", format!("cannot add stream: {e}"))
            .with_cseq(request);
    }

    playout.configure_stream(Ap2StreamRuntime {
        stream_id,
        stream_connection_id,
        audio_format,
        sample_rate,
        frames_per_packet,
    });
    if session.ap2.record_requested() {
        if let Err(e) = session.ap2.begin_recording() {
            warn!(%e, "AP2 stream committed but pending RECORD could not activate");
            session.ap2.remove_stream(stream_id);
            session.abort_ap2_stream_listener(stream_type);
            playout.clear_stream();
            return response(455, "Method Not Valid in This State")
                .header("X-Reason", format!("cannot activate pending RECORD: {e}"))
                .with_cseq(request);
        }
        playout.record();
        state.set_active(true);
        state.set_player_state(PlayerState::Playing);
        state.set_diagnostic("ap2_play_enabled", "pending-anchor");
    }

    if let Some(plist::Value::String(active_remote)) = setup.get("activeRemote") {
        session.ap2.set_active_remote(active_remote.clone());
    }
    if let Some(plist::Value::String(dacp_id)) = setup.get("dacpID") {
        session.ap2.set_dacp_id(dacp_id.clone());
    }
    dacp.update_session(
        session.ap2.dacp_id().map(str::to_string),
        session.ap2.active_remote().map(str::to_string),
        session.peer_addr,
    );

    session.is_playback_owner = true;

    if let Some(fmt) = vs.format {
        let af_bits = vs.audio_format.unwrap_or(0);
        state.set_diagnostic("ap2_audio_format", format!("{af_bits:#x}"));
        state.set_source_format(Some(fmt.description().to_string()));
    }

    // SETUP is configuration-only. RECORD and a valid timing anchor decide
    // when the scheduler may prime and when output may open.
    if session.ap2.phase() != Ap2SessionPhase::Recording {
        state.set_player_state(PlayerState::Paused);
    }
    state.set_diagnostic("ap2_stream_type", stream_label);
    let port_diagnostic = if stream_type == Ap2StreamType::BufferedAudio {
        "ap2_buffered_audio_port"
    } else {
        "ap2_realtime_audio_port"
    };
    state.set_diagnostic(port_diagnostic, data_port.to_string());
    state.set_diagnostic("ap2_control_port", control_port.to_string());
    state.set_diagnostic("ap2_shk_len", shk.len().to_string());
    if let Some(ct) = raw_stream.get("ct").and_then(plist_uint) {
        state.set_diagnostic("ap2_compression_type", ct.to_string());
    }
    info!(
        data_port,
        control_port, stream_id, expected_type, "AP2 audio stream committed"
    );

    debug!(stream_count = 1, "AP2 stream SETUP response built");
    response(200, "OK")
        .header("Content-Type", "application/x-apple-binary-plist")
        .body(body)
}

/// Handle a type-130 (data stream) SETUP for remote-control-only sessions.
///
/// Validates:
/// - Session is remote-control-only (established via timingProtocol=None).
/// - AP2 is enabled and paired.
/// - Exactly one stream dict with type=130.
/// - Integer `seed` in u64 range.
/// - `wantsDedicatedSocket` if present must be true.
/// - `controlType` if present must be 2.
///
/// Derives a data cipher from the pairing control_secret and decimal seed,
/// binds a TCP data listener, and returns `{streams: [{type:130, streamID, dataPort}]}`.
fn handle_ap2_setup_type_130(
    config: &AirplayConfig,
    state: &AppState,
    session: &mut RtspSession,
    _setup: &plist::Dictionary,
    streams: &[plist::Value],
    request: &RtspRequest,
    ap2_policy: &Ap2CapabilityPolicy,
) -> RtspResponse {
    // ── Pre-conditions ────────────────────────────────────────────
    if !session.ap2.is_remote_control_only() {
        warn!("type-130 SETUP rejected — not a remote-control-only session");
        return response(455, "Method Not Valid in This State")
            .header(
                "X-Reason",
                "type 130 only valid for remote-control-only sessions",
            )
            .with_cseq(request);
    }

    if !ap2_policy.supports_remote_control_data_stream() {
        warn!("type-130 SETUP rejected — data stream not supported by policy");
        return response(400, "Bad Request");
    }

    // ── Validate exactly one stream dict ──────────────────────────
    if streams.len() != 1 {
        warn!(
            count = streams.len(),
            "type-130 SETUP rejected — exactly one stream expected"
        );
        return response(400, "Bad Request")
            .header("X-Reason", "exactly one stream per type-130 SETUP")
            .with_cseq(request);
    }

    let stream_dict = match streams.first().and_then(|v| v.as_dictionary()) {
        Some(d) => d,
        None => {
            warn!("type-130 SETUP rejected — stream is not a dictionary");
            return response(400, "Bad Request");
        }
    };

    let type_val = stream_dict
        .get("type")
        .and_then(plist_uint)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    if type_val != 130 {
        warn!(type_val, "type-130 SETUP rejected — wrong stream type");
        return response(400, "Bad Request");
    }

    // ── Validate seed ─────────────────────────────────────────────
    let seed = match stream_dict.get("seed").and_then(plist_uint) {
        Some(s) => s,
        None => {
            warn!("type-130 SETUP rejected — missing or invalid seed");
            return response(400, "Bad Request")
                .header("X-Reason", "seed is required for type 130")
                .with_cseq(request);
        }
    };

    // ── Validate optional verified fields strictly ───────────────
    match stream_dict.get("wantsDedicatedSocket") {
        None => {}
        Some(value) if plist_bool(value) == Some(true) => {}
        Some(_) => {
            warn!("type-130 SETUP rejected — invalid wantsDedicatedSocket");
            return response(400, "Bad Request")
                .header("X-Reason", "wantsDedicatedSocket must be true")
                .with_cseq(request);
        }
    }
    match stream_dict.get("controlType") {
        None => {}
        Some(value) if plist_uint(value) == Some(2) => {}
        Some(_) => {
            warn!("type-130 SETUP rejected — invalid controlType");
            return response(400, "Bad Request")
                .header("X-Reason", "controlType must be 2")
                .with_cseq(request);
        }
    }

    if let Err(error) = validate_add_stream_phase(session.ap2.phase()) {
        warn!(%error, "type-130 SETUP rejected — invalid lifecycle phase");
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", format!("invalid phase for data SETUP: {error}"))
            .with_cseq(request);
    }

    // ── Derive stream ID ──────────────────────────────────────────
    let stream_id: u32 = stream_dict
        .get("streamID")
        .and_then(plist_uint)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(1);

    // ── Reject duplicate stream ID or duplicate type-130 ──────────
    if session.ap2.find_stream(stream_id).is_some() {
        warn!(stream_id, "type-130 SETUP rejected — duplicate stream ID");
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", format!("duplicate stream ID: {stream_id}"))
            .with_cseq(request);
    }
    if session
        .ap2
        .find_stream_by_type(Ap2StreamType::DataStream)
        .is_some()
        || session.data_listener.is_some()
        || session.data_port.is_some()
    {
        warn!("type-130 SETUP rejected — duplicate data stream");
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", "data stream already configured")
            .with_cseq(request);
    }

    // ── Derive data cipher and bind TCP listener ──────────────────
    let Some(shared_secret) = session.pairing.control_secret() else {
        warn!("type-130 SETUP rejected — no pairing secret");
        return response(503, "Service Unavailable");
    };

    let local_ip = receiver_primary_ip(
        session.local_addr.map(|addr| addr.ip()),
        config.ap2_bind_ip.as_deref(),
    );
    let bind_addr = event_bind_addr(session.local_addr, local_ip);

    let secret = Arc::new(Zeroizing::new(shared_secret.to_vec()));
    let (data_port, data_listener) = match DataStreamListener::bind_with_state(
        bind_addr,
        secret,
        seed,
        crate::airplay::ap2::data::DEFAULT_TIMEOUT,
        state.clone(),
    ) {
        Ok((port, listener)) => (port, listener),
        Err(e) => {
            warn!(%e, "type-130 SETUP failed — cannot bind data listener");
            return response(503, "Service Unavailable");
        }
    };

    // ── Build Ap2Stream record ────────────────────────────────────
    let stream_connection_id = stream_dict
        .get("streamConnectionID")
        .and_then(plist_opaque_u64);
    let ap2_stream = Ap2Stream {
        stream_id,
        stream_connection_id,
        stream_type: Ap2StreamType::DataStream,
        config: Ap2StreamConfig::Data { seed },
        data_port,
        state: Ap2StreamState::Configured,
    };

    // ── Serialize response BEFORE committing session mutations ────
    let mut stream_dict_resp = plist::Dictionary::new();
    stream_dict_resp.insert("type".to_string(), plist_uint_value(130u64));
    stream_dict_resp.insert("streamID".to_string(), plist_uint_value(stream_id as u64));
    stream_dict_resp.insert("dataPort".to_string(), plist_uint_value(data_port as u64));

    let mut response_dict = plist::Dictionary::new();
    response_dict.insert(
        "streams".to_string(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_dict_resp)]),
    );
    let mut body = Vec::new();
    if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(response_dict)).is_err() {
        // Rollback: abort the listener we just created.
        data_listener.abort();
        return response(500, "Internal Server Error");
    }

    // ── Commit: add stream and store listener ─────────────────────
    if let Err(e) = session.ap2.add_stream(ap2_stream) {
        data_listener.abort();
        return response(455, "Method Not Valid in This State")
            .header("X-Reason", format!("cannot add data stream: {e}"))
            .with_cseq(request);
    }

    session.data_port = Some(data_port);
    session.data_listener = Some(data_listener);
    state.set_diagnostic("ap2_phase", "data-stream-setup");
    state.set_diagnostic("ap2_data_port", data_port.to_string());
    info!(data_port, stream_id, "AP2 data stream (type 130) committed");

    response(200, "OK")
        .header("Content-Type", "application/x-apple-binary-plist")
        .body(body)
}

/// Handle an AirPlay 2 SETUP with binary plist body.
#[cfg(test)]
fn handle_ap2_setup(
    config: &AirplayConfig,
    state: &AppState,
    session: &mut RtspSession,
    request: &RtspRequest,
    playout: &PlayoutHandle,
    dacp: &DacpController,
    ap2_policy: &Ap2CapabilityPolicy,
) -> RtspResponse {
    // Legacy SETUP tests focus on stream validation rather than the
    // independently-tested FairPlay exchange. Production does not use this
    // helper.
    if !session.fairplay.is_complete() {
        session.fairplay = FairPlayState::Complete { mode: 0 };
    }
    handle_ap2_setup_with_transcript(
        config, state, session, request, playout, dacp, ap2_policy, None, None,
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_ap2_setup_with_transcript(
    config: &AirplayConfig,
    state: &AppState,
    session: &mut RtspSession,
    request: &RtspRequest,
    playout: &PlayoutHandle,
    dacp: &DacpController,
    ap2_policy: &Ap2CapabilityPolicy,
    transcript: Option<Arc<TranscriptRecorder>>,
    transcript_connection: Option<u64>,
) -> RtspResponse {
    let plist_body = &request.body;
    let setup = match plist::from_bytes::<plist::Dictionary>(plist_body) {
        Ok(dict) => dict,
        Err(e) => {
            warn!(%e, "failed to parse AP2 SETUP plist");
            return response(400, "Bad Request");
        }
    };
    debug!(
        key_count = setup.len(),
        body_len = request.body.len(),
        "AP2 SETUP plist parsed"
    );

    // Stream SETUP — pre-validate all streams atomically before any
    // session/state/DACP mutation or listener/socket creation.
    if let Some(plist::Value::Array(streams)) = setup.get("streams") {
        // ── Detect stream type ─────────────────────────────────────
        // We need the type to dispatch to the right handler path.
        let first_type: Option<u32> = streams.first().and_then(|v| {
            v.as_dictionary()
                .and_then(|d| d.get("type"))
                .and_then(plist_uint)
                .and_then(|v| u32::try_from(v).ok())
        });

        match first_type {
            Some(130) => {
                return handle_ap2_setup_type_130(
                    config, state, session, &setup, streams, request, ap2_policy,
                );
            }
            Some(103) => {
                return handle_ap2_setup_audio_stream(
                    Ap2StreamType::BufferedAudio,
                    config,
                    state,
                    session,
                    &setup,
                    streams,
                    request,
                    playout,
                    dacp,
                    ap2_policy,
                );
            }
            Some(96) => {
                return handle_ap2_setup_audio_stream(
                    Ap2StreamType::RealtimeAudio,
                    config,
                    state,
                    session,
                    &setup,
                    streams,
                    request,
                    playout,
                    dacp,
                    ap2_policy,
                );
            }
            _ => {
                // Run unknown/malformed types through the strict audio validator
                // to preserve the transactional 400 response shape.
                return handle_ap2_setup_audio_stream(
                    Ap2StreamType::BufferedAudio,
                    config,
                    state,
                    session,
                    &setup,
                    streams,
                    request,
                    playout,
                    dacp,
                    ap2_policy,
                );
            }
        }
    }

    if setup.contains_key("streams") {
        state.set_diagnostic("ap2_stream_setup", "rejected-malformed-streams");
        return response(400, "Bad Request");
    }

    // Initial SETUP (no streams) - handle timing protocol and event channel.
    if let Some(tp) = setup.get("timingProtocol").and_then(|v| v.as_string()) {
        let timing_protocol_label = match tp {
            "PTP" => "ptp",
            "NTP" => "ntp",
            "None" => "none",
            _ => "unknown",
        };
        info!(
            protocol = timing_protocol_label,
            "AP2 initial SETUP with timing protocol"
        );
        state.set_diagnostic("ap2_timing_protocol", timing_protocol_label);

        // ── Remote-control-only path: timingProtocol=None, isRemoteControlOnly=true ──
        if tp == "None" {
            // Check isRemoteControlOnly flag
            let is_remote_control = setup
                .get("isRemoteControlOnly")
                .and_then(plist_bool)
                .unwrap_or(false);

            if !is_remote_control {
                warn!(
                    "AP2 initial SETUP rejected — timingProtocol=None without isRemoteControlOnly=true"
                );
                state.set_diagnostic(
                    "ap2_timing_protocol_rejected",
                    "None-without-remote-control",
                );
                return response(400, "Bad Request");
            }

            if !session.ap2.is_ap2_active() {
                warn!("AP2 initial SETUP rejected — not paired");
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", "must pair before remote-control-only SETUP")
                    .with_cseq(request);
            }

            // Validate lifecycle transition.
            if let Err(e) =
                validate_transition(session.ap2.phase(), Ap2SessionPhase::TimingConfigured)
            {
                warn!(%e, "AP2 remote-control SETUP rejected — invalid phase transition");
                return response(455, "Method Not Valid in This State")
                    .header(
                        "X-Reason",
                        format!("invalid phase for remote-control SETUP: {e}"),
                    )
                    .with_cseq(request);
            }

            let local_ip = receiver_primary_ip(
                session.local_addr.map(|addr| addr.ip()),
                config.ap2_bind_ip.as_deref(),
            );

            // Open or reuse event listener.
            let mut new_event_listener: Option<(u16, EventListener)> = None;
            let event_port = if let Some(port) = session.event_port {
                port
            } else {
                let Some(shared_secret) = session.pairing.control_secret() else {
                    warn!("cannot open AP2 event listener before pairing completion");
                    return response(503, "Service Unavailable");
                };
                let event_bind = event_bind_addr(session.local_addr, local_ip);

                let update_info_body = match build_ap2_update_info_event(
                    config,
                    session.peer_addr,
                    None, // no group UUID for remote-control-only
                    None, // no group leader
                    state.snapshot().volume.airplay_db,
                    ap2_policy,
                ) {
                    Ok(body) => body,
                    Err(e) => {
                        warn!(%e, "failed to build AP2 updateInfo event");
                        return response(500, "Internal Server Error");
                    }
                };

                let secret = Arc::new(Zeroizing::new(shared_secret.to_vec()));
                match EventListener::bind_with_transcript(
                    event_bind,
                    secret,
                    update_info_body,
                    crate::airplay::ap2::event::DEFAULT_WRITE_TIMEOUT,
                    crate::airplay::ap2::event::DEFAULT_READ_TIMEOUT,
                    transcript.clone(),
                    transcript_connection,
                ) {
                    Ok((port, listener)) => {
                        new_event_listener = Some((port, listener));
                        port
                    }
                    Err(e) => {
                        warn!(%e, "failed to open AP2 event listener");
                        return response(503, "Service Unavailable");
                    }
                }
            };

            // Build response: eventPort only — no timingPeerInfo or timingPort.
            let mut response_dict = plist::Dictionary::new();
            response_dict.insert(
                "eventPort".to_string(),
                plist::Value::Integer(plist::Integer::from(event_port as u64)),
            );
            let mut body = Vec::new();
            if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(response_dict)).is_err()
            {
                if let Some((_, listener)) = new_event_listener {
                    listener.abort();
                }
                return response(500, "Internal Server Error");
            }

            // Commit session state transactionally: timing None + remote_control_only flag.
            if let Err(e) = session
                .ap2
                .configure_timing(Ap2TimingProtocol::None, None, None)
            {
                if let Some((_, listener)) = new_event_listener {
                    listener.abort();
                }
                return response(455, "Method Not Valid in This State")
                    .header(
                        "X-Reason",
                        format!("invalid phase for remote-control SETUP: {e}"),
                    )
                    .with_cseq(request);
            }
            session.ap2.set_remote_control_only(true);
            session.receiver_ip_override = Some(local_ip);
            if let Some((port, listener)) = new_event_listener {
                session.event_port = Some(port);
                session.event_listener = Some(listener);
            }
            state.set_diagnostic("ap2_phase", "remote-control-only-setup");
            state.set_diagnostic("ap2_timing_protocol", "None-remote-control");

            info!(event_port, "AP2 remote-control-only SETUP committed");

            return response(200, "OK")
                .header("Content-Type", "application/x-apple-binary-plist")
                .body(body);
        }

        // ── NTP: always rejected ───────────────────────────────────────
        if tp == "NTP" {
            warn!(
                protocol = "ntp",
                "AP2 initial SETUP rejected — NTP not supported"
            );
            state.set_diagnostic("ap2_timing_protocol_rejected", "NTP-unsupported");
            return response(400, "Bad Request");
        }

        // ── Unsupported timing protocol ─────────────────────────────────
        if !ap2_policy.supports_timing_protocol(tp) {
            warn!(
                protocol = "unknown",
                "AP2 initial SETUP rejected — unsupported timing protocol"
            );
            state.set_diagnostic("ap2_timing_protocol_rejected", "unsupported");
            return response(400, "Bad Request");
        }

        let timing_protocol = Ap2TimingProtocol::from_str(tp).unwrap_or(Ap2TimingProtocol::None);

        // ── PTP path ────────────────────────────────────────────────────
        if tp == "PTP" {
            // Validate the lifecycle before opening resources or mutating the
            // session. The actual transition is committed only after the
            // response body and event listener are ready.
            if let Err(e) =
                validate_transition(session.ap2.phase(), Ap2SessionPhase::TimingConfigured)
            {
                warn!(%e, "AP2 timing SETUP rejected — invalid phase transition");
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", format!("invalid phase for timing SETUP: {e}"))
                    .with_cseq(request);
            }

            let initial_timing_peer = match setup.get("timingPeerInfo") {
                Some(value) => match parse_initial_timing_peer(value) {
                    Ok(peer) => Some(peer),
                    Err(error) => {
                        warn!(%error, "AP2 initial timing peer rejected");
                        return response(400, "Bad Request")
                            .header("X-Reason", error.to_string())
                            .with_cseq(request);
                    }
                },
                None => None,
            };
            let group_uuid = setup
                .get("groupUUID")
                .and_then(plist::Value::as_string)
                .map(str::to_string);
            let group_leader = setup.get("groupContainsGroupLeader").and_then(plist_bool);
            let local_ip = receiver_primary_ip(
                session.local_addr.map(|addr| addr.ip()),
                config.ap2_bind_ip.as_deref(),
            );
            let local_ip_string = local_ip.to_string();
            let clock_id = ptp::local_clock_identity();
            let timing_addresses = receiver_timing_addresses(local_ip)
                .into_iter()
                .map(plist::Value::String)
                .collect::<Vec<_>>();

            let mut timing_peer_info = plist::Dictionary::new();
            timing_peer_info.insert(
                "Addresses".to_string(),
                plist::Value::Array(timing_addresses),
            );
            timing_peer_info.insert("ID".to_string(), plist::Value::String(local_ip_string));
            timing_peer_info.insert(
                "ClockID".to_string(),
                plist::Value::Integer(plist::Integer::from(clock_id)),
            );
            timing_peer_info.insert(
                "DeviceType".to_string(),
                plist::Value::Integer(plist::Integer::from(0u64)),
            );
            timing_peer_info.insert(
                "SupportsClockPortMatchingOverride".to_string(),
                plist::Value::Boolean(true),
            );

            // Hold any newly-created listener locally until every fallible
            // operation has succeeded. Existing session listeners are reused.
            let mut new_event_listener: Option<(u16, EventListener)> = None;
            let event_port = if let Some(port) = session.event_port {
                port
            } else {
                let Some(shared_secret) = session.pairing.control_secret() else {
                    warn!("cannot open AP2 event listener before pairing completion");
                    return response(503, "Service Unavailable");
                };
                let event_bind = event_bind_addr(session.local_addr, local_ip);

                // Build the updateInfo binary-plist body.
                let update_info_body = match build_ap2_update_info_event(
                    config,
                    session.peer_addr,
                    group_uuid.as_deref(),
                    group_leader,
                    state.snapshot().volume.airplay_db,
                    ap2_policy,
                ) {
                    Ok(body) => body,
                    Err(e) => {
                        warn!(%e, "failed to build AP2 updateInfo event");
                        return response(500, "Internal Server Error");
                    }
                };

                let secret = Arc::new(Zeroizing::new(shared_secret.to_vec()));
                match EventListener::bind_with_transcript(
                    event_bind,
                    secret,
                    update_info_body,
                    crate::airplay::ap2::event::DEFAULT_WRITE_TIMEOUT,
                    crate::airplay::ap2::event::DEFAULT_READ_TIMEOUT,
                    transcript.clone(),
                    transcript_connection,
                ) {
                    Ok((port, listener)) => {
                        new_event_listener = Some((port, listener));
                        port
                    }
                    Err(e) => {
                        warn!(%e, "failed to open AP2 event listener");
                        return response(503, "Service Unavailable");
                    }
                }
            };

            let mut response_dict = plist::Dictionary::new();
            response_dict.insert(
                "timingPeerInfo".to_string(),
                plist::Value::Dictionary(timing_peer_info),
            );
            response_dict.insert(
                "eventPort".to_string(),
                plist::Value::Integer(plist::Integer::from(event_port as u64)),
            );
            response_dict.insert(
                "timingPort".to_string(),
                plist::Value::Integer(plist::Integer::from(0u64)),
            );
            let mut body = Vec::new();
            if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(response_dict)).is_err()
            {
                if let Some((_, listener)) = new_event_listener {
                    listener.abort();
                }
                return response(500, "Internal Server Error");
            }

            // Commit all session state only after resources and response are ready.
            if let Err(e) =
                session
                    .ap2
                    .configure_timing(timing_protocol, group_uuid.clone(), group_leader)
            {
                if let Some((_, listener)) = new_event_listener {
                    listener.abort();
                }
                return response(455, "Method Not Valid in This State")
                    .header("X-Reason", format!("invalid phase for timing SETUP: {e}"))
                    .with_cseq(request);
            }
            if let Some(peer) = initial_timing_peer {
                session
                    .ap2
                    .set_initial_timing_peer(peer, session.peer_addr.map(|addr| addr.ip()));
                if let Some(clock_id) = session.ap2.selected_master_clock_id() {
                    state.select_ptp_master(session.connection_id, clock_id);
                }
            }
            session.receiver_ip_override = Some(local_ip);
            if let Some((port, listener)) = new_event_listener {
                session.event_port = Some(port);
                session.event_listener = Some(listener);
            }
            state.set_diagnostic("ap2_phase", "initial-ptp-setup");
            if group_uuid.is_some() {
                state.set_diagnostic("ap2_group_uuid", "present");
            }
            if let Some(gl) = group_leader {
                state.set_diagnostic("ap2_group_contains_group_leader", gl.to_string());
            }
            return response(200, "OK")
                .header("Content-Type", "application/x-apple-binary-plist")
                .body(body);
        }
    }

    state.set_diagnostic("ap2_timing_protocol_rejected", "missing");
    response(400, "Bad Request").with_cseq(request)
}

fn apply_set_parameter(
    state: &AppState,
    audio_engine: &AudioEngine,
    playout: &PlayoutHandle,
    dacp: &DacpController,
    peer_addr: Option<SocketAddr>,
    request: &RtspRequest,
) {
    let content_type = request
        .headers
        .get("Content-Type")
        .map(String::as_str)
        .unwrap_or_default();

    if content_type.contains("application/x-apple-binary-plist") {
        // AP2 metadata as binary plist
        if let Ok(dict) = plist::from_bytes::<plist::Dictionary>(&request.body) {
            apply_media_update(
                state,
                audio_engine,
                playout,
                None,
                false,
                &extract_media_update(&plist::Value::Dictionary(dict.clone())),
            );
            if let Some(plist::Value::Data(artwork)) = dict.get("artwork") {
                state.set_diagnostic("artwork_size", artwork.len().to_string());
            }
            if let Some(db) = dict.get("volume").and_then(plist_real) {
                apply_airplay_volume(state, audio_engine, db, "set-parameter-plist");
            }
            // DACP / remote control identifiers
            let dacp_id = dict.get("dacpID").and_then(plist::Value::as_string);
            let active_remote = dict.get("activeRemote").and_then(plist::Value::as_string);
            if dacp_id.is_some() || active_remote.is_some() || peer_addr.is_some() {
                dacp.update_session(
                    dacp_id.map(str::to_string),
                    active_remote.map(str::to_string),
                    peer_addr,
                );
            }
        }
    } else if content_type.contains("text/parameters") {
        let body = String::from_utf8_lossy(&request.body);
        let mut title = None;
        let mut artist = None;
        let mut album = None;
        for line in body.lines() {
            if let Some(value) = line.strip_prefix("volume:") {
                if let Ok(db) = value.trim().parse::<f64>() {
                    apply_airplay_volume(state, audio_engine, db, "set-parameter-text");
                }
            } else if let Some(value) = line.strip_prefix("title:") {
                title = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("artist:") {
                artist = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("album:") {
                album = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Progress:") {
                // Format: "Progress: position/duration"
                if let Some((progress, duration)) = parse_progress_parameter(value.trim()) {
                    state.set_progress_ms(progress);
                    if let Some(duration) = duration {
                        state.set_duration_ms(duration);
                    }
                }
            }
        }
        apply_media_update(
            state,
            audio_engine,
            playout,
            None,
            true,
            &MediaUpdate {
                title,
                artist,
                album,
                ..MediaUpdate::default()
            },
        );
    }
}

fn get_parameter_response(state: &AppState, request: &RtspRequest) -> RtspResponse {
    let requested_volume = String::from_utf8_lossy(&request.body)
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("volume"));

    if !requested_volume {
        return response(200, "OK").with_cseq(request);
    }

    let volume_db = state.snapshot().volume.airplay_db;
    response(200, "OK")
        .header("Content-Type", "text/parameters")
        .body(format!("volume: {volume_db:.6}\r\n").into_bytes())
        .with_cseq(request)
}

fn apply_ap2_command(
    state: &AppState,
    audio_engine: &AudioEngine,
    playout: &PlayoutHandle,
    player: &SharedPlayer,
    dacp: &DacpController,
    request: &RtspRequest,
) {
    state.set_diagnostic("ap2_last_command_len", request.body.len().to_string());
    if let Ok(dict) = plist::from_bytes::<plist::Dictionary>(&request.body) {
        let keys = dict.keys().cloned().collect::<Vec<_>>().join(",");
        state.set_diagnostic("ap2_last_command_keys", keys);
        let command = dict
            .get("command")
            .and_then(plist::Value::as_string)
            .or_else(|| dict.get("type").and_then(plist::Value::as_string));
        if let Some(command) = command {
            state.set_diagnostic("ap2_last_command", command.to_string());
            apply_playback_command(state, playout, player, command);
            if is_navigation_alias(command) {
                player.flush();
                playout.pause();
                playout.flush();
                state.clear_track_for_transition();
            }
            if let Some(dacp_command) = dacp_command_for_alias(command) {
                spawn_dacp_source_command(dacp.clone(), dacp_command);
            }
        }
        apply_media_update(
            state,
            audio_engine,
            playout,
            Some(player),
            false,
            &extract_media_update(&plist::Value::Dictionary(dict.clone())),
        );
        if let Some(db) = find_volume_db(&plist::Value::Dictionary(dict.clone())) {
            apply_airplay_volume(state, audio_engine, db, "ap2-command");
        }
        let params_keys = dict
            .get("params")
            .and_then(plist::Value::as_dictionary)
            .map(|params| params.keys().cloned().collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        debug!(
            command = command.unwrap_or(""),
            top_keys = ?dict.keys().collect::<Vec<_>>(),
            params_keys,
            body_len = request.body.len(),
            "AP2 /command plist parsed"
        );
        debug_ap2_mr_supported_commands(&dict);
    }
}

fn spawn_dacp_source_command(dacp: DacpController, dacp_command: &'static str) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        if let Err(err) = dacp.send(dacp_command).await {
            warn!(%err, command = dacp_command, "DACP source command failed");
        }
    });
}

fn debug_ap2_mr_supported_commands(dict: &plist::Dictionary) {
    let Some("updateMRSupportedCommands") = dict
        .get("type")
        .and_then(plist::Value::as_string)
        .or_else(|| dict.get("command").and_then(plist::Value::as_string))
    else {
        return;
    };
    let Some(plist::Value::Array(commands)) = dict
        .get("params")
        .and_then(plist::Value::as_dictionary)
        .and_then(|params| params.get("mrSupportedCommandsFromSender"))
    else {
        debug!("AP2 updateMRSupportedCommands missing mrSupportedCommandsFromSender array");
        return;
    };

    let summaries = commands
        .iter()
        .take(12)
        .enumerate()
        .map(|(idx, command)| match command {
            plist::Value::Data(data) => debug_ap2_embedded_command_summary(idx, data),
            other => format!("{idx}:{}", plist_value_kind(other)),
        })
        .collect::<Vec<_>>();
    debug!(
        count = commands.len(),
        first = ?summaries,
        "AP2 MR supported commands from sender"
    );
}

#[derive(Default)]
struct MediaUpdate {
    title: Option<String>,
    artist: Option<String>,
    album: Option<String>,
    progress_ms: Option<u64>,
    duration_ms: Option<u64>,
}

fn apply_media_update(
    state: &AppState,
    _audio_engine: &AudioEngine,
    playout: &PlayoutHandle,
    player: Option<&SharedPlayer>,
    metadata_controls_playout: bool,
    update: &MediaUpdate,
) {
    let title_changed = update
        .title
        .as_ref()
        .is_some_and(|title| state.snapshot().track.title.as_ref() != Some(title));
    if title_changed && metadata_controls_playout {
        let was_waiting_for_title = state.is_waiting_for_track_title();
        if !was_waiting_for_title {
            playout.pause();
            playout.flush();
            if let Some(player) = player {
                player.flush();
            }
        }
        state.set_diagnostic(
            "track_title_released_playback",
            (was_waiting_for_title && update.title.is_some()).to_string(),
        );
    }
    if update.title.is_some() || update.artist.is_some() || update.album.is_some() {
        state.set_track_metadata(
            update.title.clone(),
            update.artist.clone(),
            update.album.clone(),
        );
    }
    if metadata_controls_playout && title_changed && update.title.is_some() {
        enable_audio_when_track_ready(state, playout);
    }
    if let Some(duration_ms) = update.duration_ms {
        state.set_duration_ms(duration_ms);
    }
    if let Some(progress_ms) = update.progress_ms {
        state.set_progress_ms(progress_ms);
    }
}

fn extract_media_update(value: &plist::Value) -> MediaUpdate {
    let mut update = MediaUpdate::default();
    collect_media_update(value, None, &mut update);
    update
}

fn collect_media_update(value: &plist::Value, key: Option<&str>, update: &mut MediaUpdate) {
    match value {
        plist::Value::Dictionary(dict) => {
            for (child_key, child_value) in dict {
                collect_media_update(child_value, Some(child_key), update);
            }
        }
        plist::Value::Array(values) => {
            for child_value in values {
                collect_media_update(child_value, key, update);
            }
        }
        plist::Value::String(text) => {
            let Some(key) = key else {
                return;
            };
            let normalized = key.to_ascii_lowercase();
            let text = text.trim();
            if text.is_empty() {
                return;
            }
            match normalized.as_str() {
                "title" | "tracktitle" | "minm" | "itemtitle" => {
                    update.title = Some(text.to_string());
                }
                "artist" | "trackartist" | "asar" | "itemartist" => {
                    update.artist = Some(text.to_string());
                }
                "album" | "trackalbum" | "asal" | "itemalbum" => {
                    update.album = Some(text.to_string());
                }
                "progress" | "prgr" => {
                    if let Some((progress_ms, duration_ms)) = parse_progress_parameter(text) {
                        update.progress_ms = Some(progress_ms);
                        update.duration_ms = duration_ms.or(update.duration_ms);
                    }
                }
                _ => {}
            }
        }
        plist::Value::Real(value) => {
            collect_numeric_media_update(key, *value, update);
        }
        plist::Value::Integer(value) => {
            if let Some(value) = value.as_signed() {
                collect_numeric_media_update(key, value as f64, update);
            } else if let Some(value) = value.as_unsigned() {
                collect_numeric_media_update(key, value as f64, update);
            }
        }
        _ => {}
    }
}

fn collect_numeric_media_update(key: Option<&str>, value: f64, update: &mut MediaUpdate) {
    let Some(key) = key else {
        return;
    };
    if !value.is_finite() || value < 0.0 {
        return;
    }
    let normalized = key.to_ascii_lowercase();
    let ms = numeric_time_to_ms(value);
    if normalized.contains("duration") || normalized == "total" || normalized == "endtime" {
        update.duration_ms = Some(ms);
    } else if normalized.contains("progress")
        || normalized.contains("elapsed")
        || normalized.contains("position")
        || normalized == "time"
        || normalized == "currenttime"
    {
        update.progress_ms = Some(ms);
    }
}

fn numeric_time_to_ms(value: f64) -> u64 {
    if value > 10_000.0 {
        value.round() as u64
    } else {
        (value * 1000.0).round() as u64
    }
}

fn parse_progress_parameter(value: &str) -> Option<(u64, Option<u64>)> {
    let parts = value
        .split('/')
        .filter_map(|part| part.trim().parse::<u64>().ok())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [start, current, end, ..] => {
            let progress = current.saturating_sub(*start) * 1000 / 44_100;
            let duration = end.checked_sub(*start).map(|frames| frames * 1000 / 44_100);
            Some((progress, duration))
        }
        [current, end] => Some((current * 1000 / 44_100, Some(end * 1000 / 44_100))),
        [current] => Some((*current * 1000 / 44_100, None)),
        _ => None,
    }
}

fn apply_airplay_volume(
    state: &AppState,
    audio_engine: &AudioEngine,
    requested_db: f64,
    source: &'static str,
) {
    if !requested_db.is_finite() {
        warn!(
            volume_db = requested_db,
            source, "ignoring non-finite AirPlay volume"
        );
        state.set_diagnostic("ap2_volume_rejected", "non-finite");
        return;
    }

    let applied_db = requested_db.clamp(-144.0, 0.0);
    state.set_airplay_volume(applied_db);
    state.set_volume(applied_db);
    audio_engine.set_volume_db(applied_db);
    debug!(volume_db = applied_db, source, "AirPlay volume applied");
}

const MAX_VOLUME_SEARCH_DEPTH: usize = 8;

fn find_volume_db(value: &plist::Value) -> Option<f64> {
    find_volume_db_bounded(value, 0)
}

fn find_volume_db_bounded(value: &plist::Value, depth: usize) -> Option<f64> {
    if depth > MAX_VOLUME_SEARCH_DEPTH {
        return None;
    }

    match value {
        plist::Value::Dictionary(dict) => {
            for (key, value) in dict {
                let normalized_key = key.to_ascii_lowercase();
                if is_volume_key(&normalized_key)
                    && let Some(db) = plist_real(value).filter(|db| db.is_finite())
                {
                    return Some(db);
                }
                if let Some(db) = find_volume_db_bounded(value, depth + 1) {
                    return Some(db);
                }
            }
            None
        }
        plist::Value::Array(values) => values
            .iter()
            .find_map(|value| find_volume_db_bounded(value, depth + 1)),
        _ => None,
    }
}

fn is_volume_key(normalized_key: &str) -> bool {
    normalized_key == "volume"
        || normalized_key.ends_with("volumedb")
        || normalized_key.ends_with("volume")
}

fn debug_ap2_embedded_command_summary(idx: usize, data: &[u8]) -> String {
    if let Ok(value) = plist::from_bytes::<plist::Value>(data) {
        if let Some(dict) = value.as_dictionary() {
            let command = dict
                .get("command")
                .and_then(plist::Value::as_string)
                .or_else(|| dict.get("type").and_then(plist::Value::as_string))
                .or_else(|| dict.get("name").and_then(plist::Value::as_string))
                .unwrap_or("");
            let enabled = dict
                .get("enabled")
                .and_then(plist_bool)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let keys = dict.keys().cloned().collect::<Vec<_>>().join("|");
            return format!("{idx}:plist command={command} enabled={enabled} keys={keys}");
        }
        return format!("{idx}:plist {}", plist_value_kind(&value));
    }
    format!("{idx}:data len={}", data.len())
}

fn parse_flushbuffered(request: &RtspRequest) -> Result<Ap2FlushRange, &'static str> {
    const AP2_SEQUENCE_MASK: u64 = 0x7f_ffff;
    let dict = plist::from_bytes::<plist::Dictionary>(&request.body)
        .map_err(|_| "missing or invalid binary plist body")?;

    // Accept both signed and unsigned integer representations for
    // sequence numbers; reject values wider than 32-bit representation
    // (no silent truncation), then normalize the low 23 bits.
    let from_sequence = dict.get("flushFromSeq").and_then(plist_opaque_u32);
    let from_timestamp = dict.get("flushFromTS").and_then(plist_opaque_u32);
    if from_sequence.is_some() != from_timestamp.is_some() {
        return Err("flushFromSeq and flushFromTS must be supplied together");
    }
    let until_sequence = dict
        .get("flushUntilSeq")
        .and_then(plist_opaque_u32)
        .ok_or("flushUntilSeq is required")?;
    let until_timestamp = dict
        .get("flushUntilTS")
        .and_then(plist_opaque_u32)
        .ok_or("flushUntilTS is required")?;

    // Normalize sequence numbers to the 23-bit AP2 sequence space.
    let from_seq_norm = from_sequence.map(|v| v & AP2_SEQUENCE_MASK as u32);
    let until_seq_norm = until_sequence & AP2_SEQUENCE_MASK as u32;

    Ok(Ap2FlushRange {
        from_sequence: from_seq_norm,
        from_rtp_timestamp: from_timestamp,
        until_sequence: until_seq_norm,
        until_rtp_timestamp: until_timestamp,
    })
}

fn apply_flushbuffered_diagnostics(state: &AppState, range: Ap2FlushRange) {
    state.set_diagnostic("ap2_phase", "flushbuffered");
    if let Some(value) = range.from_sequence {
        state.set_diagnostic("ap2_flushFromSeq", value.to_string());
    }
    if let Some(value) = range.from_rtp_timestamp {
        state.set_diagnostic("ap2_flushFromTS", value.to_string());
    }
    state.set_diagnostic("ap2_flushUntilSeq", range.until_sequence.to_string());
    state.set_diagnostic("ap2_flushUntilTS", range.until_rtp_timestamp.to_string());
    state.set_player_state(PlayerState::Paused);
}

fn handle_feedback(session: &RtspSession, request: &RtspRequest) -> RtspResponse {
    debug!("received /feedback ({} bytes)", request.body.len());

    if session.ap2.phase() != Ap2SessionPhase::Recording {
        return response(200, "OK");
    }
    let Some(stream) = session.ap2.find_audio_stream() else {
        return response(200, "OK");
    };
    let Some(sample_rate) = stream.sample_rate() else {
        return response(200, "OK");
    };
    let stream_type = match stream.stream_type {
        Ap2StreamType::BufferedAudio => 103u64,
        Ap2StreamType::RealtimeAudio => 96u64,
        Ap2StreamType::DataStream => unreachable!("find_audio_stream returned data stream"),
    };

    let mut stream_feedback = plist::Dictionary::new();
    stream_feedback.insert("type".to_string(), plist_uint_value(stream_type));
    stream_feedback.insert("sr".to_string(), plist::Value::Real(f64::from(sample_rate)));
    let mut feedback = plist::Dictionary::new();
    feedback.insert(
        "streams".to_string(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_feedback)]),
    );
    let mut body = Vec::new();
    if plist::to_writer_binary(&mut body, &plist::Value::Dictionary(feedback)).is_err() {
        return response(500, "Internal Server Error");
    }
    response(200, "OK")
        .header("Content-Type", "application/x-apple-binary-plist")
        .body(body)
}

fn handle_audio_mode(
    state: &AppState,
    session: &mut RtspSession,
    request: &RtspRequest,
) -> RtspResponse {
    let Ok(dict) = plist::from_bytes::<plist::Dictionary>(&request.body) else {
        warn!("POST /audioMode missing or invalid plist body");
        return response(400, "Bad Request").header("X-Reason", "invalid audioMode plist");
    };
    let mode = match dict.get("audioMode") {
        Some(plist::Value::String(mode)) if !mode.is_empty() && mode.len() <= 64 => mode.clone(),
        Some(plist::Value::String(_)) => {
            return response(400, "Bad Request")
                .header("X-Reason", "audioMode must be a bounded nonempty string");
        }
        Some(_) => {
            return response(400, "Bad Request").header("X-Reason", "audioMode must be a string");
        }
        None => {
            return response(400, "Bad Request").header("X-Reason", "audioMode is required");
        }
    };

    session.ap2.set_audio_mode(mode.clone());
    state.set_diagnostic("ap2_phase", "audio_mode");
    state.set_diagnostic("ap2_audio_mode", mode.clone());
    debug!(mode, "AP2 /audioMode selected");
    response(200, "OK")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedRateAnchor {
    anchor: Option<Ap2TimelineAnchor>,
    rate: PlaybackRate,
}

fn parse_setrateanchortime(
    request: &RtspRequest,
    sample_rate: u32,
) -> Result<ParsedRateAnchor, &'static str> {
    if sample_rate == 0 {
        return Err("sample rate must be nonzero");
    }
    let dict = plist::from_bytes::<plist::Dictionary>(&request.body)
        .map_err(|_| "missing or invalid binary plist body")?;
    let rate = match dict.get("rate").and_then(plist_uint) {
        Some(0) => PlaybackRate::Paused,
        Some(1) => PlaybackRate::Normal,
        Some(_) => return Err("rate must be 0 or 1"),
        None => return Err("rate is required"),
    };

    // networkTimeTimelineID and networkTimeFrac are opaque 64-bit
    // bit patterns — accept signed or unsigned plist integer encoding.
    let timeline_id = dict.get("networkTimeTimelineID").and_then(plist_opaque_u64);
    // networkTimeSecs is a true nonnegative value (multiplied, checked
    // for overflow); reject signed representations.
    let seconds = dict.get("networkTimeSecs").and_then(plist_uint);
    let fraction = dict.get("networkTimeFrac").and_then(plist_opaque_u64);
    // rtpTime is an opaque 32-bit bit pattern — accept signed i32 or
    // unsigned u32 representations but reject values that cannot
    // represent a 32-bit bit pattern.
    let rtp_timestamp = dict.get("rtpTime").and_then(plist_opaque_u32);
    let anchor_field_count = [
        timeline_id.is_some(),
        seconds.is_some(),
        fraction.is_some(),
        rtp_timestamp.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    if rate == PlaybackRate::Normal && anchor_field_count != 4 {
        return Err("rate=1 requires a complete network/RTP anchor");
    }
    if anchor_field_count != 0 && anchor_field_count != 4 {
        return Err("anchor fields must be supplied together");
    }

    let anchor = if anchor_field_count == 4 {
        let seconds = seconds.expect("field count checked");
        let fraction = fraction.expect("field count checked");
        let whole_ns = seconds
            .checked_mul(1_000_000_000)
            .ok_or("network time overflows nanoseconds")?;
        let fractional_ns = ((fraction as u128 * 1_000_000_000u128) >> 64) as u64;
        let network_time_ns = whole_ns
            .checked_add(fractional_ns)
            .ok_or("network time overflows nanoseconds")?;
        let rtp_timestamp = rtp_timestamp.expect("field count checked");
        Some(Ap2TimelineAnchor {
            timeline_id: timeline_id.expect("field count checked"),
            network_time_ns,
            rtp_timestamp,
            sample_rate,
            rate,
        })
    } else {
        None
    };

    Ok(ParsedRateAnchor { anchor, rate })
}

fn apply_setrateanchortime(state: &AppState, playout: &PlayoutHandle, control: ParsedRateAnchor) {
    state.set_diagnostic("ap2_phase", "setrateanchortime");
    state.set_diagnostic(
        "ap2_rate",
        match control.rate {
            PlaybackRate::Paused => "0",
            PlaybackRate::Normal => "1",
        },
    );
    if let Some(anchor) = control.anchor {
        state.set_diagnostic(
            "ap2_network_time_timeline_id",
            format!("{:x}", anchor.timeline_id),
        );
        state.set_diagnostic("ap2_network_time_ns", anchor.network_time_ns.to_string());
        state.set_diagnostic("ap2_anchor_rtp_time", anchor.rtp_timestamp.to_string());
        playout.set_timeline(anchor);
    } else {
        playout.set_playback_rate(control.rate);
    }

    if control.rate == PlaybackRate::Normal {
        state.set_player_state(PlayerState::Playing);
        state.set_diagnostic("ap2_play_enabled", "timing-gated");
    } else {
        state.set_player_state(PlayerState::Paused);
        state.set_diagnostic("ap2_play_enabled", "false");
    }
}

fn apply_playback_command(
    state: &AppState,
    playout: &PlayoutHandle,
    player: &SharedPlayer,
    command: &str,
) -> bool {
    let normalized = command.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "toggle" | "playpause" | "toggle-playback" => match state.snapshot().player_state {
            PlayerState::Playing => pause_playback(state, playout, player),
            _ => play_playback(state, playout, player),
        },
        "pause" => pause_playback(state, playout, player),
        "stop" => stop_playback(state, playout, player),
        "play" | "resume" => play_playback(state, playout, player),
        _ => false,
    }
}

fn play_playback(state: &AppState, playout: &PlayoutHandle, player: &SharedPlayer) -> bool {
    let sample_rate = state.alac_sample_rate.read().unwrap_or(44_100);
    player.set_sample_rate(sample_rate);
    player.start(0);
    enable_audio_when_track_ready(state, playout);
    state.set_player_state(PlayerState::Playing);
    true
}

fn enable_audio_when_track_ready(state: &AppState, playout: &PlayoutHandle) -> bool {
    if state.is_waiting_for_track_title() {
        state.set_diagnostic("audio_waiting_for_track_title", "true");
        playout.flush();
        return false;
    }
    state.set_diagnostic("audio_waiting_for_track_title", "false");
    playout.start();
    true
}

fn pause_playback(state: &AppState, playout: &PlayoutHandle, player: &SharedPlayer) -> bool {
    player.flush();
    playout.pause();
    playout.flush();
    state.set_player_state(PlayerState::Paused);
    true
}

fn stop_playback(state: &AppState, playout: &PlayoutHandle, player: &SharedPlayer) -> bool {
    player.stop();
    playout.stop();
    state.set_player_state(PlayerState::Stopped);
    true
}

fn plist_uint(value: &plist::Value) -> Option<u64> {
    match value {
        plist::Value::Integer(i) => i.as_unsigned(),
        _ => None,
    }
}

/// Extract a plist Integer as an opaque 64-bit value, accepting both
/// unsigned and signed representations. The signed i64 bit pattern is
/// preserved when converting to u64 (two's complement wrapping in Rust).
/// Non-integer values return `None`.
///
/// This is used for fields such as `streamConnectionID` where the value
/// is an opaque identifier that happens to be a 64-bit integer, and the
/// sender may encode it as either signed or unsigned.
fn plist_opaque_u64(value: &plist::Value) -> Option<u64> {
    match value {
        plist::Value::Integer(i) => i.as_unsigned().or_else(|| i.as_signed().map(|v| v as u64)),
        _ => None,
    }
}

/// Extract a plist Integer as an opaque 32-bit value, accepting both
/// unsigned u32 and signed i32 representations. The signed i32 bit
/// pattern is preserved (two's complement reinterpret).
/// Values outside the 32-bit representable range are rejected.
/// Non-integer values return `None`.
fn plist_opaque_u32(value: &plist::Value) -> Option<u32> {
    match value {
        plist::Value::Integer(i) => {
            i.as_unsigned()
                .and_then(|v| u32::try_from(v).ok())
                .or_else(|| {
                    i.as_signed()
                        .and_then(|v| i32::try_from(v).ok())
                        .map(|v| v as u32)
                })
        }
        _ => None,
    }
}

fn plist_real(value: &plist::Value) -> Option<f64> {
    match value {
        plist::Value::Real(v) => Some(*v),
        plist::Value::Integer(i) => i.as_signed().map(|v| v as f64),
        plist::Value::String(v) => v.parse().ok(),
        _ => None,
    }
}

fn plist_int(value: &plist::Value) -> Option<i64> {
    match value {
        plist::Value::Integer(i) => i.as_signed(),
        _ => None,
    }
}

fn plist_int_value(value: impl Into<i64>) -> plist::Value {
    plist::Value::Integer(value.into().into())
}

fn plist_bool(value: &plist::Value) -> Option<bool> {
    match value {
        plist::Value::Boolean(v) => Some(*v),
        _ => None,
    }
}

fn plist_value_kind(value: &plist::Value) -> &'static str {
    match value {
        plist::Value::Array(_) => "array",
        plist::Value::Dictionary(_) => "dict",
        plist::Value::Boolean(_) => "bool",
        plist::Value::Data(_) => "data",
        plist::Value::Date(_) => "date",
        plist::Value::Integer(_) => "int",
        plist::Value::Real(_) => "real",
        plist::Value::String(_) => "string",
        plist::Value::Uid(_) => "uid",
        _ => "unknown",
    }
}

fn debug_ap2_info_payload(message: &'static str, value: &plist::Value, group_uuid: Option<&str>) {
    let Some(dict) = value.as_dictionary() else {
        return;
    };
    let (audio_stream, buffer_stream) = dict
        .get("supportedFormats")
        .and_then(plist::Value::as_dictionary)
        .map(|formats| {
            (
                formats
                    .get("audioStream")
                    .and_then(plist_uint)
                    .unwrap_or_default(),
                formats
                    .get("bufferStream")
                    .and_then(plist_uint)
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let txt_selected_keys = dict
        .get("txtAirPlay")
        .and_then(|value| match value {
            plist::Value::Data(data) => Some(txt_airplay_entries(data)),
            _ => None,
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.split_once('=').map(|(key, _)| key.to_string()))
        .filter(|key| {
            matches!(
                key.as_str(),
                "features" | "fex" | "gid" | "gcgl" | "pgid" | "pgcgl" | "pi" | "psi" | "protovers"
            )
        })
        .collect::<Vec<_>>();
    debug!(
        keys = ?dict.keys().collect::<Vec<_>>(),
        group_uuid_present = group_uuid.is_some(),
        audio_stream,
        audio_stream_hex = format_args!("{audio_stream:#x}"),
        buffer_stream,
        buffer_stream_hex = format_args!("{buffer_stream:#x}"),
        txt_keys = ?txt_selected_keys,
        body_len = dict.len(),
        message
    );
}

fn txt_airplay_entries(data: &[u8]) -> Vec<String> {
    let mut entries = Vec::new();
    let mut idx = 0;
    while idx < data.len() {
        let len = data[idx] as usize;
        idx += 1;
        if idx + len > data.len() {
            entries.push(format!("truncated(len={len})"));
            break;
        }
        entries.push(String::from_utf8_lossy(&data[idx..idx + len]).into_owned());
        idx += len;
    }
    entries
}

fn plist_uint_value(value: impl Into<u64>) -> plist::Value {
    plist::Value::Integer(plist::Integer::from(value.into()))
}

fn get_info_body(
    config: &AirplayConfig,
    peer_addr: Option<SocketAddr>,
    initial_volume_db: f64,
    ap2_policy: &Ap2CapabilityPolicy,
) -> Vec<u8> {
    get_info_body_with_group(
        config,
        peer_addr,
        None,
        false,
        initial_volume_db,
        ap2_policy,
    )
}

fn get_info_body_with_group(
    config: &AirplayConfig,
    peer_addr: Option<SocketAddr>,
    group_uuid: Option<&str>,
    group_contains_group_leader: bool,
    initial_volume_db: f64,
    ap2_policy: &Ap2CapabilityPolicy,
) -> Vec<u8> {
    use crate::airplay::crypto::accessory_public_key_for_device_id;
    use crate::airplay::txt_records::stable_uuid;
    let mut dict = Dictionary::new();
    dict.insert("vv".into(), Value::Integer(plist::Integer::from(2u64)));
    let mut playback_capabilities = Dictionary::new();
    playback_capabilities.insert("supportsInterstitials".into(), Value::Boolean(false));
    playback_capabilities.insert("supportsFPSSecureStop".into(), Value::Boolean(false));
    playback_capabilities.insert(
        "supportsUIForAudioOnlyContent".into(),
        Value::Boolean(false),
    );
    playback_capabilities.insert("canRecordScreenStream".into(), Value::Boolean(false));
    playback_capabilities.insert("keepAliveSendStatsAsBody".into(), Value::Boolean(false));
    playback_capabilities.insert("protocolVersion".into(), Value::String("1.1".to_string()));
    playback_capabilities.insert(
        "volumeControlType".into(),
        Value::Integer(plist::Integer::from(3u64)),
    );
    playback_capabilities.insert("screenDemoMode".into(), Value::Boolean(false));
    dict.insert(
        "playbackCapabilities".into(),
        Value::Dictionary(playback_capabilities),
    );
    dict.insert("deviceID".into(), Value::String(config.device_id.clone()));
    dict.insert(
        "features".into(),
        Value::Integer(plist::Integer::from(ap2_policy.features)),
    );
    dict.insert("featuresEx".into(), Value::String(ap2_policy.features_ex()));
    dict.insert(
        "statusFlags".into(),
        Value::Integer(plist::Integer::from(ap2_policy.status_flags as u64)),
    );
    dict.insert("sourceVersion".into(), Value::String("366.0".to_string()));
    dict.insert("name".into(), Value::String("Shairport RS".to_string()));
    dict.insert("model".into(), Value::String("ShairportSync".to_string()));
    // Permanent receiver identity. The AP2 TXT data carries psi/protovers.
    let pi = stable_uuid("pi", &config.device_id).to_string();
    dict.insert("pi".into(), Value::String(pi));

    // Public key as raw 32-byte data
    let pk = accessory_public_key_for_device_id(&config.device_id);
    dict.insert("pk".into(), Value::Data(pk.to_vec()));
    if let Some(peer_addr) = peer_addr {
        dict.insert(
            "senderAddress".into(),
            Value::String(format!("{}:{}", peer_addr.ip(), peer_addr.port())),
        );
    }

    // AirPlay volume is expressed in dB: 0.0 is full scale and values down
    // to -144.0 represent attenuation/mute.
    dict.insert(
        "initialVolume".into(),
        Value::Real(initial_volume_db.clamp(-144.0, 0.0)),
    );
    let mut supported_formats = Dictionary::new();
    supported_formats.insert(
        "audioStream".into(),
        Value::Integer(plist::Integer::from(ap2_policy.audio_stream_formats)),
    );
    supported_formats.insert(
        "bufferStream".into(),
        Value::Integer(plist::Integer::from(ap2_policy.buffer_stream_formats)),
    );
    dict.insert(
        "supportedFormats".into(),
        Value::Dictionary(supported_formats),
    );
    dict.insert(
        "receiverHDRCapability".into(),
        Value::String("4k60".to_string()),
    );

    // Generate txtAirPlay binary data (DNS-SD TXT format)
    let txt_data =
        build_txt_airplay_data(config, group_uuid, group_contains_group_leader, ap2_policy);
    dict.insert("txtAirPlay".into(), Value::Data(txt_data));

    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &Value::Dictionary(dict))
        .expect("serializing in-memory plist should not fail");
    out
}

fn build_txt_airplay_data(
    config: &AirplayConfig,
    group_uuid: Option<&str>,
    group_contains_group_leader: bool,
    ap2_policy: &Ap2CapabilityPolicy,
) -> Vec<u8> {
    use crate::airplay::crypto::accessory_public_key_for_device_id;
    use crate::airplay::txt_records::stable_uuid;
    let features = ap2_policy.features;
    let features_lo = (features & 0xffff_ffff) as u32;
    let features_hi = (features >> 32) as u32;
    let pk_raw = accessory_public_key_for_device_id(&config.device_id);
    let pk_hex = pk_raw
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let fex = ap2_policy.features_ex();
    let pi = stable_uuid("pi", &config.device_id).to_string();
    let psi = stable_uuid("psi", &config.device_id).to_string();
    let gid = group_uuid.unwrap_or(&pi);
    let gcgl = u8::from(group_contains_group_leader);

    let entries: Vec<String> = vec![
        "acl=0".to_string(),
        "btaddr=00:00:00:00:00:00".to_string(),
        format!("deviceid={}", config.device_id),
        format!("fex={fex}"),
        format!("features=0x{features_lo:X},0x{features_hi:X}"),
        format!("flags=0x{:x}", ap2_policy.status_flags),
        format!("gid={gid}"),
        "igl=0".to_string(),
        format!("gcgl={gcgl}"),
        format!("pgid={pi}"),
        format!("pgcgl={gcgl}"),
        "model=ShairportSync".to_string(),
        "protovers=1.1".to_string(),
        format!("pi={pi}"),
        format!("psi={psi}"),
        format!("pk={pk_hex}"),
        "srcvers=366.0".to_string(),
        "osvers=15.0".to_string(),
        "vv=2".to_string(),
    ];

    let mut out = Vec::new();
    for entry in &entries {
        let len = entry.len().min(255) as u8;
        out.push(len);
        out.extend_from_slice(entry.as_bytes());
    }
    out
}

pub fn parse_request(buf: &[u8]) -> Option<(RtspRequest, usize)> {
    let header_end = find_header_end(buf)?;
    let headers_raw = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = headers_raw.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let uri = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    let content_length = headers
        .get("Content-Length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    let consumed = body_start + content_length;
    if buf.len() < consumed {
        return None;
    }
    Some((
        RtspRequest {
            method,
            uri,
            version,
            headers,
            body: buf[body_start..consumed].to_vec(),
        },
        consumed,
    ))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn response(code: u16, reason: &'static str) -> RtspResponse {
    RtspResponse {
        code,
        reason,
        headers: vec![("Server".to_string(), "AirTunes/366.0".to_string())],
        body: Vec::new(),
    }
}

impl RtspResponse {
    fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_header(name.into(), value.into());
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    fn with_cseq(mut self, request: &RtspRequest) -> Self {
        if let Some(cseq) = request.headers.get("CSeq") {
            self.set_header("CSeq".to_string(), cseq.clone());
        }
        self
    }

    fn set_header(&mut self, name: String, value: String) {
        if let Some((_, existing)) = self
            .headers
            .iter_mut()
            .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
        {
            *existing = value;
        } else if name.eq_ignore_ascii_case("CSeq") {
            self.headers.insert(0, (name, value));
        } else {
            self.headers.push((name, value));
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("RTSP/1.0 {} {}\r\n", self.code, self.reason).into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playout::scheduler::{PlayoutCommand, PlayoutHandle};
    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit,
        aead::{Aead, Payload},
    };
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc::UnboundedReceiver;

    /// Create a test-only [`PlayoutHandle`] and its associated command and
    /// ingress receivers.  Tests that need to assert exact command sequences
    /// keep `cmd_rx`; others drop it.
    fn test_playout() -> (
        PlayoutHandle,
        UnboundedReceiver<PlayoutCommand>,
        crate::playout::ingress::IngressReceiver,
    ) {
        PlayoutHandle::command_channel_for_tests(64)
    }

    /// Drain all pending commands from the receiver and return them as a Vec.
    fn drain_cmds(rx: &mut UnboundedReceiver<PlayoutCommand>) -> Vec<PlayoutCommand> {
        let mut cmds = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            cmds.push(cmd);
        }
        cmds
    }

    /// Build a test-capability policy with AP2 enabled and PTP available.
    /// Most tests don't exercise the policy details; they just need a valid
    /// value to satisfy the `ConnectionServices` constructor.
    fn test_policy() -> Ap2CapabilityPolicy {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        Ap2CapabilityPolicy::from_config(&config, true)
    }

    #[test]
    fn parses_rtsp_request_with_body() {
        let raw = b"SET_PARAMETER rtsp://x RTSP/1.0\r\nCSeq: 4\r\nContent-Length: 15\r\n\r\nvolume: -10.0\r\n";
        let (request, consumed) = parse_request(raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(request.method, "SET_PARAMETER");
        assert_eq!(request.headers.get("CSeq").unwrap(), "4");
        assert_eq!(request.body, b"volume: -10.0\r\n");
    }

    #[test]
    fn set_parameter_volume_updates_state_and_audio_gain() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        let (audio_engine, mut consumer) = AudioEngine::new(8);
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "text/parameters".to_string());
        let request = RtspRequest {
            method: "SET_PARAMETER".to_string(),
            uri: "rtsp://x".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body: b"volume: -6.0\r\n".to_vec(),
        };

        let dacp = DacpController::disabled(state.clone());
        apply_set_parameter(&state, &audio_engine, &playout, &dacp, None, &request);

        assert_eq!(state.snapshot().volume.airplay_db, -6.0);
        let mut silence = [0.0; 2_048];
        consumer.fill_output(&mut silence);
        assert_eq!(audio_engine.enqueue_interleaved(&[1.0, 1.0]), 2);
        let mut out = [0.0; 2];
        consumer.fill_output(&mut out);
        assert!((out[0] - 0.501_187_2).abs() < 0.000_01);
    }

    #[test]
    fn set_parameter_rejects_non_finite_volume() {
        let state = AppState::new(crate::config::Config::default());
        let (audio_engine, mut consumer) = AudioEngine::new(8);
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let dacp = DacpController::disabled(state.clone());
        let request = RtspRequest {
            method: "SET_PARAMETER".to_string(),
            uri: "rtsp://x".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::from([("Content-Type".to_string(), "text/parameters".to_string())]),
            body: b"volume: NaN\r\n".to_vec(),
        };

        apply_set_parameter(&state, &audio_engine, &playout, &dacp, None, &request);

        assert_eq!(state.snapshot().volume.airplay_db, -30.0);
        assert_eq!(audio_engine.enqueue_interleaved(&[1.0, 1.0]), 2);
        let mut out = [0.0; 2];
        consumer.fill_output(&mut out);
        assert_eq!(out, [1.0, 1.0]);
    }

    #[test]
    fn get_parameter_volume_returns_current_airplay_db() {
        let state = AppState::new(crate::config::Config::default());
        state.set_airplay_volume(-12.5);
        let request = RtspRequest {
            method: "GET_PARAMETER".to_string(),
            uri: "rtsp://x".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::from([("CSeq".to_string(), "9".to_string())]),
            body: b"  VoLuMe \r\n".to_vec(),
        };

        let response = get_parameter_response(&state, &request);

        assert_eq!(response.code, 200);
        assert_eq!(response.body, b"volume: -12.500000\r\n");
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Content-Type") && value == "text/parameters"
        }));
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| name == "CSeq" && value == "9")
        );
    }

    #[test]
    fn text_progress_uses_airplay_rtp_timestamps() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let dacp = DacpController::disabled(state.clone());
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "text/parameters".to_string());
        let request = RtspRequest {
            method: "SET_PARAMETER".to_string(),
            uri: "rtsp://x".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body: b"Progress: 44100/88200/176400\r\n".to_vec(),
        };

        apply_set_parameter(&state, &audio_engine, &playout, &dacp, None, &request);

        assert_eq!(state.snapshot().track.progress_ms, Some(1_000));
        assert_eq!(state.snapshot().track.duration_ms, Some(3_000));
    }

    #[test]
    fn text_title_release_starts_playout() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        state.set_track_metadata(Some("Old song".to_string()), None, None);
        state.clear_track_for_transition();
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();
        let dacp = DacpController::disabled(state.clone());
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "text/parameters".to_string());
        let request = RtspRequest {
            method: "SET_PARAMETER".to_string(),
            uri: "rtsp://x".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body: b"title: New song\r\nartist: Singer\r\n".to_vec(),
        };

        apply_set_parameter(&state, &audio_engine, &playout, &dacp, None, &request);

        assert!(!state.is_waiting_for_track_title());
        assert_eq!(state.snapshot().track.title.as_deref(), Some("New song"));
        assert_eq!(
            drain_cmds(&mut cmd_rx).as_slice(),
            &[PlayoutCommand::Start],
            "text metadata title release must start playout"
        );
    }

    #[test]
    fn ap2_command_pause_and_play_gate_playout() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let pause = ap2_command_request("pause");
        apply_ap2_command(&state, &audio_engine, &playout, &player, &dacp, &pause);

        assert!(matches!(state.snapshot().player_state, PlayerState::Paused));
        // Pause emits exact [Pause, Flush]
        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds.as_slice(),
            &[PlayoutCommand::Pause, PlayoutCommand::Flush],
            "pause must emit exactly [Pause, Flush]"
        );

        let play = ap2_command_request("play");
        apply_ap2_command(&state, &audio_engine, &playout, &player, &dacp, &play);

        assert!(matches!(
            state.snapshot().player_state,
            PlayerState::Playing
        ));
        // Play emits Start (no waiting for title)
        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds.as_slice(),
            &[PlayoutCommand::Start],
            "play must emit exactly [Start] when title is ready"
        );
    }

    #[test]
    fn now_playing_update_is_not_misclassified_as_play_command() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let request = ap2_command_request("updateNowPlayingInfo");
        apply_ap2_command(&state, &audio_engine, &playout, &player, &dacp, &request);

        assert!(matches!(
            state.snapshot().player_state,
            PlayerState::Stopped
        ));
        assert!(drain_cmds(&mut cmd_rx).is_empty());
    }

    #[test]
    fn navigation_command_flushes_stale_track_and_audio() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        state.set_track_metadata(Some("Old song".to_string()), None, None);
        state.set_progress_ms(42_000);
        *state.alac_sample_rate.write() = Some(44_100);
        *state.alac_sample_size.write() = Some(16);
        *state.alac_channels.write() = Some(2);
        *state.frames_per_packet.write() = Some(352);
        let epoch = state.track_transition_epoch();
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let next = ap2_command_request("next");
        apply_ap2_command(&state, &audio_engine, &playout, &player, &dacp, &next);

        // Navigation should send exact [Pause, Flush]
        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds.as_slice(),
            &[PlayoutCommand::Pause, PlayoutCommand::Flush],
            "navigation must emit exactly [Pause, Flush]"
        );

        let snapshot = state.snapshot();
        assert_eq!(snapshot.track.title, None);
        assert_eq!(snapshot.track.progress_ms, Some(0));
        assert!(snapshot.track.awaiting_title);
        assert!(state.alac_sample_rate.read().is_none());
        assert!(state.alac_sample_size.read().is_none());
        assert!(state.alac_channels.read().is_none());
        assert!(state.frames_per_packet.read().is_none());
        assert!(state.track_transition_epoch() > epoch);
    }

    #[test]
    fn ap2_rate_start_does_not_wait_for_title_or_metadata() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        state.set_track_metadata(Some("Old song".to_string()), None, None);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        apply_ap2_command(
            &state,
            &audio_engine,
            &playout,
            &player,
            &dacp,
            &ap2_command_request("next"),
        );
        // Navigation sends Pause + Flush; drain them
        drain_cmds(&mut cmd_rx);

        let request = setrateanchortime_request(1);
        let control = parse_setrateanchortime(&request, 44_100).unwrap();
        apply_setrateanchortime(&state, &playout, control);

        assert!(state.snapshot().track.awaiting_title);
        // AP2 transport timing is independent of title metadata.
        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds,
            vec![PlayoutCommand::SetTimeline(control.anchor.unwrap())]
        );

        let metadata = ap2_now_playing_request("New song", "Singer", "Record");
        apply_ap2_command(&state, &audio_engine, &playout, &player, &dacp, &metadata);

        assert!(!state.snapshot().track.awaiting_title);
        // Metadata updates do not emit scheduler commands.
        let cmds = drain_cmds(&mut cmd_rx);
        assert!(cmds.is_empty());
    }

    #[test]
    fn ap1_record_emits_start_when_title_ready() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        state.set_track_metadata(Some("Song Title".to_string()), None, None);
        *state.alac_sample_rate.write() = Some(44_100);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        let request = RtspRequest {
            method: "RECORD".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);

        // Title is set → enable_audio_when_track_ready emits Start
        let cmds = drain_cmds(&mut cmd_rx);
        assert!(
            cmds.contains(&PlayoutCommand::Start),
            "AP1 RECORD must emit Start when title is ready, got {cmds:?}"
        );
    }

    #[test]
    fn ap1_record_does_not_start_when_awaiting_title() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        state.clear_track_for_transition(); // sets awaiting_title = true
        *state.alac_sample_rate.write() = Some(44_100);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        let request = RtspRequest {
            method: "RECORD".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);

        // Awaiting title → only Flush emitted, no Start
        let cmds = drain_cmds(&mut cmd_rx);
        assert!(
            !cmds.contains(&PlayoutCommand::Start),
            "AP1 RECORD must NOT emit Start when awaiting title, got {cmds:?}"
        );
        assert!(
            cmds.contains(&PlayoutCommand::Flush),
            "AP1 RECORD must emit Flush when awaiting title, got {cmds:?}"
        );
    }

    #[test]
    fn flush_emits_exact_pause_then_flush() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        let request = RtspRequest {
            method: "FLUSH".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);

        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds.as_slice(),
            &[PlayoutCommand::Pause, PlayoutCommand::Flush],
            "FLUSH must emit exactly [Pause, Flush]"
        );
        assert!(matches!(state.snapshot().player_state, PlayerState::Paused));
    }

    #[test]
    fn pause_emits_exact_pause_then_flush() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        let request = RtspRequest {
            method: "PAUSE".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);

        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds.as_slice(),
            &[PlayoutCommand::Pause, PlayoutCommand::Flush],
            "PAUSE must emit exactly [Pause, Flush]"
        );
        assert!(matches!(state.snapshot().player_state, PlayerState::Paused));
    }

    #[test]
    fn ap2_command_recursively_updates_now_playing_metadata() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        state.set_track_metadata(Some("Old song".to_string()), None, None);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        let request = ap2_now_playing_request("New song", "Singer", "Record");

        apply_ap2_command(&state, &audio_engine, &playout, &player, &dacp, &request);

        // Title changed (Old → New) while not waiting for title:
        // Pause + Flush sent, then enable_audio_when_track_ready → Start.
        let cmds = drain_cmds(&mut cmd_rx);
        assert!(cmds.is_empty());

        let track = state.snapshot().track;
        assert_eq!(track.title.as_deref(), Some("New song"));
        assert_eq!(track.artist.as_deref(), Some("Singer"));
        assert_eq!(track.album.as_deref(), Some("Record"));
        assert_eq!(track.progress_ms, Some(12_500));
        assert_eq!(track.duration_ms, Some(240_000));
    }

    #[test]
    fn serializes_cseq_response() {
        let (request, _) = parse_request(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").unwrap();
        let bytes = response(200, "OK").with_cseq(&request).to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("RTSP/1.0 200 OK"));
        assert!(text.contains("CSeq: 1"));
    }

    fn ap2_command_request(command: &str) -> RtspRequest {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "command".to_string(),
            plist::Value::String(command.to_string()),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        RtspRequest {
            method: "POST".to_string(),
            uri: "/command".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    fn ap2_now_playing_request(title: &str, artist: &str, album: &str) -> RtspRequest {
        let mut item = plist::Dictionary::new();
        item.insert("title".to_string(), plist::Value::String(title.to_string()));
        item.insert(
            "artist".to_string(),
            plist::Value::String(artist.to_string()),
        );
        item.insert("album".to_string(), plist::Value::String(album.to_string()));
        item.insert("elapsedTime".to_string(), plist::Value::Real(12.5));
        item.insert("duration".to_string(), plist::Value::Real(240.0));
        let mut params = plist::Dictionary::new();
        params.insert(
            "contentItems".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(item)]),
        );
        let mut command = plist::Dictionary::new();
        command.insert(
            "type".to_string(),
            plist::Value::String("updateContentItem".to_string()),
        );
        command.insert("params".to_string(), plist::Value::Dictionary(params));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(command)).unwrap();
        RtspRequest {
            method: "POST".to_string(),
            uri: "/command".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    fn setrateanchortime_request(rate: u64) -> RtspRequest {
        let mut dict = plist::Dictionary::new();
        dict.insert("rate".to_string(), plist_uint_value(rate));
        if rate == 1 {
            dict.insert("networkTimeTimelineID".to_string(), plist_uint_value(42u64));
            dict.insert("networkTimeSecs".to_string(), plist_uint_value(1u64));
            dict.insert("networkTimeFrac".to_string(), plist_uint_value(0u64));
            dict.insert("rtpTime".to_string(), plist_uint_value(100u64));
        }
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        RtspRequest {
            method: "SETRATEANCHORTIME".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    /// Build a SETRATEANCHORTIME request where individual anchor fields
    /// can be arbitrary plist::Value (for testing signed / high-bit values).
    fn setrateanchortime_request_with_values(
        rate: u64,
        timeline_id: Option<plist::Value>,
        secs: Option<plist::Value>,
        frac: Option<plist::Value>,
        rtp: Option<plist::Value>,
    ) -> RtspRequest {
        let mut dict = plist::Dictionary::new();
        dict.insert("rate".to_string(), plist_uint_value(rate));
        if let Some(v) = timeline_id {
            dict.insert("networkTimeTimelineID".to_string(), v);
        }
        if let Some(v) = secs {
            dict.insert("networkTimeSecs".to_string(), v);
        }
        if let Some(v) = frac {
            dict.insert("networkTimeFrac".to_string(), v);
        }
        if let Some(v) = rtp {
            dict.insert("rtpTime".to_string(), v);
        }
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        RtspRequest {
            method: "SETRATEANCHORTIME".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    #[test]
    fn setrateanchortime_requires_complete_anchor_for_rate_one() {
        let request = setrateanchortime_request(0);
        let control = parse_setrateanchortime(&request, 44_100).unwrap();
        assert_eq!(control.rate, PlaybackRate::Paused);
        assert!(control.anchor.is_none());

        let mut dict = plist::Dictionary::new();
        dict.insert("rate".to_string(), plist_uint_value(1u64));
        dict.insert("networkTimeSecs".to_string(), plist_uint_value(1u64));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        let request = RtspRequest {
            method: "SETRATEANCHORTIME".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        assert_eq!(
            parse_setrateanchortime(&request, 44_100),
            Err("rate=1 requires a complete network/RTP anchor")
        );
    }

    #[test]
    fn setrateanchortime_converts_ntp_fraction_and_validates_rtp_range() {
        let mut request = setrateanchortime_request(1);
        let mut dict: plist::Dictionary = plist::from_bytes(&request.body).unwrap();
        dict.insert("networkTimeFrac".to_string(), plist_uint_value(u64::MAX));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict.clone())).unwrap();
        request.body = body;
        let anchor = parse_setrateanchortime(&request, 48_000)
            .unwrap()
            .anchor
            .unwrap();
        assert_eq!(anchor.network_time_ns, 1_999_999_999);
        assert_eq!(anchor.sample_rate, 48_000);

        dict.insert("rtpTime".to_string(), plist_uint_value(u32::MAX as u64 + 1));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        request.body = body;
        assert_eq!(
            parse_setrateanchortime(&request, 48_000),
            Err("rate=1 requires a complete network/RTP anchor")
        );
    }

    fn flushbuffered_request(from: Option<(u64, u64)>, until: Option<(u64, u64)>) -> RtspRequest {
        let mut dict = plist::Dictionary::new();
        if let Some((sequence, timestamp)) = from {
            dict.insert("flushFromSeq".to_string(), plist_uint_value(sequence));
            dict.insert("flushFromTS".to_string(), plist_uint_value(timestamp));
        }
        if let Some((sequence, timestamp)) = until {
            dict.insert("flushUntilSeq".to_string(), plist_uint_value(sequence));
            dict.insert("flushUntilTS".to_string(), plist_uint_value(timestamp));
        }
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        RtspRequest {
            method: "FLUSHBUFFERED".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    #[test]
    fn flushbuffered_parser_accepts_immediate_and_deferred_ranges() {
        let immediate = parse_flushbuffered(&flushbuffered_request(None, Some((12, 102)))).unwrap();
        assert_eq!(immediate.from_sequence, None);
        assert_eq!(immediate.until_sequence, 12);

        let deferred =
            parse_flushbuffered(&flushbuffered_request(Some((11, 101)), Some((13, 103)))).unwrap();
        assert_eq!(deferred.from_sequence, Some(11));
        assert_eq!(deferred.from_rtp_timestamp, Some(101));
        assert_eq!(deferred.until_sequence, 13);
    }

    #[test]
    fn flushbuffered_parser_rejects_partial_and_out_of_range_fields() {
        assert_eq!(
            parse_flushbuffered(&flushbuffered_request(Some((1, 2)), None)),
            Err("flushUntilSeq is required")
        );

        let mut request = flushbuffered_request(None, Some((1, 2)));
        let mut dict: plist::Dictionary = plist::from_bytes(&request.body).unwrap();
        dict.insert("flushFromSeq".to_string(), plist_uint_value(1u64));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        request.body = body;
        assert_eq!(
            parse_flushbuffered(&request),
            Err("flushFromSeq and flushFromTS must be supplied together")
        );

        // Values wider than u32 are rejected by plist_opaque_u32 (returns None).
        assert_eq!(
            parse_flushbuffered(&flushbuffered_request(None, Some((0x1_0000_0000, 2)))),
            Err("flushUntilSeq is required")
        );
    }

    // ── SETRATEANCHORTIME signed / high-bit / opaque acceptance ──────

    #[test]
    fn setrateanchortime_accepts_signed_anchor_fields() {
        // All anchor fields as signed integers should be accepted.
        let req = setrateanchortime_request_with_values(
            1,
            Some(plist::Value::Integer(plist::Integer::from(-1i64))), // timeline_id = -1 -> u64::MAX
            Some(plist::Value::Integer(plist::Integer::from(1u64))),  // seconds strict unsigned
            Some(plist::Value::Integer(plist::Integer::from(-1i64))), // frac = -1 -> u64::MAX
            Some(plist::Value::Integer(plist::Integer::from(-100i64))), // rtpTime = -100 -> 0xffffff9c
        );
        let anchor = parse_setrateanchortime(&req, 44_100)
            .unwrap()
            .anchor
            .unwrap();
        assert_eq!(anchor.timeline_id, u64::MAX);
        assert_eq!(anchor.network_time_ns, 1_999_999_999); // 1 sec + (frac_max as ns)
        assert_eq!(anchor.rtp_timestamp, (-100i32) as u32); // 0xffffff9c
    }

    #[test]
    fn setrateanchortime_accepts_rtp_as_signed_i32_min() {
        let req = setrateanchortime_request_with_values(
            1,
            Some(plist::Value::Integer(plist::Integer::from(42u64))),
            Some(plist::Value::Integer(plist::Integer::from(0u64))),
            Some(plist::Value::Integer(plist::Integer::from(0u64))),
            Some(plist::Value::Integer(plist::Integer::from(i32::MIN as i64))),
        );
        let anchor = parse_setrateanchortime(&req, 44_100)
            .unwrap()
            .anchor
            .unwrap();
        assert_eq!(anchor.rtp_timestamp, i32::MIN as u32); // 0x80000000
    }

    #[test]
    fn setrateanchortime_rejects_rtp_wider_than_u32() {
        let req = setrateanchortime_request_with_values(
            1,
            Some(plist::Value::Integer(plist::Integer::from(42u64))),
            Some(plist::Value::Integer(plist::Integer::from(0u64))),
            Some(plist::Value::Integer(plist::Integer::from(0u64))),
            Some(plist::Value::Integer(plist::Integer::from(
                u32::MAX as u64 + 1,
            ))),
        );
        assert_eq!(
            parse_setrateanchortime(&req, 44_100),
            Err("rate=1 requires a complete network/RTP anchor")
        );
    }

    #[test]
    fn setrateanchortime_rejects_network_time_secs_signed() {
        // networkTimeSecs uses strict plist_uint — signed negative must
        // be rejected, causing an incomplete anchor.
        let req = setrateanchortime_request_with_values(
            1,
            Some(plist::Value::Integer(plist::Integer::from(42u64))),
            Some(plist::Value::Integer(plist::Integer::from(-1i64))),
            Some(plist::Value::Integer(plist::Integer::from(0u64))),
            Some(plist::Value::Integer(plist::Integer::from(100u64))),
        );
        assert_eq!(
            parse_setrateanchortime(&req, 44_100),
            Err("rate=1 requires a complete network/RTP anchor")
        );
    }

    #[test]
    fn setrateanchortime_rate_strict_zero_or_one() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "rate".to_string(),
            plist::Value::Integer(plist::Integer::from(2i64)),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        let req = RtspRequest {
            method: "SETRATEANCHORTIME".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        assert_eq!(
            parse_setrateanchortime(&req, 44_100),
            Err("rate must be 0 or 1")
        );
    }

    // ── FLUSHBUFFERED signed / high-bit / opaque acceptance ──────────

    fn flushbuffered_request_with_values(
        from_seq: Option<plist::Value>,
        from_ts: Option<plist::Value>,
        until_seq: Option<plist::Value>,
        until_ts: Option<plist::Value>,
    ) -> RtspRequest {
        let mut dict = plist::Dictionary::new();
        if let Some(v) = from_seq {
            dict.insert("flushFromSeq".to_string(), v);
        }
        if let Some(v) = from_ts {
            dict.insert("flushFromTS".to_string(), v);
        }
        if let Some(v) = until_seq {
            dict.insert("flushUntilSeq".to_string(), v);
        }
        if let Some(v) = until_ts {
            dict.insert("flushUntilTS".to_string(), v);
        }
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        RtspRequest {
            method: "FLUSHBUFFERED".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    #[test]
    fn flushbuffered_accepts_signed_sequence_normalizes_23bit() {
        // Signed negative sequence = 0xffffffff in 32-bit, low 23 bits = 0x7fffff.
        let range = parse_flushbuffered(&flushbuffered_request_with_values(
            None,
            None,
            Some(plist::Value::Integer(plist::Integer::from(-1i64))),
            Some(plist::Value::Integer(plist::Integer::from(100u64))),
        ))
        .unwrap();
        assert_eq!(range.until_sequence, 0x7f_ffff);
        assert_eq!(range.until_rtp_timestamp, 100);
    }

    #[test]
    fn flushbuffered_accepts_signed_sequence_value() {
        // Sequence = 0x800000 stored as signed i32: when read as i32 it's
        // -8388608, which when cast to u32 is 0xff800000. Low 23 bits = 0.
        let range = parse_flushbuffered(&flushbuffered_request_with_values(
            Some(plist::Value::Integer(plist::Integer::from(0x800000i64))),
            Some(plist::Value::Integer(plist::Integer::from(1u64))),
            Some(plist::Value::Integer(plist::Integer::from(0x900000i64))),
            Some(plist::Value::Integer(plist::Integer::from(2u64))),
        ))
        .unwrap();
        assert_eq!(range.from_sequence, Some(0x800000 & 0x7f_ffff));
        assert_eq!(range.until_sequence, 0x900000 & 0x7f_ffff);
    }

    #[test]
    fn flushbuffered_rejects_wider_than_32bit_sequence() {
        // u64::MAX is wider than 32 bits — plist_opaque_u32 returns None,
        // so flushUntilSeq is missing.
        assert_eq!(
            parse_flushbuffered(&flushbuffered_request_with_values(
                None,
                None,
                Some(plist::Value::Integer(plist::Integer::from(u64::MAX))),
                Some(plist::Value::Integer(plist::Integer::from(0u64))),
            )),
            Err("flushUntilSeq is required")
        );
    }

    #[test]
    fn flushbuffered_accepts_signed_timestamp() {
        let range = parse_flushbuffered(&flushbuffered_request_with_values(
            None,
            None,
            Some(plist::Value::Integer(plist::Integer::from(100u64))),
            Some(plist::Value::Integer(plist::Integer::from(-1i64))),
        ))
        .unwrap();
        assert_eq!(range.until_rtp_timestamp, u32::MAX);
    }

    // ── plist_opaque_u32 helper ──────────────────────────────────────

    #[test]
    fn plist_opaque_u32_accepts_unsigned() {
        let v = plist::Value::Integer(plist::Integer::from(42u64));
        assert_eq!(plist_opaque_u32(&v), Some(42));
    }

    #[test]
    fn plist_opaque_u32_accepts_signed_positive() {
        let v = plist::Value::Integer(plist::Integer::from(42i64));
        assert_eq!(plist_opaque_u32(&v), Some(42));
    }

    #[test]
    fn plist_opaque_u32_accepts_negative_as_bit_pattern() {
        let v = plist::Value::Integer(plist::Integer::from(-1i64));
        assert_eq!(plist_opaque_u32(&v), Some(u32::MAX));
    }

    #[test]
    fn plist_opaque_u32_accepts_i32_min() {
        let v = plist::Value::Integer(plist::Integer::from(i32::MIN as i64));
        assert_eq!(plist_opaque_u32(&v), Some(i32::MIN as u32));
    }

    #[test]
    fn plist_opaque_u32_rejects_wider_than_u32() {
        let v = plist::Value::Integer(plist::Integer::from(u32::MAX as u64 + 1));
        assert_eq!(plist_opaque_u32(&v), None);
    }

    #[test]
    fn plist_opaque_u32_rejects_i64_min() {
        let v = plist::Value::Integer(plist::Integer::from(i64::MIN));
        assert_eq!(plist_opaque_u32(&v), None);
    }

    #[test]
    fn plist_opaque_u32_rejects_non_integer() {
        let v = plist::Value::String("bad".to_string());
        assert_eq!(plist_opaque_u32(&v), None);
    }

    #[test]
    fn configure_parses_typed_fields_and_returns_homekit_identity() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let pairing = PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        );
        let mut session = RtspSession::default();
        session.ap2.mark_paired().unwrap();

        let mut nested = plist::Dictionary::new();
        nested.insert(
            "Enable_HK_Access_Control".to_string(),
            plist::Value::Boolean(true),
        );
        nested.insert("Access_Control_Level".to_string(), plist_uint_value(2u64));
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "timingProtocol".to_string(),
            plist::Value::String("PTP".to_string()),
        );
        dict.insert(
            "groupUUID".to_string(),
            plist::Value::String("private-group-value".to_string()),
        );
        dict.insert(
            "streamCategory".to_string(),
            plist::Value::String("audio".to_string()),
        );
        dict.insert(
            "ConfigurationDictionary".to_string(),
            plist::Value::Dictionary(nested),
        );
        let request = ap2_plist_request("POST", dict);

        let response = handle_configure(&config.airplay, &state, &mut session, &pairing, &request);
        assert_eq!(response.code, 200);
        let response_dict: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        assert_eq!(
            response_dict
                .get("Enable_HK_Access_Control")
                .and_then(plist_bool),
            Some(true)
        );
        assert_eq!(
            response_dict
                .get("PublicKey")
                .and_then(plist::Value::as_data)
                .map(<[u8]>::len),
            Some(32)
        );

        assert_eq!(
            session.ap2.configuration(),
            &Ap2Configuration {
                timing_protocol: Some(Ap2TimingProtocol::Ptp),
                group_uuid_present: true,
                stream_category: Some("audio".to_string()),
                enable_hk_access_control: Some(true),
                access_control_level: Some(2),
            }
        );
        assert!(!format!("{:?}", session.ap2.configuration()).contains("private-group-value"));
    }

    #[test]
    fn configure_rejects_malformed_transactionally() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let pairing = PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        );
        let mut session = RtspSession::default();
        session.ap2.mark_paired().unwrap();
        let original = session.ap2.configuration().clone();

        let mut dict = plist::Dictionary::new();
        dict.insert(
            "ConfigurationDictionary".to_string(),
            plist::Value::String("not-a-dictionary".to_string()),
        );
        let request = ap2_plist_request("POST", dict);
        let response = handle_configure(&config.airplay, &state, &mut session, &pairing, &request);

        assert_eq!(response.code, 400);
        assert_eq!(session.ap2.configuration(), &original);
    }

    #[test]
    fn fairplay_setup1_returns_mode_reply() {
        let mut request = vec![0; 16];
        request[..4].copy_from_slice(b"FPLY");
        request[4] = 3;
        request[5] = 1;
        request[6] = 1;
        request[8..12].copy_from_slice(&4u32.to_be_bytes());
        request[14] = 2;
        let mut state = FairPlayState::NotStarted;

        let reply = fairplay_setup_reply(&mut state, &request).unwrap();

        assert_eq!(reply, FAIRPLAY_REPLY_MODE_2);
        assert_eq!(state, FairPlayState::AwaitingSetup2 { mode: 2 });
    }

    #[test]
    fn fairplay_setup2_echoes_suffix_with_header() {
        let mut request = vec![0; 40];
        request[..4].copy_from_slice(b"FPLY");
        request[4] = 3;
        request[5] = 1;
        request[6] = 3;
        request[8..12].copy_from_slice(&28u32.to_be_bytes());
        for (index, byte) in request[20..].iter_mut().enumerate() {
            *byte = index as u8;
        }

        let mut state = FairPlayState::AwaitingSetup2 { mode: 1 };
        let reply = fairplay_setup_reply(&mut state, &request).unwrap();

        assert_eq!(
            &reply[..FAIRPLAY_SETUP2_HEADER.len()],
            FAIRPLAY_SETUP2_HEADER
        );
        assert_eq!(&reply[FAIRPLAY_SETUP2_HEADER.len()..], &request[20..]);
        assert_eq!(state, FairPlayState::Complete { mode: 1 });
    }

    #[test]
    fn fairplay_rejects_bad_magic_and_declared_length() {
        let mut state = FairPlayState::NotStarted;
        let mut request = vec![0; 16];
        request[4] = 3;
        request[5] = 1;
        request[6] = 1;
        request[8..12].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(
            fairplay_setup_reply(&mut state, &request),
            Err("invalid FairPlay magic")
        );

        request[..4].copy_from_slice(b"FPLY");
        request[8..12].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            fairplay_setup_reply(&mut state, &request),
            Err("FairPlay payload length mismatch")
        );
        assert_eq!(state, FairPlayState::NotStarted);
    }

    #[test]
    fn fairplay_setup2_requires_setup1() {
        let mut request = vec![0; 40];
        request[..4].copy_from_slice(b"FPLY");
        request[4] = 3;
        request[5] = 1;
        request[6] = 3;
        request[8..12].copy_from_slice(&28u32.to_be_bytes());
        let mut state = FairPlayState::NotStarted;

        assert_eq!(
            fairplay_setup_reply(&mut state, &request),
            Err("FairPlay setup2 received before setup1")
        );
        assert_eq!(state, FairPlayState::NotStarted);
    }

    #[test]
    fn fairplay_setup1_cannot_restart_an_in_progress_or_completed_exchange() {
        let mut request = vec![0; 16];
        request[..4].copy_from_slice(b"FPLY");
        request[4] = 3;
        request[5] = 1;
        request[6] = 1;
        request[8..12].copy_from_slice(&4u32.to_be_bytes());
        request[14] = 2;

        for initial in [
            FairPlayState::AwaitingSetup2 { mode: 2 },
            FairPlayState::Complete { mode: 2 },
        ] {
            let mut state = initial;
            assert_eq!(
                fairplay_setup_reply(&mut state, &request),
                Err("FairPlay setup1 received after negotiation started")
            );
            assert_eq!(state, initial);
        }
    }

    #[tokio::test]
    async fn ap2_buffered_setup_returns_ports_and_uses_session_stream_context() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.audio_port = 6000;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();
        // Must be paired + timing-configured before stream SETUP.
        session.ap2.mark_paired().unwrap();
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![7u8; 32]));
        // The real sender omits `sr`; audioFormat is authoritative for the
        // sample rate and `sr`, when present, is only a consistency check.
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0080_0000u64));
        stream.insert("spf".to_string(), plist_uint_value(1024u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();

        assert_eq!(first.get("type").and_then(plist_uint), Some(103));
        let data_port = first.get("dataPort").and_then(plist_uint).unwrap();
        let control_port = first.get("controlPort").and_then(plist_uint).unwrap();
        assert!(data_port > 0);
        assert!(control_port > 0);
        assert_ne!(data_port, control_port);
        assert_eq!(
            first.get("audioBufferSize").and_then(plist_uint),
            Some(advertised_audio_buffer_size(64 + 512) as u64)
        );
        assert_eq!(*state.session_crypto.read(), None);
        let configured = session
            .ap2
            .find_stream_by_type(Ap2StreamType::BufferedAudio)
            .unwrap();
        assert_eq!(configured.media_key(), Some(&[7u8; 32]));
        assert_eq!(
            configured.audio_format(),
            Some(AudioFormat::Aac48000F24Stereo)
        );
        assert_eq!(
            drain_cmds(&mut cmd_rx),
            vec![PlayoutCommand::ConfigureStream(Ap2StreamRuntime {
                stream_id: configured.stream_id,
                stream_connection_id: configured.stream_connection_id,
                audio_format: AudioFormat::Aac48000F24Stereo,
                sample_rate: 48_000,
                frames_per_packet: 1024,
            })]
        );
    }

    // ── Realtime type 96 / Data type 130 rejection ──────────────────────

    #[tokio::test]
    async fn ap2_setup_realtime_type96_returns_udp_ports_and_runtime() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();
        session.ap2.mark_paired().unwrap();
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(96u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![9u8; 32]));
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0080_0000u64));
        stream.insert("spf".to_string(), plist_uint_value(1024u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, mut ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 200);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();
        assert_eq!(first.get("type").and_then(plist_uint), Some(96));
        let data_port = first.get("dataPort").and_then(plist_uint).unwrap();
        let control_port = first.get("controlPort").and_then(plist_uint).unwrap();
        assert!(data_port > 0);
        assert!(control_port > 0);
        assert_ne!(data_port, control_port);
        assert!(first.get("audioBufferSize").is_none());

        let configured = session
            .ap2
            .find_stream_by_type(Ap2StreamType::RealtimeAudio)
            .unwrap();
        assert_eq!(configured.media_key(), Some(&[9u8; 32]));
        assert_eq!(
            configured.audio_format(),
            Some(AudioFormat::Aac48000F24Stereo)
        );
        assert_eq!(configured.sample_rate(), Some(48_000));
        assert_eq!(configured.frames_per_packet(), Some(1024));
        assert_eq!(session.realtime_audio_port, Some(data_port as u16));
        assert!(session.realtime_audio_listener.is_some());
        assert_eq!(
            drain_cmds(&mut cmd_rx),
            vec![PlayoutCommand::ConfigureStream(Ap2StreamRuntime {
                stream_id: configured.stream_id,
                stream_connection_id: configured.stream_connection_id,
                audio_format: AudioFormat::Aac48000F24Stereo,
                sample_rate: 48_000,
                frames_per_packet: 1024,
            })]
        );

        // Send one C-compatible encrypted realtime RTP packet to the negotiated
        // UDP data port and prove it reaches the shared AP2 ingress unchanged
        // after authentication/decryption.
        let key = [9u8; 32];
        let sequence = 0x1234u16;
        let timestamp = 0x1020_3040u32;
        let ssrc = 0x5060_7080u32;
        let nonce_suffix = 0x1122_3344_5566_7788u64.to_be_bytes();
        let compressed = b"realtime compressed frame";
        let mut header = [0u8; 12];
        header[0] = 0x80;
        header[1] = 0x60;
        header[2..4].copy_from_slice(&sequence.to_be_bytes());
        header[4..8].copy_from_slice(&timestamp.to_be_bytes());
        header[8..12].copy_from_slice(&ssrc.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&nonce_suffix);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: compressed,
                    aad: &header[4..12],
                },
            )
            .unwrap();
        let mut udp_packet = header.to_vec();
        udp_packet.extend_from_slice(&ciphertext);
        udp_packet.extend_from_slice(&nonce_suffix);
        let target_ip = session.receiver_bind_addr().ip();
        let sender_bind = match target_ip {
            IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            IpAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let sender = tokio::net::UdpSocket::bind(sender_bind).await.unwrap();
        sender
            .send_to(&udp_packet, SocketAddr::new(target_ip, data_port as u16))
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(1), ingress_rx.recv())
            .await
            .expect("realtime packet did not reach playout ingress")
            .expect("playout ingress closed");
        assert_eq!(
            received.protocol,
            crate::playout::packet::StreamProtocol::AirPlay2Realtime
        );
        assert_eq!(received.raw_sequence, u32::from(sequence));
        assert_eq!(received.extended_sequence, u64::from(sequence));
        assert_eq!(received.rtp_timestamp, timestamp);
        assert_eq!(received.ssrc, ssrc);
        assert_eq!(received.format, Some(AudioFormat::Aac48000F24Stereo));
        assert_eq!(received.payload.as_ref(), compressed);
    }

    #[tokio::test]
    async fn ap2_setup_data_type130_rejected_no_listener_activation() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(130u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        // Type-130 without remote-control-only session: 455.
        assert_eq!(response.code, 455);
        assert!(!state.snapshot().active);
    }

    #[tokio::test]
    async fn ap2_setup_unknown_stream_type_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(999u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();

        assert_eq!(first.get("type").and_then(plist_uint), Some(999));
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        assert!(first.get("controlPort").is_none());
    }

    // ── Unsupported timing protocol rejection ───────────────────────────

    #[test]
    fn ap2_initial_setup_ntp_timing_rejected_400() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut setup = plist::Dictionary::new();
        setup.insert(
            "timingProtocol".to_string(),
            plist::Value::String("NTP".to_string()),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );

        assert_eq!(response.code, 400);
        assert_eq!(
            state
                .snapshot()
                .diagnostics
                .get("ap2_timing_protocol_rejected"),
            Some(&"NTP-unsupported".to_string())
        );
    }

    #[test]
    fn ap2_initial_setup_none_timing_rejected_400() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut setup = plist::Dictionary::new();
        setup.insert(
            "timingProtocol".to_string(),
            plist::Value::String("None".to_string()),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );

        assert_eq!(response.code, 400);
        assert_eq!(
            state
                .snapshot()
                .diagnostics
                .get("ap2_timing_protocol_rejected"),
            Some(&"None-without-remote-control".to_string())
        );
    }

    #[test]
    fn ap2_initial_setup_empty_timing_rejected_400() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut setup = plist::Dictionary::new();
        setup.insert(
            "timingProtocol".to_string(),
            plist::Value::String("".to_string()),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );

        assert_eq!(response.code, 400);
    }

    // ── Unplayable format in buffered stream ────────────────────────────

    #[tokio::test]
    async fn ap2_buffered_setup_unplayable_format_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        // AlacOnly policy: AAC is not playable
        config.airplay.advertised_format_policy = crate::config::AdvertisedFormatPolicy::AlacOnly;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        // AAC 44100 (bit 22) — not playable under AlacOnly
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0040_0000u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        stream.insert("sr".to_string(), plist_uint_value(44_100u64));
        stream.insert("spf".to_string(), plist_uint_value(1024u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();

        assert_eq!(first.get("type").and_then(plist_uint), Some(103));
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        // No dataPort or controlPort — listener was never opened
        assert!(first.get("dataPort").is_none());
        assert!(first.get("controlPort").is_none());
        // State must NOT be activated
        assert!(!state.snapshot().active);
        // Diagnostics record rejection
        assert_eq!(
            state.snapshot().diagnostics.get("ap2_stream_setup"),
            Some(&"rejected-pre-validation".to_string())
        );
    }

    // ── Validation edge cases: missing/bad fields, mixed arrays ──────────

    #[tokio::test]
    async fn ap2_setup_type103_missing_audioformat_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        // audioFormat deliberately absent
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();
        assert_eq!(first.get("type").and_then(plist_uint), Some(103));
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        assert!(first.get("dataPort").is_none());
        assert!(first.get("controlPort").is_none());
        assert!(!state.snapshot().active);
        assert!(session.ap2.streams().is_empty());
        assert!(!session.is_playback_owner);
    }

    #[tokio::test]
    async fn ap2_setup_type103_unknown_audioformat_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        stream.insert("audioFormat".to_string(), plist_uint_value(0xDEAD_BEEFu64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();
        assert_eq!(first.get("type").and_then(plist_uint), Some(103));
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        assert!(first.get("dataPort").is_none());
        assert!(first.get("controlPort").is_none());
    }

    #[tokio::test]
    async fn ap2_setup_type103_short_shk_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 16])); // < 32
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("sr".to_string(), plist_uint_value(44_100u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();
        assert_eq!(first.get("type").and_then(plist_uint), Some(103));
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        assert!(first.get("dataPort").is_none());
        assert!(first.get("controlPort").is_none());
    }

    #[tokio::test]
    async fn ap2_setup_type103_identifier_ct_latency_and_key_shapes_are_strict() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();

        let invalid_fields = [
            (
                "streamID",
                plist::Value::String("not-an-integer".to_string()),
            ),
            ("streamID", plist_uint_value(u32::MAX as u64 + 1)),
            (
                "streamConnectionID",
                plist::Value::String("invalid".to_string()),
            ),
            ("ct", plist::Value::String("invalid".to_string())),
            ("latencyMin", plist::Value::String("invalid".to_string())),
            ("shk", plist::Value::Data(vec![1u8; 33])),
        ];

        for (key, value) in invalid_fields {
            let mut session = RtspSession::default();
            test_pair_with_secret(&mut session, [0x44; 32]);
            session
                .ap2
                .configure_timing(Ap2TimingProtocol::Ptp, None, None)
                .unwrap();
            let mut stream = plist::Dictionary::new();
            stream.insert("type".to_string(), plist_uint_value(103u64));
            stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
            stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
            stream.insert("sr".to_string(), plist_uint_value(44_100u64));
            stream.insert("spf".to_string(), plist_uint_value(352u64));
            stream.insert(key.to_string(), value);
            let mut setup = plist::Dictionary::new();
            setup.insert(
                "streams".to_string(),
                plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
            );
            let request = ap2_plist_request("SETUP", setup);

            let response = handle_ap2_setup(
                &config.airplay,
                &state,
                &mut session,
                &request,
                &playout,
                &dacp,
                &policy,
            );
            assert_eq!(response.code, 400, "field {key} should be rejected");
            assert!(session.buffered_audio_listener.is_none());
            assert_eq!(session.ap2.stream_count(), 0);
        }
    }

    #[tokio::test]
    async fn ap2_setup_type103_missing_shk_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        // shk deliberately absent
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("sr".to_string(), plist_uint_value(44_100u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        assert!(first.get("dataPort").is_none());
        assert!(first.get("controlPort").is_none());
    }

    #[tokio::test]
    async fn ap2_setup_type103_sample_rate_mismatch_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        // ALAC 44100 (bit 18) but sr claims 48000
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("sr".to_string(), plist_uint_value(48_000u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        let first = streams[0].as_dictionary().unwrap();
        assert_eq!(first.get("type").and_then(plist_uint), Some(103));
        assert_eq!(first.get("status").and_then(plist_uint), Some(1));
        assert!(first.get("dataPort").is_none());
        assert!(first.get("controlPort").is_none());
    }

    #[tokio::test]
    async fn ap2_setup_mixed_valid_invalid_atomic_rejection() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        // Stream 1: valid buffered audio
        let mut s1 = plist::Dictionary::new();
        s1.insert("type".to_string(), plist_uint_value(103u64));
        s1.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        s1.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        s1.insert("sr".to_string(), plist_uint_value(44_100u64));
        s1.insert("spf".to_string(), plist_uint_value(352u64));
        // Stream 2: invalid type 96
        let mut s2 = plist::Dictionary::new();
        s2.insert("type".to_string(), plist_uint_value(96u64));

        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![
                plist::Value::Dictionary(s1),
                plist::Value::Dictionary(s2),
            ]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };

        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        // Whole-request rejection: 400, all streams get status=1
        assert_eq!(response.code, 400);
        let parsed: plist::Dictionary = plist::from_bytes(&response.body).unwrap();
        let streams = parsed
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        assert_eq!(streams.len(), 2);
        for sv in streams {
            let sd = sv.as_dictionary().unwrap();
            assert_eq!(sd.get("status").and_then(plist_uint), Some(1));
            assert!(sd.get("dataPort").is_none());
            assert!(sd.get("controlPort").is_none());
        }
        // No state mutation
        assert!(!state.snapshot().active);
        assert!(session.ap2.streams().is_empty());
    }

    #[tokio::test]
    async fn ap2_stream_setup_rejected_when_ptp_unavailable() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![7u8; 32]));
        stream.insert("sr".to_string(), plist_uint_value(44_100u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = Ap2CapabilityPolicy::from_config(&config, false);

        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );

        assert_eq!(response.code, 400);
        assert!(session.ap2_control_port.is_none());
        assert!(session.buffered_audio_port.is_none());
        assert!(session.ap2.streams().is_empty());
        assert!(!session.is_playback_owner);
        assert!(!state.snapshot().active);
    }

    #[tokio::test]
    async fn ap2_empty_stream_array_rejected_without_listener() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();
        let mut setup = plist::Dictionary::new();
        setup.insert("streams".to_string(), plist::Value::Array(Vec::new()));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        assert!(session.ap2_control_port.is_none());
        assert!(session.buffered_audio_port.is_none());
        assert!(!state.snapshot().active);
    }

    #[test]
    fn ap2_non_array_streams_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::String("bad".to_string()),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        assert!(session.ap2_control_port.is_none());
        assert_eq!(
            state.snapshot().diagnostics.get("ap2_stream_setup"),
            Some(&"rejected-malformed-streams".to_string())
        );
    }

    #[test]
    fn ap2_initial_setup_missing_timing_protocol_rejected() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let mut session = RtspSession::default();
        let mut body = Vec::new();
        plist::to_writer_binary(
            &mut body,
            &plist::Value::Dictionary(plist::Dictionary::new()),
        )
        .unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let response = handle_ap2_setup(
            &config.airplay,
            &state,
            &mut session,
            &request,
            &playout,
            &dacp,
            &policy,
        );
        assert_eq!(response.code, 400);
        assert_eq!(
            state
                .snapshot()
                .diagnostics
                .get("ap2_timing_protocol_rejected"),
            Some(&"missing".to_string())
        );
        assert!(session.event_port.is_none());
    }

    // ── GET /info correctness ────────────────────────────────────────────

    #[test]
    fn ap2_info_contains_expected_binary_plist_fields() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.device_id = "AA:BB:CC:DD:EE:FF".to_string();
        config.airplay.pin = "".to_string();
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        let info_body = get_info_body(&config.airplay, None, -30.0, &policy);
        let parsed: plist::Dictionary =
            plist::from_bytes(&info_body).expect("info body must be valid binary plist");

        // Required fields
        assert_eq!(parsed.get("vv").and_then(plist_uint), Some(2));
        assert!(parsed.contains_key("features"));
        assert!(parsed.contains_key("featuresEx"));
        assert!(parsed.contains_key("statusFlags"));
        assert!(parsed.contains_key("deviceID"));
        assert!(parsed.contains_key("pi"));
        assert!(parsed.contains_key("pk"));
        assert!(parsed.contains_key("supportedFormats"));
        assert!(parsed.contains_key("txtAirPlay"));

        // features must match the policy
        let features_from_info = parsed.get("features").and_then(plist_uint).unwrap();
        assert_eq!(features_from_info, policy.features);

        // supportedFormats must match the implemented realtime and buffered policies
        let fmts = parsed
            .get("supportedFormats")
            .and_then(plist::Value::as_dictionary)
            .unwrap();
        assert_eq!(
            fmts.get("audioStream").and_then(plist_uint),
            Some(policy.audio_stream_formats),
            "realtime audio formats must match capability policy"
        );
        assert!(fmts.get("bufferStream").and_then(plist_uint).unwrap_or(0) != 0);
        assert_eq!(
            fmts.get("bufferStream").and_then(plist_uint),
            Some(policy.buffer_stream_formats)
        );

        // txtAirPlay must be valid binary data
        let txt_airplay = parsed.get("txtAirPlay").and_then(|v| v.as_data());
        assert!(txt_airplay.is_some(), "txtAirPlay must be binary data");
        let txt_bytes = txt_airplay.unwrap();
        assert!(!txt_bytes.is_empty());
        // txtAirPlay should contain key=value pairs in DNS-SD format
        let txt_str = String::from_utf8_lossy(txt_bytes);
        assert!(
            txt_str.contains("features=0x"),
            "txtAirPlay must contain features"
        );
        assert!(
            txt_str.contains("flags=0x"),
            "txtAirPlay must contain flags"
        );
        assert!(
            txt_str.contains("deviceid="),
            "txtAirPlay must contain deviceid"
        );
    }

    #[test]
    fn ap2_info_initial_volume_uses_current_airplay_db() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);

        let info_body = get_info_body(&config.airplay, None, -18.25, &policy);
        let parsed: plist::Dictionary =
            plist::from_bytes(&info_body).expect("info body must be valid binary plist");

        assert_eq!(
            parsed.get("initialVolume").and_then(plist_real),
            Some(-18.25)
        );
    }

    #[test]
    fn ap2_info_features_and_txt_airplay_use_same_policy() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        let info_body = get_info_body(&config.airplay, None, -30.0, &policy);
        let parsed: plist::Dictionary =
            plist::from_bytes(&info_body).expect("info body must be valid binary plist");

        // The features field in info
        let info_features = parsed.get("features").and_then(plist_uint).unwrap();

        // The txtAirPlay field also encodes features.
        // The binary format is length-prefixed entries: [len:u8][key=value bytes]...
        // We verify consistency by comparing against the policy value
        // and confirming both info and mDNS agree.
        assert_eq!(info_features, policy.features);

        // Extract features from mDNS airplay_txt()
        let mdnstxt = crate::airplay::txt_records::airplay_txt(&config, &policy);
        let features_entry = mdnstxt
            .iter()
            .find(|e| e.starts_with("features=0x"))
            .unwrap();
        let features_clean = features_entry.strip_prefix("features=0x").unwrap();
        let comma = features_clean.find(',').unwrap();
        let lo = u64::from_str_radix(&features_clean[..comma], 16).unwrap();
        let hi_rest = &features_clean[comma + 1..];
        // from_str_radix does not accept "0x" prefix
        let hi_hex = hi_rest.strip_prefix("0x").unwrap_or(hi_rest);
        let hi = u64::from_str_radix(hi_hex, 16).unwrap();
        let mdnstxt_features = lo | (hi << 32);

        assert_eq!(mdnstxt_features, info_features);
        assert_eq!(mdnstxt_features, policy.features);
    }

    #[test]
    fn ap2_info_txt_airplay_consistency() {
        // The same policy used for GET /info also feeds mDNS TXT records.
        // Verify that features derived from mDNS airplay_txt() match /info.
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);

        // From /info
        let info_body = get_info_body(&config.airplay, None, -30.0, &policy);
        let parsed: plist::Dictionary = plist::from_bytes(&info_body).unwrap();
        let info_features = parsed.get("features").and_then(plist_uint).unwrap();

        // From mDNS TXT
        let mdnstxt = crate::airplay::txt_records::airplay_txt(&config, &policy);
        let features_entry = mdnstxt
            .iter()
            .find(|e| e.starts_with("features=0x"))
            .unwrap();
        let features_clean = features_entry.strip_prefix("features=0x").unwrap();
        let comma = features_clean.find(',').unwrap();
        let lo = u64::from_str_radix(&features_clean[..comma], 16).unwrap();
        let hi_rest = &features_clean[comma + 1..];
        // from_str_radix does not accept "0x" prefix
        let hi_hex = hi_rest.strip_prefix("0x").unwrap_or(hi_rest);
        let hi = u64::from_str_radix(hi_hex, 16).unwrap();
        let mdnstxt_features = lo | (hi << 32);

        assert_eq!(mdnstxt_features, info_features);
        assert_eq!(mdnstxt_features, policy.features);
    }

    #[test]
    fn ap2_teardown_body_identifies_buffered_stream() {
        let mut stream = plist::Dictionary::new();
        stream.insert("streamID".to_string(), plist_uint_value(0u64));
        stream.insert("type".to_string(), plist_uint_value(103u64));
        let mut teardown = plist::Dictionary::new();
        teardown.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(teardown)).unwrap();

        assert_eq!(
            Ap2TeardownTarget::from_teardown_body(&body),
            Some(Ap2TeardownTarget::Stream(Ap2StreamType::BufferedAudio))
        );
    }

    #[test]
    fn ap2_session_teardown_body_is_session_target() {
        let mut body = Vec::new();
        plist::to_writer_binary(
            &mut body,
            &plist::Value::Dictionary(plist::Dictionary::new()),
        )
        .unwrap();

        // Empty/plain body → Session teardown
        assert_eq!(
            Ap2TeardownTarget::from_teardown_body(&body),
            Some(Ap2TeardownTarget::Session)
        );
    }

    #[test]
    fn ap2_teardown_unknown_stream_type_returns_none() {
        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(999u64));
        let mut teardown = plist::Dictionary::new();
        teardown.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(teardown)).unwrap();

        // Unknown type → None (caller returns 400)
        assert_eq!(Ap2TeardownTarget::from_teardown_body(&body), None);
    }

    #[test]
    fn ap2_teardown_empty_body_is_session() {
        assert_eq!(
            Ap2TeardownTarget::from_teardown_body(&[]),
            Some(Ap2TeardownTarget::Session)
        );
    }

    #[test]
    fn ap2_alac_only_does_not_advertise_aac_buffer_formats() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.advertised_format_policy = crate::config::AdvertisedFormatPolicy::AlacOnly;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);

        assert_ne!(policy.buffer_stream_formats & 0x0004_0000, 0);
        assert_ne!(policy.buffer_stream_formats & 0x0020_0000, 0);
        assert_eq!(policy.buffer_stream_formats & 0x0040_0000, 0);
        assert_eq!(policy.buffer_stream_formats & 0x0080_0000, 0);
    }

    #[test]
    fn ap2_aac_policy_advertises_only_stereo_aac_buffer_formats() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.advertised_format_policy =
            crate::config::AdvertisedFormatPolicy::AacIfAvailable;
        config.ptp.enabled = true;
        config.ptp.backend = crate::config::PtpBackendName::Embedded;
        let policy = Ap2CapabilityPolicy::from_config(&config, true);

        assert_ne!(policy.buffer_stream_formats & 0x0004_0000, 0);
        assert_ne!(policy.buffer_stream_formats & 0x0020_0000, 0);
        assert_ne!(policy.buffer_stream_formats & 0x0040_0000, 0);
        assert_ne!(policy.buffer_stream_formats & 0x0080_0000, 0);
        assert_eq!(policy.buffer_stream_formats & 0x2700_0000, 0);
        assert_eq!(policy.buffer_stream_formats & 0x2800_0000, 0);
    }

    // -------------------------------------------------------------------
    // Apple-Challenge → Apple-Response
    // -------------------------------------------------------------------

    #[test]
    fn apple_challenge_builds_response() {
        // Known input: challenge = [0x01; 16], local IPv4 = 127.0.0.1,
        // device_id = "00:11:22:33:44:55"
        let challenge_bytes = [0x01u8; 16];
        let challenge_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, challenge_bytes);
        let local = SocketAddr::from(([127, 0, 0, 1], 7000));
        let device_id = "00:11:22:33:44:55";

        let response = build_apple_response(&challenge_b64, Some(local), device_id);
        assert!(response.is_some(), "must produce Apple-Response");
        let resp = response.unwrap();

        // Response should be valid base64 (no padding in the output)
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, &resp);
        assert!(
            decoded.is_ok(),
            "Apple-Response must be valid base64, got: {resp}"
        );
        let sig = decoded.unwrap();

        // Signature must be 256 bytes (2048-bit RSA)
        assert_eq!(sig.len(), 256, "unexpected signature length");

        // Verify the signature round-trips with the public key
        let key = decoder::classic_rsa_private_key();
        let pub_key: rsa::RsaPublicKey = key.clone().into();

        // Reconstruct the exact input buffer that was signed
        let mut expected_buf = Vec::new();
        expected_buf.extend_from_slice(&challenge_bytes);
        expected_buf.extend_from_slice(&[127, 0, 0, 1]); // IPv4
        expected_buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // ap1_prefix
        while expected_buf.len() < 32 {
            expected_buf.push(0u8);
        }

        pub_key
            .verify(Pkcs1v15Sign::new_unprefixed(), &expected_buf, &sig)
            .expect("Apple-Response signature must verify");
    }

    #[test]
    fn apple_challenge_rejects_oversized_challenge() {
        // 17 bytes challenge (larger than the 16-byte max)
        let challenge_bytes = [0x42u8; 17];
        let challenge_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, challenge_bytes);
        let local = SocketAddr::from(([127, 0, 0, 1], 7000));
        let response = build_apple_response(&challenge_b64, Some(local), "00:11:22:33:44:55");
        assert!(response.is_none(), "oversized challenge must be rejected");
    }

    #[test]
    fn parse_mac_bytes_valid() {
        let mac = parse_mac_bytes("aa:bb:cc:dd:ee:ff");
        assert_eq!(mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn parse_mac_bytes_invalid() {
        assert_eq!(parse_mac_bytes("not-a-mac"), None);
        assert_eq!(parse_mac_bytes("aa:bb:cc"), None); // too short
        assert_eq!(parse_mac_bytes("aa:bb:cc:dd:ee:ff:00"), None); // too long
    }

    // -------------------------------------------------------------------
    // Unpadded Apple-Challenge
    // -------------------------------------------------------------------

    #[test]
    fn apple_challenge_accepts_unpadded_base64() {
        // Apple strips trailing '=' from base64 challenge strings.
        // The tolerant decoder must handle this.
        let challenge_bytes = [0x42u8; 16];
        let challenge_b64_padded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, challenge_bytes);
        let challenge_b64_unpadded = challenge_b64_padded.trim_end_matches('=');

        let local = SocketAddr::from(([127, 0, 0, 1], 7000));
        let device_id = "00:11:22:33:44:55";

        let response_padded = build_apple_response(&challenge_b64_padded, Some(local), device_id);
        let response_unpadded =
            build_apple_response(challenge_b64_unpadded, Some(local), device_id);

        // Both padded and unpadded challenge must produce the same response,
        // because they represent the same decoded bytes.
        assert!(response_padded.is_some());
        assert_eq!(response_padded, response_unpadded);
    }

    // -------------------------------------------------------------------
    // Stale crypto replacement at ANNOUNCE + 456 for invalid crypto
    // -------------------------------------------------------------------

    #[test]
    fn announce_clears_stale_session_crypto() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));

        // Pre-populate with some stale crypto
        *state.session_crypto.write() = SessionCrypto::new(&[1u8; 16], &[2u8; 16]);
        assert!(state.session_crypto.read().is_some());

        // Build a minimal ANNOUNCE request that does NOT contain crypto
        // fields.  Unencrypted sessions are rejected with 456, but the
        // stale crypto must still be cleared at the top of the handler.
        let sdp_body =
            b"v=0\r\no=iTunes 1 0 IN IP4 10.0.0.2\r\ns=AirTunes\r\nm=audio 0 RTP/AVP 96\r\n";
        let mut headers = BTreeMap::new();
        headers.insert("CSeq".to_string(), "1".to_string());
        let request = RtspRequest {
            method: "ANNOUNCE".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body: sdp_body.to_vec(),
        };

        let mut session = RtspSession::default();
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let services = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let response = route_request(&services, &mut session, &request);

        // Unencrypted ANNOUNCE is rejected
        assert_eq!(
            response.code, 456,
            "unencrypted ANNOUNCE must return 456 Parameter Not Understood"
        );
        // Stale crypto must still be cleared
        assert_eq!(
            *state.session_crypto.read(),
            None,
            "ANNOUNCE must clear stale session crypto even when rejected"
        );
        // Non-owner flag must NOT be set
        assert!(!session.is_playback_owner);
    }

    #[test]
    fn announce_with_partial_crypto_returns_456() {
        // When rsaaeskey is provided but aesiv is missing, return 456.
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));

        // SDP with rsaaeskey (encrypted with the classic key) but NO aesiv
        let data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16";
        let pub_key: rsa::RsaPublicKey = decoder::classic_rsa_private_key().clone().into();
        let mut rng = rand_core::OsRng;
        let encrypted = pub_key
            .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), data)
            .expect("encrypt");
        let rsaaeskey_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);

        let sdp_body = format!(
            "v=0\r\no=iTunes 1 0 IN IP4 10.0.0.2\r\ns=AirTunes\r\nm=audio 0 RTP/AVP 96\r\na=rsaaeskey:{rsaaeskey_b64}\r\n"
        );
        let mut headers = BTreeMap::new();
        headers.insert("CSeq".to_string(), "1".to_string());
        let request = RtspRequest {
            method: "ANNOUNCE".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body: sdp_body.into_bytes(),
        };

        let mut session = RtspSession::default();
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let services = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let response = route_request(&services, &mut session, &request);

        assert_eq!(
            response.code, 456,
            "partial crypto (key without IV) must return 456"
        );
        assert!(!session.is_playback_owner);
    }

    // -------------------------------------------------------------------
    // perform_connection_cleanup idempotency + ownership
    // -------------------------------------------------------------------

    #[test]
    fn connection_cleanup_owner_clears_global_state() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        // Set up state that an owner cleanup should clear
        *state.session_crypto.write() = SessionCrypto::new(&[3u8; 16], &[4u8; 16]);
        state.set_active(true);
        state.set_player_state(PlayerState::Playing);

        let mut session = RtspSession::default();
        session.is_playback_owner = true;

        // Owner cleanup must clear global state and emit Stop
        perform_connection_cleanup(
            &state,
            &audio_engine,
            &player,
            &dacp,
            &playout,
            &mut session,
        );
        assert_eq!(*state.session_crypto.read(), None);
        let cmds = drain_cmds(&mut cmd_rx);
        assert_eq!(
            cmds.as_slice(),
            &[PlayoutCommand::Stop],
            "owner cleanup must emit exactly one Stop"
        );

        // Second cleanup must not repeat global cleanup or emit another command.
        perform_connection_cleanup(
            &state,
            &audio_engine,
            &player,
            &dacp,
            &playout,
            &mut session,
        );
        assert_eq!(*state.session_crypto.read(), None);
        assert!(drain_cmds(&mut cmd_rx).is_empty());
    }

    #[test]
    fn connection_cleanup_non_owner_preserves_global_state() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();

        // Set up state representing an active session owned by someone else
        *state.session_crypto.write() = SessionCrypto::new(&[3u8; 16], &[4u8; 16]);
        state.set_active(true);
        state.set_player_state(PlayerState::Playing);

        let mut session = RtspSession::default();
        // is_playback_owner defaults to false — this is a non-owner probe

        // Non-owner cleanup must NOT clear global state
        perform_connection_cleanup(
            &state,
            &audio_engine,
            &player,
            &dacp,
            &playout,
            &mut session,
        );
        assert!(
            state.session_crypto.read().is_some(),
            "non-owner cleanup must not clear session_crypto"
        );
        // Non-owner must emit no commands
        let cmds = drain_cmds(&mut cmd_rx);
        assert!(
            cmds.is_empty(),
            "non-owner cleanup must not emit any playout command, got {cmds:?}"
        );
    }

    // -------------------------------------------------------------------
    // Stream TEARDOWN ownership gating
    // -------------------------------------------------------------------

    /// Non-owner stream TEARDOWN must remain session-local and must not stop
    /// the active global transport owned by another connection.
    #[test]
    fn stream_teardown_non_owner_preserves_global_transport() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));

        *state.session_crypto.write() = SessionCrypto::new(&[3u8; 16], &[4u8; 16]);
        state.set_active(true);
        state.set_player_state(PlayerState::Playing);

        // Build a buffered-audio stream TEARDOWN body (type 103)
        let mut stream = plist::Dictionary::new();
        stream.insert("streamID".to_string(), plist_uint_value(1u64));
        stream.insert("type".to_string(), plist_uint_value(103u64));
        let mut teardown = plist::Dictionary::new();
        teardown.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(teardown)).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert("CSeq".to_string(), "10".to_string());
        let request = RtspRequest {
            method: "TEARDOWN".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body,
        };

        // Non-owner session (is_playback_owner defaults to false)
        let mut session = RtspSession::default();
        session.fairplay = FairPlayState::Complete { mode: 0 };

        let (playout, mut cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let response = route_request(&svc, &mut session, &request);

        assert_eq!(response.code, 200);
        assert_eq!(session.fairplay, FairPlayState::NotStarted);
        assert!(state.session_crypto.read().is_some());
        assert!(state.snapshot().active);
        assert_eq!(state.snapshot().player_state, PlayerState::Playing);
        assert!(drain_cmds(&mut cmd_rx).is_empty());
    }

    /// Owner stream TEARDOWN removes its session-owned key/context and resets
    /// FairPlay so the next SETUP must negotiate fresh state.
    #[test]
    fn stream_teardown_owner_clears_session_owned_stream_context() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));

        // Build a buffered-audio stream TEARDOWN body (type 103)
        let mut stream = plist::Dictionary::new();
        stream.insert("streamID".to_string(), plist_uint_value(1u64));
        stream.insert("type".to_string(), plist_uint_value(103u64));
        let mut teardown = plist::Dictionary::new();
        teardown.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(teardown)).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert("CSeq".to_string(), "10".to_string());
        let request = RtspRequest {
            method: "TEARDOWN".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body,
        };

        let mut session = RtspSession::default();
        session.is_playback_owner = true;
        session.fairplay = FairPlayState::Complete { mode: 0 };
        // Register a buffered audio stream in the session so teardown
        // recognizes it as the last (and only) buffered stream.
        session.ap2.mark_paired().unwrap();
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        session
            .ap2
            .add_stream(Ap2Stream {
                stream_id: 1,
                stream_connection_id: None,
                stream_type: Ap2StreamType::BufferedAudio,
                config: Ap2StreamConfig::BufferedAudio {
                    runtime: Arc::new(BufferedStreamContext::new(
                        [0xCDu8; 32],
                        AudioFormat::Alac44100S16Stereo,
                        44100,
                        352,
                        1,
                        None,
                    )),
                },
                data_port: 6000,
                state: Ap2StreamState::Configured,
            })
            .unwrap();

        let (playout, mut cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let response = route_request(&svc, &mut session, &request);

        assert_eq!(response.code, 200);
        assert!(
            session
                .ap2
                .find_stream_by_type(Ap2StreamType::BufferedAudio)
                .is_none()
        );
        assert_eq!(session.fairplay, FairPlayState::NotStarted);
        assert_eq!(drain_cmds(&mut cmd_rx), vec![PlayoutCommand::ClearStream]);
    }

    // -------------------------------------------------------------------
    // Sub-16-byte payload preservation (aes_cbc_decrypt_in_place)
    // -------------------------------------------------------------------

    #[test]
    fn aes_cbc_short_payload_preserved() {
        // Verify that aes_cbc_decrypt_in_place leaves sub-block payloads
        // unchanged rather than dropping them.
        let key = [0xabu8; 16];
        let iv = [0x06u8; 16];

        // 5 bytes: no complete block
        let mut short = [0x01, 0x02, 0x03, 0x04, 0x05];
        let original = short;
        crate::decoder::aes_cbc_decrypt_in_place(&key, &iv, &mut short).unwrap();
        assert_eq!(
            short, original,
            "payload < 16 bytes must be preserved unchanged"
        );

        // 17 bytes: 1 full block + 1 trailing byte
        let mut mixed = [0x42u8; 17];
        crate::decoder::aes_cbc_decrypt_in_place(&key, &iv, &mut mixed).unwrap();
        // The last byte must be unchanged; first 16 are decrypted
        assert_eq!(mixed[16], 0x42, "trailing byte must be unchanged");
    }

    // -------------------------------------------------------------------
    // AP1 Transport header parser
    // -------------------------------------------------------------------

    #[test]
    fn parse_ap1_transport_ipv4_lowercase() {
        let params = parse_ap1_transport_header(
            "RTP/AVP/UDP;unicast;mode=record;control_port=6001;timing_port=6002",
        )
        .unwrap();
        assert_eq!(params.control_port, 6001);
        assert_eq!(params.timing_port, 6002);
    }

    #[test]
    fn parse_ap1_transport_mixed_case_keys() {
        let params = parse_ap1_transport_header(
            "RTP/AVP/UDP;unicast;mode=record;Control_Port=7000;TimingPort=7001",
        )
        .unwrap();
        assert_eq!(params.control_port, 7000);
        assert_eq!(params.timing_port, 7001);
    }

    #[test]
    fn parse_ap1_transport_extra_tokens_tolerated() {
        let params = parse_ap1_transport_header(
            "RTP/AVP/UDP;unicast;mode=record;control_port=5000;timing_port=5001;foo=bar;baz",
        )
        .unwrap();
        assert_eq!(params.control_port, 5000);
        assert_eq!(params.timing_port, 5001);
    }

    #[test]
    fn parse_ap1_transport_missing_control_port() {
        let err = parse_ap1_transport_header("RTP/AVP/UDP;unicast;mode=record;timing_port=6002")
            .unwrap_err();
        assert!(err.contains("missing control_port"));
    }

    #[test]
    fn parse_ap1_transport_missing_timing_port() {
        let err = parse_ap1_transport_header("RTP/AVP/UDP;unicast;mode=record;control_port=6001")
            .unwrap_err();
        assert!(err.contains("missing timing_port"));
    }

    #[test]
    fn parse_ap1_transport_zero_control_port() {
        let err = parse_ap1_transport_header(
            "RTP/AVP/UDP;unicast;mode=record;control_port=0;timing_port=6002",
        )
        .unwrap_err();
        assert!(err.contains("must not be zero"));
    }

    #[test]
    fn parse_ap1_transport_non_numeric_port() {
        let err = parse_ap1_transport_header(
            "RTP/AVP/UDP;unicast;mode=record;control_port=abc;timing_port=6002",
        )
        .unwrap_err();
        assert!(err.contains("invalid control_port"));
    }

    #[test]
    fn parse_ap1_transport_port_out_of_range() {
        let err = parse_ap1_transport_header(
            "RTP/AVP/UDP;unicast;mode=record;control_port=99999;timing_port=6002",
        )
        .unwrap_err();
        assert!(err.contains("invalid control_port"));
    }

    // -------------------------------------------------------------------
    // AP1 SETUP stores remote endpoints, advertises local ports
    // -------------------------------------------------------------------

    #[test]
    fn ap1_setup_stores_endpoints_and_returns_local_ports() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let mut session = RtspSession::default();
        let peer: SocketAddr = "192.168.1.50:51234".parse().unwrap();
        session.peer_addr = Some(peer);
        session.local_addr = Some("0.0.0.0:5000".parse().unwrap());

        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: [(
                "tRaNsPoRt".to_string(),
                "RTP/AVP/UDP;unicast;mode=record;control_port=6001;timing_port=6002".to_string(),
            )]
            .into(),
            body: vec![],
        };

        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let resp = route_request(&svc, &mut session, &request);

        assert_eq!(resp.code, 200);

        // Response must advertise local ports
        let transport = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Transport"))
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(transport.contains(&format!("server_port={}", config.airplay.audio_port)));
        assert!(transport.contains(&format!("control_port={}", config.airplay.control_port)));
        assert!(transport.contains(&format!("timing_port={}", config.airplay.timing_port)));
        assert!(state.snapshot().active);
        assert_eq!(session.session_id.as_deref(), Some("1"));

        // AppState must have the remote endpoints
        let eps = state.ap1_remote_endpoints().unwrap();
        assert_eq!(eps.control, SocketAddr::new(peer.ip(), 6001));
        assert_eq!(eps.timing, SocketAddr::new(peer.ip(), 6002));

        // Session must have the remote ports
        assert_eq!(session.ap1_remote_control_port, Some(6001));
        assert_eq!(session.ap1_remote_timing_port, Some(6002));
    }

    #[test]
    fn ap1_setup_ipv6_stores_endpoints() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let mut session = RtspSession::default();
        let peer: SocketAddr = "[fd00::1]:51234".parse().unwrap();
        session.peer_addr = Some(peer);
        session.local_addr = Some("[::]:5000".parse().unwrap());

        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: [(
                "Transport".to_string(),
                "RTP/AVP/UDP;unicast;mode=record;control_port=7000;timing_port=7001".to_string(),
            )]
            .into(),
            body: vec![],
        };

        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let resp = route_request(&svc, &mut session, &request);
        assert_eq!(resp.code, 200);

        let eps = state.ap1_remote_endpoints().unwrap();
        assert_eq!(eps.control, SocketAddr::new(peer.ip(), 7000));
        assert_eq!(eps.timing, SocketAddr::new(peer.ip(), 7001));
    }

    #[test]
    fn ap1_setup_missing_transport_returns_400() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let mut session = RtspSession::default();
        session.peer_addr = Some("10.0.0.1:12345".parse().unwrap());

        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: vec![],
        };

        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let resp = route_request(&svc, &mut session, &request);
        assert_eq!(resp.code, 400);
        assert!(!state.snapshot().active);
        assert!(state.ap1_remote_endpoints().is_none());
        assert!(session.session_id.is_none());
    }

    #[test]
    fn ap1_setup_invalid_transport_returns_400() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let mut session = RtspSession::default();
        session.peer_addr = Some("10.0.0.1:12345".parse().unwrap());

        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: [(
                "Transport".to_string(),
                "RTP/AVP/UDP;unicast;mode=record;control_port=0;timing_port=6002".to_string(),
            )]
            .into(),
            body: vec![],
        };

        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let resp = route_request(&svc, &mut session, &request);
        assert_eq!(resp.code, 400);
        assert!(!state.snapshot().active);
        assert!(state.ap1_remote_endpoints().is_none());
        assert!(session.session_id.is_none());
    }

    #[test]
    fn ap1_setup_missing_peer_returns_400_without_activation() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let mut session = RtspSession::default();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: [(
                "Transport".to_string(),
                "RTP/AVP/UDP;unicast;mode=record;control_port=6001;timing_port=6002".to_string(),
            )]
            .into(),
            body: vec![],
        };
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };

        let resp = route_request(&svc, &mut session, &request);
        assert_eq!(resp.code, 400);
        assert!(!state.snapshot().active);
        assert!(state.ap1_remote_endpoints().is_none());
        assert!(session.session_id.is_none());
    }

    #[test]
    fn owner_cleanup_clears_ap1_remote_endpoints() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let mut session = RtspSession::default();
        let peer: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        session.peer_addr = Some(peer);
        session.is_playback_owner = true;

        // Set up remote endpoints first
        state.set_ap1_remote_endpoints(peer.ip(), 6001, 6002);
        assert!(state.ap1_remote_endpoints().is_some());

        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        perform_connection_cleanup(
            &state,
            &audio_engine,
            &player,
            &dacp,
            &playout,
            &mut session,
        );

        assert!(state.ap1_remote_endpoints().is_none());
        let snap = state.snapshot();
        assert!(!snap.diagnostics.contains_key("ap1_remote_control"));
        assert!(!snap.diagnostics.contains_key("ap1_remote_timing"));
    }

    #[test]
    fn non_owner_cleanup_preserves_ap1_remote_endpoints() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let mut session = RtspSession::default();
        let peer: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        session.peer_addr = Some(peer);
        // is_playback_owner defaults to false — non-owner probe

        // Set up remote endpoints
        state.set_ap1_remote_endpoints(peer.ip(), 6001, 6002);
        assert!(state.ap1_remote_endpoints().is_some());

        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        perform_connection_cleanup(
            &state,
            &audio_engine,
            &player,
            &dacp,
            &playout,
            &mut session,
        );

        // Non-owner cleanup must NOT clear AP1 remote endpoints
        assert!(state.ap1_remote_endpoints().is_some());
        let snap = state.snapshot();
        assert!(snap.diagnostics.contains_key("ap1_remote_control"));
        assert!(snap.diagnostics.contains_key("ap1_remote_timing"));
    }

    // ── Full route-level lifecycle test ────────────────────────────────

    /// Test-only helper: pair the session (simulate successful pair-verify).
    fn test_pair(session: &mut RtspSession) {
        session.ap2.mark_paired().unwrap();
    }

    fn test_pair_with_secret(session: &mut RtspSession, secret: [u8; 32]) {
        test_pair(session);
        session.pairing.install_test_control_secret(secret);
        session.fairplay = FairPlayState::Complete { mode: 0 };
    }

    #[tokio::test]
    async fn real_sender_prefix_accepts_record_before_stream_setup_without_output() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        );
        let (playout, mut cmd_rx, mut ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        test_pair_with_secret(&mut session, [0x31; 32]);
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        let record = RtspRequest {
            method: "RECORD".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = route_request(&svc, &mut session, &record);

        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
        assert!(session.ap2.record_requested());
        assert!(!session.ap2.has_streams());
        assert_eq!(state.snapshot().player_state, PlayerState::Stopped);
        assert!(drain_cmds(&mut cmd_rx).is_empty());

        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("streamID".to_string(), plist_uint_value(17u64));
        stream.insert("shk".to_string(), plist::Value::Data((0u8..32).collect()));
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("sr".to_string(), plist_uint_value(44_100u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let request = ap2_plist_request("SETUP", setup);
        let response = route_request(&svc, &mut session, &request);

        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Recording);
        assert_eq!(state.snapshot().player_state, PlayerState::Playing);
        assert_eq!(
            drain_cmds(&mut cmd_rx),
            vec![
                PlayoutCommand::ConfigureStream(Ap2StreamRuntime {
                    stream_id: 17,
                    stream_connection_id: None,
                    audio_format: AudioFormat::Alac44100S16Stereo,
                    sample_rate: 44_100,
                    frames_per_packet: 352,
                }),
                PlayoutCommand::Record,
            ]
        );

        // Exercise the listener returned by the real route with an
        // independently generated encrypted packet. This proves that the
        // exact 32-byte `shk` from SETUP is the key used by the buffered
        // receiver, not material derived from the pair-verify secret.
        const CIPHERTEXT_AND_TAG: [u8; 33] = [
            0x8e, 0x96, 0x97, 0xd5, 0xd7, 0xe3, 0xdd, 0xe8, 0x75, 0x92, 0x8e, 0xbf, 0xf2, 0x98,
            0x52, 0x2c, 0xf0, 0x08, 0x57, 0x2e, 0x11, 0xde, 0x35, 0x26, 0x9b, 0x9f, 0x7a, 0x45,
            0x75, 0x10, 0x97, 0xd6, 0x54,
        ];
        let response_dict = plist::from_bytes::<plist::Dictionary>(&response.body).unwrap();
        let response_stream = response_dict["streams"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap();
        let data_port = plist_uint(&response_stream["dataPort"]).unwrap() as u16;
        let mut wire = Vec::new();
        let block_len = 2 + 12 + CIPHERTEXT_AND_TAG.len() + 8;
        wire.extend_from_slice(&(block_len as u16).to_be_bytes());
        wire.extend_from_slice(&0x007f_fffeu32.to_be_bytes());
        wire.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        wire.extend_from_slice(&0x0000_FACEu32.to_be_bytes());
        wire.extend_from_slice(&CIPHERTEXT_AND_TAG);
        wire.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut audio_stream =
            TcpStream::connect(SocketAddr::new(session.receiver_ip(), data_port))
                .await
                .unwrap();
        audio_stream.write_all(&wire).await.unwrap();
        audio_stream.shutdown().await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), ingress_rx.recv())
            .await
            .expect("encrypted buffered packet did not reach ingress")
            .expect("ingress closed");
        assert_eq!(packet.payload.as_ref(), b"ap2-route-fixture");
        assert_eq!(packet.rtp_timestamp, 0x0102_0304);
        assert_eq!(packet.ssrc, 0x0000_FACE);
        session.abort_ap2_listeners();
    }

    fn ap2_plist_request(method: &str, dictionary: plist::Dictionary) -> RtspRequest {
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dictionary)).unwrap();
        RtspRequest {
            method: method.to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: [(
                "Content-Type".to_string(),
                "application/x-apple-binary-plist".to_string(),
            )]
            .into(),
            body,
        }
    }

    fn test_buffered_stream(stream_id: u32, sample_rate: u32) -> Ap2Stream {
        Ap2Stream {
            stream_id,
            stream_connection_id: Some(u64::from(stream_id)),
            stream_type: Ap2StreamType::BufferedAudio,
            config: Ap2StreamConfig::BufferedAudio {
                runtime: Arc::new(BufferedStreamContext::new(
                    [0x5au8; 32],
                    AudioFormat::Alac44100S16Stereo,
                    sample_rate,
                    352,
                    stream_id,
                    None,
                )),
            },
            data_port: 6000,
            state: Ap2StreamState::Configured,
        }
    }

    #[test]
    fn feedback_is_empty_until_buffered_stream_is_recording() {
        let session = RtspSession::default();
        let request = RtspRequest {
            method: "POST".to_string(),
            uri: "/feedback".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = handle_feedback(&session, &request);

        assert_eq!(response.code, 200);
        assert!(response.body.is_empty());
        assert!(
            response
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("Content-Type"))
        );
    }

    #[test]
    fn feedback_reports_recording_buffered_stream_type_and_rate() {
        let mut session = RtspSession::default();
        session.ap2.mark_paired().unwrap();
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();
        session
            .ap2
            .add_stream(test_buffered_stream(7, 44_100))
            .unwrap();
        session.ap2.begin_recording().unwrap();
        let request = RtspRequest {
            method: "POST".to_string(),
            uri: "/feedback".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let response = handle_feedback(&session, &request);

        assert_eq!(response.code, 200);
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Content-Type") && value == "application/x-apple-binary-plist"
        }));
        let root = plist::from_bytes::<plist::Dictionary>(&response.body).unwrap();
        let streams = root["streams"].as_array().unwrap();
        let stream = streams[0].as_dictionary().unwrap();
        assert_eq!(plist_uint(&stream["type"]), Some(103));
        assert_eq!(stream["sr"].as_real(), Some(44_100.0));
    }

    #[test]
    fn audio_mode_is_validated_and_committed_transactionally() {
        let config = crate::config::Config::default();
        let state = AppState::new(config);
        let mut session = RtspSession::default();
        let mut valid = plist::Dictionary::new();
        valid.insert(
            "audioMode".to_string(),
            plist::Value::String("default".to_string()),
        );

        let response = handle_audio_mode(&state, &mut session, &ap2_plist_request("POST", valid));

        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.audio_mode(), Some("default"));

        let mut invalid = plist::Dictionary::new();
        invalid.insert("audioMode".to_string(), plist_uint_value(1u64));
        let response = handle_audio_mode(&state, &mut session, &ap2_plist_request("POST", invalid));

        assert_eq!(response.code, 400);
        assert_eq!(session.ap2.audio_mode(), Some("default"));
        session.ap2.clear_sensitive();
        assert_eq!(session.ap2.audio_mode(), None);
    }

    fn type130_setup_request(
        seed: Option<plist::Value>,
        wants_dedicated_socket: Option<plist::Value>,
        control_type: Option<plist::Value>,
        stream_id: Option<u64>,
    ) -> RtspRequest {
        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(130u64));
        if let Some(seed) = seed {
            stream.insert("seed".to_string(), seed);
        }
        if let Some(value) = wants_dedicated_socket {
            stream.insert("wantsDedicatedSocket".to_string(), value);
        }
        if let Some(value) = control_type {
            stream.insert("controlType".to_string(), value);
        }
        if let Some(stream_id) = stream_id {
            stream.insert("streamID".to_string(), plist_uint_value(stream_id));
        }
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        ap2_plist_request("SETUP", setup)
    }

    fn stream_teardown_request(stream_type: u64) -> RtspRequest {
        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(stream_type));
        let mut teardown = plist::Dictionary::new();
        teardown.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        ap2_plist_request("TEARDOWN", teardown)
    }

    async fn assert_tcp_closed(stream: &mut TcpStream) {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("TCP stream did not close")
        {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) => {}
            other => panic!("expected closed TCP stream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn remote_control_only_route_lifecycle_has_no_audio_side_effects() {
        let secret = [0x6du8; 32];
        let seed = 987_654_321u64;
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        state.set_player_state(PlayerState::Paused);
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        session.local_addr = Some("127.0.0.1:7000".parse().unwrap());
        session.peer_addr = Some("127.0.0.1:7001".parse().unwrap());
        test_pair_with_secret(&mut session, secret);

        let mut setup = plist::Dictionary::new();
        setup.insert(
            "timingProtocol".to_string(),
            plist::Value::String("None".to_string()),
        );
        setup.insert(
            "isRemoteControlOnly".to_string(),
            plist::Value::Boolean(true),
        );
        let response = route_request(&svc, &mut session, &ap2_plist_request("SETUP", setup));
        assert_eq!(response.code, 200);
        let setup_response = plist::from_bytes::<plist::Dictionary>(&response.body).unwrap();
        assert_eq!(setup_response.len(), 1);
        let event_port = setup_response
            .get("eventPort")
            .and_then(plist_uint)
            .unwrap() as u16;
        assert!(event_port > 0);
        assert_eq!(session.event_port, Some(event_port));
        assert!(session.event_listener.is_some());
        assert!(session.ap2.is_remote_control_only());
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
        assert!(!session.is_playback_owner);
        assert!(!state.snapshot().active);
        assert_eq!(state.snapshot().player_state, PlayerState::Paused);
        assert!(drain_cmds(&mut cmd_rx).is_empty());

        let record = RtspRequest {
            method: "RECORD".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &record);
        assert_eq!(response.code, 200);
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| name == "Audio-Latency" && value == "0")
        );
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
        assert_eq!(session.ap2.stream_count(), 0);
        assert!(!session.is_playback_owner);
        assert!(!state.snapshot().active);
        assert_eq!(state.snapshot().player_state, PlayerState::Paused);
        assert!(drain_cmds(&mut cmd_rx).is_empty());

        let request = type130_setup_request(
            Some(plist_uint_value(seed)),
            Some(plist::Value::Boolean(true)),
            Some(plist_uint_value(2u64)),
            Some(77),
        );
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        let response_dict = plist::from_bytes::<plist::Dictionary>(&response.body).unwrap();
        let streams = response_dict
            .get("streams")
            .and_then(plist::Value::as_array)
            .unwrap();
        assert_eq!(streams.len(), 1);
        let stream = streams[0].as_dictionary().unwrap();
        assert_eq!(stream.len(), 3);
        assert_eq!(stream.get("type").and_then(plist_uint), Some(130));
        assert_eq!(stream.get("streamID").and_then(plist_uint), Some(77));
        assert!(stream.get("controlPort").is_none());
        let data_port = stream.get("dataPort").and_then(plist_uint).unwrap() as u16;
        assert_eq!(session.data_port, Some(data_port));
        assert!(session.data_listener.is_some());
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::StreamConfigured);
        assert_eq!(session.ap2.stream_count(), 1);
        assert!(!session.is_playback_owner);
        assert!(!state.snapshot().active);
        assert_eq!(state.snapshot().player_state, PlayerState::Paused);
        assert!(drain_cmds(&mut cmd_rx).is_empty());

        let mut data_stream = TcpStream::connect(("127.0.0.1", data_port)).await.unwrap();
        let mut client_cipher = PairCipher::data_for_client(&secret, seed);
        let mut sync = vec![0u8; 32];
        sync[0..4].copy_from_slice(&32u32.to_be_bytes());
        sync[4..8].copy_from_slice(b"sync");
        sync[20..28].copy_from_slice(&55u64.to_be_bytes());
        let encrypted = client_cipher.encrypt_blocks(&sync).unwrap();
        data_stream.write_all(&encrypted).await.unwrap();
        let mut encrypted_reply = vec![0u8; 50];
        tokio::time::timeout(
            Duration::from_secs(2),
            data_stream.read_exact(&mut encrypted_reply),
        )
        .await
        .expect("sync reply timed out")
        .unwrap();
        let (reply, consumed) = client_cipher.decrypt_blocks(&encrypted_reply).unwrap();
        assert_eq!(consumed, encrypted_reply.len());
        assert_eq!(reply.len(), 32);
        assert_eq!(&reply[4..8], b"rply");
        assert_eq!(u64::from_be_bytes(reply[20..28].try_into().unwrap()), 55);

        let duplicate = route_request(&svc, &mut session, &request);
        assert_eq!(duplicate.code, 455);
        assert_eq!(session.data_port, Some(data_port));
        assert_eq!(session.ap2.stream_count(), 1);

        let response = route_request(&svc, &mut session, &stream_teardown_request(130));
        assert_eq!(response.code, 200);
        assert_tcp_closed(&mut data_stream).await;
        assert!(session.data_listener.is_none());
        assert!(session.data_port.is_none());
        assert_eq!(session.ap2.stream_count(), 0);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
        assert!(session.event_listener.is_some());
        assert_eq!(session.event_port, Some(event_port));
        assert!(!state.snapshot().active);
        assert_eq!(state.snapshot().player_state, PlayerState::Paused);
        assert!(drain_cmds(&mut cmd_rx).is_empty());

        let teardown = RtspRequest {
            method: "TEARDOWN".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &teardown);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Closed);
        assert!(!session.ap2.is_remote_control_only());
        assert_eq!(session.ap2.stream_count(), 0);
        assert!(session.event_listener.is_none());
        assert!(session.event_port.is_none());
        assert!(session.data_listener.is_none());
        assert!(session.data_port.is_none());
        assert!(!state.snapshot().active);
        assert_eq!(state.snapshot().player_state, PlayerState::Paused);
        assert!(drain_cmds(&mut cmd_rx).is_empty());
    }

    #[tokio::test]
    async fn type130_rejections_are_transactional_and_strict() {
        let secret = [0x42u8; 32];
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, mut cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        session.local_addr = Some("127.0.0.1:7000".parse().unwrap());
        test_pair_with_secret(&mut session, secret);
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::None, None, None)
            .unwrap();
        session.ap2.set_remote_control_only(true);

        let cases = [
            type130_setup_request(None, None, None, None),
            type130_setup_request(
                Some(plist::Value::String("1".to_string())),
                None,
                None,
                None,
            ),
            type130_setup_request(
                Some(plist_uint_value(1u64)),
                Some(plist::Value::Boolean(false)),
                None,
                None,
            ),
            type130_setup_request(
                Some(plist_uint_value(1u64)),
                Some(plist::Value::String("true".to_string())),
                None,
                None,
            ),
            type130_setup_request(
                Some(plist_uint_value(1u64)),
                None,
                Some(plist_uint_value(1u64)),
                None,
            ),
            type130_setup_request(
                Some(plist_uint_value(1u64)),
                None,
                Some(plist::Value::String("2".to_string())),
                None,
            ),
        ];

        for request in cases {
            let response = route_request(&svc, &mut session, &request);
            assert_eq!(response.code, 400);
            assert!(session.data_listener.is_none());
            assert!(session.data_port.is_none());
            assert_eq!(session.ap2.stream_count(), 0);
            assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
            assert!(!session.is_playback_owner);
            assert!(!state.snapshot().active);
            assert!(drain_cmds(&mut cmd_rx).is_empty());
        }

        let valid = type130_setup_request(
            Some(plist_uint_value(1u64)),
            Some(plist::Value::Boolean(true)),
            Some(plist_uint_value(2u64)),
            Some(9),
        );
        let response = route_request(&svc, &mut session, &valid);
        assert_eq!(response.code, 200);
        assert!(session.data_listener.is_some());
        assert!(session.data_port.is_some());
        assert_eq!(session.ap2.stream_count(), 1);
        session.abort_ap2_listeners();
    }

    #[tokio::test]
    async fn full_lifecycle_paired_to_teardown() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();

        // 1. Pair
        test_pair(&mut session);
        session.fairplay = FairPlayState::Complete { mode: 0 };
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paired);

        // 2. Initial PTP SETUP through the real route. The test installs a
        // prebound event port so no network listener or pairing cipher fixture
        // is required, while the production transaction path is exercised.
        session.install_test_event_port(49_152);
        let mut timing_setup = plist::Dictionary::new();
        timing_setup.insert(
            "timingProtocol".to_string(),
            plist::Value::String("PTP".to_string()),
        );
        let mut sender_timing_peer = plist::Dictionary::new();
        sender_timing_peer.insert(
            "Addresses".into(),
            plist::Value::Array(vec![plist::Value::String("192.0.2.10".into())]),
        );
        sender_timing_peer.insert(
            "ClockID".into(),
            plist::Value::Integer(0x1122_3344_5566_7788u64.into()),
        );
        timing_setup.insert(
            "timingPeerInfo".into(),
            plist::Value::Dictionary(sender_timing_peer),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(timing_setup)).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_string(),
            "application/x-apple-binary-plist".to_string(),
        );
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body,
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
        assert_eq!(session.event_port, Some(49_152));
        assert_eq!(
            session.ap2.selected_master_clock_id(),
            Some(0x1122_3344_5566_7788)
        );
        assert!(state.ptp_servo.accepts_master(0x1122_3344_5566_7788));

        // 3. SETPEERS
        let mut peer_body = Vec::new();
        plist::to_writer_binary(
            &mut peer_body,
            &plist::Value::Array(vec![plist::Value::String("192.0.2.10".into())]),
        )
        .unwrap();
        let request = RtspRequest {
            method: "SETPEERS".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: peer_body,
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::PeersConfigured);

        // 4. Stream SETUP (via route)
        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("sr".to_string(), plist_uint_value(44100u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_string(),
            "application/x-apple-binary-plist".to_string(),
        );
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body,
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::StreamConfigured);

        // 5. RECORD
        let request = RtspRequest {
            method: "RECORD".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Recording);

        // 6. PAUSE
        let request = RtspRequest {
            method: "PAUSE".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paused);

        // 7. SETRATEANCHORTIME rate=1 (resume)
        let request = setrateanchortime_request(1);
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Recording);

        // 8. Stream TEARDOWN
        let mut stream = plist::Dictionary::new();
        stream.insert("streamID".to_string(), plist_uint_value(0u64));
        stream.insert("type".to_string(), plist_uint_value(103u64));
        let mut teardown = plist::Dictionary::new();
        teardown.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(teardown)).unwrap();
        let request = RtspRequest {
            method: "TEARDOWN".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        // Stream removed → regress to PeersConfigured
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::PeersConfigured);
        assert_eq!(session.fairplay, FairPlayState::NotStarted);

        // 9. Session TEARDOWN
        let request = RtspRequest {
            method: "TEARDOWN".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 200);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Closed);
        assert_eq!(session.fairplay, FairPlayState::NotStarted);
        assert!(state.ptp_servo.accepts_master(0x99));
        assert_eq!(state.snapshot().ptp.master_clock_id, None);
    }

    #[test]
    fn setup_before_pairing_returns_455() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();

        // Stream SETUP before pairing → 455
        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(103u64));
        stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
        stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
        stream.insert("sr".to_string(), plist_uint_value(44100u64));
        stream.insert("spf".to_string(), plist_uint_value(352u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_string(),
            "application/x-apple-binary-plist".to_string(),
        );
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers,
            body,
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 455);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Connected);
    }

    // ── AppState snapshot: invalid/failure paths do not mutate ─────────

    #[test]
    fn appstate_snapshot_before_failure_unchanged() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let snap_before = state.snapshot();

        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };

        // Connected session — SETPEERS should fail and not mutate AppState
        let mut session = RtspSession::default();
        let request = RtspRequest {
            method: "SETPEERS".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 455);

        let snap_after = state.snapshot();
        assert_eq!(snap_before.active, snap_after.active);
        assert_eq!(snap_before.player_state, snap_after.player_state);
        assert_eq!(snap_before.track.title, snap_after.track.title);
    }

    #[test]
    fn appstate_unchanged_after_invalid_stream_setup() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        test_pair(&mut session);
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let snap_before = state.snapshot();

        // Send stream SETUP with unknown type → rejected, AppState unchanged
        let mut stream = plist::Dictionary::new();
        stream.insert("type".to_string(), plist_uint_value(999u64));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let request = RtspRequest {
            method: "SETUP".to_string(),
            uri: "rtsp://example/session".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body,
        };
        let response = route_request(&svc, &mut session, &request);
        assert_eq!(response.code, 400);

        let snap_after = state.snapshot();
        assert_eq!(snap_before.active, snap_after.active);
        assert_eq!(snap_before.player_state, snap_after.player_state);
        assert_eq!(snap_before.track.title, snap_after.track.title);
    }

    #[test]
    fn appstate_unchanged_after_invalid_pause() {
        let config = crate::config::Config::default();
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        test_pair(&mut session);
        session
            .ap2
            .configure_timing(Ap2TimingProtocol::Ptp, None, None)
            .unwrap();

        let before = state.snapshot();
        let request = RtspRequest {
            method: "PAUSE".to_string(),
            uri: "*".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let response = route_request(&svc, &mut session, &request);

        assert_eq!(response.code, 455);
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::TimingConfigured);
        let after = state.snapshot();
        assert_eq!(before.active, after.active);
        assert_eq!(before.player_state, after.player_state);
        assert_eq!(before.track.title, after.track.title);
    }

    #[test]
    fn coalesced_cipher_activation_decrypts_residual_once() {
        let secret = [0x42u8; 32];
        let mut client = PairCipher::control_for_client(&secret);
        let mut server = PairCipher::control_for_server(&secret);
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        let encrypted = client.encrypt_blocks(request).unwrap();
        let mut plaintext_buf = encrypted;
        let mut encrypted_buf = Vec::new();

        handoff_coalesced_encrypted_control(
            false,
            Some(&mut server),
            &mut plaintext_buf,
            &mut encrypted_buf,
        )
        .unwrap();

        assert!(encrypted_buf.is_empty());
        let (parsed, consumed) = parse_request(&plaintext_buf).unwrap();
        assert_eq!(parsed.method, "OPTIONS");
        assert_eq!(consumed, plaintext_buf.len());
    }

    #[test]
    fn already_encrypted_pipelined_requests_are_not_decrypted_twice() {
        let secret = [0x24u8; 32];
        let mut client = PairCipher::control_for_client(&secret);
        let mut server = PairCipher::control_for_server(&secret);
        let first = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        let second = b"GET /info RTSP/1.0\r\nCSeq: 2\r\n\r\n";
        let mut combined = Vec::new();
        combined.extend_from_slice(first);
        combined.extend_from_slice(second);
        let encrypted = client.encrypt_blocks(&combined).unwrap();
        let mut plaintext_buf = Vec::new();
        let mut encrypted_buf = encrypted;
        let consumed =
            decrypt_control_blocks(&mut server, &encrypted_buf, &mut plaintext_buf).unwrap();
        encrypted_buf.drain(..consumed);

        handoff_coalesced_encrypted_control(
            true,
            Some(&mut server),
            &mut plaintext_buf,
            &mut encrypted_buf,
        )
        .unwrap();

        assert!(encrypted_buf.is_empty());
        let (request1, used1) = parse_request(&plaintext_buf).unwrap();
        assert_eq!(request1.method, "OPTIONS");
        let (request2, used2) = parse_request(&plaintext_buf[used1..]).unwrap();
        assert_eq!(request2.method, "GET");
        assert_eq!(used1 + used2, plaintext_buf.len());
    }

    #[test]
    fn control_buffer_limits_accept_boundary_and_reject_overflow() {
        let mut plaintext = vec![0u8; MAX_PLAINTEXT_CONTROL_BUF - 1];
        append_control_plaintext(&mut plaintext, &[1]).unwrap();
        assert_eq!(plaintext.len(), MAX_PLAINTEXT_CONTROL_BUF);
        assert!(append_control_plaintext(&mut plaintext, &[2]).is_err());

        let mut encrypted = vec![0u8; MAX_ENCRYPTED_CONTROL_BUF - 1];
        append_encrypted_control(&mut encrypted, &[1]).unwrap();
        assert_eq!(encrypted.len(), MAX_ENCRYPTED_CONTROL_BUF);
        assert!(append_encrypted_control(&mut encrypted, &[2]).is_err());
    }

    #[test]
    fn pairing_tlv_error_never_activates_control_cipher() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        let state = AppState::new(config.clone());
        let (audio_engine, _consumer) = AudioEngine::new(8);
        let player = SharedPlayer::new();
        let dacp = DacpController::disabled(state.clone());
        let pairing = Arc::new(PairingService::new(
            IdentityKey::load_or_generate(None, &config.airplay.device_id),
            config.airplay.device_id.clone(),
            config.airplay.pin.clone(),
            None::<std::path::PathBuf>,
        ));
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();
        let svc = ConnectionServices {
            config: &config.airplay,
            state: &state,
            pairing: &pairing,
            audio_engine: &audio_engine,
            playout: &playout,
            player: &player,
            dacp: &dacp,
            ap2_policy: &policy,
        };
        let mut session = RtspSession::default();
        let mut tlv = crate::airplay::tlv::Tlv::default();
        tlv.insert(crate::airplay::pairing::TLV_STATE, [1]);
        tlv.insert(crate::airplay::pairing::TLV_METHOD, [1]);
        let request = RtspRequest {
            method: "POST".to_string(),
            uri: "/pair-setup".to_string(),
            version: "RTSP/1.0".to_string(),
            headers: BTreeMap::new(),
            body: tlv.encode(),
        };

        let response = route_request(&svc, &mut session, &request);
        let reply_tlv = crate::airplay::tlv::Tlv::parse(&response.body);
        assert_eq!(response.code, 200);
        assert!(
            reply_tlv
                .first(crate::airplay::pairing::TLV_ERROR)
                .is_some()
        );
        assert!(session.control_cipher.is_none());
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Connected);
    }

    #[test]
    fn rejected_pairing_completion_installs_no_cipher() {
        let mut session = RtspSession::default();
        session.ap2.begin_teardown().unwrap();
        session.ap2.close().unwrap();
        let completion = PairingCompletion::Verify {
            shared_secret: [0x33; 32],
        };
        assert!(activate_pairing_completion(&mut session, &completion).is_err());
        assert!(session.control_cipher.is_none());
    }

    // ── activate_pairing_completion compliance ─────────────────────────

    #[test]
    fn full_setup_marks_paired_and_leaves_control_cipher_none() {
        let mut session = RtspSession::default();
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Connected);
        assert!(session.control_cipher.is_none());

        let completion = PairingCompletion::FullSetup {
            key: [0xAA; 64],
            client_id: "test-client".into(),
        };
        activate_pairing_completion(&mut session, &completion).unwrap();

        // FullSetup must advance the phase to Paired.
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paired);
        // FullSetup must NOT install control encryption.
        assert!(session.control_cipher.is_none());
    }

    #[test]
    fn verify_installs_cipher() {
        let mut session = RtspSession::default();
        let secret: [u8; 32] = [0x77; 32];
        let completion = PairingCompletion::Verify {
            shared_secret: secret,
        };
        activate_pairing_completion(&mut session, &completion).unwrap();

        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paired);
        // Verify must install a control cipher using the X25519 shared secret.
        assert!(session.control_cipher.is_some());
    }

    #[test]
    fn transient_setup_installs_cipher() {
        let mut session = RtspSession::default();
        let completion = PairingCompletion::TransientSetup {
            key: [0xBB; 64],
            client_id: None,
        };
        activate_pairing_completion(&mut session, &completion).unwrap();

        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paired);
        // TransientSetup must install control encryption (no subsequent verify).
        assert!(session.control_cipher.is_some());
    }

    /// After a non-transient FullSetup (control_cipher left None), a
    /// plaintext pair-verify-like RTSP request must remain parseable as
    /// plaintext.  It must not be routed into encrypted-parsing.
    #[test]
    fn full_setup_leaves_control_plaintext_for_next_request() {
        let mut session = RtspSession::default();

        // 1. Complete a non-transient pair-setup.
        let completion = PairingCompletion::FullSetup {
            key: [0xCC; 64],
            client_id: "test-client-2".into(),
        };
        activate_pairing_completion(&mut session, &completion).unwrap();
        assert!(session.control_cipher.is_none());

        // 2. Simulate residual plaintext pair-verify bytes after the
        //    FullSetup response. The production handoff helper must leave
        //    them in the plaintext buffer because no cipher was activated.
        let raw = b"POST /pair-verify RTSP/1.0\r\n\
                     Content-Type: application/octet-stream\r\n\
                     Content-Length: 6\r\n\
                     \r\n\
                     \x00\x01\x02\x03\x04\x05";
        let mut plaintext = raw.to_vec();
        let mut encrypted = Vec::new();
        handoff_coalesced_encrypted_control(
            false,
            session.control_cipher.as_mut(),
            &mut plaintext,
            &mut encrypted,
        )
        .unwrap();
        assert_eq!(plaintext, raw);
        assert!(encrypted.is_empty());

        let (parsed, consumed) = parse_request(&plaintext).unwrap();
        assert_eq!(consumed, plaintext.len());
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.uri, "/pair-verify");
        assert_eq!(
            parsed.headers.get("Content-Type").map(|s| s.as_str()),
            Some("application/octet-stream")
        );
        assert_eq!(parsed.body, b"\x00\x01\x02\x03\x04\x05");
    }

    /// After a TransientSetup installs the cipher, the next request on
    /// the wire is encrypted — the coalesced handoff path must still
    /// work (regression guard for the existing behaviour).
    #[test]
    fn transient_setup_cipher_activated_coalesced_handoff_guard() {
        let mut session = RtspSession::default();
        let completion = PairingCompletion::TransientSetup {
            key: [0xDD; 64],
            client_id: None,
        };
        activate_pairing_completion(&mut session, &completion).unwrap();
        // After TransientSetup the cipher must be active — the next
        // request must be encrypted.
        assert!(session.control_cipher.is_some());
    }

    /// Verify-after-FullSetup must install the cipher: simulate a
    /// non-transient pair-setup followed by a pair-verify completion.
    #[test]
    fn verify_after_full_setup_installs_cipher() {
        let mut session = RtspSession::default();

        // Step 1: FullSetup — no cipher.
        let setup_completion = PairingCompletion::FullSetup {
            key: [0xEE; 64],
            client_id: "client-3".into(),
        };
        activate_pairing_completion(&mut session, &setup_completion).unwrap();
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paired);
        assert!(session.control_cipher.is_none());

        // Step 2: Verify — cipher must be installed.
        let secret: [u8; 32] = [0xFF; 32];
        let verify_completion = PairingCompletion::Verify {
            shared_secret: secret,
        };
        activate_pairing_completion(&mut session, &verify_completion).unwrap();
        assert_eq!(session.ap2.phase(), Ap2SessionPhase::Paired);
        assert!(session.control_cipher.is_some());
    }

    // ── plist_opaque_u64 helper ─────────────────────────────────────

    #[test]
    fn plist_opaque_u64_accepts_unsigned() {
        let v = plist::Value::Integer(plist::Integer::from(42u64));
        assert_eq!(plist_opaque_u64(&v), Some(42));
    }

    #[test]
    fn plist_opaque_u64_accepts_positive_signed() {
        let v = plist::Value::Integer(plist::Integer::from(42i64));
        assert_eq!(plist_opaque_u64(&v), Some(42));
    }

    #[test]
    fn plist_opaque_u64_accepts_negative_signed() {
        let v = plist::Value::Integer(plist::Integer::from(-1i64));
        assert_eq!(plist_opaque_u64(&v), Some(u64::MAX));
    }

    #[test]
    fn plist_opaque_u64_accepts_high_bit_signed() {
        // i64::MIN = -9223372036854775808, as u64 = 0x8000_0000_0000_0000
        let v = plist::Value::Integer(plist::Integer::from(i64::MIN));
        assert_eq!(plist_opaque_u64(&v), Some(i64::MIN as u64));
    }

    #[test]
    fn plist_opaque_u64_rejects_non_integer() {
        let v = plist::Value::String("not-an-integer".to_string());
        assert_eq!(plist_opaque_u64(&v), None);
    }

    #[test]
    fn plist_opaque_u64_rejects_boolean() {
        let v = plist::Value::Boolean(true);
        assert_eq!(plist_opaque_u64(&v), None);
    }

    #[test]
    fn plist_opaque_u64_rejects_real() {
        let v = plist::Value::Real(3.125);
        assert_eq!(plist_opaque_u64(&v), None);
    }

    #[test]
    fn plist_opaque_u64_u64_max_unsigned() {
        let v = plist::Value::Integer(plist::Integer::from(u64::MAX));
        assert_eq!(plist_opaque_u64(&v), Some(u64::MAX));
    }

    // ── plist_uint unchanged for truly-nonnegative fields ───────────

    #[test]
    fn plist_uint_rejects_signed_negative() {
        let v = plist::Value::Integer(plist::Integer::from(-1i64));
        assert_eq!(plist_uint(&v), None);
    }

    #[test]
    fn plist_uint_accepts_unsigned() {
        let v = plist::Value::Integer(plist::Integer::from(42u64));
        assert_eq!(plist_uint(&v), Some(42));
    }

    #[test]
    fn plist_uint_rejects_non_integer() {
        let v = plist::Value::String("bad".to_string());
        assert_eq!(plist_uint(&v), None);
    }

    // ── streamConnectionID signed-integer acceptance through handler ─

    #[tokio::test]
    async fn ap2_setup_type103_stream_connection_id_signed_accepted() {
        let mut config = crate::config::Config::default();
        config.airplay.airplay2_enabled = true;
        config.airplay.control_port = 6001;
        let state = AppState::new(config.clone());
        let dacp = DacpController::disabled(state.clone());
        let (playout, _cmd_rx, _ingress_rx) = test_playout();
        let policy = test_policy();

        for (label, conn_id_value) in [
            (
                "unsigned-42",
                plist::Value::Integer(plist::Integer::from(42u64)),
            ),
            (
                "signed-42",
                plist::Value::Integer(plist::Integer::from(42i64)),
            ),
            (
                "signed-minus-1",
                plist::Value::Integer(plist::Integer::from(-1i64)),
            ),
            (
                "signed-i64-min",
                plist::Value::Integer(plist::Integer::from(i64::MIN)),
            ),
        ] {
            let mut session = RtspSession::default();
            test_pair_with_secret(&mut session, [0x44; 32]);
            session
                .ap2
                .configure_timing(Ap2TimingProtocol::Ptp, None, None)
                .unwrap();

            let mut stream = plist::Dictionary::new();
            stream.insert("type".to_string(), plist_uint_value(103u64));
            stream.insert("shk".to_string(), plist::Value::Data(vec![1u8; 32]));
            stream.insert("audioFormat".to_string(), plist_uint_value(0x0004_0000u64));
            stream.insert("sr".to_string(), plist_uint_value(44_100u64));
            stream.insert("spf".to_string(), plist_uint_value(352u64));
            stream.insert("streamConnectionID".to_string(), conn_id_value);

            let mut setup = plist::Dictionary::new();
            setup.insert(
                "streams".to_string(),
                plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
            );
            let request = ap2_plist_request("SETUP", setup);

            let response = handle_ap2_setup(
                &config.airplay,
                &state,
                &mut session,
                &request,
                &playout,
                &dacp,
                &policy,
            );
            assert_eq!(
                response.code, 200,
                "streamConnectionID {label} should be accepted, got {}",
                response.code
            );
        }
    }
}
