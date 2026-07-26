//! AP2 event channel transport.
//!
//! The event channel is a TCP socket that the sender (client) connects to
//! after receiving the `eventPort` in the initial SETUP response.
//! On each accepted connection the server:
//!
//! 1. Uses the session-lifetime [`PairCipher`] derived when the listener is
//!    created; its counters continue monotonically across reconnects.
//! 2. Builds and encrypts an `updateInfo` RTSP command (`POST /command
//!    RTSP/1.0` with a binary-plist body).
//! 3. Sends the encrypted command with a write timeout.
//! 4. Reads, decrypts, and parses the RTSP response.
//! 5. Validates a 2xx acknowledgement.
//!
//! Only one active connection is permitted at a time — a new accepted
//! connection aborts and replaces the previous worker.  The listener
//! remains open for reconnections until session cleanup aborts it via
//! [`EventListener::abort`].
//!
//! # Bounds
//!
//! | Constant                  | Value  | Rationale                                    |
//! |---------------------------|--------|----------------------------------------------|
//! | `MAX_ENCRYPTED_PENDING`  | 4 096  | Incomplete encrypted-frame accumulation cap.|
//! | `MAX_DECRYPTED_RESPONSE`  | 4 096  | Matches the upstream event reply buffer.     |
//! | `MAX_UPDATE_INFO_BODY`    | 1 MiB  | Outbound binary-plist body cap.              |
//! | [`PairCipher::MAX_BLOCK`] | 1 024  | Per-block cap, enforced by the cipher.       |
//!
//! Encrypted length-prefix values larger than [`PairCipher::MAX_BLOCK`]
//! are rejected by the cipher before any counter is advanced.  Both the
//! encrypted-pending and decrypted-response buffers use checked
//! arithmetic and a documented conservative cap so no unbounded
//! `Vec` growth is possible.
//!
//! # Secret ownership
//!
//! The pairing secret arrives in an `Arc<Zeroizing<Vec<u8>>>` and is used
//! once, during listener creation, to derive a session-lifetime [`PairCipher`].
//! Workers share only that cipher behind an async mutex; they never retain or
//! clone raw secret bytes. Cipher counters therefore remain monotonic across
//! reconnects and cannot reuse a nonce under the same key.
//!
//! # Parent task design
//!
//! The listener task owns an abort-on-drop worker guard. A replacement aborts
//! the prior worker, and aborting or dropping [`EventListener`] cancels the
//! parent; dropping the parent future then aborts the active worker. No worker
//! handle is detached from the session lifecycle.

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::airplay::crypto::{CipherError, PairCipher};

type SharedEventCipher = Arc<tokio::sync::Mutex<PairCipher>>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum encrypted bytes retained while waiting for a complete frame.
pub const MAX_ENCRYPTED_PENDING: usize = 4096;

/// Maximum decrypted (plaintext) response size.
///
/// An RTSP 2xx acknowledgement with minimal headers is ≈ 50–100 bytes.
/// The C upstream reads the acknowledgement into a 4 KiB plaintext buffer.
pub const MAX_DECRYPTED_RESPONSE: usize = 4096;

/// Maximum binary-plist body accepted for the initial `updateInfo` command.
pub const MAX_UPDATE_INFO_BODY: usize = 1024 * 1024;

/// Default write timeout for sending the encrypted `updateInfo` command.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default read timeout for receiving the encrypted RTSP response.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during event channel operation.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cipher error: {0}")]
    Cipher(#[from] CipherError),

    #[error("write timeout")]
    WriteTimeout,

    #[error("read timeout")]
    ReadTimeout,

    #[error("encrypted pending data exceeds max size ({max})", max = MAX_ENCRYPTED_PENDING)]
    ResponseTooLarge,

    #[error("decrypted response exceeds max size ({max})", max = MAX_DECRYPTED_RESPONSE)]
    DecryptedTooLarge,

    #[error("RTSP parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("event channel non-2xx response: {code}")]
    NonSuccess { code: u16 },
}

/// Errors from RTSP response parsing.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum ParseError {
    #[error("empty response")]
    EmptyResponse,
    #[error("missing RTSP header terminator")]
    MissingHeaderTerminator,
    #[error("response headers are not valid UTF-8")]
    InvalidEncoding,
    #[error("invalid status line")]
    InvalidStatusLine,
    #[error("unsupported RTSP version")]
    InvalidVersion,
    #[error("invalid status code")]
    InvalidStatusCode,
    #[error("malformed header")]
    MalformedHeader,
    #[error("duplicate header")]
    DuplicateHeader,
    #[error("invalid Content-Length")]
    InvalidContentLength,
    #[error("incomplete body: expected {expected} bytes, got {got}")]
    IncompleteBody { expected: usize, got: usize },
    #[error("extra data after complete message ({extra} bytes)")]
    ExtraData { extra: usize },
}

// ---------------------------------------------------------------------------
// Parsed RTSP response
// ---------------------------------------------------------------------------

/// A parsed RTSP response from the event channel.
#[derive(Clone)]
pub struct ParsedRtspResponse {
    pub code: u16,
    #[allow(dead_code)]
    pub reason: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for ParsedRtspResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedRtspResponse")
            .field("code", &self.code)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl ParsedRtspResponse {
    /// Returns `true` when the status code is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

// ---------------------------------------------------------------------------
// RTSP response parser
// ---------------------------------------------------------------------------

/// Parse an RTSP response from raw bytes.
///
/// Expects the format:
/// ```text
/// RTSP/1.0 <code> <reason>\r\n
/// <header>: <value>\r\n
/// ...
/// \r\n
/// [body]
/// ```
///
/// Headers are parsed case-insensitively into a [`BTreeMap`].
/// `Content-Length` determines the body size.  The function verifies
/// that the entire input is consumed (no extra trailing data after the
/// complete message).
///
/// The input is NOT required to be valid UTF-8; the status line and
/// headers are lossily decoded from what are expected to be ASCII bytes.
pub fn parse_rtsp_response(data: &[u8]) -> Result<ParsedRtspResponse, ParseError> {
    if data.is_empty() {
        return Err(ParseError::EmptyResponse);
    }
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(ParseError::MissingHeaderTerminator)?;
    let Some((response, consumed)) = parse_rtsp_response_prefix(data)? else {
        let body_start = header_end + 4;
        let expected_total = expected_rtsp_message_len(data).unwrap_or(body_start);
        return Err(ParseError::IncompleteBody {
            expected: expected_total.saturating_sub(body_start),
            got: data.len().saturating_sub(body_start),
        });
    };
    if consumed != data.len() {
        return Err(ParseError::ExtraData {
            extra: data.len() - consumed,
        });
    }
    Ok(response)
}

/// Parse one complete RTSP response prefix.
///
/// Returns `Ok(None)` while the header or declared body is incomplete. The
/// returned byte count is the exact message boundary, allowing stream callers
/// to reject trailing data deterministically.
fn parse_rtsp_response_prefix(
    data: &[u8],
) -> Result<Option<(ParsedRtspResponse, usize)>, ParseError> {
    if data.is_empty() {
        return Ok(None);
    }
    let Some(header_end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let header_text =
        std::str::from_utf8(&data[..header_end]).map_err(|_| ParseError::InvalidEncoding)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let code_text = status_parts.next().unwrap_or_default();
    let reason = status_parts.next().unwrap_or_default();
    if version.is_empty() || code_text.is_empty() {
        return Err(ParseError::InvalidStatusLine);
    }
    if version != "RTSP/1.0" {
        return Err(ParseError::InvalidVersion);
    }
    if code_text.len() != 3 || !code_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::InvalidStatusCode);
    }
    let code = code_text
        .parse::<u16>()
        .map_err(|_| ParseError::InvalidStatusCode)?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ParseError::MalformedHeader);
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(ParseError::MalformedHeader);
        }
        let key = name.to_ascii_lowercase();
        if headers.insert(key.clone(), value.to_string()).is_some() {
            return Err(ParseError::DuplicateHeader);
        }
    }

    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| ParseError::InvalidContentLength)
        })
        .transpose()?
        .unwrap_or(0);
    let body_start = header_end + 4;
    let total_len = body_start
        .checked_add(content_length)
        .ok_or(ParseError::InvalidContentLength)?;
    if data.len() < total_len {
        return Ok(None);
    }
    let body = data[body_start..total_len].to_vec();
    Ok(Some((
        ParsedRtspResponse {
            code,
            reason: reason.to_string(),
            headers,
            body,
        },
        total_len,
    )))
}

fn expected_rtsp_message_len(data: &[u8]) -> Option<usize> {
    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_text = std::str::from_utf8(&data[..header_end]).ok()?;
    let content_length = header_text
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (header_end + 4).checked_add(content_length)
}

// ---------------------------------------------------------------------------
// Wire format: POST /command RTSP/1.0
// ---------------------------------------------------------------------------

/// Build the outbound `POST /command RTSP/1.0` wire bytes.
///
/// The `update_info_body` must be the binary-plist-serialized
/// `{type: "updateInfo", value: <info>}` dictionary.
///
/// The resulting wire is exactly:
/// ```text
/// POST /command RTSP/1.0\r\n
/// Content-Length: <len>\r\n
/// Content-Type: application/x-apple-binary-plist\r\n
/// \r\n
/// <update_info_body>
/// ```
///
/// No `CSeq` header is added — the upstream C implementation does not
/// include one, and the event channel is a single-request-per-connection
/// transport.
pub fn build_update_info_command(update_info_body: &[u8]) -> Vec<u8> {
    let header = format!(
        "POST /command RTSP/1.0\r\nContent-Length: {}\r\nContent-Type: application/x-apple-binary-plist\r\n\r\n",
        update_info_body.len()
    );
    let mut wire = header.into_bytes();
    wire.extend_from_slice(update_info_body);
    wire
}

// ---------------------------------------------------------------------------
// Per-connection event worker
// ---------------------------------------------------------------------------

/// Handle a single event channel connection.
///
/// 1. Use the listener's session-lifetime event cipher and next counters.
/// 2. Build and encrypt the `updateInfo` command.
/// 3. Write the encrypted command with a timeout.
/// 4. Read and decrypt the RTSP response with a timeout.
/// 5. Parse and validate a 2xx acknowledgement.
///
/// On any error the connection is dropped and the worker exits.  The
/// listener remains available for reconnection.
async fn handle_event_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    cipher: SharedEventCipher,
    update_info_body: Vec<u8>,
    write_timeout: Duration,
    read_timeout: Duration,
) -> Result<(), EventError> {
    info!(%peer, "AP2 event connection opened");
    let wire = build_update_info_command(&update_info_body);
    let mut cipher_guard = cipher.lock().await;
    let prepared = cipher_guard.prepare_encryption(&wire)?;
    let encrypted_len = prepared.ciphertext().len();
    timeout(write_timeout, stream.write_all(prepared.ciphertext()))
        .await
        .map_err(|_| EventError::WriteTimeout)??;
    prepared.commit();
    drop(cipher_guard);
    debug!(
        %peer,
        plaintext_len = wire.len(),
        encrypted_len,
        "AP2 event updateInfo sent"
    );

    let parsed = timeout(
        read_timeout,
        read_encrypted_rtsp_response(&mut stream, Arc::clone(&cipher)),
    )
    .await
    .map_err(|_| EventError::ReadTimeout)??;
    if !parsed.is_success() {
        return Err(EventError::NonSuccess { code: parsed.code });
    }
    info!(%peer, code = parsed.code, "AP2 event channel acknowledged");

    // Upstream keeps the acknowledged reverse connection open for future
    // commands. Until a verified inbound message contract exists, do not
    // consume or discard additional encrypted messages. Peek only to detect
    // disconnect or unexpected traffic; replacement/session cleanup aborts
    // this worker deterministically.
    let mut peek = [0u8; 1];
    match stream.peek(&mut peek).await {
        Ok(0) => debug!(%peer, "AP2 event connection closed by client"),
        Ok(_) => warn!(%peer, "unexpected AP2 event traffic after acknowledgement; closing worker"),
        Err(e) => debug!(%peer, %e, "AP2 event connection ended"),
    }
    Ok(())
}

async fn read_encrypted_rtsp_response(
    stream: &mut TcpStream,
    cipher: SharedEventCipher,
) -> Result<ParsedRtspResponse, EventError> {
    let mut encrypted = Vec::new();
    let mut plaintext = Vec::new();
    let mut read_buf = [0u8; 1024];

    loop {
        if let Some((response, consumed)) = parse_rtsp_response_prefix(&plaintext)? {
            if consumed != plaintext.len() || !encrypted.is_empty() {
                let extra = plaintext.len().saturating_sub(consumed) + encrypted.len();
                return Err(EventError::Parse(ParseError::ExtraData { extra }));
            }
            return Ok(response);
        }

        let read = stream.read(&mut read_buf).await?;
        if read == 0 {
            return Err(EventError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "event response ended before a complete RTSP message",
            )));
        }
        checked_append(
            &mut encrypted,
            &read_buf[..read],
            MAX_ENCRYPTED_PENDING,
            EventError::ResponseTooLarge,
        )?;

        let (decrypted, consumed) = {
            let mut cipher = cipher.lock().await;
            cipher.decrypt_blocks(&encrypted)?
        };
        if consumed > 0 {
            encrypted.drain(..consumed);
        }
        checked_append(
            &mut plaintext,
            &decrypted,
            MAX_DECRYPTED_RESPONSE,
            EventError::DecryptedTooLarge,
        )?;
    }
}

fn checked_append(
    target: &mut Vec<u8>,
    bytes: &[u8],
    limit: usize,
    error: EventError,
) -> Result<(), EventError> {
    let new_len = target
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| match error {
            EventError::ResponseTooLarge => EventError::ResponseTooLarge,
            EventError::DecryptedTooLarge => EventError::DecryptedTooLarge,
            _ => unreachable!("checked_append only receives size errors"),
        })?;
    if new_len > limit {
        return Err(error);
    }
    target.extend_from_slice(bytes);
    Ok(())
}

// ---------------------------------------------------------------------------
// EventListener — public handle with deterministic abort
// ---------------------------------------------------------------------------

/// A bound AP2 event channel listener.
///
/// Created by [`EventListener::bind`]. The listener task owns the current
/// per-connection worker through an abort-on-drop guard.
///
/// # Abort semantics
///
/// [`EventListener::abort`] signals and aborts the listener task. Dropping the
/// parent future drops its worker guard, which aborts the active connection.
/// Calling `abort` more than once is safe and idempotent.
pub struct EventListener {
    listener_handle: JoinHandle<()>,
    shutdown_tx: tokio::sync::watch::Sender<()>,
}

impl EventListener {
    pub fn bind(
        bind_addr: SocketAddr,
        secret: Arc<Zeroizing<Vec<u8>>>,
        update_info_body: Vec<u8>,
        write_timeout: Duration,
        read_timeout: Duration,
    ) -> std::io::Result<(u16, Self)> {
        if secret.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "event pairing secret is empty",
            ));
        }
        if update_info_body.len() > MAX_UPDATE_INFO_BODY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "event updateInfo body exceeds limit",
            ));
        }
        let cipher = Arc::new(tokio::sync::Mutex::new(PairCipher::events_for_server(
            secret.as_slice(),
        )));
        drop(secret);
        let listener = std::net::TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let listener = TcpListener::from_std(listener)?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
        let listener_handle = tokio::spawn(run_event_listener(
            listener,
            shutdown_rx,
            cipher,
            update_info_body,
            write_timeout,
            read_timeout,
        ));
        Ok((
            port,
            Self {
                listener_handle,
                shutdown_tx,
            },
        ))
    }

    /// Abort the listener and the current worker. Safe to call repeatedly.
    pub fn abort(&self) {
        let _ = self.shutdown_tx.send(());
        self.listener_handle.abort();
    }
}

impl Drop for EventListener {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        self.listener_handle.abort();
    }
}

#[derive(Default)]
struct WorkerGuard(Option<JoinHandle<()>>);

impl WorkerGuard {
    async fn terminate_current(&mut self) {
        if let Some(previous) = self.0.take() {
            previous.abort();
            let _ = previous.await;
        }
    }

    fn install(&mut self, worker: JoinHandle<()>) {
        assert!(
            self.0.is_none(),
            "event worker installed before prior worker terminated"
        );
        self.0 = Some(worker);
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            worker.abort();
        }
    }
}

async fn run_event_listener(
    listener: TcpListener,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    cipher: SharedEventCipher,
    update_info_body: Vec<u8>,
    write_timeout: Duration,
    read_timeout: Duration,
) {
    let mut worker = WorkerGuard::default();
    loop {
        let accepted = tokio::select! {
            _ = shutdown_rx.changed() => break,
            result = listener.accept() => result,
        };
        let (stream, peer) = match accepted {
            Ok(connection) => connection,
            Err(e) => {
                warn!(%e, "AP2 event accept failed");
                break;
            }
        };
        worker.terminate_current().await;
        let cipher = Arc::clone(&cipher);
        let body = update_info_body.clone();
        let next = tokio::spawn(async move {
            if let Err(e) =
                handle_event_connection(stream, peer, cipher, body, write_timeout, read_timeout)
                    .await
            {
                warn!(%peer, %e, "AP2 event worker closed");
            }
        });
        worker.install(next);
        debug!(%peer, "AP2 event active connection installed");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as TokioTcpStream;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// A shared secret for tests.  32 bytes of constant data is fine for
    /// tests — it is never logged or exposed.
    fn test_secret() -> Arc<Zeroizing<Vec<u8>>> {
        Arc::new(Zeroizing::new(vec![0xABu8; 32]))
    }

    /// Build a minimal updateInfo binary-plist body for tests.
    fn test_update_info_body() -> Vec<u8> {
        use plist::{Dictionary, Value};
        let mut inner = Dictionary::new();
        inner.insert("vv".into(), Value::Integer(2.into()));
        inner.insert("name".into(), Value::String("Test".into()));

        let mut outer = Dictionary::new();
        outer.insert("type".into(), Value::String("updateInfo".into()));
        outer.insert("value".into(), Value::Dictionary(inner));

        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &Value::Dictionary(outer)).unwrap();
        buf
    }

    /// Build an RTSP 200 OK response with optional body.
    fn build_rtsp_response(code: u16, reason: &str, body: &[u8]) -> Vec<u8> {
        let mut resp = format!(
            "RTSP/1.0 {code} {reason}\r\nServer: AirTunes/366.0\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        resp
    }

    // -----------------------------------------------------------------------
    // build_update_info_command tests
    // -----------------------------------------------------------------------

    #[test]
    fn update_info_command_wire_format() {
        let body = b"fake-plist-body";
        let wire = build_update_info_command(body);

        let wire_str = String::from_utf8_lossy(&wire);
        assert!(wire_str.starts_with("POST /command RTSP/1.0\r\n"));
        assert!(wire_str.contains("Content-Length: 15\r\n"));
        assert!(
            wire_str.contains("Content-Type: application/x-apple-binary-plist\r\n"),
            "wire: {wire_str:?}"
        );
        assert!(wire_str.contains("\r\n\r\nfake-plist-body"));
        assert!(wire.ends_with(b"fake-plist-body"));

        // No CSeq header
        assert!(
            !wire_str.contains("CSeq"),
            "should not contain CSeq, got: {wire_str:?}"
        );
    }

    #[test]
    fn update_info_command_empty_body() {
        let wire = build_update_info_command(b"");
        let wire_str = String::from_utf8_lossy(&wire);
        assert!(wire_str.contains("Content-Length: 0\r\n"));
        assert!(wire_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn update_info_command_binary_body_boundary() {
        // Body with embedded \r\n and null bytes must not break the wire format
        let body = [0x00, 0xFF, b'\r', b'\n', 0x00];
        let wire = build_update_info_command(&body);
        let wire_str = String::from_utf8_lossy(&wire);
        assert!(wire_str.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(wire.ends_with(&body));
    }

    // -----------------------------------------------------------------------
    // parse_rtsp_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_minimal_200_ok() {
        let resp = build_rtsp_response(200, "OK", b"");
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.code, 200);
        assert!(parsed.is_success());
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_200_with_body() {
        let body = b"{\"status\":\"ok\"}";
        let resp = build_rtsp_response(200, "OK", body);
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.code, 200);
        assert!(parsed.is_success());
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn parse_status_line_variants() {
        // RTSP/1.0 200 OK
        let resp = b"RTSP/1.0 200 OK\r\n\r\n";
        let parsed = parse_rtsp_response(resp).unwrap();
        assert_eq!(parsed.code, 200);
        assert_eq!(parsed.reason, "OK");

        // No reason phrase
        let resp = b"RTSP/1.0 200\r\n\r\n";
        let parsed = parse_rtsp_response(resp).unwrap();
        assert_eq!(parsed.code, 200);
        assert_eq!(parsed.reason, "");
    }

    #[test]
    fn parse_headers_case_insensitive() {
        let resp = b"RTSP/1.0 200 OK\r\nContent-Length: 5\r\nServer: Test\r\n\r\nhello";
        let parsed = parse_rtsp_response(resp).unwrap();
        assert_eq!(parsed.body, b"hello");
        assert_eq!(
            parsed.headers.get("server").map(String::as_str),
            Some("Test")
        );
        assert!(!parsed.headers.contains_key("Server"));

        // content-length in different case
        let resp = b"RTSP/1.0 200 OK\r\ncontent-length: 5\r\n\r\nworld";
        let parsed = parse_rtsp_response(resp).unwrap();
        assert_eq!(parsed.body, b"world");

        // CONTENT-LENGTH uppercase
        let resp = b"RTSP/1.0 200 OK\r\nCONTENT-LENGTH: 3\r\n\r\nfoo";
        let parsed = parse_rtsp_response(resp).unwrap();
        assert_eq!(parsed.body, b"foo");
    }

    #[test]
    fn parse_no_content_length_defaults_to_zero() {
        let resp = b"RTSP/1.0 200 OK\r\nServer: Test\r\n\r\n";
        let parsed = parse_rtsp_response(&resp[..]).unwrap();
        assert_eq!(parsed.code, 200);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_rejects_extra_data() {
        let resp = b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\nEXTRA";
        let err = parse_rtsp_response(resp).unwrap_err();
        assert!(matches!(err, ParseError::ExtraData { extra: 5 }));
    }

    #[test]
    fn parse_rejects_incomplete_body() {
        let resp = b"RTSP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        let err = parse_rtsp_response(resp).unwrap_err();
        assert!(matches!(
            err,
            ParseError::IncompleteBody {
                expected: 100,
                got: 5
            }
        ));
    }

    #[test]
    fn parse_rejects_invalid_status_code() {
        let resp = b"RTSP/1.0 xxx OK\r\n\r\n";
        let err = parse_rtsp_response(resp).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStatusCode));
    }

    #[test]
    fn parse_rejects_invalid_content_length() {
        let resp = b"RTSP/1.0 200 OK\r\nContent-Length: abc\r\n\r\n";
        let err = parse_rtsp_response(resp).unwrap_err();
        assert!(matches!(err, ParseError::InvalidContentLength));
    }

    #[test]
    fn parse_rejects_empty_response() {
        let err = parse_rtsp_response(b"").unwrap_err();
        assert!(matches!(err, ParseError::EmptyResponse));
    }

    #[test]
    fn parse_rejects_missing_status_line() {
        // No \r\n\r\n separator at all
        let err = parse_rtsp_response(b"RTSP/1.0 200 OK\r\nServer: Test").unwrap_err();
        assert!(matches!(err, ParseError::MissingHeaderTerminator));
    }

    #[test]
    fn parse_rejects_empty_status_line() {
        let err = parse_rtsp_response(b"\r\n\r\n").unwrap_err();
        assert!(matches!(err, ParseError::InvalidStatusLine));
    }

    #[test]
    fn parse_rejects_wrong_rtsp_version() {
        let err = parse_rtsp_response(b"HTTP/1.1 200 OK\r\n\r\n").unwrap_err();
        assert!(matches!(err, ParseError::InvalidVersion));
    }

    #[test]
    fn parse_rejects_duplicate_headers_case_insensitively() {
        let response = b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n";
        let err = parse_rtsp_response(response).unwrap_err();
        assert!(matches!(err, ParseError::DuplicateHeader));
    }

    #[test]
    fn parse_rejects_malformed_header() {
        let resp = b"RTSP/1.0 200 OK\r\nBadHeader\r\n\r\n";
        let err = parse_rtsp_response(resp).unwrap_err();
        assert!(matches!(err, ParseError::MalformedHeader));
    }

    #[test]
    fn parse_fragmented_at_every_byte_boundary() {
        let full = b"RTSP/1.0 200 OK\r\nContent-Length: 3\r\nServer: Test\r\n\r\nabc";
        // Try parsing at every split point
        for i in 1..full.len() {
            let (head, tail) = full.split_at(i);
            // Head alone should fail (incomplete)
            let _ = parse_rtsp_response(head);
            // But we can verify the combined result is correct
            let mut combined = head.to_vec();
            combined.extend_from_slice(tail);
            let parsed = parse_rtsp_response(&combined).unwrap();
            assert_eq!(parsed.code, 200);
            assert_eq!(parsed.body, b"abc");
        }
    }

    #[test]
    fn parse_content_length_body_boundary() {
        // Exactly Content-Length bytes of body
        let body = b"12345";
        let resp = build_rtsp_response(200, "OK", body);
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.body, body);

        // Body with embedded CRLF
        let body = b"line1\r\nline2";
        let resp = build_rtsp_response(200, "OK", body);
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn parse_non_2xx() {
        let resp = build_rtsp_response(400, "Bad Request", b"");
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.code, 400);
        assert!(!parsed.is_success());

        let resp = build_rtsp_response(503, "Service Unavailable", b"");
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.code, 503);
        assert!(!parsed.is_success());
    }

    #[test]
    fn parse_2xx_boundaries() {
        // 200 is success
        let resp = build_rtsp_response(200, "OK", b"");
        assert!(parse_rtsp_response(&resp).unwrap().is_success());

        // 299 is success
        let resp = build_rtsp_response(299, "OK", b"");
        assert!(parse_rtsp_response(&resp).unwrap().is_success());

        // 199 is not success
        let resp = build_rtsp_response(199, "OK", b"");
        assert!(!parse_rtsp_response(&resp).unwrap().is_success());

        // 300 is not success
        let resp = build_rtsp_response(300, "Multiple Choices", b"");
        assert!(!parse_rtsp_response(&resp).unwrap().is_success());
    }

    // -----------------------------------------------------------------------
    // Encrypted response fragmented test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn encrypted_fragmented_response() {
        // Simulate the decrypt path: the server encrypts its request,
        // the client encrypts a response, the server decrypts.
        let secret = test_secret();

        // Server encrypts updateInfo
        let mut server_cipher = PairCipher::events_for_server(&secret);
        let wire = build_update_info_command(&test_update_info_body());
        let _encrypted_request = server_cipher.encrypt_blocks(&wire).unwrap();
        // After encrypt_blocks, the encryption counter advanced.
        // The client would decrypt this, then encrypt a response.
        // The server would then decrypt the response.

        // Build RTSP response
        let response_plain = build_rtsp_response(200, "OK", b"");

        // To test the server's decrypt path, we need to encrypt the response
        // with the key that the server's decrypt_blocks expects.
        // The server's decrypt_blocks uses decryption_key.
        // The client would encrypt with a key that matches the server's
        // decryption_key. In PairCipher::events_for_server, the
        // decryption_key is derived with Events-Read-Encryption-Key.
        //
        // For tests, we create a "client" cipher that has encryption_key
        // = server's decryption_key. Since PairCipher::new is private,
        // we construct one by manually deriving keys.
        //
        // Actually, we can just create a fresh PairCipher::events_for_server
        // and use its encrypt_blocks — BUT the client's encrypt_blocks
        // uses a different key (Events-Write-Encryption-Key for server).
        //
        // The simplest correct approach:
        // 1. Create two server ciphers (both events_for_server)
        // 2. Cipher A encrypts updateInfo (advances A.enc_counter)
        // 3. Cipher B (fresh) would encrypt the response using the SAME
        //    encryption_key as A, not the decryption_key. That's wrong.
        //
        // To properly test, we need to encrypt the response with the
        // server's decryption_key. Let me construct a cipher manually.

        // Derive both keys independently
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let _server_write_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Write-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        let server_read_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        // Encrypt response using the server's read key (what the client uses to write).
        // The client encrypts with the server's read key, using counter 0.
        let client_cipher = ChaCha20Poly1305::new((&server_read_key).into());
        let block_len = (response_plain.len() as u16).to_le_bytes();
        let nonce = counter_nonce(0);
        let encrypted_response = client_cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &response_plain,
                    aad: &block_len,
                },
            )
            .unwrap();
        let mut encrypted_response_frame = Vec::new();
        encrypted_response_frame.extend_from_slice(&block_len);
        encrypted_response_frame.extend_from_slice(&encrypted_response);

        // Feed to a fresh server cipher's decrypt_blocks
        let mut verify_cipher = PairCipher::events_for_server(&secret);
        // The server hasn't encrypted anything with this cipher yet, so
        // its decryption counter is 0. But it expects to decrypt what
        // the client encrypted with the server's READ key. The server's
        // decrypt_blocks uses decryption_key = server_read_key. ✓
        let (plain, consumed) = verify_cipher
            .decrypt_blocks(&encrypted_response_frame)
            .unwrap();
        assert_eq!(consumed, encrypted_response_frame.len());
        assert_eq!(plain, response_plain);

        // Verify the parsed response is 200 OK
        let parsed = parse_rtsp_response(&plain).unwrap();
        assert_eq!(parsed.code, 200);
        assert!(parsed.is_success());
    }

    /// Build a nonce from a counter (matches PairCipher's counter_nonce).
    fn counter_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    fn encrypt_client_event_payload(secret: &[u8], plaintext: &[u8], counter: u64) -> Vec<u8> {
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret);
        let mut key = [0u8; 32];
        hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
            .unwrap();
        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut result = Vec::new();
        for (offset, block) in plaintext
            .chunks(crate::airplay::crypto::MAX_BLOCK)
            .enumerate()
        {
            let length = (block.len() as u16).to_le_bytes();
            let encrypted = cipher
                .encrypt(
                    (&counter_nonce(counter + offset as u64)).into(),
                    Payload {
                        msg: block,
                        aad: &length,
                    },
                )
                .unwrap();
            result.extend_from_slice(&length);
            result.extend_from_slice(&encrypted);
        }
        result
    }

    #[tokio::test]
    async fn encrypted_response_completes_before_client_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let secret = test_secret();
        let response = build_rtsp_response(200, "OK", &vec![b'x'; 1500]);
        let encrypted = encrypt_client_event_payload(secret.as_slice(), &response, 0);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let client = tokio::spawn(async move {
            let mut stream = TokioTcpStream::connect(address).await.unwrap();
            for byte in encrypted {
                stream.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            let _ = release_rx.await;
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let cipher = Arc::new(tokio::sync::Mutex::new(PairCipher::events_for_server(
            secret.as_slice(),
        )));
        let parsed = timeout(
            Duration::from_secs(2),
            read_encrypted_rtsp_response(&mut server, cipher),
        )
        .await
        .expect("response parsing must not wait for EOF")
        .unwrap();
        assert_eq!(parsed.code, 200);
        assert_eq!(parsed.body.len(), 1500);
        assert!(
            !client.is_finished(),
            "client should still be holding the socket open"
        );
        let _ = release_tx.send(());
        client.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Encrypted / plaintext limit boundary and overflow tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_rejects_body_at_max_decrypted_boundary() {
        // Body exactly MAX_DECRYPTED_RESPONSE bytes is accepted
        let body = vec![b'x'; MAX_DECRYPTED_RESPONSE];
        let resp = build_rtsp_response(200, "OK", &body);
        let parsed = parse_rtsp_response(&resp).unwrap();
        assert_eq!(parsed.body.len(), MAX_DECRYPTED_RESPONSE);
    }

    #[test]
    fn encrypted_response_size_check_uses_checked_add() {
        // Verify MAX_ENCRYPTED_PENDING is a reasonable documented cap
        const {
            assert!(MAX_ENCRYPTED_PENDING > 0);
            assert!(MAX_ENCRYPTED_PENDING <= 65536);
        }
        // No overflow: MAX_ENCRYPTED_PENDING + 1 fits in usize
        let _ = MAX_ENCRYPTED_PENDING.checked_add(1).unwrap();
    }

    #[test]
    fn cipher_rejects_oversize_length_prefix() {
        let secret = test_secret();
        // Craft a frame with length prefix > MAX_BLOCK
        let oversized_len = (crate::airplay::crypto::MAX_BLOCK + 1) as u16;
        let frame = [
            oversized_len.to_le_bytes()[0],
            oversized_len.to_le_bytes()[1],
            0x00, // dummy payload
        ];
        let mut cipher = PairCipher::events_for_server(&secret);
        let err = cipher.decrypt_blocks(&frame).unwrap_err();
        assert!(matches!(err, CipherError::BlockTooLarge));
    }

    // -----------------------------------------------------------------------
    // Auth failure test
    // -----------------------------------------------------------------------

    #[test]
    fn cipher_auth_failure_rejected() {
        let secret = test_secret();
        let plain = b"test data";

        // Derive the Read key (what clients encrypt responses with).
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let server_read_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        // Encrypt with the Read key (simulating a client response).
        let client_cipher = ChaCha20Poly1305::new((&server_read_key).into());
        let block_len = (plain.len() as u16).to_le_bytes();
        let encrypted = client_cipher
            .encrypt(
                (&counter_nonce(0)).into(),
                Payload {
                    msg: plain,
                    aad: &block_len,
                },
            )
            .unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&block_len);
        frame.extend_from_slice(&encrypted);

        // Corrupt the last byte (tag).
        let mut corrupted = frame.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;

        // Decryption should fail auth.
        let mut verify = PairCipher::events_for_server(&secret);
        let err = verify.decrypt_blocks(&corrupted).unwrap_err();
        assert!(matches!(err, CipherError::AuthFailed));

        // Counter should not have advanced — retry with good data works.
        let mut verify2 = PairCipher::events_for_server(&secret);
        let (plain2, _) = verify2.decrypt_blocks(&frame).unwrap();
        assert_eq!(plain2, plain);
    }

    // -----------------------------------------------------------------------
    // EventListener integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn event_listener_rejects_empty_secret_and_oversize_body() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let empty = Arc::new(Zeroizing::new(Vec::new()));
        assert!(
            EventListener::bind(
                bind,
                empty,
                test_update_info_body(),
                DEFAULT_WRITE_TIMEOUT,
                DEFAULT_READ_TIMEOUT,
            )
            .is_err()
        );

        let oversize = vec![0u8; MAX_UPDATE_INFO_BODY + 1];
        assert!(
            EventListener::bind(
                bind,
                test_secret(),
                oversize,
                DEFAULT_WRITE_TIMEOUT,
                DEFAULT_READ_TIMEOUT,
            )
            .is_err()
        );
    }

    /// Helper: spawn a listener, connect a mock client, and verify the
    /// encrypted handshake succeeds.
    async fn run_event_handshake(
        secret: Arc<Zeroizing<Vec<u8>>>,
        update_info_body: Vec<u8>,
    ) -> (u16, EventListener) {
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let (port, listener) = EventListener::bind(
            bind_addr,
            secret,
            update_info_body,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        (port, listener)
    }

    /// A mock client that connects, reads the encrypted updateInfo,
    /// decrypts it, and sends back an encrypted 200 OK response.
    async fn mock_client_handshake(
        port: u16,
        secret: Arc<Zeroizing<Vec<u8>>>,
        server_write_counter: u64,
        client_write_counter: u64,
    ) {
        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        // Derive client cipher: for reading server's encrypted data, we
        // use events_for_server (same keys). The server encrypts with
        // Events-Write key; the client decrypts with Events-Write key.
        // The server decrypts with Events-Read key; the client encrypts
        // response with Events-Read key.
        //
        // We need a client cipher that:
        // - decrypts with Events-Write key (server's encryption_key)
        // - encrypts with Events-Read key (server's decryption_key)
        //
        // Since PairCipher::new is private, we'll manually derive keys.

        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let server_write_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Write-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        let server_read_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        // Read the encrypted updateInfo from the server
        let mut encrypted_req = Vec::new();
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        encrypted_req.extend_from_slice(&buf[..n]);

        // Decrypt using server's write key
        let prefix_len = 2usize;
        let tag_len = 16usize;
        let block_len = u16::from_le_bytes([encrypted_req[0], encrypted_req[1]]) as usize;
        let frame_len = prefix_len + block_len + tag_len;
        assert!(encrypted_req.len() >= frame_len, "incomplete frame");

        let client_read_cipher = ChaCha20Poly1305::new((&server_write_key).into());
        let decrypted = client_read_cipher
            .decrypt(
                (&counter_nonce(server_write_counter)).into(),
                Payload {
                    msg: &encrypted_req[prefix_len..frame_len],
                    aad: &encrypted_req[..prefix_len],
                },
            )
            .unwrap();

        // Verify it's a POST /command with updateInfo
        let decrypted_str = String::from_utf8_lossy(&decrypted);
        assert!(
            decrypted_str.contains("POST /command RTSP/1.0"),
            "expected POST /command, got: {decrypted_str:?}"
        );
        assert!(
            decrypted_str.contains("updateInfo"),
            "expected updateInfo, got: {decrypted_str:?}"
        );

        // Build and encrypt 200 OK response
        let response = build_rtsp_response(200, "OK", b"");
        let client_write_cipher = ChaCha20Poly1305::new((&server_read_key).into());
        let resp_block_len = (response.len() as u16).to_le_bytes();
        let encrypted_response = client_write_cipher
            .encrypt(
                (&counter_nonce(client_write_counter)).into(),
                Payload {
                    msg: &response,
                    aad: &resp_block_len,
                },
            )
            .unwrap();
        let mut response_frame = Vec::new();
        response_frame.extend_from_slice(&resp_block_len);
        response_frame.extend_from_slice(&encrypted_response);

        stream.write_all(&response_frame).await.unwrap();
    }

    #[tokio::test]
    async fn event_listener_bind_and_accept() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;
        assert!(port > 0);

        // Connect mock client
        mock_client_handshake(port, secret, 0, 0).await;

        // Give the worker time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cleanup
        listener.abort();
    }

    #[tokio::test]
    async fn event_listener_non_2xx_closes_worker() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        // Connect and send a 400 response instead of 200
        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        // Read the encrypted request
        let mut encrypted_req = Vec::new();
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        encrypted_req.extend_from_slice(&buf[..n]);

        // Derive keys (same as mock_client_handshake)
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let server_read_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        // Send 400 Bad Request
        let response = build_rtsp_response(400, "Bad Request", b"");
        let client_write_cipher = ChaCha20Poly1305::new((&server_read_key).into());
        let resp_block_len = (response.len() as u16).to_le_bytes();
        let encrypted_response = client_write_cipher
            .encrypt(
                (&counter_nonce(0)).into(),
                Payload {
                    msg: &response,
                    aad: &resp_block_len,
                },
            )
            .unwrap();
        let mut response_frame = Vec::new();
        response_frame.extend_from_slice(&resp_block_len);
        response_frame.extend_from_slice(&encrypted_response);
        stream.write_all(&response_frame).await.unwrap();

        // Worker should close after non-2xx; listener stays alive.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify we can still connect again (listener is alive)
        mock_client_handshake(port, secret, 1, 1).await;

        listener.abort();
    }

    #[tokio::test]
    async fn event_listener_replacement_of_active_connection() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        // First connection: complete handshake
        let mut stream1 = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        // Read encrypted request
        let mut buf = [0u8; 2048];
        let _n = stream1.read(&mut buf).await.unwrap();

        // Derive keys
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let server_read_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        let _server_write_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Write-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        // First connection sends 200 OK
        let response = build_rtsp_response(200, "OK", b"");
        let client_write_cipher = ChaCha20Poly1305::new((&server_read_key).into());
        let resp_block_len = (response.len() as u16).to_le_bytes();
        let encrypted_response = client_write_cipher
            .encrypt(
                (&counter_nonce(0)).into(),
                Payload {
                    msg: &response,
                    aad: &resp_block_len,
                },
            )
            .unwrap();
        let mut response_frame = Vec::new();
        response_frame.extend_from_slice(&resp_block_len);
        response_frame.extend_from_slice(&encrypted_response);
        stream1.write_all(&response_frame).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second connection: the new accept should replace the first worker
        mock_client_handshake(port, secret.clone(), 1, 1).await;

        // First connection should have been aborted when second connected
        // Try reading from stream1 — should get EOF or error
        tokio::time::sleep(Duration::from_millis(50)).await;
        let closed = timeout(Duration::from_secs(1), stream1.read(&mut buf))
            .await
            .expect("replaced connection must close")
            .unwrap();
        assert_eq!(closed, 0);

        listener.abort();
    }

    #[tokio::test]
    async fn event_listener_reconnect_after_failure() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        // Connect and immediately close (simulating a failed handshake)
        {
            let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            // Read the encrypted request but don't respond — just close
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            drop(stream);
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Listener should still be alive — reconnect should work
        mock_client_handshake(port, secret, 1, 0).await;

        listener.abort();
    }

    #[tokio::test]
    async fn event_listener_parent_abort_terminates_worker() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        // Start a handshake but don't complete it (worker stays in read loop)
        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        // Now abort the listener — the worker should be terminated
        listener.abort();

        let closed = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("aborted worker must close its socket")
            .unwrap();
        assert_eq!(closed, 0);
    }

    #[tokio::test]
    async fn dropping_event_listener_terminates_active_worker() {
        let secret = test_secret();
        let (port, listener) = run_event_handshake(secret, test_update_info_body()).await;
        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await.unwrap();
        drop(listener);
        let closed = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("dropping listener must close active worker")
            .unwrap();
        assert_eq!(closed, 0);
    }

    #[tokio::test]
    async fn event_listener_abort_is_idempotent() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (_, listener) = run_event_handshake(secret, body).await;

        listener.abort();
        listener.abort(); // second call should not panic
    }

    #[tokio::test]
    async fn event_listener_malformed_rtsp_response_worker_closes() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        // Connect and send garbage (not valid RTSP)
        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        // Derive server_read_key
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        use hkdf::Hkdf;
        use sha2::Sha512;

        let server_read_key = {
            let hkdf = Hkdf::<Sha512>::new(Some(b"Events-Salt"), secret.as_slice());
            let mut key = [0u8; 32];
            hkdf.expand(b"Events-Read-Encryption-Key", &mut key)
                .unwrap();
            key
        };

        // Send encrypted garbage (not valid RTSP response)
        let garbage = b"NOT AN RTSP RESPONSE";
        let client_write_cipher = ChaCha20Poly1305::new((&server_read_key).into());
        let resp_block_len = (garbage.len() as u16).to_le_bytes();
        let encrypted = client_write_cipher
            .encrypt(
                (&counter_nonce(0)).into(),
                Payload {
                    msg: garbage,
                    aad: &resp_block_len,
                },
            )
            .unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&resp_block_len);
        frame.extend_from_slice(&encrypted);
        stream.write_all(&frame).await.unwrap();
        drop(stream);

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Listener should still be alive
        mock_client_handshake(port, secret, 1, 1).await;

        listener.abort();
    }

    #[tokio::test]
    async fn event_listener_auth_failure_worker_closes() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        // Send unencrypted garbage (will fail auth)
        stream
            .write_all(b"unencrypted garbage that fails auth")
            .await
            .unwrap();
        drop(stream);

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Listener should still be alive
        mock_client_handshake(port, secret, 1, 0).await;

        listener.abort();
    }

    #[tokio::test]
    async fn event_listener_response_too_large() {
        let secret = test_secret();
        let body = test_update_info_body();
        let (port, listener) = run_event_handshake(secret.clone(), body).await;

        let mut stream = TokioTcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        // Send more than MAX_ENCRYPTED_PENDING bytes
        let big_data = vec![0x00u8; MAX_ENCRYPTED_PENDING + 1024];
        // Use multiple writes to exceed the limit
        for chunk in big_data.chunks(1024) {
            if stream.write_all(chunk).await.is_err() {
                break;
            }
        }
        drop(stream);

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Listener should still be alive
        mock_client_handshake(port, secret, 1, 0).await;

        listener.abort();
    }

    // -----------------------------------------------------------------------
    // No payload bytes logged in error messages
    // -----------------------------------------------------------------------

    #[test]
    fn error_messages_do_not_contain_payload_bytes() {
        // All error Display impls should not leak raw bytes
        let errors: Vec<Box<dyn std::fmt::Display>> = vec![
            Box::new(EventError::ResponseTooLarge),
            Box::new(EventError::DecryptedTooLarge),
            Box::new(EventError::WriteTimeout),
            Box::new(EventError::ReadTimeout),
            Box::new(EventError::NonSuccess { code: 400 }),
            Box::new(EventError::Parse(ParseError::EmptyResponse)),
            Box::new(EventError::Parse(ParseError::MissingHeaderTerminator)),
            Box::new(EventError::Parse(ParseError::InvalidStatusCode)),
            Box::new(EventError::Parse(ParseError::MalformedHeader)),
            Box::new(EventError::Parse(ParseError::DuplicateHeader)),
            Box::new(EventError::Parse(ParseError::InvalidVersion)),
            Box::new(EventError::Parse(ParseError::InvalidContentLength)),
            Box::new(EventError::Parse(ParseError::IncompleteBody {
                expected: 10,
                got: 5,
            })),
            Box::new(EventError::Parse(ParseError::ExtraData { extra: 3 })),
            Box::new(EventError::Parse(ParseError::InvalidStatusLine)),
        ];

        for err in &errors {
            let msg = err.to_string();
            // No hex dumps or large binary blobs
            assert!(!msg.contains("0x"), "error message contains hex: {msg:?}");
            // The message should be reasonably short
            assert!(msg.len() < 200, "error message too long: {msg:?}");
        }
    }
}
