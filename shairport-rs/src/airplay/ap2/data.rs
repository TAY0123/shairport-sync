//! AirPlay 2 encrypted data-stream transport (stream type 130).
//!
//! The channel is used by remote-control-only sessions. It implements the
//! verified transport envelope, mandatory `sync` acknowledgement, and the
//! outbound MediaRemote playback-command subset used by the local/system media
//! control surfaces.
//!
//! A data frame consists of a 32-byte big-endian header followed by an
//! optional binary-plist payload:
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | total frame size, including the header |
//! | 4 | 12 | zero-padded message type |
//! | 16 | 4 | zero-padded command |
//! | 20 | 8 | sequence number |
//! | 28 | 4 | zero padding |
//!
//! The pairing secret is used once to derive a session-lifetime cipher. The
//! cipher is shared across reconnects so both nonce counters remain monotonic.
//! A replacement connection is not started until the previous worker has been
//! aborted and joined. Dropping the listener also aborts the active worker.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, broadcast},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::{
    airplay::{
        ap2::mrp::{self, MrpCommand},
        crypto::{CipherError, PairCipher},
    },
    state::AppState,
};

/// Size of the unencrypted data-stream header.
pub const DATA_HEADER_LEN: usize = 32;
/// Maximum complete plaintext frame size.
pub const MAX_FRAME_SIZE: usize = 256 * 1024;
/// Maximum encrypted bytes retained while waiting for complete cipher blocks.
pub const MAX_ENCRYPTED_PENDING: usize = 512 * 1024;
/// Maximum decrypted bytes retained while waiting for complete data frames.
pub const MAX_PLAINTEXT_PENDING: usize = 512 * 1024;
/// Maximum binary-plist payload size.
pub const MAX_PLIST_PAYLOAD: usize = MAX_FRAME_SIZE - DATA_HEADER_LEN;
/// Default idle, partial-frame, and write timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

const SYNC_PREFIX: &[u8; 4] = b"sync";
const REPLY_TYPE: [u8; 12] = [b'r', b'p', b'l', b'y', 0, 0, 0, 0, 0, 0, 0, 0];
const EMPTY_COMMAND: [u8; 4] = [0; 4];
const COMMAND_TYPE: [u8; 12] = [b's', b'y', b'n', b'c', 0, 0, 0, 0, 0, 0, 0, 0];
const COMMAND_NAME: [u8; 4] = *b"comm";

type SharedDataCipher = Arc<Mutex<PairCipher>>;

/// Data-stream transport or framing error.
#[derive(Debug, thiserror::Error)]
pub enum DataStreamError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cipher error: {0}")]
    Cipher(#[from] CipherError),
    #[error("data stream timed out")]
    Timeout,
    #[error("connection ended with an incomplete data frame")]
    UnexpectedEof,
    #[error("frame size is below the 32-byte header")]
    FrameTooSmall,
    #[error("frame size exceeds configured limit")]
    FrameTooLarge,
    #[error("frame padding is not zero")]
    InvalidPadding,
    #[error("encrypted pending data exceeds configured limit")]
    EncryptedPendingTooLarge,
    #[error("plaintext pending data exceeds configured limit")]
    PlaintextPendingTooLarge,
    #[error("invalid binary-plist payload")]
    InvalidPlist,
    #[error("failed to serialize outbound binary-plist payload")]
    OutboundPlist,
}

/// Parsed 32-byte data-stream header.
#[derive(Clone, Eq, PartialEq)]
pub struct DataHeader {
    pub total_size: u32,
    message_type: [u8; 12],
    command: [u8; 4],
    pub seqno: u64,
    pub padding: u32,
}

impl std::fmt::Debug for DataHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataHeader")
            .field("total_size", &self.total_size)
            .field("is_sync", &self.is_sync())
            .field("seqno", &self.seqno)
            .field("padding", &self.padding)
            .finish()
    }
}

impl DataHeader {
    /// Parse and validate a header. Incomplete input returns `Ok(None)`.
    pub fn parse(buf: &[u8]) -> Result<Option<Self>, DataStreamError> {
        if buf.len() < DATA_HEADER_LEN {
            return Ok(None);
        }
        let total_size = u32::from_be_bytes(buf[0..4].try_into().expect("fixed slice"));
        let total_size_usize = total_size as usize;
        if total_size_usize < DATA_HEADER_LEN {
            return Err(DataStreamError::FrameTooSmall);
        }
        if total_size_usize > MAX_FRAME_SIZE {
            return Err(DataStreamError::FrameTooLarge);
        }
        let mut message_type = [0u8; 12];
        message_type.copy_from_slice(&buf[4..16]);
        let mut command = [0u8; 4];
        command.copy_from_slice(&buf[16..20]);
        let seqno = u64::from_be_bytes(buf[20..28].try_into().expect("fixed slice"));
        let padding = u32::from_be_bytes(buf[28..32].try_into().expect("fixed slice"));
        if padding != 0 {
            return Err(DataStreamError::InvalidPadding);
        }
        Ok(Some(Self {
            total_size,
            message_type,
            command,
            seqno,
            padding,
        }))
    }

    /// Canonical message-type prefix, stopping at the first NUL byte.
    pub fn message_type(&self) -> &[u8] {
        zero_terminated_prefix(&self.message_type)
    }

    /// Canonical command prefix, stopping at the first NUL byte.
    pub fn command(&self) -> &[u8] {
        zero_terminated_prefix(&self.command)
    }

    pub fn is_sync(&self) -> bool {
        self.message_type.starts_with(SYNC_PREFIX)
    }
}

fn zero_terminated_prefix(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

/// Build the mandatory empty `rply` frame for a `sync*` request.
pub fn build_sync_reply(seqno: u64) -> Vec<u8> {
    build_frame(&REPLY_TYPE, &EMPTY_COMMAND, seqno, &[])
}

fn build_mrp_command_frame(seqno: u64, command: MrpCommand) -> Result<Vec<u8>, DataStreamError> {
    let protobuf = mrp::encode_send_command(command);
    let mut params = plist::Dictionary::new();
    params.insert("data".into(), plist::Value::Data(protobuf));
    let mut root = plist::Dictionary::new();
    root.insert("params".into(), plist::Value::Dictionary(params));
    let mut payload = Vec::new();
    plist::to_writer_binary(&mut payload, &plist::Value::Dictionary(root))
        .map_err(|_| DataStreamError::OutboundPlist)?;
    if payload.len() > MAX_PLIST_PAYLOAD {
        return Err(DataStreamError::FrameTooLarge);
    }
    Ok(build_frame(&COMMAND_TYPE, &COMMAND_NAME, seqno, &payload))
}

fn build_frame(message_type: &[u8], command: &[u8], seqno: u64, payload: &[u8]) -> Vec<u8> {
    let total_size = DATA_HEADER_LEN
        .checked_add(payload.len())
        .expect("bounded in-memory frame size");
    assert!(total_size <= u32::MAX as usize);
    let mut frame = vec![0u8; DATA_HEADER_LEN];
    frame[0..4].copy_from_slice(&(total_size as u32).to_be_bytes());
    let message_len = message_type.len().min(12);
    frame[4..4 + message_len].copy_from_slice(&message_type[..message_len]);
    let command_len = command.len().min(4);
    frame[16..16 + command_len].copy_from_slice(&command[..command_len]);
    frame[20..28].copy_from_slice(&seqno.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[derive(Debug, Eq, PartialEq)]
struct PlistShape {
    has_params: bool,
    has_data: bool,
    data_len: Option<usize>,
}

fn inspect_plist_shape(payload: &[u8]) -> Result<PlistShape, DataStreamError> {
    if payload.is_empty() {
        return Ok(PlistShape {
            has_params: false,
            has_data: false,
            data_len: None,
        });
    }
    if payload.len() > MAX_PLIST_PAYLOAD {
        return Err(DataStreamError::FrameTooLarge);
    }
    let dict = plist::from_bytes::<plist::Dictionary>(payload)
        .map_err(|_| DataStreamError::InvalidPlist)?;
    let params = dict.get("params").and_then(plist::Value::as_dictionary);
    let nested_data = params
        .and_then(|value| value.get("data"))
        .and_then(plist::Value::as_data);
    let direct_data = dict.get("data").and_then(plist::Value::as_data);
    let data = nested_data.or(direct_data);
    Ok(PlistShape {
        has_params: dict.contains_key("params"),
        has_data: dict.contains_key("data") || nested_data.is_some(),
        data_len: data.map(<[u8]>::len),
    })
}

/// Bound encrypted data-stream listener.
pub struct DataStreamListener {
    parent: JoinHandle<()>,
    port: u16,
}

impl DataStreamListener {
    pub fn bind(
        bind_addr: SocketAddr,
        shared_secret: Arc<Zeroizing<Vec<u8>>>,
        seed: u64,
        timeout_duration: Duration,
    ) -> std::io::Result<(u16, Self)> {
        Self::bind_inner(bind_addr, shared_secret, seed, timeout_duration, None)
    }

    /// Bind a type-130 transport that can also emit MediaRemote playback
    /// commands from [`AppState`]. The command subscription is created only
    /// after a peer connects, so callers never report source-control success
    /// merely because a listener is idle.
    pub fn bind_with_state(
        bind_addr: SocketAddr,
        shared_secret: Arc<Zeroizing<Vec<u8>>>,
        seed: u64,
        timeout_duration: Duration,
        state: AppState,
    ) -> std::io::Result<(u16, Self)> {
        Self::bind_inner(
            bind_addr,
            shared_secret,
            seed,
            timeout_duration,
            Some(state),
        )
    }

    fn bind_inner(
        bind_addr: SocketAddr,
        shared_secret: Arc<Zeroizing<Vec<u8>>>,
        seed: u64,
        timeout_duration: Duration,
        command_state: Option<AppState>,
    ) -> std::io::Result<(u16, Self)> {
        if shared_secret.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data-stream pairing secret is empty",
            ));
        }
        if timeout_duration.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data-stream timeout is zero",
            ));
        }

        let cipher = Arc::new(Mutex::new(PairCipher::data_for_server(
            shared_secret.as_slice(),
            seed,
        )));
        drop(shared_secret);

        let listener = std::net::TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let listener = TcpListener::from_std(listener)?;
        let parent = tokio::spawn(run_listener(
            listener,
            cipher,
            timeout_duration,
            command_state,
        ));
        Ok((port, Self { parent, port }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn abort(&self) {
        self.parent.abort();
    }
}

impl Drop for DataStreamListener {
    fn drop(&mut self) {
        self.parent.abort();
    }
}

#[derive(Default)]
struct WorkerGuard(Option<JoinHandle<()>>);

impl WorkerGuard {
    async fn terminate_current(&mut self) {
        if let Some(worker) = self.0.take() {
            worker.abort();
            let _ = worker.await;
        }
    }

    fn install(&mut self, worker: JoinHandle<()>) {
        assert!(
            self.0.is_none(),
            "data worker installed before prior worker terminated"
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

async fn run_listener(
    listener: TcpListener,
    cipher: SharedDataCipher,
    timeout_duration: Duration,
    command_state: Option<AppState>,
) {
    let mut worker = WorkerGuard::default();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                warn!(%error, "AP2 data listener stopped");
                break;
            }
        };
        worker.terminate_current().await;
        let cipher = Arc::clone(&cipher);
        let command_state = command_state.clone();
        let next = tokio::spawn(async move {
            if let Err(error) = data_worker(stream, cipher, timeout_duration, command_state).await {
                warn!(%peer, %error, "AP2 data worker closed");
            }
        });
        worker.install(next);
        info!(%peer, "AP2 data connection installed");
    }
}

async fn read_with_deadline(
    reader: &mut OwnedReadHalf,
    read_buf: &mut [u8],
    partial_deadline: Option<Instant>,
    timeout_duration: Duration,
) -> Result<usize, DataStreamError> {
    match partial_deadline {
        Some(deadline) => timeout_at(deadline, reader.read(read_buf))
            .await
            .map_err(|_| DataStreamError::Timeout)?
            .map_err(DataStreamError::Io),
        None => timeout(timeout_duration, reader.read(read_buf))
            .await
            .map_err(|_| DataStreamError::Timeout)?
            .map_err(DataStreamError::Io),
    }
}

async fn send_encrypted_frame(
    writer: &mut OwnedWriteHalf,
    cipher: &SharedDataCipher,
    frame: &[u8],
    timeout_duration: Duration,
) -> Result<(), DataStreamError> {
    let mut cipher = cipher.lock().await;
    let prepared = cipher.prepare_encryption(frame)?;
    timeout(timeout_duration, writer.write_all(prepared.ciphertext()))
        .await
        .map_err(|_| DataStreamError::Timeout)??;
    prepared.commit();
    Ok(())
}

async fn data_worker(
    stream: TcpStream,
    cipher: SharedDataCipher,
    timeout_duration: Duration,
    command_state: Option<AppState>,
) -> Result<(), DataStreamError> {
    let (mut reader, mut writer) = stream.into_split();
    let mut command_rx = command_state.as_ref().map(AppState::subscribe_mrp_commands);
    let mut command_seqno = 0x1_0000_0000u64 | u64::from(rand::random::<u32>());
    let mut encrypted_pending = Vec::new();
    let mut plaintext_pending = Vec::new();
    let mut read_buf = [0u8; 8192];
    let mut partial_deadline: Option<Instant> = None;

    loop {
        let action = if let Some(rx) = command_rx.as_mut() {
            tokio::select! {
                read = read_with_deadline(
                    &mut reader,
                    &mut read_buf,
                    partial_deadline,
                    timeout_duration,
                ) => WorkerAction::Read(read?),
                command = rx.recv() => match command {
                    Ok(command) => WorkerAction::Command(command),
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "AP2 MediaRemote command queue lagged");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        command_rx = None;
                        continue;
                    }
                },
            }
        } else {
            WorkerAction::Read(
                read_with_deadline(
                    &mut reader,
                    &mut read_buf,
                    partial_deadline,
                    timeout_duration,
                )
                .await?,
            )
        };

        match action {
            WorkerAction::Command(command) => {
                let frame = build_mrp_command_frame(command_seqno, command)?;
                send_encrypted_frame(&mut writer, &cipher, &frame, timeout_duration).await?;
                debug!(
                    seqno = command_seqno,
                    command = ?command,
                    "AP2 MediaRemote command sent"
                );
                command_seqno = command_seqno.wrapping_add(1);
                continue;
            }
            WorkerAction::Read(read) => {
                if read == 0 {
                    if encrypted_pending.is_empty() && plaintext_pending.is_empty() {
                        return Ok(());
                    }
                    return Err(DataStreamError::UnexpectedEof);
                }
                if partial_deadline.is_none() {
                    partial_deadline = Some(Instant::now() + timeout_duration);
                }
                checked_append_encrypted(&mut encrypted_pending, &read_buf[..read])?;

                let (plaintext, consumed) = {
                    let mut cipher = cipher.lock().await;
                    cipher.decrypt_blocks(&encrypted_pending)?
                };
                if consumed > 0 {
                    encrypted_pending.drain(..consumed);
                    checked_append_plaintext(&mut plaintext_pending, &plaintext)?;
                }

                process_complete_frames(
                    &mut writer,
                    &cipher,
                    &mut plaintext_pending,
                    timeout_duration,
                )
                .await?;

                if encrypted_pending.is_empty() && plaintext_pending.is_empty() {
                    partial_deadline = None;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum WorkerAction {
    Read(usize),
    Command(MrpCommand),
}

fn checked_append_encrypted(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DataStreamError> {
    let new_len = target
        .len()
        .checked_add(bytes.len())
        .ok_or(DataStreamError::EncryptedPendingTooLarge)?;
    if new_len > MAX_ENCRYPTED_PENDING {
        return Err(DataStreamError::EncryptedPendingTooLarge);
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn checked_append_plaintext(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DataStreamError> {
    let new_len = target
        .len()
        .checked_add(bytes.len())
        .ok_or(DataStreamError::PlaintextPendingTooLarge)?;
    if new_len > MAX_PLAINTEXT_PENDING {
        return Err(DataStreamError::PlaintextPendingTooLarge);
    }
    target.extend_from_slice(bytes);
    Ok(())
}

async fn process_complete_frames(
    writer: &mut OwnedWriteHalf,
    cipher: &SharedDataCipher,
    plaintext_pending: &mut Vec<u8>,
    timeout_duration: Duration,
) -> Result<(), DataStreamError> {
    loop {
        let Some(header) = DataHeader::parse(plaintext_pending)? else {
            return Ok(());
        };
        let total_size = header.total_size as usize;
        if plaintext_pending.len() < total_size {
            return Ok(());
        }
        let frame: Vec<u8> = plaintext_pending.drain(..total_size).collect();
        let payload = &frame[DATA_HEADER_LEN..];
        let shape = inspect_plist_shape(payload)?;
        debug!(
            seqno = header.seqno,
            is_sync = header.is_sync(),
            total_size,
            payload_len = payload.len(),
            has_params = shape.has_params,
            has_data = shape.has_data,
            data_len = shape.data_len,
            "AP2 data frame received"
        );

        if header.is_sync() {
            let reply = build_sync_reply(header.seqno);
            send_encrypted_frame(writer, cipher, &reply, timeout_duration).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tokio::time::sleep;

    const SEED: u64 = 123_456_789;

    fn test_secret() -> Arc<Zeroizing<Vec<u8>>> {
        Arc::new(Zeroizing::new(vec![0x5au8; 32]))
    }

    fn test_plist(data: &[u8]) -> Vec<u8> {
        let mut params = plist::Dictionary::new();
        params.insert("data".to_string(), plist::Value::Data(data.to_vec()));
        let mut dict = plist::Dictionary::new();
        dict.insert("params".to_string(), plist::Value::Dictionary(params));
        let mut payload = Vec::new();
        plist::to_writer_binary(&mut payload, &plist::Value::Dictionary(dict)).unwrap();
        payload
    }

    fn test_frame(message_type: &[u8], seqno: u64, payload: &[u8]) -> Vec<u8> {
        build_frame(message_type, b"comm", seqno, payload)
    }

    async fn bind_listener(timeout_duration: Duration) -> (u16, DataStreamListener) {
        DataStreamListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            test_secret(),
            SEED,
            timeout_duration,
        )
        .unwrap()
    }

    async fn send_encrypted(stream: &mut TcpStream, cipher: &mut PairCipher, plaintext: &[u8]) {
        let encrypted = cipher.encrypt_blocks(plaintext).unwrap();
        stream.write_all(&encrypted).await.unwrap();
    }

    async fn send_encrypted_bytewise(
        stream: &mut TcpStream,
        cipher: &mut PairCipher,
        plaintext: &[u8],
    ) {
        let encrypted = cipher.encrypt_blocks(plaintext).unwrap();
        for byte in encrypted {
            stream.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    async fn read_encrypted_frame(stream: &mut TcpStream, cipher: &mut PairCipher) -> Vec<u8> {
        let mut encrypted = Vec::new();
        let mut plaintext = Vec::new();
        let mut buf = [0u8; 128];
        timeout(Duration::from_secs(2), async {
            loop {
                if let Some(header) = DataHeader::parse(&plaintext).unwrap() {
                    let total = header.total_size as usize;
                    if plaintext.len() >= total {
                        return plaintext.drain(..total).collect();
                    }
                }
                let read = stream.read(&mut buf).await.unwrap();
                assert!(read > 0, "socket closed before encrypted reply completed");
                encrypted.extend_from_slice(&buf[..read]);
                let (plain, consumed) = cipher.decrypt_blocks(&encrypted).unwrap();
                if consumed > 0 {
                    encrypted.drain(..consumed);
                    plaintext.extend_from_slice(&plain);
                }
            }
        })
        .await
        .expect("encrypted reply timed out")
    }

    async fn assert_socket_closed(stream: &mut TcpStream) {
        let mut byte = [0u8; 1];
        match timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("socket did not close")
        {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) => {}
            other => panic!("expected closed socket, got {other:?}"),
        }
    }

    #[test]
    fn header_is_big_endian_and_canonicalizes_fields() {
        let frame = test_frame(b"syncXYZ", 0x0102_0304_0506_0708, &[]);
        let header = DataHeader::parse(&frame).unwrap().unwrap();
        assert_eq!(header.total_size, 32);
        assert_eq!(header.message_type(), b"syncXYZ");
        assert_eq!(header.command(), b"comm");
        assert_eq!(header.seqno, 0x0102_0304_0506_0708);
        assert!(header.is_sync());
        assert_eq!(&frame[0..4], &32u32.to_be_bytes());
        assert_eq!(&frame[20..28], &0x0102_0304_0506_0708u64.to_be_bytes());
    }

    #[test]
    fn fragmented_header_returns_none_at_every_boundary() {
        let frame = test_frame(b"sync", 7, &[]);
        for split in 0..DATA_HEADER_LEN {
            assert!(DataHeader::parse(&frame[..split]).unwrap().is_none());
        }
        assert!(DataHeader::parse(&frame).unwrap().is_some());
    }

    #[test]
    fn parser_rejects_small_large_and_nonzero_padding() {
        let mut small = test_frame(b"sync", 1, &[]);
        small[0..4].copy_from_slice(&31u32.to_be_bytes());
        assert!(matches!(
            DataHeader::parse(&small),
            Err(DataStreamError::FrameTooSmall)
        ));

        let mut large = test_frame(b"sync", 1, &[]);
        large[0..4].copy_from_slice(&((MAX_FRAME_SIZE + 1) as u32).to_be_bytes());
        assert!(matches!(
            DataHeader::parse(&large),
            Err(DataStreamError::FrameTooLarge)
        ));

        let mut padding = test_frame(b"sync", 1, &[]);
        padding[31] = 1;
        assert!(matches!(
            DataHeader::parse(&padding),
            Err(DataStreamError::InvalidPadding)
        ));
    }

    #[test]
    fn sync_reply_has_exact_header_and_seqno() {
        let reply = build_sync_reply(0xfedc_ba98_7654_3210);
        assert_eq!(reply.len(), DATA_HEADER_LEN);
        assert_eq!(&reply[0..4], &32u32.to_be_bytes());
        assert_eq!(&reply[4..16], &REPLY_TYPE);
        assert_eq!(&reply[16..20], &[0u8; 4]);
        assert_eq!(
            u64::from_be_bytes(reply[20..28].try_into().unwrap()),
            0xfedc_ba98_7654_3210
        );
        assert_eq!(&reply[28..32], &[0u8; 4]);
    }

    #[test]
    fn plist_shape_accepts_nested_and_direct_data() {
        let nested = inspect_plist_shape(&test_plist(b"abc")).unwrap();
        assert_eq!(
            nested,
            PlistShape {
                has_params: true,
                has_data: true,
                data_len: Some(3)
            }
        );

        let mut dict = plist::Dictionary::new();
        dict.insert("data".to_string(), plist::Value::Data(vec![1, 2]));
        let mut payload = Vec::new();
        plist::to_writer_binary(&mut payload, &plist::Value::Dictionary(dict)).unwrap();
        let direct = inspect_plist_shape(&payload).unwrap();
        assert_eq!(direct.data_len, Some(2));
        assert!(direct.has_data);
    }

    #[test]
    fn plist_shape_accepts_empty_and_rejects_malformed() {
        assert_eq!(
            inspect_plist_shape(&[]).unwrap(),
            PlistShape {
                has_params: false,
                has_data: false,
                data_len: None
            }
        );
        assert!(matches!(
            inspect_plist_shape(b"not a plist"),
            Err(DataStreamError::InvalidPlist)
        ));
    }

    #[test]
    fn checked_append_enforces_bounds_before_growth() {
        let mut encrypted = vec![0u8; MAX_ENCRYPTED_PENDING];
        assert!(matches!(
            checked_append_encrypted(&mut encrypted, &[1]),
            Err(DataStreamError::EncryptedPendingTooLarge)
        ));
        assert_eq!(encrypted.len(), MAX_ENCRYPTED_PENDING);

        let mut plaintext = vec![0u8; MAX_PLAINTEXT_PENDING];
        assert!(matches!(
            checked_append_plaintext(&mut plaintext, &[1]),
            Err(DataStreamError::PlaintextPendingTooLarge)
        ));
        assert_eq!(plaintext.len(), MAX_PLAINTEXT_PENDING);
    }

    #[tokio::test]
    async fn connected_worker_sends_encrypted_mrp_pause_command() {
        let state = AppState::new(Config::default());
        let (port, listener) = DataStreamListener::bind_with_state(
            "127.0.0.1:0".parse().unwrap(),
            test_secret(),
            SEED,
            Duration::from_secs(2),
            state.clone(),
        )
        .unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut client = PairCipher::data_for_client(test_secret().as_slice(), SEED);

        timeout(Duration::from_secs(1), async {
            while state.mrp_command_receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("type-130 worker never subscribed for MRP commands");

        assert!(state.send_mrp_command(MrpCommand::Pause));
        let frame = read_encrypted_frame(&mut stream, &mut client).await;
        let header = DataHeader::parse(&frame).unwrap().unwrap();
        assert_eq!(header.message_type(), b"sync");
        assert_eq!(header.command(), b"comm");
        assert!(header.seqno >= 0x1_0000_0000);

        let payload = &frame[DATA_HEADER_LEN..];
        let plist = plist::from_bytes::<plist::Dictionary>(payload).unwrap();
        let protobuf = plist
            .get("params")
            .and_then(plist::Value::as_dictionary)
            .and_then(|params| params.get("data"))
            .and_then(plist::Value::as_data)
            .expect("missing params.data protobuf");
        assert_eq!(
            &protobuf[1..9],
            &[0x08, 0x01, 0x20, 0x00, 0x32, 0x02, 0x08, 0x02]
        );
        assert_eq!(protobuf[0] as usize, protobuf.len() - 1);
        listener.abort();
    }

    #[tokio::test]
    async fn encrypted_fragmented_sync_round_trip_keeps_socket_open() {
        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut client = PairCipher::data_for_client(test_secret().as_slice(), SEED);
        let request = test_frame(b"sync", 77, &test_plist(b"payload"));
        send_encrypted_bytewise(&mut stream, &mut client, &request).await;
        let reply = read_encrypted_frame(&mut stream, &mut client).await;
        let header = DataHeader::parse(&reply).unwrap().unwrap();
        assert_eq!(header.message_type(), b"rply");
        assert_eq!(header.seqno, 77);
        let mut byte = [0u8; 1];
        assert!(
            timeout(Duration::from_millis(100), stream.read(&mut byte))
                .await
                .is_err()
        );
        listener.abort();
    }

    #[tokio::test]
    async fn reconnect_continues_both_cipher_counters() {
        let secret = test_secret();
        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let mut client = PairCipher::data_for_client(secret.as_slice(), SEED);

        for seqno in [1, 2] {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            send_encrypted(&mut stream, &mut client, &test_frame(b"sync", seqno, &[])).await;
            let reply = read_encrypted_frame(&mut stream, &mut client).await;
            assert_eq!(DataHeader::parse(&reply).unwrap().unwrap().seqno, seqno);
            drop(stream);
            sleep(Duration::from_millis(20)).await;
        }
        listener.abort();
    }

    #[tokio::test]
    async fn authentication_failure_preserves_counter_for_reconnect() {
        let secret = test_secret();
        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let request = test_frame(b"sync", 9, &[]);
        let mut first_client = PairCipher::data_for_client(secret.as_slice(), SEED);
        let mut bad = first_client.encrypt_blocks(&request).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 0x80;
        let mut bad_stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        bad_stream.write_all(&bad).await.unwrap();
        assert_socket_closed(&mut bad_stream).await;

        let mut retry_client = PairCipher::data_for_client(secret.as_slice(), SEED);
        let mut retry_stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        send_encrypted(&mut retry_stream, &mut retry_client, &request).await;
        let reply = read_encrypted_frame(&mut retry_stream, &mut retry_client).await;
        assert_eq!(DataHeader::parse(&reply).unwrap().unwrap().seqno, 9);
        listener.abort();
    }

    #[tokio::test]
    async fn replacement_closes_previous_socket_before_new_worker_runs() {
        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_socket_closed(&mut first).await;

        let mut client = PairCipher::data_for_client(test_secret().as_slice(), SEED);
        send_encrypted(&mut second, &mut client, &test_frame(b"sync", 4, &[])).await;
        let reply = read_encrypted_frame(&mut second, &mut client).await;
        assert_eq!(DataHeader::parse(&reply).unwrap().unwrap().seqno, 4);
        listener.abort();
    }

    #[tokio::test]
    async fn abort_and_drop_close_active_worker() {
        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        listener.abort();
        assert_socket_closed(&mut stream).await;

        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        drop(listener);
        assert_socket_closed(&mut stream).await;
    }

    #[tokio::test]
    async fn partial_encrypted_frame_has_fixed_deadline() {
        let (port, listener) = bind_listener(Duration::from_millis(100)).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut client = PairCipher::data_for_client(test_secret().as_slice(), SEED);
        let encrypted = client.encrypt_blocks(&test_frame(b"sync", 1, &[])).unwrap();
        stream.write_all(&encrypted[..1]).await.unwrap();
        sleep(Duration::from_millis(60)).await;
        stream.write_all(&encrypted[1..2]).await.unwrap();
        assert_socket_closed(&mut stream).await;
        listener.abort();
    }

    #[tokio::test]
    async fn non_sync_message_gets_no_reply() {
        let (port, listener) = bind_listener(Duration::from_secs(1)).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut client = PairCipher::data_for_client(test_secret().as_slice(), SEED);
        send_encrypted(
            &mut stream,
            &mut client,
            &test_frame(b"comm", 3, &test_plist(b"x")),
        )
        .await;
        let mut byte = [0u8; 1];
        assert!(
            timeout(Duration::from_millis(100), stream.read(&mut byte))
                .await
                .is_err()
        );
        listener.abort();
    }

    #[tokio::test]
    async fn malformed_plist_and_invalid_header_close_worker() {
        let secret = test_secret();
        let (port, listener) = bind_listener(Duration::from_secs(2)).await;
        let mut client = PairCipher::data_for_client(secret.as_slice(), SEED);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        send_encrypted(
            &mut stream,
            &mut client,
            &test_frame(b"comm", 1, b"invalid"),
        )
        .await;
        assert_socket_closed(&mut stream).await;

        let mut retry = PairCipher::data_for_client(secret.as_slice(), SEED);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut invalid = test_frame(b"comm", 2, &[]);
        invalid[0..4].copy_from_slice(&16u32.to_be_bytes());
        send_encrypted(&mut stream, &mut retry, &invalid).await;
        assert_socket_closed(&mut stream).await;
        listener.abort();
    }

    #[tokio::test]
    async fn bind_rejects_empty_secret_and_zero_timeout() {
        let bind = "127.0.0.1:0".parse().unwrap();
        assert!(
            DataStreamListener::bind(
                bind,
                Arc::new(Zeroizing::new(Vec::new())),
                SEED,
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(DataStreamListener::bind(bind, test_secret(), SEED, Duration::ZERO).is_err());
    }

    #[test]
    fn error_messages_do_not_contain_payload_data() {
        for error in [
            DataStreamError::Timeout,
            DataStreamError::UnexpectedEof,
            DataStreamError::FrameTooSmall,
            DataStreamError::FrameTooLarge,
            DataStreamError::InvalidPadding,
            DataStreamError::EncryptedPendingTooLarge,
            DataStreamError::PlaintextPendingTooLarge,
            DataStreamError::InvalidPlist,
        ] {
            let message = error.to_string();
            assert!(!message.contains("0x"));
            assert!(message.len() < 160);
        }
    }
}
