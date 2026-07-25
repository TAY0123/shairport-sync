use std::fmt;

/// Per-RTSP-session crypto state for classic (AP1 / RAOP) AirPlay.
///
/// This is populated from the SDP ANNOUNCE fields `a=rsaaeskey` (RSA-encrypted
/// AES-128 key) and `a=aesiv` (AES initialisation vector).  The structures are
/// held in [`crate::state::AppState`] so the RTP audio-receive task can pick
/// them up once the RTSP handshake completes.
///
/// **Security note:** This struct deliberately omits `Serialize` and
/// `Deserialize`, and implements `Debug` with key-material redaction,
/// to prevent accidental logging or serialisation of in-memory key material.
#[derive(Clone, PartialEq)]
pub struct SessionCrypto {
    /// AES-128 key — 16 bytes decrypted from `rsaaeskey`.
    pub aes_key: [u8; 16],
    /// AES-CBC initialisation vector — 16 bytes from `aesiv`.
    pub aes_iv: [u8; 16],
}

impl fmt::Debug for SessionCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCrypto")
            .field("aes_key", &"[redacted;16]")
            .field("aes_iv", &"[redacted;16]")
            .finish()
    }
}

impl SessionCrypto {
    /// Create a new session crypto state from raw slices.
    /// Returns `None` if either slice is not exactly 16 bytes.
    pub fn new(aes_key: &[u8], aes_iv: &[u8]) -> Option<Self> {
        if aes_key.len() != 16 || aes_iv.len() != 16 {
            return None;
        }
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        key.copy_from_slice(aes_key);
        iv.copy_from_slice(aes_iv);
        Some(Self {
            aes_key: key,
            aes_iv: iv,
        })
    }
}
