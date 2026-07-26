use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// DerivedKey — 32-byte HKDF output with zeroize-on-drop and no Clone/Debug
// ---------------------------------------------------------------------------

/// A 32-byte derived key from HKDF-SHA-512.
///
/// Intentionally **not** [`Clone`], [`Debug`], [`PartialEq`], [`Eq`],
/// [`Serialize`](serde::Serialize), or [`Deserialize`](serde::Deserialize)
/// to avoid accidental copying or logging of secret material.
/// On [`Drop`] the inner bytes are zeroed.
pub struct DerivedKey(pub [u8; 32]);

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for DerivedKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// ---------------------------------------------------------------------------
// PairCipher — ChaCha20-Poly1305 AEAD with per-direction counters
// ---------------------------------------------------------------------------

/// Maximum plaintext size per encrypted block.
pub const MAX_BLOCK: usize = 1024;

/// Framing constants.
const LENGTH_PREFIX_LEN: usize = 2;
const TAG_LEN: usize = 16; // Poly1305 authentication tag

/// Error returned when encrypting or decrypting a block fails.
#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("encrypted block length exceeds MAX_BLOCK ({max})", max = MAX_BLOCK)]
    BlockTooLarge,
    #[error("authentication failed")]
    AuthFailed,
    #[error("encryption counter exhausted — nonce reuse prevented")]
    CounterExhausted,
    #[error("encryption failed")]
    EncryptionFailed,
}

/// ChaCha20-Poly1305 cipher with per-direction counters.
///
/// Intentionally **not** [`Clone`] or [`Debug`] to avoid copying or
/// logging secret key material.  On [`Drop`] all internal key bytes and
/// counters are zeroed.
///
/// # Counter behaviour
///
/// Counters use checked arithmetic.  An encryption that would exceed
/// [`u64::MAX`] returns [`CipherError::CounterExhausted`] **before** any
/// nonce is reused.  Decryption does not advance the counter on
/// authentication failure.
///
/// # Framing
///
/// `encrypt_blocks` pre-flights every block before writing any output,
/// so failure is transactional — the caller keeps the plaintext and no
/// ciphertext is emitted.  `decrypt_blocks` rejects length-prefix values
/// larger than [`MAX_BLOCK`] immediately without advancing the counter.
pub struct PairCipher {
    encryption_key: DerivedKey,
    decryption_key: DerivedKey,
    encryption_counter: u64,
    decryption_counter: u64,
}

impl Drop for PairCipher {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.decryption_key.zeroize();
        self.encryption_counter.zeroize();
        self.decryption_counter.zeroize();
    }
}

impl PairCipher {
    // ── Named constructors ───────────────────────────────────────────

    /// Control-direction cipher (server perspective).
    pub fn control_for_server(shared_secret: &[u8]) -> Self {
        Self::new(
            shared_secret,
            b"Control-Salt",
            b"Control-Read-Encryption-Key",
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
        )
    }

    /// Client-direction control cipher (for test round-trips).
    #[cfg(test)]
    pub fn control_for_client(shared_secret: &[u8]) -> Self {
        Self::new(
            shared_secret,
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
            b"Control-Salt",
            b"Control-Read-Encryption-Key",
        )
    }

    pub fn events_for_server(shared_secret: &[u8]) -> Self {
        Self::new(
            shared_secret,
            b"Events-Salt",
            b"Events-Write-Encryption-Key",
            b"Events-Salt",
            b"Events-Read-Encryption-Key",
        )
    }

    #[allow(dead_code)]
    pub fn data_for_server(shared_secret: &[u8], seed: &str) -> Self {
        let write_salt = format!("DataStream-Salt{seed}");
        let read_salt = format!("DataStream-Salt{seed}");
        Self::new(
            shared_secret,
            write_salt.as_bytes(),
            b"DataStream-Input-Encryption-Key",
            read_salt.as_bytes(),
            b"DataStream-Output-Encryption-Key",
        )
    }

    // ── Internal constructor ─────────────────────────────────────────

    fn new(
        shared_secret: &[u8],
        write_salt: &[u8],
        write_info: &[u8],
        read_salt: &[u8],
        read_info: &[u8],
    ) -> Self {
        Self {
            encryption_key: hkdf_sha512(shared_secret, write_salt, write_info),
            decryption_key: hkdf_sha512(shared_secret, read_salt, read_info),
            encryption_counter: 0,
            decryption_counter: 0,
        }
    }

    // ── Encryption ───────────────────────────────────────────────────

    /// Encrypt `plaintext` as one or more ChaCha20-Poly1305 framed blocks.
    ///
    /// Each block is output as `[2-byte length LE][ciphertext][16-byte tag]`.
    /// The function **pre-flights** every block before writing any output:
    /// if any block would fail the entire operation is rejected without
    /// emitting partial ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`CipherError::BlockTooLarge`] if any block exceeds
    /// [`MAX_BLOCK`], or [`CipherError::CounterExhausted`] if advancing a
    /// counter would overflow `u64`.
    pub fn encrypt_blocks(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let num_blocks = if plaintext.is_empty() {
            1
        } else {
            plaintext.len().div_ceil(MAX_BLOCK)
        };
        let blocks = u64::try_from(num_blocks).map_err(|_| CipherError::CounterExhausted)?;
        let final_counter = self
            .encryption_counter
            .checked_add(blocks)
            .ok_or(CipherError::CounterExhausted)?;

        // Build all ciphertext with a local counter. The object counter is
        // committed only after every block has encrypted successfully.
        let mut counter = self.encryption_counter;
        let mut out =
            Vec::with_capacity(plaintext.len() + num_blocks * (LENGTH_PREFIX_LEN + TAG_LEN));
        let cipher = ChaCha20Poly1305::new((&self.encryption_key.0).into());

        if plaintext.is_empty() {
            let block_len_bytes = 0u16.to_le_bytes();
            let nonce = counter_nonce(counter);
            let encrypted = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &[],
                        aad: &block_len_bytes,
                    },
                )
                .map_err(|_| CipherError::EncryptionFailed)?;
            out.extend_from_slice(&block_len_bytes);
            out.extend_from_slice(&encrypted);
        } else {
            for block in plaintext.chunks(MAX_BLOCK) {
                let block_len_bytes = (block.len() as u16).to_le_bytes();
                let nonce = counter_nonce(counter);
                let encrypted = cipher
                    .encrypt(
                        (&nonce).into(),
                        Payload {
                            msg: block,
                            aad: &block_len_bytes,
                        },
                    )
                    .map_err(|_| CipherError::EncryptionFailed)?;
                out.extend_from_slice(&block_len_bytes);
                out.extend_from_slice(&encrypted);
                counter = counter
                    .checked_add(1)
                    .ok_or(CipherError::CounterExhausted)?;
            }
        }

        self.encryption_counter = final_counter;
        Ok(out)
    }

    // ── Decryption ───────────────────────────────────────────────────

    /// Decrypt one or more framed blocks from `ciphertext`.
    ///
    /// Returns `(plaintext, consumed)` where `consumed` is the number of
    /// input bytes consumed (may be zero if an incomplete frame is
    /// present).  Processes as many complete blocks as available in the
    /// input.
    ///
    /// # Rejection rules
    ///
    /// * Length-prefix > [`MAX_BLOCK`] → rejected immediately (counter not
    ///   advanced, no bytes consumed).
    /// * Incomplete frame (not enough bytes for prefix+payload+tag) →
    ///   returns what was consumed so far (possibly zero).
    /// * Authentication failure → returns `Err(CipherError::AuthFailed)`
    ///   without advancing the decryption counter beyond the last good block.
    /// * Counter exhausted → returns `Err(CipherError::CounterExhausted)`.
    pub fn decrypt_blocks(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, usize), CipherError> {
        let mut consumed = 0;
        let mut out = Vec::new();
        let mut counter = self.decryption_counter;
        let cipher = ChaCha20Poly1305::new((&self.decryption_key.0).into());

        loop {
            let remaining = ciphertext.len().saturating_sub(consumed);
            if remaining < LENGTH_PREFIX_LEN {
                break;
            }

            let block_len =
                u16::from_le_bytes([ciphertext[consumed], ciphertext[consumed + 1]]) as usize;
            if block_len > MAX_BLOCK {
                return Err(CipherError::BlockTooLarge);
            }

            let block_total = LENGTH_PREFIX_LEN + block_len + TAG_LEN;
            if remaining < block_total {
                break;
            }

            let next_counter = counter
                .checked_add(1)
                .ok_or(CipherError::CounterExhausted)?;
            let block_len_bytes = [ciphertext[consumed], ciphertext[consumed + 1]];
            let payload_start = consumed + LENGTH_PREFIX_LEN;
            let payload = &ciphertext[payload_start..consumed + block_total];
            let nonce = counter_nonce(counter);
            let decrypted = cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: payload,
                        aad: &block_len_bytes,
                    },
                )
                .map_err(|_| CipherError::AuthFailed)?;

            out.extend_from_slice(&decrypted);
            consumed += block_total;
            counter = next_counter;
        }

        // Commit only the counters corresponding to bytes returned as
        // consumed. Any error above leaves the object counter unchanged.
        self.decryption_counter = counter;
        Ok((out, consumed))
    }
}

// ---------------------------------------------------------------------------
// IdentityKey & AgreementKey
// ---------------------------------------------------------------------------

pub struct IdentityKey {
    signing: SigningKey,
}

pub struct AgreementKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl IdentityKey {
    #[allow(dead_code)]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing }
    }

    pub fn for_device_id(device_id: &str) -> Self {
        let mut seed = [0u8; 32];
        let id = device_id.as_bytes();
        let len = id.len().min(seed.len());
        seed[..len].copy_from_slice(&id[..len]);
        let key = Self::from_seed(seed);
        seed.zeroize();
        key
    }

    /// Load identity key from a file, or generate and save if not present.
    pub fn load_or_generate(path: Option<&std::path::Path>, device_id: &str) -> Self {
        if let Some(path) = path {
            if let Ok(data) = std::fs::read(path)
                && data.len() == 32
            {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&data);
                let key = Self::from_seed(seed);
                seed.zeroize();
                return key;
            }
            // Generate and persist
            let key = Self::generate();
            let seed = Zeroizing::new(key.signing.to_bytes());
            if let Err(e) = std::fs::write(path, seed.as_slice()) {
                tracing::warn!(%e, "failed to persist identity key");
            }
            return key;
        }
        // Match the advertised TXT `pk` when no persistent identity file is configured.
        Self::for_device_id(device_id)
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let signature = Signature::from_bytes(signature);
        key.verify(message, &signature).is_ok()
    }
}

pub fn nonce_from_label(label: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let len = label.len().min(8);
    nonce[4..4 + len].copy_from_slice(&label[..len]);
    nonce
}

pub fn accessory_public_key_for_device_id(device_id: &str) -> [u8; 32] {
    IdentityKey::for_device_id(device_id).verifying_key()
}

impl AgreementKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn shared_secret(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&PublicKey::from(*peer_public))
            .to_bytes()
    }
}

// ---------------------------------------------------------------------------
// HKDF & AEAD helpers (internal use only — PairCipher is the public API)
// ---------------------------------------------------------------------------

pub(crate) fn hkdf_sha512(secret: &[u8], salt: &[u8], info: &[u8]) -> DerivedKey {
    let hk = Hkdf::<Sha512>::new(Some(salt), secret);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32-byte HKDF output is valid");
    DerivedKey(out)
}

#[allow(dead_code)]
pub(crate) fn seal(
    key: &DerivedKey,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new((&key.0).into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("chacha20-poly1305 encryption failed"))
}

#[allow(dead_code)]
pub(crate) fn open(
    key: &DerivedKey,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new((&key.0).into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("chacha20-poly1305 decryption failed"))
}

// ---------------------------------------------------------------------------
// Counter → nonce
// ---------------------------------------------------------------------------

fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_signatures_verify() {
        let key = IdentityKey::generate();
        let public = key.verifying_key();
        let signature = key.sign(b"message");
        assert!(IdentityKey::verify(&public, b"message", &signature));
        assert!(!IdentityKey::verify(&public, b"other", &signature));
    }

    #[test]
    fn device_id_identity_matches_advertised_public_key() {
        let device_id = "00:11:22:33:44:55";
        assert_eq!(
            IdentityKey::load_or_generate(None, device_id).verifying_key(),
            accessory_public_key_for_device_id(device_id)
        );
    }

    #[test]
    fn x25519_shared_secret_matches() {
        let a = AgreementKey::generate();
        let b = AgreementKey::generate();
        assert_eq!(
            a.shared_secret(&b.public_key()),
            b.shared_secret(&a.public_key())
        );
    }

    #[test]
    fn chacha_round_trip() {
        let key = hkdf_sha512(b"secret", b"salt", b"info");
        let nonce = *b"123456789012";
        let ciphertext = seal(&key, &nonce, b"aad", b"plain").unwrap();
        let plaintext = open(&key, &nonce, b"aad", &ciphertext).unwrap();
        assert_eq!(plaintext, b"plain");
    }

    // ── PairCipher framing tests ─────────────────────────────────────

    fn test_cipher_pair() -> (PairCipher, PairCipher) {
        let shared = [0xabu8; 32];
        let server = PairCipher::control_for_server(&shared);
        let client = PairCipher::control_for_client(&shared);
        (server, client)
    }

    #[test]
    fn pair_cipher_round_trips_single_block() {
        let (mut writer, mut reader) = test_cipher_pair();
        let plaintext = b"hello encrypted rtsp";
        let encrypted = writer.encrypt_blocks(plaintext).unwrap();
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pair_cipher_round_trips_multi_block() {
        let (mut writer, mut reader) = test_cipher_pair();
        let plaintext: Vec<u8> = (0..2500).map(|i| (i % 256) as u8).collect();
        let encrypted = writer.encrypt_blocks(&plaintext).unwrap();
        // 2500 bytes → 3 blocks (1024 + 1024 + 452)
        assert_eq!(
            encrypted.len(),
            2 + 1024 + 16 + 2 + 1024 + 16 + 2 + 452 + 16
        );
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pair_cipher_round_trips_empty_plaintext() {
        let (mut writer, mut reader) = test_cipher_pair();
        let encrypted = writer.encrypt_blocks(b"").unwrap();
        assert_eq!(encrypted.len(), 2 + 16); // prefix + empty ciphertext + tag
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert!(decrypted.is_empty());
    }

    #[test]
    fn pair_cipher_round_trips_exactly_max_block() {
        let (mut writer, mut reader) = test_cipher_pair();
        let plaintext = vec![0x42u8; MAX_BLOCK];
        let encrypted = writer.encrypt_blocks(&plaintext).unwrap();
        assert_eq!(encrypted.len(), 2 + MAX_BLOCK + 16);
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_oversize_prefix() {
        let (mut _writer, mut reader) = test_cipher_pair();
        // Craft a buffer with a length prefix > MAX_BLOCK
        let mut buf = vec![0x00u8; 2 + 2048 + 16];
        buf[0] = 0x01; // (MAX_BLOCK + 1) as u16 LE = 1025 → 0x01, 0x04
        buf[1] = 0x04;
        let result = reader.decrypt_blocks(&buf);
        assert!(matches!(result, Err(CipherError::BlockTooLarge)));
    }

    #[test]
    fn incomplete_frame_returns_partial_and_consumes_remainder_when_completed() {
        let (mut writer, mut reader) = test_cipher_pair();
        let encrypted = writer.encrypt_blocks(b"hello").unwrap();
        // Feed only part of the encrypted block
        let partial = &encrypted[..encrypted.len() - 5];
        let (decrypted, consumed) = reader.decrypt_blocks(partial).unwrap();
        assert_eq!(consumed, 0); // incomplete — prefix + payload + tag not all present
        assert!(decrypted.is_empty());
        // Now feed the full encrypted block — should consume it fully
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, b"hello");
    }

    #[test]
    fn auth_failure_does_not_advance_counter() {
        let (mut writer, mut reader) = test_cipher_pair();
        let encrypted = writer.encrypt_blocks(b"first").unwrap();
        let (_, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());

        // Tampered block
        let mut tampered = encrypted.clone();
        let tampered_len = tampered.len();
        if tampered_len > 0 {
            tampered[tampered_len - 2] ^= 0xFF; // flip last byte of tag
        }
        let result = reader.decrypt_blocks(&tampered);
        assert!(matches!(result, Err(CipherError::AuthFailed)));

        // Decrypt with original cipher again — reader should still work
        // with a fresh encryption (counter 1 expected from writer since
        // reader didn't advance on auth failure).
        //
        // Wait — the writer advanced to counter 0 for "first".  The
        // reader advanced to 1 after successfully decrypting "first".
        // The auth failure happened with the tampered block at reader
        // counter 1.  Since auth failure doesn't advance, reader is
        // still at 1.  Writer is at 1.  So re-encrypting should work.
        let encrypted2 = writer.encrypt_blocks(b"second").unwrap();
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted2).unwrap();
        assert_eq!(consumed, encrypted2.len());
        assert_eq!(decrypted, b"second");
    }

    #[test]
    fn later_block_auth_failure_rolls_back_entire_decrypt_call() {
        let (mut writer, mut reader) = test_cipher_pair();
        let plaintext = vec![0x5au8; MAX_BLOCK + 8];
        let encrypted = writer.encrypt_blocks(&plaintext).unwrap();
        let first_block_total = LENGTH_PREFIX_LEN + MAX_BLOCK + TAG_LEN;
        let mut tampered = encrypted.clone();
        tampered[first_block_total + LENGTH_PREFIX_LEN] ^= 0x80;

        assert!(matches!(
            reader.decrypt_blocks(&tampered),
            Err(CipherError::AuthFailed)
        ));
        assert_eq!(reader.decryption_counter, 0);

        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn counter_exhaustion_detected_before_nonce_reuse() {
        let (mut writer, _reader) = test_cipher_pair();
        // Set counter near max
        writer.encryption_counter = u64::MAX;
        let result = writer.encrypt_blocks(b"data");
        assert!(matches!(result, Err(CipherError::CounterExhausted)));
        // Counter is still at u64::MAX (no half-advance)
        assert_eq!(writer.encryption_counter, u64::MAX);
    }

    #[test]
    fn empty_plaintext_counter_exhaustion_is_transactional() {
        let (mut writer, _reader) = test_cipher_pair();
        writer.encryption_counter = u64::MAX;
        let result = writer.encrypt_blocks(b"");
        assert!(matches!(result, Err(CipherError::CounterExhausted)));
        assert_eq!(writer.encryption_counter, u64::MAX);
    }

    #[test]
    fn multi_block_encryption_is_transactional() {
        let (mut writer, _reader) = test_cipher_pair();
        // Craft plaintext that's valid in block 1 but fails counter in block 2
        // Force counter near MAX so the second block's check fails.
        // We need a plaintext that spans 2 blocks and counter near overflow.
        // With 1024 bytes in first block, we'd need counter at u64::MAX for
        // the first block to pass, then the overflow check kills the second.
        // Actually: plaintext > 1024 → 2 blocks. Set counter to u64::MAX-1.
        // Block 1: counter u64::MAX-1 passes, block 2: counter u64::MAX passes,
        // then u64::MAX+1 overflows.  Wait, checked_add for block 2 → u64::MAX+1
        // which is None.
        let plaintext = vec![0x7fu8; MAX_BLOCK + 1]; // spans 2 blocks
        writer.encryption_counter = u64::MAX - 1;
        let result = writer.encrypt_blocks(&plaintext);
        assert!(matches!(result, Err(CipherError::CounterExhausted)));
        // Counter not advanced — transactional
        assert_eq!(writer.encryption_counter, u64::MAX - 1);
    }

    #[test]
    fn client_control_cipher_round_trips_with_server() {
        let shared = [0x55u8; 32];
        let mut server = PairCipher::control_for_server(&shared);
        let mut client = PairCipher::control_for_client(&shared);
        // Encryption done by client, decryption by server
        let msg = b"client-to-server encrypted rtsp";
        let encrypted = client.encrypt_blocks(msg).unwrap();
        let (decrypted, consumed) = server.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, msg);
        // And the other direction
        let reply = b"server-to-client encrypted reply";
        let encrypted = server.encrypt_blocks(reply).unwrap();
        let (decrypted, consumed) = client.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        assert_eq!(decrypted, reply);
    }

    #[test]
    fn fragmented_encrypted_header_decodes_at_boundary() {
        let (mut writer, mut reader) = test_cipher_pair();
        let encrypted = writer.encrypt_blocks(b"hello world").unwrap();
        // Feed the encrypted data one byte at a time into an accumulator,
        // then try decrypting.  An incomplete prefix returns 0 consumed.
        let mut acc = Vec::new();
        let mut total_plaintext = Vec::new();
        for &byte in &encrypted {
            acc.push(byte);
            let (plain, consumed) = reader.decrypt_blocks(&acc).unwrap();
            if consumed > 0 {
                acc.drain(..consumed);
                total_plaintext.extend_from_slice(&plain);
            }
        }
        assert_eq!(total_plaintext, b"hello world");
        assert!(acc.is_empty(), "all encrypted bytes should be consumed");
    }

    #[test]
    fn fragmented_header_at_every_boundary_round_trips() {
        let (mut writer, mut reader) = test_cipher_pair();
        let msg = b"fragmented header boundary test";
        let encrypted = writer.encrypt_blocks(msg).unwrap();
        let expected_total = 2 + msg.len() + 16;
        assert_eq!(encrypted.len(), expected_total);
        // Feed one byte at a time into an accumulator
        let mut acc = Vec::new();
        let mut total_plaintext = Vec::new();
        for &byte in &encrypted {
            acc.push(byte);
            let (plain, consumed) = reader.decrypt_blocks(&acc).unwrap();
            if consumed > 0 {
                acc.drain(..consumed);
                total_plaintext.extend_from_slice(&plain);
            }
        }
        assert_eq!(total_plaintext, msg);
        assert!(acc.is_empty());
    }

    #[test]
    fn decrypt_counter_does_not_advance_on_auth_failure_consecutive() {
        let (mut writer, mut reader) = test_cipher_pair();
        let encrypted = writer.encrypt_blocks(b"good").unwrap();
        let (_, consumed) = reader.decrypt_blocks(&encrypted).unwrap();
        assert_eq!(consumed, encrypted.len());
        // reader counter is now 1

        // Tamper and try — auth fails, counter stays at 1
        let mut bad = encrypted.clone();
        bad[3] ^= 1;
        assert!(reader.decrypt_blocks(&bad).is_err());

        // Try good data at counter 1 — should work
        let encrypted2 = writer.encrypt_blocks(b"also good").unwrap();
        let (decrypted, consumed) = reader.decrypt_blocks(&encrypted2).unwrap();
        assert_eq!(consumed, encrypted2.len());
        assert_eq!(decrypted, b"also good");
    }

    #[test]
    fn plaintext_larger_than_max_block_is_accepted_as_multi_block() {
        let (mut writer, _reader) = test_cipher_pair();
        let plaintext = vec![0u8; MAX_BLOCK + 1];
        // Should be accepted — gets split into two blocks
        let result = writer.encrypt_blocks(&plaintext);
        assert!(result.is_ok());
        let encrypted = result.unwrap();
        // 2 blocks: prefix(2) + 1024 + tag(16) + prefix(2) + 1 + tag(16)
        assert_eq!(encrypted.len(), 2 + MAX_BLOCK + 16 + 2 + 1 + 16);
    }

    #[test]
    fn max_block_exceeds_prefix_rejected() {
        let (_writer, mut reader) = test_cipher_pair();
        let mut buf = vec![0u8; LENGTH_PREFIX_LEN + MAX_BLOCK + 1 + TAG_LEN];
        let bad_len = (MAX_BLOCK + 1) as u16;
        let prefix = bad_len.to_le_bytes();
        buf[0] = prefix[0];
        buf[1] = prefix[1];
        let result = reader.decrypt_blocks(&buf);
        assert!(matches!(result, Err(CipherError::BlockTooLarge)));
    }
}
