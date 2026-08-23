use std::path::Path;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2_011::Sha512 as SrpSha512;
use srp::{ClientG3072, ServerG3072};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::airplay::{
    crypto::{AgreementKey, DerivedKey, IdentityKey, hkdf_sha512, nonce_from_label, open, seal},
    tlv::Tlv,
};

pub const TLV_METHOD: u8 = 0;
pub const TLV_IDENTIFIER: u8 = 1;
pub const TLV_SALT: u8 = 2;
pub const TLV_PUBLIC_KEY: u8 = 3;
pub const TLV_PROOF: u8 = 4;
pub const TLV_ENCRYPTED_DATA: u8 = 5;
pub const TLV_STATE: u8 = 6;
pub const TLV_ERROR: u8 = 7;
pub const TLV_SIGNATURE: u8 = 10;
pub const TLV_FLAGS: u8 = 19;
pub const TLV_ERROR_AUTHENTICATION: u8 = 2;
const PAIRING_FLAGS_TRANSIENT: u8 = 0x10;
const PAIR_SETUP_USERNAME: &[u8] = b"Pair-Setup";

// ---------------------------------------------------------------------------
// Pairing-completion signal
// ---------------------------------------------------------------------------

/// Signals that a pairing protocol step completed successfully and provides the
/// secret material needed to install a [`crate::airplay::crypto::PairCipher`].
///
/// Intentionally **not** [`Clone`], [`Debug`], [`PartialEq`], or [`Eq`] to
/// avoid copying or logging of secret bytes.
/// On [`Drop`] all inner secret material is zeroed.
pub enum PairingCompletion {
    /// Transient pair-setup completed (after M3/M4).  `key` is the raw 64-byte
    /// SRP session key K used to derive the control cipher.
    TransientSetup {
        key: [u8; 64],
        /// Client identifier from M5 inner TLV (for non-transient; None for transient).
        client_id: Option<String>,
    },
    /// Non-transient pair-setup completed (after M5/M6).  `key` is the raw
    /// 64-byte SRP session key K.  The client has been persisted to the pairing
    /// database.
    FullSetup { key: [u8; 64], client_id: String },
    /// Pair-verify completed (after M3/M4).  `shared_secret` is the verified
    /// 32-byte X25519 shared secret used to derive the control cipher.
    Verify { shared_secret: [u8; 32] },
}

impl Drop for PairingCompletion {
    fn drop(&mut self) {
        match self {
            PairingCompletion::TransientSetup { key, client_id } => {
                key.zeroize();
                if let Some(id) = client_id {
                    id.zeroize();
                }
            }
            PairingCompletion::FullSetup { key, client_id } => {
                key.zeroize();
                client_id.zeroize();
            }
            PairingCompletion::Verify { shared_secret } => {
                shared_secret.zeroize();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing endpoint & reply
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PairingEndpoint {
    Setup,
    Verify,
    Add,
    Remove,
    List,
}

pub struct PairingReply {
    pub status_code: u16,
    pub body: Vec<u8>,
    /// Present only after a successful terminal pairing step with no TLV error.
    pub completion: Option<PairingCompletion>,
}

// ---------------------------------------------------------------------------
// Pairing session
// ---------------------------------------------------------------------------

/// Per-connection session state for pair-setup and pair-verify.
///
/// Intentionally **not** [`Clone`], [`Debug`], [`PartialEq`], or [`Eq`] —
/// these traits would risk accidental copying or logging of secret key
/// material.  On [`Drop`] all secret fields are zeroed.
#[derive(Default)]
pub struct PairingSession {
    setup: Option<PairSetupState>,
    // Raw SRP session key K (64 bytes), available after M3.
    setup_session_key: Option<[u8; 64]>,
    verify_agreement: Option<AgreementKey>,
    verify_shared_secret: Option<[u8; 32]>,
    verify_session_key: Option<DerivedKey>,
    client_ephemeral_public_key: Option<[u8; 32]>,
    pub verified: bool,
    // Client's Ed25519 public key (from M5 inner TLV), stored for pair-verify M3.
    pub client_public_key: Option<[u8; 32]>,
    // Client's device identifier.
    pub client_device_id: Option<String>,
}

impl Drop for PairingSession {
    fn drop(&mut self) {
        self.reset_setup();
        self.reset_verify();
    }
}

impl PairingSession {
    /// The verified X25519 shared secret from pair-verify, available only
    /// after `verified` is true.
    pub fn shared_secret(&self) -> Option<&[u8; 32]> {
        self.verify_shared_secret.as_ref().filter(|_| self.verified)
    }

    /// Raw SRP session key K (64 bytes), for HKDF key derivation.
    pub fn session_key(&self) -> Option<&[u8; 64]> {
        self.setup_session_key.as_ref()
    }

    /// Secret used to derive encrypted control/event channels after a
    /// successful terminal pairing step. Pair-verify takes precedence when
    /// present; transient/full pair-setup uses the SRP session key.
    pub fn control_secret(&self) -> Option<&[u8]> {
        if !self.verified {
            return None;
        }
        self.verify_shared_secret
            .as_ref()
            .map(|secret| secret.as_slice())
            .or_else(|| self.setup_session_key.as_ref().map(|key| key.as_slice()))
    }

    /// Install a verified control secret for protocol integration tests.
    #[cfg(test)]
    pub(crate) fn install_test_control_secret(&mut self, secret: [u8; 32]) {
        self.reset_verify();
        self.verify_shared_secret = Some(secret);
        self.verified = true;
    }

    fn finish_setup_exchange(&mut self) {
        if let Some(ref mut state) = self.setup {
            state.zeroize();
        }
        self.setup = None;
    }

    fn finish_verify_exchange(&mut self) {
        self.verify_agreement = None;
        self.client_ephemeral_public_key = None;
    }

    /// Reset pair-setup state and zero all associated secret material.
    pub fn reset_setup(&mut self) {
        if let Some(ref mut state) = self.setup {
            state.zeroize();
        }
        self.setup = None;
        if let Some(ref mut key) = self.setup_session_key {
            key.zeroize();
        }
        self.setup_session_key = None;
    }

    /// Reset pair-verify state and zero all associated secret material.
    pub fn reset_verify(&mut self) {
        self.verify_agreement = None;
        if let Some(ref mut sec) = self.verify_shared_secret {
            sec.zeroize();
        }
        self.verify_shared_secret = None;
        self.verify_session_key = None; // Drop impl zeros DerivedKey
        self.client_ephemeral_public_key = None;
        self.verified = false;
    }

    /// Clear both setup and verify state (used on connection close / drop).
    pub fn clear(&mut self) {
        self.reset_setup();
        self.reset_verify();
        self.client_public_key = None;
        self.client_device_id = None;
    }
}

// ---------------------------------------------------------------------------
// PairSetupState
// ---------------------------------------------------------------------------

struct PairSetupState {
    salt: [u8; 16],
    verifier_bytes: Vec<u8>,
    server_private: Vec<u8>,
    server_public: Vec<u8>,
    is_transient: bool,
}

impl Zeroize for PairSetupState {
    fn zeroize(&mut self) {
        self.salt.zeroize();
        self.verifier_bytes.zeroize();
        self.server_private.zeroize();
        self.server_public.zeroize();
    }
}

impl Drop for PairSetupState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Pairing service
// ---------------------------------------------------------------------------

type SrpServer = ServerG3072<sha2_011::Sha512>;

/// A stored client pairing entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairedClient {
    pub identifier: String,
    #[serde(with = "hex_serde")]
    pub public_key: [u8; 32],
    pub added_at: String,
}

/// Persistent pairing database.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingDatabase {
    pub allowed_clients: Vec<PairedClient>,
}

impl PairingDatabase {
    pub fn load(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self {
                allowed_clients: Vec::new(),
            };
        };
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(db) => db,
                Err(e) => {
                    warn!(%e, "failed to parse pairing DB, starting fresh");
                    Self {
                        allowed_clients: Vec::new(),
                    }
                }
            },
            Err(_) => Self {
                allowed_clients: Vec::new(),
            },
        }
    }

    pub fn save(&self, path: Option<&Path>) {
        let Some(path) = path else {
            return;
        };
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, &content);
        }
    }

    pub fn find_client(&self, identifier: &str) -> Option<&PairedClient> {
        self.allowed_clients
            .iter()
            .find(|c| c.identifier == identifier)
    }

    pub fn add_client(&mut self, identifier: String, public_key: [u8; 32]) {
        if self
            .allowed_clients
            .iter()
            .any(|c| c.identifier == identifier)
        {
            return;
        }
        let now = std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".to_string());
        self.allowed_clients.push(PairedClient {
            identifier,
            public_key,
            added_at: now,
        });
    }

    pub fn remove_client(&mut self, identifier: &str) -> bool {
        let len = self.allowed_clients.len();
        self.allowed_clients.retain(|c| c.identifier != identifier);
        self.allowed_clients.len() < len
    }
}

pub struct PairingService {
    identity: IdentityKey,
    device_id: String,
    pin_text: String,
    db_path: Option<std::path::PathBuf>,
    pub db: parking_lot::RwLock<PairingDatabase>,
}

impl PairingService {
    pub fn new(
        identity: IdentityKey,
        device_id: impl Into<String>,
        pin_text: impl Into<String>,
        db_path: Option<impl Into<std::path::PathBuf>>,
    ) -> Self {
        let device_id = device_id.into();
        let pin_text = pin_text.into();
        // A blank configured PIN means the receiver is not user-password
        // protected (`pw=false`). HomeKit pair-setup nevertheless uses 3939
        // as its protocol PIN, matching upstream pair_homekit.c.
        let pin_text = if pin_text.is_empty() {
            "3939".to_string()
        } else {
            pin_text
        };
        let db_path = db_path.map(|p| p.into());
        let db = PairingDatabase::load(db_path.as_deref());
        Self {
            identity,
            device_id,
            pin_text,
            db_path,
            db: parking_lot::RwLock::new(db),
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn identity_public_key(&self) -> [u8; 32] {
        self.identity.verifying_key()
    }

    // ── Top-level dispatch ───────────────────────────────────────────

    pub fn handle(
        &self,
        session: &mut PairingSession,
        endpoint: PairingEndpoint,
        body: &[u8],
    ) -> PairingReply {
        let incoming = Tlv::parse(body);
        let requested_state = incoming
            .first(TLV_STATE)
            .and_then(|state| state.first().copied())
            .unwrap_or(1);
        debug!(
            ?endpoint,
            requested_state,
            body_len = body.len(),
            tlv = %incoming.debug_summary(),
            session_verified = session.verified,
            has_setup_key = session.setup_session_key.is_some(),
            has_verify_key = session.verify_session_key.is_some(),
            "pairing request"
        );

        let (tlv, completion) = match endpoint {
            PairingEndpoint::Setup => match requested_state {
                1 => self.setup_m1(session, &incoming),
                3 => self.setup_m3(session, &incoming),
                5 => self.setup_m5(session, &incoming),
                _ => {
                    session.reset_setup();
                    (auth_error(requested_state.saturating_add(1).min(6)), None)
                }
            },
            PairingEndpoint::Verify => match requested_state {
                1 => self.verify_m1(session, &incoming),
                3 => self.verify_m3(session, &incoming),
                _ => {
                    session.reset_verify();
                    (auth_error(requested_state.saturating_add(1).min(4)), None)
                }
            },
            PairingEndpoint::Add => self.pair_add(session, &incoming),
            PairingEndpoint::Remove => self.pair_remove(session, &incoming),
            PairingEndpoint::List => self.pair_list(session),
        };

        let has_error = tlv.first(TLV_ERROR).is_some();
        debug!(
            ?endpoint,
            requested_state,
            response_tlv = %tlv.debug_summary(),
            has_error,
            completion = if completion.is_some() { "Some" } else { "None" },
            "pairing response"
        );

        // Only signal completion when the TLV has no error — this is the key
        // fix: Apple sends TLV errors with HTTP 200, so we must NOT infer
        // success from the status code.
        let completion = if has_error { None } else { completion };

        PairingReply {
            status_code: 200, // Apple uses 200 whether or not error TLV is present
            body: tlv.encode(),
            completion,
        }
    }

    // ── Pair-setup handlers ──────────────────────────────────────────

    fn setup_m1(
        &self,
        session: &mut PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        // A new M1 starts a fresh pairing exchange and clears stale setup,
        // verify, client identity, and verification state.
        session.clear();

        let method = incoming
            .first(TLV_METHOD)
            .and_then(|value| value.first().copied())
            .unwrap_or(0);
        if method != 0 {
            warn!(method, "unsupported pair-setup method");
            return (auth_error(2), None);
        }

        let is_transient = incoming
            .first(TLV_FLAGS)
            .and_then(|value| value.first().copied())
            .is_some_and(|flags| flags & PAIRING_FLAGS_TRANSIENT != 0);
        let flags = incoming
            .first(TLV_FLAGS)
            .and_then(|value| value.first().copied())
            .unwrap_or(0);

        let pin_bytes = self.pin_text.as_bytes();
        let server = ServerG3072::<SrpSha512>::new_with_options(true);
        let client = ClientG3072::<SrpSha512>::new_with_options(true);
        let salt = random_salt();
        let server_secret = random_server_secret();
        let verifier = client.compute_verifier(PAIR_SETUP_USERNAME, pin_bytes, &salt);
        let server_public = server.compute_public_ephemeral(&server_secret, &verifier);

        // Public-only logging: no secret bytes.
        debug!(
            method,
            flags = format_args!("0x{flags:02x}"),
            is_transient,
            srp_username_in_x = true,
            srp_pad_g_in_m1 = false,
            pin_len = pin_bytes.len(),
            salt_len = 16,
            verifier_len = verifier.len(),
            server_public_len = server_public.len(),
            server_private_len = server_secret.len(),
            "pair-setup M1 accepted"
        );

        session.setup = Some(PairSetupState {
            salt,
            verifier_bytes: verifier,
            server_private: server_secret.to_vec(),
            server_public: server_public.clone(),
            is_transient,
        });

        let mut out = Tlv::default();
        out.insert(TLV_STATE, [2]);
        out.insert(TLV_SALT, salt);
        out.insert(TLV_PUBLIC_KEY, server_public);
        (out, None)
    }

    fn setup_m3(
        &self,
        session: &mut PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        let Some(setup) = session.setup.as_mut() else {
            warn!("pair-setup M3 received before M1 setup state");
            return (auth_error(4), None);
        };
        let Some(client_public) = incoming.joined(TLV_PUBLIC_KEY) else {
            warn!(
                tlv = %incoming.debug_summary(),
                "pair-setup M3 missing client public key"
            );
            session.reset_setup();
            return (auth_error(4), None);
        };
        let Some(client_proof) = incoming.joined(TLV_PROOF) else {
            warn!(
                tlv = %incoming.debug_summary(),
                "pair-setup M3 missing client proof"
            );
            session.reset_setup();
            return (auth_error(4), None);
        };
        debug!(
            is_transient = setup.is_transient,
            client_public_len = client_public.len(),
            client_proof_len = client_proof.len(),
            "pair-setup M3 SRP input"
        );

        let server = SrpServer::new_with_options(true);
        let verifier = match server.process_reply(
            PAIR_SETUP_USERNAME,
            &setup.salt,
            &setup.server_private,
            &setup.verifier_bytes,
            &client_public,
        ) {
            Ok(v) => {
                debug!(
                    premaster_len = v.key().len(),
                    server_proof_len = v.proof().len(),
                    "pair-setup M3 SRP verifier built"
                );
                v
            }
            Err(err) => {
                warn!(
                    %err,
                    client_public_len = client_public.len(),
                    server_public_len = setup.server_public.len(),
                    "pair-setup SRP reply rejected"
                );
                session.reset_setup();
                return (auth_error(4), None);
            }
        };

        let mut session_key = match verifier.verify_client(&client_proof) {
            Ok(session_key) => {
                debug!(
                    session_key_len = session_key.len(),
                    server_proof_len = verifier.proof().len(),
                    "pair-setup M3 SRP proof verified"
                );
                let mut key = [0u8; 64];
                key.copy_from_slice(session_key);
                key
            }
            Err(err) => {
                warn!(
                    %err,
                    client_proof_len = client_proof.len(),
                    server_public_len = setup.server_public.len(),
                    "pair-setup client proof rejected"
                );
                session.reset_setup();
                return (auth_error(4), None);
            }
        };

        info!("pair-setup SRP proof verified, session key established");

        session.setup_session_key = Some(session_key);

        let mut out = Tlv::default();
        out.insert(TLV_STATE, [4]);
        out.insert(TLV_PROOF, verifier.proof());

        let completion = if setup.is_transient {
            session.verified = true;
            session.finish_setup_exchange();
            info!("transient pair-setup completed; control cipher available");
            Some(PairingCompletion::TransientSetup {
                key: session_key,
                client_id: None,
            })
        } else {
            None
        };
        session_key.zeroize();
        (out, completion)
    }

    /// M5: Client sends encrypted TLV (State=5, EncryptedData).
    /// Inner TLV: Identifier, PublicKey, Signature.
    fn setup_m5(
        &self,
        session: &mut PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        let session_key = match session.session_key() {
            Some(k) => zeroize::Zeroizing::new(*k),
            None => {
                warn!("pair-setup M5 received without SRP session key");
                session.reset_setup();
                return (auth_error(6), None);
            }
        };
        let Some(encrypted_data) = incoming.joined(TLV_ENCRYPTED_DATA) else {
            warn!(
                tlv = %incoming.debug_summary(),
                "pair-setup M5 missing encrypted data"
            );
            session.reset_setup();
            return (auth_error(6), None);
        };
        debug!(
            session_key_len = session_key.len(),
            encrypted_len = encrypted_data.len(),
            "pair-setup M5 decrypt input"
        );

        // Derive encryption key
        let enc_key = hkdf_sha512(
            &session_key[..],
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        );
        let nonce = nonce_from_label(b"PS-Msg05");

        // Decrypt
        let plaintext = match chacha_open(&enc_key, &nonce, &[], &encrypted_data) {
            Ok(p) => {
                debug!(plaintext_len = p.len(), "pair-setup M5 decrypted");
                p
            }
            Err(e) => {
                warn!(%e, encrypted_len = encrypted_data.len(), "pair-setup M5 decryption failed");
                session.reset_setup();
                return (auth_error(6), None);
            }
        };

        let inner = Tlv::parse(&plaintext);
        debug!(inner_tlv = %inner.debug_summary(), "pair-setup M5 inner TLV");
        let Some(client_id) = inner
            .first(TLV_IDENTIFIER)
            .map(|v| String::from_utf8_lossy(v).to_string())
        else {
            warn!(inner_tlv = %inner.debug_summary(), "pair-setup M5 missing client id");
            session.reset_setup();
            return (auth_error(6), None);
        };
        let Some(client_pk) = inner.first(TLV_PUBLIC_KEY).and_then(as_32_bytes) else {
            warn!(inner_tlv = %inner.debug_summary(), "pair-setup M5 missing client public key");
            session.reset_setup();
            return (auth_error(6), None);
        };
        let Some(client_sig) = inner.first(TLV_SIGNATURE).and_then(as_64_bytes) else {
            warn!(inner_tlv = %inner.debug_summary(), "pair-setup M5 missing client signature");
            session.reset_setup();
            return (auth_error(6), None);
        };

        // Derive device_x
        let device_x = hkdf_sha512(
            &session_key[..],
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        );

        // Build signed info: device_x(32) || client_id || client_pk(32)
        let mut signed_info = Vec::with_capacity(32 + client_id.len() + 32);
        signed_info.extend_from_slice(&device_x.0);
        signed_info.extend_from_slice(client_id.as_bytes());
        signed_info.extend_from_slice(&client_pk);

        // Verify Ed25519 signature
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&client_pk)
            .map_err(|_| "invalid client public key")
            .ok();
        let Some(vk) = vk else {
            warn!(
                client_id,
                "pair-setup M5: invalid client Ed25519 public key"
            );
            session.reset_setup();
            return (auth_error(6), None);
        };
        let sig = ed25519_dalek::Signature::from_bytes(&client_sig);
        if vk.verify_strict(&signed_info, &sig).is_err() {
            warn!(
                client_id,
                signed_info_len = signed_info.len(),
                "pair-setup M5: Ed25519 signature verification failed"
            );
            session.reset_setup();
            return (auth_error(6), None);
        }

        debug!(
            client_identifier_len = client_id.len(),
            "pair-setup M5 client signature verified"
        );

        // Generate M6 before persisting or marking the session verified.
        let m6_tlv = match self.setup_m6(&session_key) {
            Ok(tlv) => tlv,
            Err(e) => {
                warn!(%e, "pair-setup M6 generation failed");
                session.reset_setup();
                return (auth_error(6), None);
            }
        };

        // Commit identity and pairing database state only after M6 exists.
        session.client_device_id = Some(client_id.clone());
        session.client_public_key = Some(client_pk);
        {
            let mut db = self.db.write();
            db.add_client(client_id.clone(), client_pk);
            db.save(self.db_path.as_deref());
        }
        session.verified = true;
        info!("non-transient pair-setup completed and client persisted");

        drop(enc_key);
        drop(device_x);

        (
            m6_tlv,
            Some(PairingCompletion::FullSetup {
                key: *session_key,
                client_id,
            }),
        )
    }

    /// M6: Server sends encrypted TLV with server identity + Ed25519 signature.
    fn setup_m6(&self, session_key: &[u8; 64]) -> anyhow::Result<Tlv> {
        // Derive device_x for accessory
        let device_x = hkdf_sha512(
            session_key,
            b"Pair-Setup-Accessory-Sign-Salt",
            b"Pair-Setup-Accessory-Sign-Info",
        );

        // Build signed info: device_x(32) || device_id || server_pk(32)
        let pk = self.identity.verifying_key();
        let mut signed_info = Vec::with_capacity(32 + self.device_id.len() + 32);
        signed_info.extend_from_slice(&device_x.0);
        signed_info.extend_from_slice(self.device_id.as_bytes());
        signed_info.extend_from_slice(&pk);

        // Sign with server identity key
        let sig = self.identity.sign(&signed_info);

        let mut inner = Tlv::default();
        inner.insert(TLV_IDENTIFIER, self.device_id.as_bytes());
        inner.insert(TLV_PUBLIC_KEY, pk);
        inner.insert(TLV_SIGNATURE, &sig[..]);
        let inner_encoded = inner.encode();
        debug!(
            device_id = %self.device_id,
            inner_tlv = %inner.debug_summary(),
            inner_len = inner_encoded.len(),
            signed_info_len = signed_info.len(),
            "pair-setup M6 inner TLV"
        );

        // Derive encryption key for M6
        let enc_key = hkdf_sha512(
            session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        );
        let nonce = nonce_from_label(b"PS-Msg06");

        let encrypted = chacha_seal(&enc_key, &nonce, &[], &inner_encoded)?;
        debug!(encrypted_len = encrypted.len(), "pair-setup M6 encrypted");

        drop(enc_key);
        drop(device_x);

        let mut out = Tlv::default();
        out.insert(TLV_STATE, [6]);
        out.insert(TLV_ENCRYPTED_DATA, encrypted);
        Ok(out)
    }

    // ── Pair-verify handlers ─────────────────────────────────────────

    fn verify_m1(
        &self,
        session: &mut PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        // A new M1 starts a fresh pairing exchange and clears stale setup,
        // verify, client identity, and verification state.
        session.clear();

        let Some(client_public) = incoming.first(TLV_PUBLIC_KEY).and_then(as_32_bytes) else {
            warn!(
                tlv = %incoming.debug_summary(),
                "pair-verify M1 missing client public key"
            );
            return (auth_error(2), None);
        };
        let agreement = AgreementKey::generate();
        let public = agreement.public_key();
        let mut shared_secret = agreement.shared_secret(&client_public);
        let session_key = hkdf_sha512(
            &shared_secret,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        );

        let mut info = Vec::with_capacity(32 + self.device_id.len() + 32);
        info.extend_from_slice(&public);
        info.extend_from_slice(self.device_id.as_bytes());
        info.extend_from_slice(&client_public);

        let mut sub_tlv = Tlv::default();
        sub_tlv.insert(TLV_IDENTIFIER, self.device_id.as_bytes());
        sub_tlv.insert(TLV_SIGNATURE, self.identity.sign(&info));

        let encrypted = match seal(
            &session_key,
            &nonce_from_label(b"PV-Msg02"),
            &[],
            &sub_tlv.encode(),
        ) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                warn!(%e, "pair-verify M2 encryption failed");
                return (auth_error(2), None);
            }
        };
        debug!(
            client_public_len = 32,
            server_public_len = 32,
            encrypted_len = encrypted.len(),
            "pair-verify M1 accepted"
        );

        session.verify_agreement = Some(agreement);
        session.verify_shared_secret = Some(shared_secret);
        session.verify_session_key = Some(session_key);
        session.client_ephemeral_public_key = Some(client_public);
        shared_secret.zeroize();

        let mut out = Tlv::default();
        out.insert(TLV_STATE, [2]);
        out.insert(TLV_PUBLIC_KEY, public);
        out.insert(TLV_ENCRYPTED_DATA, encrypted);
        (out, None)
    }

    fn verify_m3(
        &self,
        session: &mut PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        let Some(ref session_key) = session.verify_session_key else {
            warn!("pair-verify M3 received without session key");
            session.reset_verify();
            return (auth_error(4), None);
        };
        let Some(encrypted) = incoming.joined(TLV_ENCRYPTED_DATA) else {
            warn!(
                tlv = %incoming.debug_summary(),
                "pair-verify M3 missing encrypted data"
            );
            session.reset_verify();
            return (auth_error(4), None);
        };
        let decrypted = match open(session_key, &nonce_from_label(b"PV-Msg03"), &[], &encrypted) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                warn!(%e, encrypted_len = encrypted.len(), "pair-verify M3 decryption failed");
                session.reset_verify();
                return (auth_error(4), None);
            }
        };

        let inner = Tlv::parse(&decrypted);
        debug!(
            decrypted_len = decrypted.len(),
            inner_tlv = %inner.debug_summary(),
            "pair-verify M3 decrypted"
        );
        let Some(client_id) = inner.first(TLV_IDENTIFIER) else {
            warn!(inner_tlv = %inner.debug_summary(), "pair-verify M3 missing client id");
            session.reset_verify();
            return (auth_error(4), None);
        };
        let Some(client_sig_raw) = inner.first(TLV_SIGNATURE) else {
            warn!(inner_tlv = %inner.debug_summary(), "pair-verify M3 missing client signature");
            session.reset_verify();
            return (auth_error(4), None);
        };
        let Ok(client_sig) = <[u8; 64]>::try_from(client_sig_raw) else {
            warn!(
                signature_len = client_sig_raw.len(),
                "pair-verify M3 invalid client signature length"
            );
            session.reset_verify();
            return (auth_error(4), None);
        };

        let Some(client_public) = session.client_ephemeral_public_key else {
            session.reset_verify();
            return (auth_error(4), None);
        };
        let Some(ref agreement) = session.verify_agreement else {
            session.reset_verify();
            return (auth_error(4), None);
        };

        let our_pub = agreement.public_key();

        let mut signed_message = Vec::with_capacity(32 + 32 + client_id.len());
        signed_message.extend_from_slice(&client_public);
        signed_message.extend_from_slice(client_id);
        signed_message.extend_from_slice(&our_pub);

        let client_identifier = String::from_utf8_lossy(client_id);
        let db = self.db.read();
        let verified = match db.find_client(&client_identifier) {
            Some(stored) => IdentityKey::verify(&stored.public_key, &signed_message, &client_sig),
            None => {
                warn!("client not found in pairing DB");
                false
            }
        };

        if !verified {
            warn!(
                identifier_len = client_id.len(),
                signed_message_len = signed_message.len(),
                "pair-verify: client signature verification failed"
            );
            session.reset_verify();
            return (auth_error(4), None);
        }

        debug!("pair-verify: client authenticated");
        session.verified = true;

        // Capture the shared secret before it's consumed.
        let mut shared_secret = session
            .verify_shared_secret
            .expect("shared secret set in M1");
        session.finish_verify_exchange();

        let mut out = Tlv::default();
        out.insert(TLV_STATE, [4]);
        let completion = PairingCompletion::Verify { shared_secret };
        shared_secret.zeroize();
        (out, Some(completion))
    }

    // ── Pair management ──────────────────────────────────────────────

    fn pair_add(
        &self,
        session: &PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        if !session.verified {
            warn!("pair-add attempted without verified session");
            return (auth_error(2), None);
        }
        let Some(encrypted) = incoming.joined(TLV_ENCRYPTED_DATA) else {
            return (auth_error(2), None);
        };
        let Some(ref session_key) = session.verify_session_key else {
            return (auth_error(2), None);
        };
        let decrypted = match open(session_key, &nonce_from_label(b"PA-Msg04"), &[], &encrypted) {
            Ok(d) => d,
            Err(_) => return (auth_error(2), None),
        };
        let inner = Tlv::parse(&decrypted);
        let Some(identifier) = inner
            .first(TLV_IDENTIFIER)
            .map(|v| String::from_utf8_lossy(v).to_string())
        else {
            return (auth_error(2), None);
        };
        let Some(pk) = inner.first(TLV_PUBLIC_KEY).and_then(as_32_bytes) else {
            return (auth_error(2), None);
        };

        let mut db = self.db.write();
        db.add_client(identifier.clone(), pk);
        db.save(self.db_path.as_deref());
        info!(identifier, "client paired");
        let mut out = Tlv::default();
        out.insert(TLV_STATE, [1]);
        (out, None)
    }

    fn pair_remove(
        &self,
        session: &PairingSession,
        incoming: &Tlv,
    ) -> (Tlv, Option<PairingCompletion>) {
        if !session.verified {
            warn!("pair-remove attempted without verified session");
            return (auth_error(2), None);
        }
        // Preserve the existing payload interpretation; this phase adds only
        // the verified-session authorization gate and does not invent a new
        // nonce or encryption envelope for pair-remove.
        let Some(payload) = incoming.joined(TLV_ENCRYPTED_DATA) else {
            return (auth_error(2), None);
        };
        let inner = Tlv::parse(&payload);
        let Some(identifier) = inner
            .first(TLV_IDENTIFIER)
            .map(|v| String::from_utf8_lossy(v).to_string())
        else {
            return (auth_error(2), None);
        };

        let mut db = self.db.write();
        if db.remove_client(&identifier) {
            db.save(self.db_path.as_deref());
            info!(identifier, "client unpaired");
        }
        let mut out = Tlv::default();
        out.insert(TLV_STATE, [1]);
        (out, None)
    }

    fn pair_list(&self, session: &PairingSession) -> (Tlv, Option<PairingCompletion>) {
        if !session.verified {
            warn!("pair-list attempted without verified session");
            return (auth_error(2), None);
        }
        let db = self.db.read();
        let mut out = Tlv::default();
        out.insert(TLV_STATE, [1]);
        for client in &db.allowed_clients {
            let mut entry = Vec::with_capacity(1 + client.identifier.len() + 1 + 32);
            entry.push(TLV_IDENTIFIER);
            entry.push(client.identifier.len() as u8);
            entry.extend_from_slice(client.identifier.as_bytes());
            entry.push(TLV_PUBLIC_KEY);
            entry.push(32);
            entry.extend_from_slice(&client.public_key);
            out.insert(0x0f, entry);
        }
        (out, None)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn auth_error(state: u8) -> Tlv {
    let mut out = Tlv::default();
    out.insert(TLV_STATE, [state]);
    out.insert(TLV_ERROR, [TLV_ERROR_AUTHENTICATION]);
    out
}

fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn random_server_secret() -> [u8; 48] {
    let mut secret = [0u8; 48];
    OsRng.fill_bytes(&mut secret);
    secret
}

fn as_32_bytes(value: &[u8]) -> Option<[u8; 32]> {
    value.try_into().ok()
}

fn as_64_bytes(value: &[u8]) -> Option<[u8; 64]> {
    value.try_into().ok()
}

/// Chacha20-Poly1305 encrypt. Returns ciphertext || 16-byte tag.
fn chacha_seal(
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

/// Chacha20-Poly1305 decrypt. Expects ciphertext || 16-byte tag.
fn chacha_open(
    key: &DerivedKey,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new((&key.0).into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_with_tag,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("chacha20-poly1305 decryption failed"))
}

/// Serde module for hex-encoded 32-byte arrays.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = hex_impl(bytes);
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex_decode_impl(&s).ok_or_else(|| serde::de::Error::custom("invalid hex"))?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    fn hex_impl(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for &b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn hex_decode_impl(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }
}

// ── Test helpers ─────────────────────────────────────────────────────────

fn test_pairing_service() -> PairingService {
    let identity = IdentityKey::generate();
    let db = PairingDatabase {
        allowed_clients: Vec::new(),
    };
    PairingService {
        identity,
        device_id: "00:11:22:33:44:55".to_string(),
        pin_text: "3939".to_string(),
        db_path: None,
        db: parking_lot::RwLock::new(db),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

// END PRODUCTION PAIRING SOURCE
#[cfg(test)]
mod tests {
    use super::*;
    use crate::airplay::crypto::{hkdf_sha512, nonce_from_label, open, seal};
    use srp::{
        Group,
        groups::G3072,
        utils::{compute_hash, compute_m1_rfc5054},
    };

    // ── Setup completion tests ─────────────────────────────────────────

    #[test]
    fn empty_configured_pin_uses_homekit_pairing_default() {
        let service = PairingService::new(
            IdentityKey::generate(),
            "00:11:22:33:44:55",
            "",
            None::<std::path::PathBuf>,
        );
        assert_eq!(service.pin_text, "3939");
    }

    #[test]
    fn pair_setup_m1_returns_srp_salt_and_public_key() {
        let mut input = Tlv::default();
        input.insert(TLV_METHOD, [0]);
        input.insert(TLV_STATE, [1]);
        input.insert(TLV_FLAGS, [PAIRING_FLAGS_TRANSIENT]);

        let service = test_pairing_service();
        let mut session = PairingSession::default();
        let reply = service.handle(&mut session, PairingEndpoint::Setup, &input.encode());
        let tlv = Tlv::parse(&reply.body);

        assert_eq!(reply.status_code, 200);
        assert_eq!(tlv.first(TLV_STATE), Some([2].as_slice()));
        assert_eq!(tlv.first(TLV_SALT).unwrap().len(), 16);
        assert!(tlv.joined(TLV_PUBLIC_KEY).unwrap().len() > 300);
        assert!(tlv.first(TLV_ERROR).is_none());
        assert!(reply.completion.is_none()); // not yet complete
    }

    #[test]
    fn transient_pair_setup_completion_signals_after_m3() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();

        let mut m1 = Tlv::default();
        m1.insert(TLV_METHOD, [0]);
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_FLAGS, [PAIRING_FLAGS_TRANSIENT]);
        let m2 = service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());
        let m2_tlv = Tlv::parse(&m2.body);
        let salt = m2_tlv.first(TLV_SALT).unwrap();
        let server_public = m2_tlv.joined(TLV_PUBLIC_KEY).unwrap();

        let client = ClientG3072::<SrpSha512>::new_with_options(true);
        let client_secret = [0x7bu8; 48];
        let client_public = client.compute_public_ephemeral(&client_secret);
        let client_verifier = client
            .process_reply(
                &client_secret,
                PAIR_SETUP_USERNAME,
                service.pin_text.as_bytes(),
                salt,
                &server_public,
            )
            .unwrap();
        let session_key = compute_hash::<SrpSha512>(client_verifier.key());
        let proof = compute_m1_rfc5054::<SrpSha512>(
            &G3072::generator(),
            true,
            PAIR_SETUP_USERNAME,
            salt,
            &client_public,
            &server_public,
            session_key.as_slice(),
        );

        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_PUBLIC_KEY, client_public);
        m3.insert(TLV_PROOF, proof.as_slice());
        let m4 = service.handle(&mut session, PairingEndpoint::Setup, &m3.encode());
        let m4_tlv = Tlv::parse(&m4.body);

        assert_eq!(m4_tlv.first(TLV_STATE), Some([4].as_slice()));
        assert!(m4_tlv.first(TLV_ERROR).is_none());
        assert_eq!(m4_tlv.first(TLV_PROOF).unwrap().len(), 64);
        assert!(session.verified);
        assert!(session.session_key().is_some());
        // Completion signal is present for transient setup
        assert!(m4.completion.is_some());
        assert!(matches!(
            m4.completion,
            Some(PairingCompletion::TransientSetup { .. })
        ));
    }

    #[test]
    fn non_transient_pair_setup_completion_signals_after_m5_m6() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();

        // M1: non-transient (no flags)
        let mut m1 = Tlv::default();
        m1.insert(TLV_METHOD, [0]);
        m1.insert(TLV_STATE, [1]);
        let m2 = service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());
        let m2_tlv = Tlv::parse(&m2.body);
        assert!(m2.completion.is_none());

        let salt = m2_tlv.first(TLV_SALT).unwrap();
        let server_public = m2_tlv.joined(TLV_PUBLIC_KEY).unwrap();

        // M3: SRP proof
        let client = ClientG3072::<SrpSha512>::new_with_options(true);
        let client_secret = [0x7bu8; 48];
        let client_public = client.compute_public_ephemeral(&client_secret);
        let client_verifier = client
            .process_reply(
                &client_secret,
                PAIR_SETUP_USERNAME,
                service.pin_text.as_bytes(),
                salt,
                &server_public,
            )
            .unwrap();
        let sess_key = compute_hash::<SrpSha512>(client_verifier.key());
        let proof = compute_m1_rfc5054::<SrpSha512>(
            &G3072::generator(),
            true,
            PAIR_SETUP_USERNAME,
            salt,
            &client_public,
            &server_public,
            sess_key.as_slice(),
        );

        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_PUBLIC_KEY, client_public);
        m3.insert(TLV_PROOF, proof.as_slice());
        let m4 = service.handle(&mut session, PairingEndpoint::Setup, &m3.encode());
        assert!(m4.completion.is_none()); // non-transient, not complete yet
        assert!(!session.verified);
        assert!(session.session_key().is_some());

        // M5: client identity
        let client_identity = IdentityKey::generate();
        let enc_key = hkdf_sha512(
            &sess_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        );
        let device_x = hkdf_sha512(
            &sess_key,
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        );

        let expected_id = "test-client-non-transient";
        let mut signed_info = Vec::with_capacity(32 + expected_id.len() + 32);
        signed_info.extend_from_slice(&device_x.0);
        signed_info.extend_from_slice(expected_id.as_bytes());
        signed_info.extend_from_slice(&client_identity.verifying_key());
        let client_sig = client_identity.sign(&signed_info);

        let mut inner_m5 = Tlv::default();
        inner_m5.insert(TLV_IDENTIFIER, expected_id.as_bytes());
        inner_m5.insert(TLV_PUBLIC_KEY, client_identity.verifying_key());
        inner_m5.insert(TLV_SIGNATURE, client_sig);

        let encrypted_m5 = seal(
            &enc_key,
            &nonce_from_label(b"PS-Msg05"),
            &[],
            &inner_m5.encode(),
        )
        .unwrap();
        let mut m5 = Tlv::default();
        m5.insert(TLV_STATE, [5]);
        m5.insert(TLV_ENCRYPTED_DATA, encrypted_m5);

        let m6 = service.handle(&mut session, PairingEndpoint::Setup, &m5.encode());
        let m6_tlv = Tlv::parse(&m6.body);

        assert_eq!(m6_tlv.first(TLV_STATE), Some([6].as_slice()));
        assert!(m6_tlv.first(TLV_ERROR).is_none());
        assert!(session.verified);
        // Completion signal is present
        assert!(m6.completion.is_some());
        assert!(
            matches!(m6.completion, Some(PairingCompletion::FullSetup { ref client_id, .. }) if *client_id == expected_id)
        );

        // Verify client was persisted to DB
        let db = service.db.read();
        assert!(db.find_client(expected_id).is_some());

        // Verify M6 can be decrypted
        let encrypted = m6_tlv.joined(TLV_ENCRYPTED_DATA).unwrap();
        let plaintext = open(&enc_key, &nonce_from_label(b"PS-Msg06"), &[], &encrypted).unwrap();
        let inner = Tlv::parse(&plaintext);
        assert_eq!(
            inner.first(TLV_IDENTIFIER),
            Some(service.device_id.as_bytes())
        );
        assert_eq!(
            inner.first(TLV_PUBLIC_KEY),
            Some(service.identity.verifying_key().as_slice())
        );
        assert_eq!(inner.first(TLV_SIGNATURE).unwrap().len(), 64);
    }

    #[test]
    fn tlv_error_http_200_never_completes() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();

        // M1
        let mut m1 = Tlv::default();
        m1.insert(TLV_METHOD, [1]); // unsupported method → should fail
        m1.insert(TLV_STATE, [1]);

        let reply = service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());
        assert_eq!(reply.status_code, 200);
        let tlv = Tlv::parse(&reply.body);
        assert!(tlv.first(TLV_ERROR).is_some());
        assert!(reply.completion.is_none());
    }

    #[test]
    fn tlv_error_in_transient_setup_m3_never_completes() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();

        // M1: valid
        let mut m1 = Tlv::default();
        m1.insert(TLV_METHOD, [0]);
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_FLAGS, [PAIRING_FLAGS_TRANSIENT]);
        service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());

        // M3: corrupted client proof
        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_PUBLIC_KEY, vec![0u8; 384]);
        m3.insert(TLV_PROOF, vec![0x00u8; 64]);
        let reply = service.handle(&mut session, PairingEndpoint::Setup, &m3.encode());
        assert_eq!(reply.status_code, 200);
        let tlv = Tlv::parse(&reply.body);
        assert!(tlv.first(TLV_ERROR).is_some());
        assert!(reply.completion.is_none());
        assert!(!session.verified);
    }

    // ── Verify tests ─────────────────────────────────────────────────

    #[test]
    fn verify_m1_includes_ephemeral_key_and_signature() {
        let service = test_pairing_service();
        let client = AgreementKey::generate();
        let mut input = Tlv::default();
        input.insert(TLV_STATE, [1]);
        input.insert(TLV_PUBLIC_KEY, client.public_key());
        let mut session = PairingSession::default();
        let reply = service.handle(&mut session, PairingEndpoint::Verify, &input.encode());
        let tlv = Tlv::parse(&reply.body);
        assert_eq!(tlv.first(TLV_PUBLIC_KEY).unwrap().len(), 32);
        assert!(tlv.first(TLV_ENCRYPTED_DATA).unwrap().len() > 64);
        assert!(session.verify_session_key.is_some());
        assert!(reply.completion.is_none()); // not complete yet
    }

    #[test]
    fn verify_m3_fails_when_client_not_in_db() {
        let service = test_pairing_service();
        let client = AgreementKey::generate();
        let client_ed25519 = IdentityKey::generate();
        let client_identifier = b"test-client";
        let mut session = PairingSession::default();

        // M1
        let mut m1 = Tlv::default();
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_PUBLIC_KEY, client.public_key());
        let m2 = service.handle(&mut session, PairingEndpoint::Verify, &m1.encode());
        let m2_tlv = Tlv::parse(&m2.body);
        let server_public = as_32_bytes(m2_tlv.first(TLV_PUBLIC_KEY).unwrap()).unwrap();

        let shared = client.shared_secret(&server_public);
        let key = hkdf_sha512(
            &shared,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        );

        // Construct the signed message: client_pub || identifier || server_pub
        let mut signed_msg = Vec::with_capacity(32 + 32 + client_identifier.len());
        signed_msg.extend_from_slice(&client.public_key());
        signed_msg.extend_from_slice(client_identifier);
        signed_msg.extend_from_slice(&server_public);
        let signature = client_ed25519.sign(&signed_msg);

        // M3 with valid signature but client not in DB
        let mut inner = Tlv::default();
        inner.insert(TLV_IDENTIFIER, client_identifier);
        inner.insert(TLV_SIGNATURE, signature);

        let encrypted = seal(&key, &nonce_from_label(b"PV-Msg03"), &[], &inner.encode()).unwrap();
        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_ENCRYPTED_DATA, encrypted);
        let m4 = service.handle(&mut session, PairingEndpoint::Verify, &m3.encode());
        let m4_tlv = Tlv::parse(&m4.body);

        assert!(m4_tlv.first(TLV_ERROR).is_some());
        assert!(m4.completion.is_none());
        assert!(!session.verified);
    }

    #[test]
    fn verify_m3_completion_signals_after_success() {
        let client_ed25519 = IdentityKey::generate();
        let client_identifier = b"test-client";

        // Pre-pair the client
        let mut db = PairingDatabase {
            allowed_clients: Vec::new(),
        };
        db.add_client(
            String::from_utf8_lossy(client_identifier).to_string(),
            client_ed25519.verifying_key(),
        );

        let service = PairingService {
            identity: IdentityKey::generate(),
            device_id: "00:11:22:33:44:55".to_string(),
            pin_text: "3939".to_string(),
            db_path: None,
            db: parking_lot::RwLock::new(db),
        };

        let client = AgreementKey::generate();
        let mut session = PairingSession::default();

        // M1
        let mut m1 = Tlv::default();
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_PUBLIC_KEY, client.public_key());
        let m2 = service.handle(&mut session, PairingEndpoint::Verify, &m1.encode());
        let m2_tlv = Tlv::parse(&m2.body);
        let server_public = as_32_bytes(m2_tlv.first(TLV_PUBLIC_KEY).unwrap()).unwrap();

        let shared = client.shared_secret(&server_public);
        let key = hkdf_sha512(
            &shared,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        );

        let mut signed_msg = Vec::with_capacity(32 + 32 + client_identifier.len());
        signed_msg.extend_from_slice(&client.public_key());
        signed_msg.extend_from_slice(client_identifier);
        signed_msg.extend_from_slice(&server_public);
        let signature = client_ed25519.sign(&signed_msg);

        let mut inner = Tlv::default();
        inner.insert(TLV_IDENTIFIER, client_identifier);
        inner.insert(TLV_SIGNATURE, signature);

        let encrypted = seal(&key, &nonce_from_label(b"PV-Msg03"), &[], &inner.encode()).unwrap();
        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_ENCRYPTED_DATA, encrypted);
        let m4 = service.handle(&mut session, PairingEndpoint::Verify, &m3.encode());
        let m4_tlv = Tlv::parse(&m4.body);

        assert_eq!(m4_tlv.first(TLV_STATE), Some([4].as_slice()));
        assert!(m4_tlv.first(TLV_ERROR).is_none());
        assert!(session.verified);
        assert!(m4.completion.is_some());
        assert!(matches!(
            m4.completion,
            Some(PairingCompletion::Verify { .. })
        ));
    }

    #[test]
    fn control_secret_prefers_verified_pair_verify_secret() {
        let mut session = PairingSession::default();
        session.setup_session_key = Some([0x11; 64]);
        session.verify_shared_secret = Some([0x22; 32]);
        session.verified = true;
        assert_eq!(session.control_secret(), Some([0x22; 32].as_slice()));
    }

    // ── Stale state reset tests ──────────────────────────────────────

    #[test]
    fn setup_m1_resets_stale_setup_state() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();

        // Start a setup
        let mut m1 = Tlv::default();
        m1.insert(TLV_METHOD, [0]);
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_FLAGS, [PAIRING_FLAGS_TRANSIENT]);
        service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());
        assert!(session.setup.is_some());
        assert!(session.setup_session_key.is_none());

        // Send another M1 — should reset the stale setup
        let reply = service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());
        assert!(reply.completion.is_none());
        assert!(session.setup.is_some()); // new setup created
    }

    #[test]
    fn auth_failure_in_setup_m3_resets_state() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();

        // M1
        let mut m1 = Tlv::default();
        m1.insert(TLV_METHOD, [0]);
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_FLAGS, [PAIRING_FLAGS_TRANSIENT]);
        service.handle(&mut session, PairingEndpoint::Setup, &m1.encode());
        assert!(session.setup.is_some());

        // M3: corrupted
        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_PUBLIC_KEY, vec![0u8; 384]);
        m3.insert(TLV_PROOF, vec![0x00u8; 64]);
        let reply = service.handle(&mut session, PairingEndpoint::Setup, &m3.encode());
        assert!(Tlv::parse(&reply.body).first(TLV_ERROR).is_some());
        assert!(session.setup.is_none()); // reset on failure
    }

    #[test]
    fn verify_m1_resets_stale_verify_state() {
        let service = test_pairing_service();
        let client = AgreementKey::generate();
        let mut session = PairingSession::default();

        // First M1
        let mut m1 = Tlv::default();
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_PUBLIC_KEY, client.public_key());
        service.handle(&mut session, PairingEndpoint::Verify, &m1.encode());
        assert!(session.verify_session_key.is_some());

        // Second M1 — should reset
        service.handle(&mut session, PairingEndpoint::Verify, &m1.encode());
        assert!(session.verify_session_key.is_some());
    }

    #[test]
    fn auth_failure_in_verify_m3_resets_state() {
        let service = test_pairing_service();
        let client = AgreementKey::generate();
        let mut session = PairingSession::default();

        // M1
        let mut m1 = Tlv::default();
        m1.insert(TLV_STATE, [1]);
        m1.insert(TLV_PUBLIC_KEY, client.public_key());
        service.handle(&mut session, PairingEndpoint::Verify, &m1.encode());
        assert!(session.verify_session_key.is_some());

        // M3: corrupted encrypted data
        let mut m3 = Tlv::default();
        m3.insert(TLV_STATE, [3]);
        m3.insert(TLV_ENCRYPTED_DATA, vec![0u8; 32]);
        let reply = service.handle(&mut session, PairingEndpoint::Verify, &m3.encode());
        assert!(Tlv::parse(&reply.body).first(TLV_ERROR).is_some());
        assert!(!session.verified);
        assert!(session.verify_session_key.is_none()); // reset on failure
    }

    #[test]
    fn unsupported_pairing_state_clears_stale_exchange() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();
        session.setup_session_key = Some([0x41; 64]);
        session.verify_shared_secret = Some([0x42; 32]);
        session.verified = true;
        let mut request = Tlv::default();
        request.insert(TLV_STATE, [9]);
        let reply = service.handle(&mut session, PairingEndpoint::Setup, &request.encode());
        assert!(Tlv::parse(&reply.body).first(TLV_ERROR).is_some());
        assert!(session.setup_session_key.is_none());
    }

    // ── Pair management auth gate tests ──────────────────────────────

    #[test]
    fn pair_add_rejects_unverified_session() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();
        let mut body = Tlv::default();
        body.insert(TLV_ENCRYPTED_DATA, vec![0u8; 10]);
        let reply = service.handle(&mut session, PairingEndpoint::Add, &body.encode());
        let tlv = Tlv::parse(&reply.body);
        assert!(tlv.first(TLV_ERROR).is_some());
    }

    #[test]
    fn pair_remove_rejects_unverified_session() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();
        let mut body = Tlv::default();
        body.insert(TLV_ENCRYPTED_DATA, vec![0u8; 10]);
        let reply = service.handle(&mut session, PairingEndpoint::Remove, &body.encode());
        let tlv = Tlv::parse(&reply.body);
        assert!(tlv.first(TLV_ERROR).is_some());
    }

    #[test]
    fn pair_list_rejects_unverified_session() {
        let service = test_pairing_service();
        let mut session = PairingSession::default();
        let reply = service.handle(&mut session, PairingEndpoint::List, &[]);
        let tlv = Tlv::parse(&reply.body);
        assert!(tlv.first(TLV_ERROR).is_some());
    }

    // ── Zeroization test ─────────────────────────────────────────────

    #[test]
    fn reset_setup_zeros_session_key() {
        let mut session = PairingSession::default();
        session.setup_session_key = Some([0xabu8; 64]);
        let _key_ptr = session.setup_session_key.as_ref().unwrap().as_ptr();

        session.reset_setup();
        // Keys should be zero
        assert!(session.setup_session_key.is_none());
        // The memory that was at key_ptr is now freed; this is a best-effort
        // smoke test. In practice, we rely on the Drop impl.
    }

    #[test]
    fn pairing_session_clear_zeros_all() {
        let mut session = PairingSession::default();
        session.setup_session_key = Some([0x42u8; 64]);
        session.verify_shared_secret = Some([0x43u8; 32]);
        session.verify_session_key = Some(hkdf_sha512(b"test", b"salt", b"info"));
        session.verified = true;
        session.client_device_id = Some("test-device".to_string());

        session.clear();

        assert!(session.setup_session_key.is_none());
        assert!(session.verify_shared_secret.is_none());
        assert!(!session.verified);
        assert!(session.client_device_id.is_none());
    }

    // ── Secret logging guard ─────────────────────────────────────────

    #[test]
    fn production_logs_do_not_format_secret_material() {
        let production = include_str!("pairing.rs")
            .split_once("// END PRODUCTION PAIRING SOURCE")
            .map(|(production, _)| production)
            .expect("production source boundary marker");
        for forbidden in [
            "hex_prefix(",
            "shared_secret = %",
            "session_key = %",
            "server_private = %",
            "premaster = %",
            "enc_key = %",
            "plaintext = %",
            "decrypted = %",
            "first={}",
        ] {
            assert!(
                !production.contains(forbidden),
                "secret logging fragment present: {forbidden}"
            );
        }
    }

    #[test]
    fn setup_m6_includes_accessory_public_key() {
        let service = test_pairing_service();
        let session_key = [0x42u8; 64];
        let reply_tlv = service.setup_m6(&session_key).unwrap();
        let encrypted = reply_tlv.joined(TLV_ENCRYPTED_DATA).unwrap();
        let enc_key = hkdf_sha512(
            &session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        );
        let plaintext = open(&enc_key, &nonce_from_label(b"PS-Msg06"), &[], &encrypted).unwrap();
        let inner = Tlv::parse(&plaintext);

        assert_eq!(
            inner.first(TLV_IDENTIFIER),
            Some(service.device_id.as_bytes())
        );
        assert_eq!(
            inner.first(TLV_PUBLIC_KEY),
            Some(service.identity.verifying_key().as_slice())
        );
        assert_eq!(inner.first(TLV_SIGNATURE).unwrap().len(), 64);
    }
}
