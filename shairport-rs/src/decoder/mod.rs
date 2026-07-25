use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{Oaep, RsaPrivateKey};
use sha1::Sha1;
use std::sync::LazyLock;

/// Decode standard base64 input that may be missing trailing `=` padding.
///
/// Apple's AirPlay implementations routinely strip padding from base64
/// strings (Apple-Challenge, rsaaeskey, aesiv, etc.).  The standard
/// `base64` crate rejects unpadded input, so this helper pads the input
/// to a multiple of 4 before decoding.
pub fn tolerant_base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // Pad to a multiple of 4 with '=' characters.
    let padding_needed = (4 - (trimmed.len() % 4)) % 4;
    let mut padded = String::with_capacity(trimmed.len() + padding_needed);
    padded.push_str(trimmed);
    for _ in 0..padding_needed {
        padded.push('=');
    }
    base64::engine::general_purpose::STANDARD.decode(&padded)
}

type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Decrypt an AES-128-CBC encrypted payload in place.
/// `key` must be 16 bytes. `iv` must be 16 bytes.
/// Only complete 16-byte blocks are decrypted; any trailing partial block
/// is left unchanged. This matches the classic Shairport Sync C behaviour.
pub fn aes_cbc_decrypt_in_place(
    key: &[u8; 16],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<(), &'static str> {
    let full_blocks_len = data.len() & !0xf;
    if full_blocks_len == 0 {
        return Ok(()); // nothing to decrypt
    }
    let plaintext = Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut data[..full_blocks_len])
        .map_err(|_| "AES-CBC decryption failed")?;
    let _ = plaintext;
    Ok(())
}

// ---------------------------------------------------------------------------
// Classic Shairport Sync / AirPort Express RSA 2048-bit private key.
// This is the well-known key that Apple's AirPlay (RAOP) senders encrypt
// the AES session key against. It is NOT a secret — every open-source
// AirPlay receiver embeds it.
// ---------------------------------------------------------------------------

const CLASSIC_AIRPLAY_RSA_PEM_BODY: &str = "\
MIIEpQIBAAKCAQEA59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUt\
wC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4U\
wPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf\
/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/\
UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEewIDAQABAoIBAQDl8Axy9XfW\
BLmkzkEiqoSwF0PsmVrPzH9KsnwLGH+QZlvjWd8SWYGN7u1507HvhF5N3drJoVU3O14nDY4TFQAa\
LlJ9VM35AApXaLyY1ERrN7u9ALKd2LUwYhM7Km539O4yUFYikE2nIPscEsA5ltpxOgUGCY7b7ez5\
NtD6nL1ZKauw7aNXmVAvmJTcuPxWmoktF3gDJKK2wxZuNGcJE0uFQEG4Z3BrWP7yoNuSK3dii2jm\
lpPHr0O/KnPQtzI3eguhe0TwUem/eYSdyzMyVx/YpwkzwtYL3sR5k0o9rKQLtvLzfAqdBxBurciz\
aaA/L0HIgAmOit1GJA2saMxTVPNhAoGBAPfgv1oeZxgxmotiCcMXFEQEWflzhWYTsXrhUIuz5jFu\
a39GLS99ZEErhLdrwj8rDDViRVJ5skOp9zFvlYAHs0xh92ji1E7V/ysnKBfsMrPkk5KSKPrnjndM\
oPdevWnVkgJ5jxFuNgxkOLMuG9i53B4yMvDTCRiIPMQ++N2iLDaRAoGBAO9v//mU8eVkQaoANf0Z\
oMjW8CN4xwWA2cSEIHkd9AfFkftuv8oyLDCG3ZAf0vrhrrtkrfa7ef+AUb69DNggq4mHQAYBp7L+\
k5DKzJrKuO0r+R0YbY9pZD1+/g9dVt91d6LQNepUE/yY2PP5CNoFmjedpLHMOPFdVgqDzDFxU8hL\
AoGBANDrr7xAJbqBjHVwIzQ4To9pb4BNeqDndk5Qe7fT3+/H1njGaC0/rXE0Qb7q5ySgnsCb3DvA\
cJyRM9SJ7OKlGt0FMSdJD5KG0XPIpAVNwgpXXH5MDJg09KHeh0kXo+QA6viFBi21y340NonnEfdf\
54PX4ZGS/Xac1UK+pLkBB+zRAoGAf0AY3H3qKS2lMEI4bzEFoHeK3G895pDaK3TFBVmD7fV0Zhov\
17fegFPMwOII8MisYm9ZfT2Z0s5Ro3s5rkt+nvLAdfC/PYPKzTLalpGSwomSNYJcB9HNMlmhkGzc\
1JnLYT4iyUyx6pcZBmCd8bD0iwY/FzcgNDaUmbX9+XDvRA0CgYEAkE7pIPlE71qvfJQgoA9em0gI\
LAuE4Pu13aKiJnfft7hIjbK+5kyb3TysZvoyDnb3HOKvInK7vXbKuU4ISgxB2bB3HcYzQMGsz1qJ\
2gG0N5hvJpzwwhbhXqFKA4zaaSrw622wDniAK5MlIE0tIAKKP4yxNGjoD2QYjhBGuhvkWKY=";

static CLASSIC_RSA_KEY: LazyLock<RsaPrivateKey> = LazyLock::new(|| {
    let der = tolerant_base64_decode(CLASSIC_AIRPLAY_RSA_PEM_BODY)
        .expect("failed to base64-decode classic AirPlay RSA key body");
    rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(&der)
        .expect("failed to parse classic AirPlay RSA private key")
});

/// Return a reference to the well-known classic AirPlay RSA private key.
pub fn classic_rsa_private_key() -> &'static RsaPrivateKey {
    &CLASSIC_RSA_KEY
}

/// Decrypt an RSA-OAEP-SHA1 encrypted blob using the classic AirPlay private key.
/// This is used to unwrap the `rsaaeskey` field from the SDP ANNOUNCE.
pub fn classic_rsa_oaep_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    CLASSIC_RSA_KEY
        .decrypt(Oaep::new::<Sha1>(), ciphertext)
        .map_err(|_| "RSA-OAEP decryption of AES key failed")
}

/// Sign data with RSA PKCS1 v1.5 (unprefixed, no hash) using the classic key.
/// This is used for the Apple-Challenge → Apple-Response flow.
pub fn classic_rsa_pkcs1_sign(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    CLASSIC_RSA_KEY
        .sign(Pkcs1v15Sign::new_unprefixed(), data)
        .map_err(|_| "RSA PKCS1v1.5 signing failed")
}

/// Generate a 2048-bit RSA private key (for tests / diagnostic use only —
/// AirPlay crypto must use the classic embedded key above).
pub fn generate_rsa_key() -> RsaPrivateKey {
    let mut rng = rand_core::OsRng;
    RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key")
}

/// Decrypt an RSA-OAEP-SHA1 encrypted blob using an arbitrary private key
/// (for tests / diagnostic use).
pub fn rsa_oaep_decrypt(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    private_key
        .decrypt(Oaep::new::<Sha1>(), ciphertext)
        .map_err(|_| "RSA-OAEP decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::Oaep;
    use rsa::traits::PublicKeyParts;

    // -----------------------------------------------------------------------
    // AES-CBC
    // -----------------------------------------------------------------------

    #[test]
    fn aes_cbc_decrypts_full_blocks() {
        // Known test vector: AES-128-CBC, key=2b.., iv=01.., plaintext=10..
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<Aes128>;

        let key = [0x2bu8; 16];
        let iv = [0x01u8; 16];
        let plaintext = [0x10u8; 32];
        let mut ciphertext = plaintext;
        Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut ciphertext, 32)
            .unwrap();

        let mut decrypted = ciphertext;
        aes_cbc_decrypt_in_place(&key, &iv, &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_cbc_leaves_trailing_bytes_unchanged() {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<Aes128>;

        let key = [0xabu8; 16];
        let iv = [0x06u8; 16];
        // 17 bytes: 16-byte block + 1 extra trailing byte
        let plaintext: [u8; 17] = [0x42; 17];
        let mut ciphertext = [0u8; 17];
        // Encrypt only the first 16 bytes in CBC mode
        {
            let mut block: [u8; 16] = plaintext[..16].try_into().unwrap();
            Aes128CbcEnc::new(&key.into(), &iv.into())
                .encrypt_padded_mut::<NoPadding>(&mut block, 16)
                .unwrap();
            ciphertext[..16].copy_from_slice(&block);
        }
        ciphertext[16] = 0xFF; // trailing byte

        let mut decrypted = ciphertext;
        aes_cbc_decrypt_in_place(&key, &iv, &mut decrypted).unwrap();
        // First 16 bytes should be recovered
        assert_eq!(&decrypted[..16], &plaintext[..16]);
        // Trailing byte should be unchanged
        assert_eq!(decrypted[16], 0xFF);
    }

    #[test]
    fn aes_cbc_empty_no_panic() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let mut data = [0u8; 0];
        assert!(aes_cbc_decrypt_in_place(&key, &iv, &mut data).is_ok());
    }

    #[test]
    fn aes_cbc_short_blocks_no_panic() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let mut data = [0x42u8; 15]; // less than one full block
        let original = data;
        aes_cbc_decrypt_in_place(&key, &iv, &mut data).unwrap();
        assert_eq!(data, original, "data < 16 bytes must be unchanged");
    }

    // -----------------------------------------------------------------------
    // tolerant_base64_decode
    // -----------------------------------------------------------------------

    #[test]
    fn tolerant_base64_padded() {
        let input = "AQIDBAUGBwgJCgsMDQ4PEA==";
        let decoded = tolerant_base64_decode(input).unwrap();
        assert_eq!(
            decoded,
            &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn tolerant_base64_unpadded() {
        // Apple convention: trailing '=' stripped
        let input = "AQIDBAUGBwgJCgsMDQ4PEA";
        let decoded = tolerant_base64_decode(input).unwrap();
        assert_eq!(
            decoded,
            &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            "unpadded base64 must decode correctly"
        );
    }

    #[test]
    fn tolerant_base64_empty() {
        assert_eq!(tolerant_base64_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(tolerant_base64_decode("  ").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn tolerant_base64_rejects_invalid() {
        // '!' is not in the base64 alphabet
        assert!(tolerant_base64_decode("!!!!").is_err());
    }

    // -----------------------------------------------------------------------
    // Classic RSA key
    // -----------------------------------------------------------------------

    #[test]
    fn classic_rsa_key_parses() {
        let key = classic_rsa_private_key();
        assert!(key.n().bits() >= 2048);
        // Sanity: validate() should succeed
        key.validate().expect("classic key should validate");
    }

    #[test]
    fn classic_rsa_oaep_round_trip() {
        let key = classic_rsa_private_key();
        let data = b"hello alac world!";
        let mut rng = rand_core::OsRng;
        let pub_key = rsa::RsaPublicKey::from(key.clone());
        let encrypted = pub_key
            .encrypt(&mut rng, Oaep::new::<Sha1>(), data)
            .expect("RSA encrypt");
        let decrypted = classic_rsa_oaep_decrypt(&encrypted).expect("RSA OAEP decrypt");
        assert_eq!(&decrypted, data);
    }

    #[test]
    fn classic_rsa_pkcs1_sign_round_trip() {
        let key = classic_rsa_private_key();
        let msg = b"test challenge payload";
        let sig = classic_rsa_pkcs1_sign(msg).expect("signing");
        // Verify with the public key
        let pub_key: rsa::RsaPublicKey = key.clone().into();
        pub_key
            .verify(Pkcs1v15Sign::new_unprefixed(), msg, &sig)
            .expect("verification failed");
        // Signature length should equal key size (256 bytes for 2048-bit)
        assert_eq!(sig.len(), key.size());
    }

    // -----------------------------------------------------------------------
    // generate_rsa_key / rsa_oaep_decrypt (diagnostic helpers)
    // -----------------------------------------------------------------------

    #[test]
    fn rsa_key_generates() {
        let key = generate_rsa_key();
        assert!(key.n().bits() >= 2048);
    }

    #[test]
    fn rsa_oaep_round_trip() {
        let key = generate_rsa_key();
        let data = b"hello alac world!";
        let mut rng = rand_core::OsRng;
        let pub_key = rsa::RsaPublicKey::from(&key);
        let encrypted = pub_key
            .encrypt(&mut rng, Oaep::new::<Sha1>(), data)
            .expect("RSA encrypt");
        let decrypted = rsa_oaep_decrypt(&key, &encrypted).expect("RSA decrypt");
        assert_eq!(&decrypted, data);
    }
}
