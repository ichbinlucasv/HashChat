//! Shared Argon2id + AES-256-GCM at-rest envelope (audit H2).
//!
//! Format: `[version(1) | salt(16) | nonce(12) | ciphertext+tag]`
//! Empty passphrase is always refused — there is no silent weak path here.

use argon2::{Argon2, Params, Version};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use zeroize::Zeroize;

const ARGON_MEM_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON_ITERS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const ENVELOPE_VERSION: u8 = 1;

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32], &'static str> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_ITERS, ARGON_PARALLELISM, Some(32))
        .map_err(|_| "bad argon params")?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| "argon2 kdf failed")?;
    Ok(key)
}

/// Seal `plaintext` under Argon2id(passphrase). Refuses empty passphrase.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if passphrase.is_empty() {
        return Err("empty passphrase refused");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut key = derive_key_argon2id(passphrase, &salt)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "aead key error")?;
    key.zeroize();
    let lsk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.to_vec();
    lsk.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "encryption failed")?;

    let mut envelope = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + buf.len());
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&buf);
    Ok(envelope)
}

/// Open an envelope produced by [`seal`]. Refuses empty passphrase.
pub fn open(passphrase: &[u8], envelope: &[u8]) -> Result<Vec<u8>, &'static str> {
    if passphrase.is_empty() {
        return Err("empty passphrase refused");
    }
    if envelope.len() < 1 + SALT_LEN + NONCE_LEN + 16 {
        return Err("envelope too short");
    }
    if envelope[0] != ENVELOPE_VERSION {
        return Err("unsupported envelope version");
    }

    let salt: [u8; SALT_LEN] = envelope[1..1 + SALT_LEN]
        .try_into()
        .map_err(|_| "bad salt")?;
    let nonce_bytes: [u8; NONCE_LEN] = envelope[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| "bad nonce")?;
    let ciphertext = &envelope[1 + SALT_LEN + NONCE_LEN..];

    let mut key = derive_key_argon2id(passphrase, &salt)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "aead key error")?;
    key.zeroize();
    let lsk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = ciphertext.to_vec();
    let plain = lsk
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "decryption failed")?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let env = seal(b"correct horse battery", b"secret-bytes").unwrap();
        let out = open(b"correct horse battery", &env).unwrap();
        assert_eq!(out, b"secret-bytes");
    }

    #[test]
    fn empty_passphrase_refused() {
        assert!(seal(b"", b"x").is_err());
        assert!(open(b"", &[1u8; 64]).is_err());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let env = seal(b"right", b"payload").unwrap();
        assert!(open(b"wrong", &env).is_err());
    }
}
