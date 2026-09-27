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

/// Minimum passphrase length (Unicode scalars) for a **new** store, Standard posture.
pub const MIN_NEW_PASSPHRASE_CHARS: usize = 12;
/// Minimum passphrase length for a new store under Extreme posture.
pub const MIN_NEW_PASSPHRASE_CHARS_EXTREME: usize = 16;
/// Minimum number of distinct characters (rejects e.g. one key held down).
const MIN_DISTINCT_CHARS: usize = 5;

/// Creation-time floor for the at-rest passphrase. `state.enc` can be attacked
/// offline, and Argon2id does not rescue a very short passphrase. Existing
/// stores are not re-checked on unlock. The error never echoes the input.
pub fn check_new_passphrase(pass: &str, extreme: bool) -> Result<(), &'static str> {
    let min = if extreme {
        MIN_NEW_PASSPHRASE_CHARS_EXTREME
    } else {
        MIN_NEW_PASSPHRASE_CHARS
    };
    let n = pass.chars().count();
    if n < min {
        return Err(if extreme {
            "passphrase too short (Extreme: at least 16 characters)"
        } else {
            "passphrase too short (at least 12 characters)"
        });
    }
    if pass.trim().chars().count() < min {
        return Err("passphrase is mostly whitespace");
    }
    let mut distinct: Vec<char> = Vec::with_capacity(MIN_DISTINCT_CHARS);
    for c in pass.chars() {
        if !distinct.contains(&c) {
            distinct.push(c);
            if distinct.len() >= MIN_DISTINCT_CHARS {
                break;
            }
        }
    }
    let enough = distinct.len() >= MIN_DISTINCT_CHARS;
    distinct.zeroize();
    if !enough {
        return Err("passphrase too repetitive");
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn new_passphrase_floor() {
        assert!(check_new_passphrase("", false).is_err());
        assert!(check_new_passphrase("short", false).is_err());
        assert!(check_new_passphrase("elevenchars", false).is_err());
        assert!(check_new_passphrase("aaaaaaaaaaaaaaaa", false).is_err());
        assert!(check_new_passphrase("abababababababab", false).is_err());
        assert!(check_new_passphrase("      abcdef      ", false).is_err());
        assert!(check_new_passphrase("twelve chars", false).is_ok());
        assert!(check_new_passphrase("correct horse battery", false).is_ok());
        // Extreme needs 16.
        assert!(check_new_passphrase("fifteen chars!!", true).is_err());
        assert!(check_new_passphrase("sixteen chars ok", true).is_ok());
        // Counted in characters, not bytes.
        assert!(check_new_passphrase("äöüéèàçñßøåæ", false).is_ok());
        assert!(check_new_passphrase("äöüéèàçñß", false).is_err());
        // Errors never echo input.
        let e = check_new_passphrase("hunter2", false).unwrap_err();
        assert!(!e.contains("hunter2"));
    }
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
