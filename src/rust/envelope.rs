//! Shared Argon2id + AES-256-GCM at-rest envelope (audit H2).
//!
//! Format: `[version(1) | salt(16) | nonce(12) | ciphertext+tag]`
//! Empty passphrase is always refused — there is no silent weak path here.
//! Salts and nonces come from the OS CSPRNG (`getrandom`); failures are errors.

use argon2::{Argon2, Params, Version};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Argon2id-derived store key together with the salt it was derived with.
///
/// Lets a caller unlock once and keep only this 32-byte key (not the
/// passphrase) for later saves. Sealing with it writes the same envelope format
/// (the salt goes in the header as before) with a fresh random nonce per seal,
/// so repeated saves reuse the salt but never a (key, nonce) pair in practice
/// (96-bit random nonces; save counts are far below the GCM random-nonce bound).
///
/// Zeroized on drop. Deliberately no `Debug`, `Clone` or accessor for the key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StoreKey {
    salt: [u8; SALT_LEN],
    key: [u8; 32],
}

impl StoreKey {
    /// Derive a key under a fresh random salt (new store / first save).
    pub fn derive_new(passphrase: &[u8]) -> Result<Self, &'static str> {
        if passphrase.is_empty() {
            return Err("empty passphrase refused");
        }
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|_| "csprng failed")?;
        let key = derive_key_argon2id(passphrase, &salt)?;
        Ok(Self { salt, key })
    }

    /// Derive the key for an existing envelope, using the salt in its header.
    /// Does not check the passphrase; [`open_with_key`] does (AEAD tag).
    pub fn derive_for_envelope(passphrase: &[u8], envelope: &[u8]) -> Result<Self, &'static str> {
        if passphrase.is_empty() {
            return Err("empty passphrase refused");
        }
        let (salt, _, _) = split_envelope(envelope)?;
        let key = derive_key_argon2id(passphrase, &salt)?;
        Ok(Self { salt, key })
    }

    /// Best-effort `mlock` of the key bytes (Linux). Keep the `StoreKey` at a
    /// stable address (e.g. boxed) for this to be meaningful.
    pub fn mlock_best_effort(&self) -> bool {
        crate::mlock_bytes(&self.key)
    }
}

fn split_envelope(envelope: &[u8]) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], &[u8]), &'static str> {
    if envelope.len() < 1 + SALT_LEN + NONCE_LEN + 16 {
        return Err("envelope too short");
    }
    if envelope[0] != ENVELOPE_VERSION {
        return Err("unsupported envelope version");
    }
    let salt: [u8; SALT_LEN] = envelope[1..1 + SALT_LEN]
        .try_into()
        .map_err(|_| "bad salt")?;
    let nonce: [u8; NONCE_LEN] = envelope[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| "bad nonce")?;
    Ok((salt, nonce, &envelope[1 + SALT_LEN + NONCE_LEN..]))
}

/// Seal with an already-derived key. Same format as [`seal`].
pub fn seal_with_key(k: &StoreKey, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| "csprng failed")?;
    let unbound = UnboundKey::new(&AES_256_GCM, &k.key).map_err(|_| "aead key error")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Sealed in place: after success `body` holds only ciphertext + tag.
    let mut body = Vec::with_capacity(plaintext.len() + 16);
    body.extend_from_slice(plaintext);
    if lsk
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
        .is_err()
    {
        body.zeroize();
        return Err("encryption failed");
    }
    let mut envelope = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + body.len());
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&k.salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&body);
    Ok(envelope)
}

/// Open with an already-derived key. The envelope's salt must match the key's
/// (otherwise the key was derived for a different store / passphrase epoch).
pub fn open_with_key(k: &StoreKey, envelope: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (salt, nonce_bytes, ciphertext) = split_envelope(envelope)?;
    let same_salt: bool = subtle::ConstantTimeEq::ct_eq(&salt[..], &k.salt[..]).into();
    if !same_salt {
        return Err("store key does not match envelope");
    }
    let unbound = UnboundKey::new(&AES_256_GCM, &k.key).map_err(|_| "aead key error")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = ciphertext.to_vec();
    let out = match lsk.open_in_place(nonce, Aad::empty(), &mut buf) {
        Ok(plain) => Ok(plain.to_vec()),
        Err(_) => Err("decryption failed"),
    };
    buf.zeroize();
    out
}

/// Seal `plaintext` under Argon2id(passphrase) with a fresh salt. Refuses empty passphrase.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let k = StoreKey::derive_new(passphrase)?;
    seal_with_key(&k, plaintext)
}

/// Open an envelope produced by [`seal`] / [`seal_with_key`]. Refuses empty passphrase.
pub fn open(passphrase: &[u8], envelope: &[u8]) -> Result<Vec<u8>, &'static str> {
    let k = StoreKey::derive_for_envelope(passphrase, envelope)?;
    open_with_key(&k, envelope)
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
    fn seal_with_key_matches_passphrase_format() {
        let k = StoreKey::derive_new(b"pass phrase one").unwrap();
        let env = seal_with_key(&k, b"payload").unwrap();
        assert_eq!(env[0], ENVELOPE_VERSION);
        assert_eq!(open(b"pass phrase one", &env).unwrap(), b"payload");
        assert!(open(b"pass phrase two", &env).is_err());
        let k2 = StoreKey::derive_for_envelope(b"pass phrase one", &env).unwrap();
        assert_eq!(open_with_key(&k2, &env).unwrap(), b"payload");
        // Wrong passphrase with the right salt: derives, but AEAD fails.
        let bad = StoreKey::derive_for_envelope(b"nope nope nope", &env).unwrap();
        assert!(open_with_key(&bad, &env).is_err());
        assert!(StoreKey::derive_for_envelope(b"x", &env[..10]).is_err());
    }

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
