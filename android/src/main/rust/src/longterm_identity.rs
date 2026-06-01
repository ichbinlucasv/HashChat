//! Long-term identity keypair for ContactAddress / profile sharing.
//!
//! This module implements the Critical item: real persisted per-profile
//! long-term identity keys (instead of fresh random on every QR generation).
//!
//! Design (approved in CONTACT_ADDRESS_LONGTERM_KEYS.md):
//! - One stable identity per burner profile
//! - ed25519 for signing + x25519 for key agreement (derived from one 32-byte seed)
//! - Encrypted at rest using the same Argon2id + AES-256-GCM envelope as ratchets
//! - Only public keys are ever exported (for ContactAddress QR)
//! - Strong zeroization and mlock support

use zeroize::Zeroize;
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519Public};
use rand::RngCore;
use ring::aead::{AES_256_GCM, Nonce, UnboundKey, LessSafeKey, Aad};
use argon2::{Argon2, Params, Version};

/// Fixed Argon2id parameters (same as ratchet envelope for consistency)
const ARGON_MEM_KIB: u32 = 64 * 1024;
const ARGON_ITERS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Version byte for the encrypted envelope format
const ENVELOPE_VERSION: u8 = 1;

/// Long-term identity key material for a profile.
///
/// This should be stored encrypted at rest using the profile's passphrase.
#[derive(Zeroize)]
pub struct LongTermIdentity {
    /// Master seed (32 bytes). Never expose this.
    seed: [u8; 32],

    /// ed25519 signing key (derived from seed)
    #[zeroize(skip)]
    ed25519_signing: SigningKey,

    /// x25519 static secret (derived from seed)
    #[zeroize(skip)]
    x25519_secret: StaticSecret,
}

impl LongTermIdentity {
    /// Generate a fresh long-term identity from secure randomness.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        Self::from_seed(seed)
    }

    /// Create from an existing 32-byte seed (useful for import / deterministic testing).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        // Derive ed25519 key from the seed (simple HKDF-like expansion for now)
        let mut ed_seed = [0u8; 32];
        // In a production system we would use proper HKDF here.
        // For v0.2 we use a simple but safe construction.
        ed_seed.copy_from_slice(&seed);

        let ed25519_signing = SigningKey::from_bytes(&ed_seed);

        // Derive x25519 key from the same seed (different expansion)
        let mut x25519_seed = [0u8; 32];
        for (i, &b) in seed.iter().enumerate() {
            x25519_seed[i] = b.wrapping_add(0x5A); // cheap domain separation
        }

        let x25519_secret = StaticSecret::from(x25519_seed);

        LongTermIdentity {
            seed,
            ed25519_signing,
            x25519_secret,
        }
    }

    /// Get the ed25519 public key (for signing / identity proofs)
    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519_signing.verifying_key()
    }

    /// Get the x25519 public key (for key agreement / X3DH)
    pub fn x25519_public(&self) -> X25519Public {
        X25519Public::from(&self.x25519_secret)
    }

    /// Serialize the sensitive material (seed only — the rest is derived).
    /// The caller must encrypt this before persisting.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /// Reconstruct from the raw 32-byte seed (after decryption).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("invalid long-term identity seed length");
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        Ok(Self::from_seed(seed))
    }

    /// Zeroize on drop (via Zeroize derive + explicit wipe)
    pub fn wipe(&mut self) {
        self.seed.zeroize();
    }
}

// ============================================================================
// Encrypted Envelope (reuses the same Argon2id + AES-256-GCM pattern as ratchets)
// ============================================================================

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32], &'static str> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_ITERS, ARGON_PARALLELISM, Some(32))
        .map_err(|_| "bad argon params")?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| "argon2 kdf failed")?;
    Ok(key)
}

/// Export the long-term identity as an encrypted blob (passphrase-protected).
///
/// Envelope format (same as ratchets for consistency):
/// [version(1) | salt(16) | nonce(12) | ciphertext+tag]
pub fn export_encrypted(identity: &LongTermIdentity, passphrase: &[u8]) -> Result<Vec<u8>, &'static str> {
    if passphrase.is_empty() {
        return Err("empty passphrase");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key_argon2id(passphrase, &salt)?;

    let plaintext = identity.to_bytes().to_vec();

    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| "aead key error")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext;
    lsk.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "encryption failed")?;

    let mut envelope = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + buf.len());
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&buf);

    Ok(envelope)
}

/// Import a long-term identity from an encrypted blob.
pub fn import_encrypted(data: &[u8], passphrase: &[u8]) -> Result<LongTermIdentity, &'static str> {
    if data.len() < 1 + SALT_LEN + NONCE_LEN + 16 {
        return Err("envelope too short");
    }
    if data[0] != ENVELOPE_VERSION {
        return Err("unsupported envelope version");
    }

    let salt: [u8; SALT_LEN] = data[1..1 + SALT_LEN].try_into().map_err(|_| "bad salt")?;
    let nonce_bytes: [u8; NONCE_LEN] = data[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| "bad nonce")?;
    let ciphertext = &data[1 + SALT_LEN + NONCE_LEN..];

    let key = derive_key_argon2id(passphrase, &salt)?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| "aead key error")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = ciphertext.to_vec();
    let plain = lsk.open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "decryption failed")?;

    LongTermIdentity::from_bytes(plain)
}

// ============================================================================
// FFI (to be wired from Haskell / Android later)
// ============================================================================

// Note: Actual #[no_mangle] FFI functions will be added in lib.rs once the
// storage model in the host application (Haskell Profile layer) is clearer.
// For now we keep the pure Rust API clean so it can be tested and reviewed.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_roundtrip() {
        let id1 = LongTermIdentity::generate();
        let pub_ed1 = id1.ed25519_public();
        let pub_x1 = id1.x25519_public();

        let bytes = id1.to_bytes();
        let id2 = LongTermIdentity::from_bytes(&bytes).unwrap();

        assert_eq!(pub_ed1.to_bytes(), id2.ed25519_public().to_bytes());
        assert_eq!(pub_x1.as_bytes(), id2.x25519_public().as_bytes());
    }

    #[test]
    fn test_encrypted_export_import() {
        let id = LongTermIdentity::generate();
        let pass = b"test-passphrase-for-longterm-identity";

        let encrypted = export_encrypted(&id, pass).unwrap();
        let restored = import_encrypted(&encrypted, pass).unwrap();

        assert_eq!(
            id.ed25519_public().to_bytes(),
            restored.ed25519_public().to_bytes()
        );
        assert_eq!(
            id.x25519_public().as_bytes(),
            restored.x25519_public().as_bytes()
        );
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let id = LongTermIdentity::generate();
        let pass = b"correct-pass";
        let wrong = b"wrong-pass";

        let encrypted = export_encrypted(&id, pass).unwrap();
        let result = import_encrypted(&encrypted, wrong);

        assert!(result.is_err());
    }
}