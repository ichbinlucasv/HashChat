//! Long-term identity keypair for signed contact bootstrap (audit H1).
//!
//! One 32-byte seed derives:
//! - ed25519 signing key (identity / link signatures)
//! - x25519 static secret (authenticated static-DH bootstrap — NOT X3DH)
//!
//! Only public keys are ever placed in contact links. Private material stays local.
//! At rest (audit H2): wrap the seed with Argon2id + AES-256-GCM via
//! [`export_encrypted`] / [`import_encrypted`], or use [`crate::session_persist`]
//! for identity+onion state. Empty passphrase is refused on the secure path.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Long-term identity for a burner profile.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LongTermIdentity {
    seed: [u8; 32],
    #[zeroize(skip)]
    ed25519_signing: SigningKey,
    #[zeroize(skip)]
    x25519_secret: StaticSecret,
}

impl LongTermIdentity {
    /// Fresh identity from OS CSPRNG.
    pub fn generate() -> Result<Self, &'static str> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| "csprng failed")?;
        Ok(Self::from_seed(seed))
    }

    /// Deterministic identity from a 32-byte seed (tests / import after decrypt).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut ed_seed = [0u8; 32];
        let mut x_seed = [0u8; 32];

        let hk = Hkdf::<Sha256>::new(Some(b"HashChat-v1-longterm"), &seed);
        hk.expand(b"ed25519-seed", &mut ed_seed)
            .expect("HKDF ed25519 expand");
        hk.expand(b"x25519-seed", &mut x_seed)
            .expect("HKDF x25519 expand");

        let ed25519_signing = SigningKey::from_bytes(&ed_seed);
        let x25519_secret = StaticSecret::from(x_seed);

        ed_seed.zeroize();
        x_seed.zeroize();

        LongTermIdentity {
            seed,
            ed25519_signing,
            x25519_secret,
        }
    }

    pub fn seed_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519_signing.verifying_key()
    }

    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519_public().to_bytes()
    }

    pub fn x25519_public(&self) -> X25519Public {
        X25519Public::from(&self.x25519_secret)
    }

    pub fn x25519_public_bytes(&self) -> [u8; 32] {
        *self.x25519_public().as_bytes()
    }

    /// Static-DH with peer's x25519 public (contact bootstrap).
    pub fn x25519_dh(&self, peer: &X25519Public) -> [u8; 32] {
        self.x25519_secret.diffie_hellman(peer).to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.ed25519_signing.sign(message)
    }

    pub fn verify(pub_bytes: &[u8; 32], message: &[u8], sig_bytes: &[u8; 64]) -> bool {
        let vk = match VerifyingKey::from_bytes(pub_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(sig_bytes);
        vk.verify(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_roundtrip_stable_pubs() {
        let id1 = LongTermIdentity::from_seed([7u8; 32]);
        let id2 = LongTermIdentity::from_seed(id1.seed_bytes());
        assert_eq!(id1.ed25519_public_bytes(), id2.ed25519_public_bytes());
        assert_eq!(id1.x25519_public_bytes(), id2.x25519_public_bytes());
    }

    #[test]
    fn dh_is_symmetric() {
        let a = LongTermIdentity::from_seed([1u8; 32]);
        let b = LongTermIdentity::from_seed([2u8; 32]);
        let ab = a.x25519_dh(&b.x25519_public());
        let ba = b.x25519_dh(&a.x25519_public());
        assert_eq!(ab, ba);
    }
}

// ============================================================================
// Encrypted at-rest export (Argon2id envelope — audit H2)
// ============================================================================

use crate::envelope;

/// Export the long-term seed as an Argon2id + AES-256-GCM envelope.
/// Empty passphrase is refused.
pub fn export_encrypted(
    identity: &LongTermIdentity,
    passphrase: &[u8],
) -> Result<Vec<u8>, &'static str> {
    envelope::seal(passphrase, &identity.seed_bytes())
}

/// Import a long-term identity from an Argon2id envelope.
pub fn import_encrypted(
    data: &[u8],
    passphrase: &[u8],
) -> Result<LongTermIdentity, &'static str> {
    let plain = envelope::open(passphrase, data)?;
    if plain.len() != 32 {
        return Err("invalid long-term identity seed length");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain);
    Ok(LongTermIdentity::from_seed(seed))
}

#[cfg(test)]
mod envelope_tests {
    use super::*;

    #[test]
    fn identity_export_import_roundtrip() {
        let id = LongTermIdentity::from_seed([9u8; 32]);
        let blob = export_encrypted(&id, b"test-pass-phrase").unwrap();
        let restored = import_encrypted(&blob, b"test-pass-phrase").unwrap();
        assert_eq!(id.ed25519_public_bytes(), restored.ed25519_public_bytes());
        assert_eq!(id.x25519_public_bytes(), restored.x25519_public_bytes());
    }

    #[test]
    fn identity_empty_passphrase_refused() {
        let id = LongTermIdentity::from_seed([1u8; 32]);
        assert!(export_encrypted(&id, b"").is_err());
    }
}
