//! Long-term identity keypair for signed contact bootstrap (audit H1).
//!
//! One 32-byte seed derives:
//! - ed25519 signing key (identity / link signatures)
//! - x25519 static secret (authenticated static-DH bootstrap — NOT X3DH)
//!
//! Only public keys are ever placed in contact links. Private material stays local.

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
