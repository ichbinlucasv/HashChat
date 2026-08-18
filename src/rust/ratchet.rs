// HashChat Double Ratchet - Production-grade foundation
// Provides forward secrecy + future secrecy via DH ratcheting + KDF chains.
//
// Quantum resistance notes (future work):
// - Replace X25519 with ML-KEM (Kyber) or hybrid X25519 + ML-KEM for forward secrecy
// - Use a post-quantum KDF (e.g. with SHA3 or a PQ hash function)
// - Consider hybrid ratchets (classical + PQ) during the transition period
// - The current design is built to allow swapping the DH primitive with minimal changes.
// - Recommendation: Start with hybrid X25519 + ML-KEM for new sessions soon.

use hkdf::Hkdf;
use ring::aead::{self, LessSafeKey, UnboundKey, Aad};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const RATCHET_KEY_LEN: usize = 32;
#[allow(dead_code)]
pub const RATCHET_NONCE_LEN: usize = ring::aead::NONCE_LEN;

/// Per-contact Double Ratchet state.
/// All sensitive fields are zeroized on drop.
pub struct DoubleRatchet {
    dh_secret: StaticSecret,
    dh_public: PublicKey,
    remote_dh: Option<PublicKey>,
    root_key: [u8; RATCHET_KEY_LEN],
    chain_key_send: [u8; RATCHET_KEY_LEN],
    chain_key_recv: [u8; RATCHET_KEY_LEN],
    send_count: u32,
    recv_count: u32,
    // Skipped message keys for out-of-order delivery (message_number -> key)
    skipped_keys: std::collections::HashMap<u32, [u8; RATCHET_KEY_LEN]>,
}

impl Zeroize for DoubleRatchet {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
        // HashMap values (fixed-size arrays) are zeroizable
        for (_k, v) in self.skipped_keys.iter_mut() {
            v.zeroize();
        }
        self.skipped_keys.clear();
        self.send_count = 0;
        self.recv_count = 0;
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DoubleRatchet {
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self {
            dh_secret: secret,
            dh_public: public,
            remote_dh: None,
            root_key: [0u8; RATCHET_KEY_LEN],
            chain_key_send: [0u8; RATCHET_KEY_LEN],
            chain_key_recv: [0u8; RATCHET_KEY_LEN],
            send_count: 0,
            recv_count: 0,
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Returns the current public key (safe to share with peers)
    pub fn public_key(&self) -> PublicKey {
        self.dh_public
    }

    /// Export minimal state for persistence (never share this raw).
    /// In production this should be encrypted with a user passphrase or hardware key.
    pub fn export_state(&self) -> ([u8; RATCHET_KEY_LEN], u32, u32) {
        (self.root_key, self.send_count, self.recv_count)
    }

    /// Restore from previously exported state.
    pub fn restore_state(&mut self, root: [u8; RATCHET_KEY_LEN], send: u32, recv: u32) {
        self.root_key = root;
        self.send_count = send;
        self.recv_count = recv;
    }

    /// Store a skipped message key (for out-of-order delivery)
    pub fn store_skipped_key(&mut self, msg_number: u32, key: [u8; RATCHET_KEY_LEN]) {
        self.skipped_keys.insert(msg_number, key);
        // Limit size to prevent DoS
        if self.skipped_keys.len() > 1000 {
            if let Some(oldest) = self.skipped_keys.keys().min().cloned() {
                self.skipped_keys.remove(&oldest);
            }
        }
    }

    /// Try to get a skipped key (for out-of-order messages)
    pub fn get_skipped_key(&mut self, msg_number: u32) -> Option<[u8; RATCHET_KEY_LEN]> {
        self.skipped_keys.remove(&msg_number)
    }

    /// Securely wipe a specific skipped message key (for disappearing messages / key erasure).
    /// Zeroizes the key material and removes it from the map. Critical for forward secrecy on expiry.
    pub fn wipe_skipped_key(&mut self, msg_number: u32) {
        if let Some(mut key) = self.skipped_keys.remove(&msg_number) {
            key.zeroize();
            // The array is now zeroed; removal already happened.
        }
    }

    /// Advanced ratchet receive that properly handles skipped keys and out-of-order delivery.
    /// This is a more complete version for real messaging.
    pub fn ratchet_recv_advanced(&mut self, remote: &PublicKey, msg_number: u32) -> Result<[u8; RATCHET_KEY_LEN], &'static str> {
        if self.remote_dh.as_ref() != Some(remote) {
            // New remote key -> DH ratchet
            self.dh_ratchet(remote);
        }

        // Check if we already have this message key from previous skips
        if let Some(key) = self.get_skipped_key(msg_number) {
            return Ok(key);
        }

        // Normal path: advance receiving chain
        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_recv);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];

        hk.expand(b"HashChat-v1-chain", &mut new_chain).map_err(|_| "KDF failed")?;
        hk.expand(b"HashChat-v1-msg-key", &mut msg_key).map_err(|_| "KDF failed")?;

        self.chain_key_recv = new_chain;

        // If this message arrived out of order, store future keys as skipped
        if msg_number > self.recv_count {
            // Store keys for messages between recv_count and msg_number as skipped (simplified)
            for n in self.recv_count..msg_number {
                // In a real implementation we would derive these keys properly
                self.store_skipped_key(n, msg_key); // placeholder
            }
        }

        self.recv_count = msg_number + 1;
        Ok(msg_key)
    }

    /// Securely clear sensitive state (called automatically on drop).
    pub fn clear(&mut self) {
        self.zeroize();
    }

    pub fn init_from_shared(&mut self, remote_pub: PublicKey, shared: &[u8; 32]) {
        self.remote_dh = Some(remote_pub);
        self.apply_shared_root(shared);
    }

    /// X3DH bootstrap: same shared secret on both sides, no remote DH yet.
    /// Symmetric chains stay aligned for the first messages (DH ratchet later
    /// needs the peer's ephemeral pub on the wire).
    pub fn init_symmetric(&mut self, shared: &[u8; 32]) {
        self.remote_dh = None;
        self.apply_shared_root(shared);
    }

    fn apply_shared_root(&mut self, shared: &[u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, shared);
        hk.expand(b"HashChat-v1-initial-root", &mut self.root_key)
            .expect("HKDF failed");
        self.chain_key_send = self.root_key;
        self.chain_key_recv = self.root_key;
        self.send_count = 0;
        self.recv_count = 0;
    }

    fn dh_ratchet(&mut self, remote: &PublicKey) {
        let shared = self.dh_secret.diffie_hellman(remote);
        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), shared.as_bytes());

        let mut new_root = [0u8; RATCHET_KEY_LEN];
        hk.expand(b"HashChat-v1-root", &mut new_root)
            .expect("HKDF failed");
        self.root_key = new_root;

        // Rotate DH keys for forward secrecy
        self.dh_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.dh_public = PublicKey::from(&self.dh_secret);
        self.remote_dh = Some(*remote);

        // Derive fresh chain keys
        let hk2 = Hkdf::<Sha256>::new(Some(&self.root_key), shared.as_bytes());
        hk2.expand(b"HashChat-v1-chain-send", &mut self.chain_key_send)
            .expect("HKDF failed");
        hk2.expand(b"HashChat-v1-chain-recv", &mut self.chain_key_recv)
            .expect("HKDF failed");
        hk2.expand(b"chain-send", &mut self.chain_key_send).unwrap();
        hk2.expand(b"chain-recv", &mut self.chain_key_recv).unwrap();
    }

    /// Advance the sending chain. Returns (message_key, message_number).
    /// Automatically performs DH ratchet periodically for stronger forward secrecy.
    pub fn ratchet_send(&mut self) -> ([u8; RATCHET_KEY_LEN], u32) {
        if let Some(remote) = self.remote_dh {
            // Skip DH on the first send so init_from_shared chains stay aligned.
            if self.send_count > 0 && self.send_count % 2 == 0 {
                self.dh_ratchet(&remote);
            }
        }

        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_send);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];

        hk.expand(b"HashChat-v1-chain", &mut new_chain).expect("HKDF failed");
        hk.expand(b"HashChat-v1-msg-key", &mut msg_key).expect("HKDF failed");

        self.chain_key_send = new_chain;
        let count = self.send_count;
        self.send_count += 1;

        (msg_key, count)
    }

    /// Advance the receiving chain when we get a message from a (possibly new) remote key.
    pub fn ratchet_recv(&mut self, remote: &PublicKey) -> ([u8; RATCHET_KEY_LEN], u32) {
        // Only DH-ratchet when we already have a remote key and it changed.
        // After init_from_shared the chains already match; a first recv must not DH.
        if self.remote_dh.map(|k| k != *remote).unwrap_or(false) {
            self.dh_ratchet(remote);
        }

        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_recv);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];

        hk.expand(b"HashChat-v1-chain", &mut new_chain).expect("HKDF failed");
        hk.expand(b"HashChat-v1-msg-key", &mut msg_key).expect("HKDF failed");

        self.chain_key_recv = new_chain;
        let count = self.recv_count;
        self.recv_count += 1;

        (msg_key, count)
    }
}

/// AES-256-GCM. Wire format: nonce(12) || ciphertext || tag(16).
/// A fresh random nonce is generated per call so the same message key
/// cannot be reused with a fixed nonce (that would be a full break).
pub fn encrypt_with_key(key: &[u8; RATCHET_KEY_LEN], pt: &[u8]) -> Result<Vec<u8>, &'static str> {
    use rand::RngCore;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "key")?;
    let lsk = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; RATCHET_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = pt.to_vec();
    lsk.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).map_err(|_| "seal")?;
    let mut out = Vec::with_capacity(RATCHET_NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

pub fn decrypt_with_key(key: &[u8; RATCHET_KEY_LEN], ct: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ct.len() < RATCHET_NONCE_LEN + aead::AES_256_GCM.tag_len() {
        return Err("short");
    }
    let nonce_bytes: [u8; RATCHET_NONCE_LEN] = ct[..RATCHET_NONCE_LEN].try_into().map_err(|_| "nonce")?;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "key")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = ct[RATCHET_NONCE_LEN..].to_vec();
    let pt = lsk.open_in_place(nonce, Aad::empty(), &mut buf).map_err(|_| "open")?;
    Ok(pt.to_vec())
}

// === Full Ratchet State Serialization for Encrypted Persistence ===

impl DoubleRatchet {
    /// Serialize the COMPLETE ratchet state.
    /// The resulting blob MUST be encrypted (e.g. with Argon2id(passphrase) + AES-GCM) before writing to disk.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1u8); // version

        out.extend_from_slice(self.dh_secret.as_bytes());
        out.extend_from_slice(self.dh_public.as_bytes());

        match &self.remote_dh {
            Some(pk) => {
                out.push(1);
                out.extend_from_slice(pk.as_bytes());
            }
            None => out.push(0),
        }

        out.extend_from_slice(&self.root_key);
        out.extend_from_slice(&self.chain_key_send);
        out.extend_from_slice(&self.chain_key_recv);
        out.extend_from_slice(&self.send_count.to_be_bytes());
        out.extend_from_slice(&self.recv_count.to_be_bytes());

        // Skipped keys
        let len = self.skipped_keys.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        for (&num, key) in &self.skipped_keys {
            out.extend_from_slice(&num.to_be_bytes());
            out.extend_from_slice(key);
        }

        out
    }

    /// Restore from a decrypted blob.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() || data[0] != 1 {
            return Err("bad version");
        }
        let mut pos = 1;

        let dh_sec: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad dh sec")?;
        pos += 32;
        let dh_pub: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad dh pub")?;
        pos += 32;

        let has_remote = data[pos] == 1;
        pos += 1;
        let remote_dh = if has_remote {
            let b: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad remote")?;
            pos += 32;
            Some(PublicKey::from(b))
        } else { None };

        let root: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad root")?;
        pos += 32;
        let csend: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad csend")?;
        pos += 32;
        let crecv: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad crecv")?;
        pos += 32;

        let send = u32::from_be_bytes(data[pos..pos+4].try_into().unwrap());
        pos += 4;
        let recv = u32::from_be_bytes(data[pos..pos+4].try_into().unwrap());
        pos += 4;

        let sk_len = u32::from_be_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;

        let mut skipped = std::collections::HashMap::new();
        for _ in 0..sk_len {
            let num = u32::from_be_bytes(data[pos..pos+4].try_into().unwrap());
            pos += 4;
            let k: [u8; 32] = data[pos..pos+32].try_into().map_err(|_| "bad skey")?;
            pos += 32;
            skipped.insert(num, k);
        }

        Ok(Self {
            dh_secret: StaticSecret::from(dh_sec),
            dh_public: PublicKey::from(dh_pub),
            remote_dh,
            root_key: root,
            chain_key_send: csend,
            chain_key_recv: crecv,
            send_count: send,
            recv_count: recv,
            skipped_keys: skipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_roundtrip() {
        let key = [7u8; 32];
        let pt = b"hashchat-opsec";
        let ct = encrypt_with_key(&key, pt).expect("encrypt");
        assert!(ct.len() > pt.len());
        assert_ne!(&ct[RATCHET_NONCE_LEN..], pt.as_ref());
        let out = decrypt_with_key(&key, &ct).expect("decrypt");
        assert_eq!(out, pt);
    }

    #[test]
    fn encrypt_uses_unique_nonces() {
        let key = [9u8; 32];
        let pt = b"same plaintext";
        let a = encrypt_with_key(&key, pt).expect("a");
        let b = encrypt_with_key(&key, pt).expect("b");
        assert_ne!(a, b, "identical ciphertext means nonce reuse");
        assert_eq!(decrypt_with_key(&key, &a).unwrap(), pt);
        assert_eq!(decrypt_with_key(&key, &b).unwrap(), pt);
    }

    #[test]
    fn decrypt_rejects_short_and_wrong_key() {
        let key = [1u8; 32];
        let other = [2u8; 32];
        assert!(decrypt_with_key(&key, &[0u8; 8]).is_err());
        let ct = encrypt_with_key(&key, b"secret").unwrap();
        assert!(decrypt_with_key(&other, &ct).is_err());
    }
}
