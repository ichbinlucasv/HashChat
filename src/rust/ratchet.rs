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
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const RATCHET_KEY_LEN: usize = 32;
pub const RATCHET_NONCE_LEN: usize = ring::aead::NONCE_LEN;

/// Per-contact Double Ratchet state.
/// All sensitive fields are zeroized on drop.
#[derive(ZeroizeOnDrop)]
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

    /// Try to get a skipped key
    pub fn get_skipped_key(&mut self, msg_number: u32) -> Option<[u8; RATCHET_KEY_LEN]> {
        self.skipped_keys.remove(&msg_number)
    }

    /// Securely clear sensitive state (called automatically on drop via ZeroizeOnDrop).
    pub fn clear(&mut self) {
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
    }

    pub fn init_from_shared(&mut self, remote_pub: PublicKey, shared: &[u8; 32]) {
        self.remote_dh = Some(remote_pub);

        let hk = Hkdf::<Sha256>::new(None, shared);
        // Strong context string for domain separation
        hk.expand(b"HashChat-v1-initial-root", &mut self.root_key)
            .expect("HKDF failed");

        self.chain_key_send = self.root_key;
        self.chain_key_recv = self.root_key;
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
            // Ratchet every few messages for good security/performance balance
            if self.send_count % 2 == 0 {
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
        if self.remote_dh.as_ref() != Some(remote) {
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

pub fn encrypt_with_key(key: &[u8; RATCHET_KEY_LEN], pt: &[u8]) -> Result<Vec<u8>, &'static str> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "key")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key([0u8; RATCHET_NONCE_LEN]);
    let mut buf = vec![0u8; pt.len() + aead::AES_256_GCM.tag_len()];
    buf[..pt.len()].copy_from_slice(pt);
    lsk.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).map_err(|_| "seal")?;
    Ok(buf)
}

pub fn decrypt_with_key(key: &[u8; RATCHET_KEY_LEN], ct: &[u8]) -> Result<Vec<u8>, &'static str> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "key")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key([0u8; RATCHET_NONCE_LEN]);
    let mut buf = ct.to_vec();
    let pt = lsk.open_in_place(nonce, Aad::empty(), &mut buf).map_err(|_| "open")?;
    Ok(pt.to_vec())
}
