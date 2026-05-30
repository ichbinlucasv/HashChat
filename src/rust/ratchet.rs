// HashChat Double Ratchet - Improved implementation
// Provides real forward secrecy via DH ratcheting + KDF chains.

use hkdf::Hkdf;
use ring::aead::{self, LessSafeKey, UnboundKey, Aad};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const RATCHET_KEY_LEN: usize = 32;
pub const RATCHET_NONCE_LEN: usize = ring::aead::NONCE_LEN;

#[derive(Clone)]
pub struct DoubleRatchet {
    pub dh_secret: StaticSecret,
    pub dh_public: PublicKey,
    pub remote_dh: Option<PublicKey>,
    pub root_key: [u8; RATCHET_KEY_LEN],
    pub chain_key_send: [u8; RATCHET_KEY_LEN],
    pub chain_key_recv: [u8; RATCHET_KEY_LEN],
    pub send_count: u32,
    pub recv_count: u32,
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
        }
    }

    pub fn init_from_shared(&mut self, remote_pub: PublicKey, shared: &[u8; 32]) {
        self.remote_dh = Some(remote_pub);
        let hk = Hkdf::<Sha256>::new(None, shared);
        hk.expand(b"root", &mut self.root_key).unwrap();
        self.chain_key_send = self.root_key;
        self.chain_key_recv = self.root_key;
    }

    fn dh_ratchet(&mut self, remote: &PublicKey) {
        let shared = self.dh_secret.diffie_hellman(remote);
        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), shared.as_bytes());
        let mut new_root = [0u8; RATCHET_KEY_LEN];
        hk.expand(b"root", &mut new_root).unwrap();
        self.root_key = new_root;

        // Rotate our keys
        self.dh_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.dh_public = PublicKey::from(&self.dh_secret);
        self.remote_dh = Some(*remote);

        // Derive new chains
        let hk2 = Hkdf::<Sha256>::new(Some(&self.root_key), shared.as_bytes());
        hk2.expand(b"chain-send", &mut self.chain_key_send).unwrap();
        hk2.expand(b"chain-recv", &mut self.chain_key_recv).unwrap();
    }

    pub fn ratchet_send(&mut self) -> ([u8; RATCHET_KEY_LEN], u32) {
        if let Some(remote) = self.remote_dh {
            // Perform DH ratchet on send if needed (simplified policy)
            if self.send_count % 3 == 0 {
                self.dh_ratchet(&remote);
            }
        }

        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_send);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];
        hk.expand(b"chain", &mut new_chain).unwrap();
        hk.expand(b"msg", &mut msg_key).unwrap();
        self.chain_key_send = new_chain;
        let c = self.send_count;
        self.send_count += 1;
        (msg_key, c)
    }

    pub fn ratchet_recv(&mut self, remote: &PublicKey) -> ([u8; RATCHET_KEY_LEN], u32) {
        if self.remote_dh != Some(*remote) {
            self.dh_ratchet(remote);
        }
        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_recv);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];
        hk.expand(b"chain", &mut new_chain).unwrap();
        hk.expand(b"msg", &mut msg_key).unwrap();
        self.chain_key_recv = new_chain;
        let c = self.recv_count;
        self.recv_count += 1;
        (msg_key, c)
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
