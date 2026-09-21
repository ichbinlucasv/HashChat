// HashChat Double Ratchet
// Forward secrecy + future secrecy via DH ratcheting + KDF chains.
//
// Post-quantum notes (future work, gated module):
// - Hybrid X25519 + ML-KEM (or replace DH) for new sessions when an audited crate is ready
// - Keep KDF domain separation and zeroize requirements if primitives change

use hkdf::Hkdf;
use ring::aead::{self, LessSafeKey, UnboundKey, Aad};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const RATCHET_KEY_LEN: usize = 32;
#[allow(dead_code)]
pub const RATCHET_NONCE_LEN: usize = ring::aead::NONCE_LEN;

/// Wire protocol version bound into AEAD AAD (frame v2).
pub const WIRE_VERSION_V2: u8 = 2;

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
        }
    }

    /// Advanced ratchet receive that properly handles skipped keys and out-of-order delivery.
    /// This is a more complete version for real messaging.
    pub fn ratchet_recv_advanced(&mut self, remote: &PublicKey, msg_number: u32) -> Result<[u8; RATCHET_KEY_LEN], &'static str> {
        if self.remote_dh.as_ref() != Some(remote) {
            self.dh_ratchet(remote);
        }

        if let Some(key) = self.get_skipped_key(msg_number) {
            return Ok(key);
        }

        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_recv);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];

        hk.expand(b"HashChat-v1-chain", &mut new_chain).map_err(|_| "KDF failed")?;
        hk.expand(b"HashChat-v1-msg-key", &mut msg_key).map_err(|_| "KDF failed")?;

        self.chain_key_recv = new_chain;

        if msg_number > self.recv_count {
            for n in self.recv_count..msg_number {
                self.store_skipped_key(n, msg_key);
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

        let hk = Hkdf::<Sha256>::new(None, shared);
        hk.expand(b"HashChat-v1-initial-root", &mut self.root_key)
            .expect("HKDF failed");

        self.chain_key_send = self.root_key;
        self.chain_key_recv = self.root_key;
    }

    /// Symmetric bootstrap (same shared secret, no remote ephemeral yet).
    pub fn init_symmetric(&mut self, shared: &[u8; 32]) {
        self.remote_dh = None;
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

        self.dh_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.dh_public = PublicKey::from(&self.dh_secret);
        self.remote_dh = Some(*remote);

        let hk2 = Hkdf::<Sha256>::new(Some(&self.root_key), shared.as_bytes());
        hk2.expand(b"HashChat-v1-chain-send", &mut self.chain_key_send)
            .expect("HKDF failed");
        hk2.expand(b"HashChat-v1-chain-recv", &mut self.chain_key_recv)
            .expect("HKDF failed");
    }

    /// Advance the sending chain. Returns (message_key, message_number).
    pub fn ratchet_send(&mut self) -> ([u8; RATCHET_KEY_LEN], u32) {
        if let Some(remote) = self.remote_dh {
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
    /// First frame teaches us their ephemeral without DH (symmetric bootstrap).
    /// Later ephemeral changes trigger a DH ratchet.
    pub fn ratchet_recv(&mut self, remote: &PublicKey) -> ([u8; RATCHET_KEY_LEN], u32) {
        match self.remote_dh {
            None => self.remote_dh = Some(*remote),
            Some(existing) if existing != *remote => self.dh_ratchet(remote),
            Some(_) => {}
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

    /// C1 — Speculative receive: ratchet on a scratch copy, AEAD-open, commit only on success.
    /// On AEAD failure the live ratchet is left unchanged (exportable bytes identical).
    pub fn try_recv_decrypt(
        &mut self,
        remote: &PublicKey,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, u32), &'static str> {
        let snap = self.to_bytes();
        let mut scratch = DoubleRatchet::from_bytes(&snap)?;
        let (mut key, step) = scratch.ratchet_recv(remote);
        let pt = match decrypt_with_key(&key, ciphertext, aad) {
            Ok(p) => p,
            Err(e) => {
                key.zeroize();
                return Err(e);
            }
        };
        key.zeroize();
        // Commit scratch into self by replaying serialized state.
        let committed = scratch.to_bytes();
        let restored = DoubleRatchet::from_bytes(&committed)?;
        *self = restored;
        Ok((pt, step))
    }
}

/// Canonical wire AAD: version || hint || step(be32) || sender_dh(32).
pub fn build_wire_aad(version: u8, hint: &[u8], step: u32, sender_dh: &[u8; 32]) -> Vec<u8> {
    let hint = if hint.len() > 32 { &hint[..32] } else { hint };
    let mut aad = Vec::with_capacity(1 + hint.len() + 4 + 32);
    aad.push(version);
    aad.extend_from_slice(hint);
    aad.extend_from_slice(&step.to_be_bytes());
    aad.extend_from_slice(sender_dh);
    aad
}

/// AES-256-GCM. Wire format: nonce(12) || ciphertext || tag(16).
/// Fresh random nonce per call (getrandom errors propagate — never ignored).
pub fn encrypt_with_key(
    key: &[u8; RATCHET_KEY_LEN],
    pt: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "key")?;
    let lsk = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; RATCHET_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| "getrandom")?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = pt.to_vec();
    lsk.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| "seal")?;
    let mut out = Vec::with_capacity(RATCHET_NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

pub fn decrypt_with_key(
    key: &[u8; RATCHET_KEY_LEN],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if ct.len() < RATCHET_NONCE_LEN + aead::AES_256_GCM.tag_len() {
        return Err("short");
    }
    let nonce_bytes: [u8; RATCHET_NONCE_LEN] =
        ct[..RATCHET_NONCE_LEN].try_into().map_err(|_| "nonce")?;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "key")?;
    let lsk = LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = ct[RATCHET_NONCE_LEN..].to_vec();
    let pt = lsk
        .open_in_place(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| "open")?;
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

        let dh_sec: [u8; 32] = data.get(pos..pos + 32).ok_or("bad dh sec")?.try_into().map_err(|_| "bad dh sec")?;
        pos += 32;
        let dh_pub: [u8; 32] = data.get(pos..pos + 32).ok_or("bad dh pub")?.try_into().map_err(|_| "bad dh pub")?;
        pos += 32;

        let has_remote = *data.get(pos).ok_or("bad remote flag")? == 1;
        pos += 1;
        let remote_dh = if has_remote {
            let b: [u8; 32] = data.get(pos..pos + 32).ok_or("bad remote")?.try_into().map_err(|_| "bad remote")?;
            pos += 32;
            Some(PublicKey::from(b))
        } else {
            None
        };

        let root: [u8; 32] = data.get(pos..pos + 32).ok_or("bad root")?.try_into().map_err(|_| "bad root")?;
        pos += 32;
        let csend: [u8; 32] = data.get(pos..pos + 32).ok_or("bad csend")?.try_into().map_err(|_| "bad csend")?;
        pos += 32;
        let crecv: [u8; 32] = data.get(pos..pos + 32).ok_or("bad crecv")?.try_into().map_err(|_| "bad crecv")?;
        pos += 32;

        let send = u32::from_be_bytes(data.get(pos..pos + 4).ok_or("bad send")?.try_into().map_err(|_| "bad send")?);
        pos += 4;
        let recv = u32::from_be_bytes(data.get(pos..pos + 4).ok_or("bad recv")?.try_into().map_err(|_| "bad recv")?);
        pos += 4;

        let sk_len = u32::from_be_bytes(data.get(pos..pos + 4).ok_or("bad sklen")?.try_into().map_err(|_| "bad sklen")?) as usize;
        pos += 4;

        let mut skipped = std::collections::HashMap::new();
        for _ in 0..sk_len {
            let num = u32::from_be_bytes(data.get(pos..pos + 4).ok_or("bad snum")?.try_into().map_err(|_| "bad snum")?);
            pos += 4;
            let k: [u8; 32] = data.get(pos..pos + 32).ok_or("bad skey")?.try_into().map_err(|_| "bad skey")?;
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
    fn encrypt_roundtrip_with_aad() {
        let key = [7u8; 32];
        let pt = b"hashchat-opsec";
        let aad = build_wire_aad(WIRE_VERSION_V2, b"hint", 3, &[9u8; 32]);
        let ct = encrypt_with_key(&key, pt, &aad).expect("encrypt");
        assert!(ct.len() > pt.len());
        let out = decrypt_with_key(&key, &ct, &aad).expect("decrypt");
        assert_eq!(out, pt);
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = [1u8; 32];
        let aad_ok = build_wire_aad(WIRE_VERSION_V2, b"alice", 1, &[2u8; 32]);
        let aad_bad = build_wire_aad(WIRE_VERSION_V2, b"bob", 1, &[2u8; 32]);
        let ct = encrypt_with_key(&key, b"secret", &aad_ok).unwrap();
        assert!(decrypt_with_key(&key, &ct, &aad_bad).is_err());
        assert!(decrypt_with_key(&key, &ct, &aad_ok).is_ok());
    }

    #[test]
    fn encrypt_uses_unique_nonces() {
        let key = [9u8; 32];
        let aad = b"aad";
        let a = encrypt_with_key(&key, b"same", aad).expect("a");
        let b = encrypt_with_key(&key, b"same", aad).expect("b");
        assert_ne!(a, b, "identical ciphertext means nonce reuse");
    }

    #[test]
    fn garbled_ciphertext_does_not_advance_ratchet() {
        let shared = [0x42u8; 32];
        let mut alice = DoubleRatchet::new();
        let mut bob = DoubleRatchet::new();
        alice.init_symmetric(&shared);
        bob.init_symmetric(&shared);

        let (mut key, step) = alice.ratchet_send();
        let dh = *alice.public_key().as_bytes();
        let hint = [0x11u8; 32];
        let aad = build_wire_aad(WIRE_VERSION_V2, &hint, step, &dh);
        let ct = encrypt_with_key(&key, b"hello", &aad).expect("enc");
        key.zeroize();

        let before = bob.to_bytes();
        let mut garbled = ct.clone();
        let last = garbled.len() - 1;
        garbled[last] ^= 0xff;

        let remote = PublicKey::from(dh);
        assert!(bob.try_recv_decrypt(&remote, &garbled, &aad).is_err());
        assert_eq!(
            bob.to_bytes(),
            before,
            "C1: AEAD failure must not commit ratchet state"
        );

        // Valid ciphertext still works after the failed speculative attempt.
        let (pt, _) = bob.try_recv_decrypt(&remote, &ct, &aad).expect("ok");
        assert_eq!(pt, b"hello");
    }
}
