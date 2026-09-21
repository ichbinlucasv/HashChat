// =============================================================================
// HashChat Android Double Ratchet - VERBATIM SYNC COPY
// =============================================================================
// This is an EXACT copy of src/rust/ratchet.rs for the Android cdylib.
// 
// CRITICAL AUDIT RULE (high-4 / expert requirement):
// - Any modification to DoubleRatchet logic, to_bytes/from_bytes, skipped_keys
//   handling, zeroization, ratchet_send/recv, dh_ratchet, or the KDF context
//   strings MUST be applied to BOTH files in the same commit.
// - Before any release or signed tag, run: diff -u src/rust/ratchet.rs \
//   android/src/main/rust/src/ratchet.rs  (must be identical except this header).
// - This guarantees the phone and desktop have byte-for-byte identical ratchet
//   behavior for cross-device export, group sender keys, and disappearing msgs.
// - The Android side deliberately does NOT depend on the root crate to keep
//   NDK builds simple and reproducible (see long-11 Nix work).
//
// All security properties (ZeroizeOnDrop, skipped key wipe, full state export)
// are preserved here.
//
// Quantum notes and side-channel requirements are inherited from the original.
// =============================================================================
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

/// After mutual DH publics are known, perform a send-side DH ratchet every N
/// messages on the current sending chain. Both peers use the same N.
pub const DH_SEND_EVERY: u32 = 5;

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
    /// Messages sent since the last send-side DH (or since init). Used with
    /// `DH_SEND_EVERY` so both peers agree when a header DH public will change.
    sends_since_dh: u32,
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
        self.sends_since_dh = 0;
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
            sends_since_dh: 0,
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
            self.dh_ratchet_recv(remote);
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
        self.sends_since_dh = 0;
    }

    /// HKDF root + one directional chain from a DH shared secret.
    /// Send and recv use the **same** chain label so keys match across the wire.
    fn kdf_root_and_dh_chain(
        root: &[u8; RATCHET_KEY_LEN],
        shared: &[u8],
        out_chain: &mut [u8; RATCHET_KEY_LEN],
    ) -> [u8; RATCHET_KEY_LEN] {
        let hk = Hkdf::<Sha256>::new(Some(root), shared);
        let mut new_root = [0u8; RATCHET_KEY_LEN];
        hk.expand(b"HashChat-v1-root", &mut new_root)
            .expect("HKDF failed");
        let hk2 = Hkdf::<Sha256>::new(Some(&new_root), shared);
        hk2.expand(b"HashChat-v1-dh-chain", out_chain)
            .expect("HKDF failed");
        new_root
    }

    /// Send-side DH: generate a fresh local ephemeral **first**, then
    /// DH(new_local, remote) → new root + send chain. Header carries the new public.
    /// Does not modify the recv chain (peer still sends under the prior epoch).
    fn dh_ratchet_send(&mut self) {
        let remote = match self.remote_dh {
            Some(r) => r,
            None => return,
        };
        self.dh_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.dh_public = PublicKey::from(&self.dh_secret);
        let shared = self.dh_secret.diffie_hellman(&remote);
        let mut new_send = [0u8; RATCHET_KEY_LEN];
        self.root_key =
            Self::kdf_root_and_dh_chain(&self.root_key, shared.as_bytes(), &mut new_send);
        self.chain_key_send = new_send;
        self.sends_since_dh = 0;
    }

    /// Recv-side DH when `sender_dh` changes: DH(old_local, remote_new) → new root +
    /// recv chain. Local ephemeral is left unchanged until a later send-side step so
    /// the peer's stored `remote_dh` stays valid for one-way traffic.
    fn dh_ratchet_recv(&mut self, remote: &PublicKey) {
        let shared = self.dh_secret.diffie_hellman(remote);
        let mut new_recv = [0u8; RATCHET_KEY_LEN];
        self.root_key =
            Self::kdf_root_and_dh_chain(&self.root_key, shared.as_bytes(), &mut new_recv);
        self.chain_key_recv = new_recv;
        self.remote_dh = Some(*remote);
    }


    /// Advance the sending chain. Returns (message_key, message_number).
    ///
    /// After `init_symmetric` (signed contact bootstrap), both peers share the same
    /// chain keys. The first send after learning `remote_dh` must **not** DH-ratchet:
    /// the peer may still have `remote_dh = None` and would only *store* our public
    /// without deriving matching chains (bootstrap desync fixed in 7d116c8).
    ///
    /// Once `sends_since_dh >= DH_SEND_EVERY` and `remote_dh` is known, a send-side
    /// DH step runs (`dh_ratchet_send`); the peer's `ratchet_recv` matches via
    /// `dh_ratchet_recv` when the header public changes.
    pub fn ratchet_send(&mut self) -> ([u8; RATCHET_KEY_LEN], u32) {
        if self.remote_dh.is_some() && self.sends_since_dh >= DH_SEND_EVERY {
            self.dh_ratchet_send();
        }

        let hk = Hkdf::<Sha256>::new(None, &self.chain_key_send);
        let mut new_chain = [0u8; RATCHET_KEY_LEN];
        let mut msg_key = [0u8; RATCHET_KEY_LEN];

        hk.expand(b"HashChat-v1-chain", &mut new_chain).expect("HKDF failed");
        hk.expand(b"HashChat-v1-msg-key", &mut msg_key).expect("HKDF failed");

        self.chain_key_send = new_chain;
        let count = self.send_count;
        self.send_count += 1;
        self.sends_since_dh = self.sends_since_dh.saturating_add(1);

        (msg_key, count)
    }

    /// Advance the receiving chain when we get a message from a (possibly new) remote key.
    /// First frame teaches us their ephemeral without DH (symmetric bootstrap).
    /// Later ephemeral changes trigger a DH ratchet.
    pub fn ratchet_recv(&mut self, remote: &PublicKey) -> ([u8; RATCHET_KEY_LEN], u32) {
        match self.remote_dh {
            None => self.remote_dh = Some(*remote),
            Some(existing) if existing != *remote => self.dh_ratchet_recv(remote),
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
        out.push(2u8); // version (v2 adds sends_since_dh)

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
        out.extend_from_slice(&self.sends_since_dh.to_be_bytes());

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
        if data.is_empty() || (data[0] != 1 && data[0] != 2) {
            return Err("bad version");
        }
        let version = data[0];
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

        // v1 blobs predate sends_since_dh; default 0 (next DH after DH_SEND_EVERY sends).
        let sends_since_dh = if version >= 2 {
            let v = u32::from_be_bytes(data.get(pos..pos + 4).ok_or("bad sends_since_dh")?.try_into().map_err(|_| "bad sends_since_dh")?);
            pos += 4;
            v
        } else {
            0
        };

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
            sends_since_dh,
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

    fn seal(sender: &mut DoubleRatchet, hint: &[u8; 32], pt: &[u8]) -> (Vec<u8>, [u8; 32], u32, Vec<u8>) {
        let (mut key, step) = sender.ratchet_send();
        let dh = *sender.public_key().as_bytes();
        let aad = build_wire_aad(WIRE_VERSION_V2, hint, step, &dh);
        let ct = encrypt_with_key(&key, pt, &aad).expect("enc");
        key.zeroize();
        (ct, dh, step, aad)
    }

    /// Two-device path: mutual symmetric bootstrap, ping/pong/ping without desync.
    #[test]
    fn two_peer_ping_pong() {
        let shared = [0x55u8; 32];
        let mut alice = DoubleRatchet::new();
        let mut bob = DoubleRatchet::new();
        alice.init_symmetric(&shared);
        bob.init_symmetric(&shared);

        let hint_b = [0xBBu8; 32];
        let (ct, dh, _step, aad) = seal(&mut bob, &hint_b, b"ping");
        let (pt, _) = alice
            .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
            .expect("alice recv ping");
        assert_eq!(pt, b"ping");

        let hint_a = [0xAAu8; 32];
        let (ct2, dh2, _step2, aad2) = seal(&mut alice, &hint_a, b"pong");
        let (pt2, _) = bob
            .try_recv_decrypt(&PublicKey::from(dh2), &ct2, &aad2)
            .expect("bob recv pong");
        assert_eq!(pt2, b"pong");

        let (ct3, dh3, _step3, aad3) = seal(&mut bob, &hint_b, b"ping2");
        let (pt3, _) = alice
            .try_recv_decrypt(&PublicKey::from(dh3), &ct3, &aad3)
            .expect("alice recv ping2");
        assert_eq!(pt3, b"ping2");
    }

    /// Several messages each direction stay decryptable (chain advance only).
    #[test]
    fn two_peer_multi_round() {
        let shared = [0x77u8; 32];
        let mut a = DoubleRatchet::new();
        let mut b = DoubleRatchet::new();
        a.init_symmetric(&shared);
        b.init_symmetric(&shared);
        let ha = [1u8; 32];
        let hb = [2u8; 32];
        for i in 0..5u8 {
            let msg = [b'A', i];
            let (ct, dh, _, aad) = seal(&mut a, &ha, &msg);
            let (pt, _) = b
                .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
                .expect("b recv");
            assert_eq!(pt, msg);

            let msg2 = [b'B', i];
            let (ct2, dh2, _, aad2) = seal(&mut b, &hb, &msg2);
            let (pt2, _) = a
                .try_recv_decrypt(&PublicKey::from(dh2), &ct2, &aad2)
                .expect("a recv");
            assert_eq!(pt2, msg2);
        }
    }

    /// After mutual DH learning, the N-th further send rotates the sender public;
    /// peer decrypts via matching recv DH. Bootstrap reply path stays chain-only.
    #[test]
    fn intentional_send_dh_step() {
        let shared = [0x99u8; 32];
        let mut a = DoubleRatchet::new();
        let mut b = DoubleRatchet::new();
        a.init_symmetric(&shared);
        b.init_symmetric(&shared);
        let ha = [3u8; 32];
        let hb = [4u8; 32];

        // Bootstrap exchange: learn each other's wire DH without send-side DH.
        let (ct, dh, _, aad) = seal(&mut a, &ha, b"a0");
        let pk_a0 = dh;
        let (pt, _) = b
            .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
            .expect("b recv a0");
        assert_eq!(pt, b"a0");

        let (ct, dh, _, aad) = seal(&mut b, &hb, b"b0");
        let (pt, _) = a
            .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
            .expect("a recv b0");
        assert_eq!(pt, b"b0");

        // Drain until just before the periodic DH threshold.
        for i in 1..DH_SEND_EVERY {
            let msg = format!("a{i}");
            let (ct, dh, _, aad) = seal(&mut a, &ha, msg.as_bytes());
            assert_eq!(dh, pk_a0, "pre-threshold sends must keep bootstrap DH public");
            let (pt, _) = b
                .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
                .expect("b recv pre-dh");
            assert_eq!(pt, msg.as_bytes());
        }

        // Next send: sends_since_dh >= DH_SEND_EVERY → send-side DH.
        let (ct, dh_rot, _, aad) = seal(&mut a, &ha, b"a-dh");
        assert_ne!(dh_rot, pk_a0, "send-side DH must advertise a new ephemeral");
        let (pt, _) = b
            .try_recv_decrypt(&PublicKey::from(dh_rot), &ct, &aad)
            .expect("b recv after DH");
        assert_eq!(pt, b"a-dh");

        // Post-DH traffic both ways still decrypts.
        let (ct, dh, _, aad) = seal(&mut b, &hb, b"b-after");
        let (pt, _) = a
            .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
            .expect("a recv b-after");
        assert_eq!(pt, b"b-after");

        let (ct, dh, _, aad) = seal(&mut a, &ha, b"a-after");
        let (pt, _) = b
            .try_recv_decrypt(&PublicKey::from(dh), &ct, &aad)
            .expect("b recv a-after");
        assert_eq!(pt, b"a-after");
    }

    #[test]
    fn ratchet_state_v2_roundtrip_preserves_sends_since_dh() {
        let mut r = DoubleRatchet::new();
        r.init_symmetric(&[0x11u8; 32]);
        let _ = r.ratchet_send();
        let _ = r.ratchet_send();
        let bytes = r.to_bytes();
        assert_eq!(bytes[0], 2);
        let r2 = DoubleRatchet::from_bytes(&bytes).expect("v2");
        assert_eq!(r2.to_bytes(), bytes);
    }
}
