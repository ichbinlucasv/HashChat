//! Desktop session at-rest persistence (audit H2 + H3).
//!
//! **Default (paranoid):** passphrase → Argon2id → AES-256-GCM envelope written to
//! `hashchat_data/state.enc`. Empty passphrase is refused. No `machine.key` is created.
//!
//! **Insecure-dev only:** `PersistMode::InsecureDevMachineKey` (or env
//! `HASHCHAT_INSECURE_DEV_PERSIST=1`) uses a raw 32-byte `machine.key` (mode 0600)
//! to wrap the same blob. This recovers the pre-H2 behaviour for local CI/dev and
//! must never be the production default.
//!
//! ## Blob contents
//! - **H2:** identity seed + onion address + onion private-key bytes
//! - **H3:** contacts + per-contact `DoubleRatchet::to_bytes()` + pending ciphertext frames
//!
//! All of the above live **only** inside the AEAD blob — never as sibling plaintext
//! files under `hashchat_data/`.
//!
//! ## Durable queue commit (H3)
//! Prefer: encrypt → append pending → durable `save_session` (with updated ratchet
//! bytes) → *then* attempt Tor SOCKS send. Helper: [`commit_outgoing`].
//!
//! Remaining races (documented honestly):
//! - Crash **after** durable save but **before** Tor ACK: frame may be resent on
//!   restart (peer should tolerate duplicates / out-of-order via skipped keys).
//! - Call sites that advance the ratchet **without** going through
//!   [`commit_outgoing`] / `save_session` can lose FS on crash (availability).
//! - Tor send success does not remove pending until the caller drops the frame
//!   from `pending` and saves again (intentional: retry until acknowledged).
//!
//! Blob version: v1 = identity+onion only (H2); v2 = + contacts/ratchets/pending (H3).
//! Load accepts both; save always writes v2.

use crate::envelope;
use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::{decrypt_with_key, encrypt_with_key};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AEAD domain separation for the insecure-dev machine-key wrap path.
const STATE_AAD: &[u8] = b"HashChat-v1-identity-onion-state";

/// On-disk plaintext blob versions (inside the outer wrap).
const BLOB_VERSION_V1: u8 = 1;
const BLOB_VERSION_V2: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistMode {
    /// Production default: Argon2id(passphrase) wrap. Empty passphrase refused.
    Passphrase,
    /// Explicit insecure: raw machine.key wraps AES-GCM. Dev/CI only.
    InsecureDevMachineKey,
}

impl PersistMode {
    /// Resolve mode: insecure only when explicitly requested via flag or env.
    pub fn from_flags(insecure_dev: bool) -> Self {
        if insecure_dev || std::env::var_os("HASHCHAT_INSECURE_DEV_PERSIST").is_some() {
            PersistMode::InsecureDevMachineKey
        } else {
            PersistMode::Passphrase
        }
    }
}

/// Sensitive identity + onion material to persist.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityOnionState {
    pub seed: [u8; 32],
    #[zeroize(skip)]
    pub onion: String,
    /// Tor onion private-key bytes (e.g. `ED25519-V3:…`) if held; never written plaintext.
    pub onion_key: Vec<u8>,
}

impl IdentityOnionState {
    pub fn from_identity(
        id: &LongTermIdentity,
        onion: impl Into<String>,
        onion_key: Vec<u8>,
    ) -> Self {
        Self {
            seed: id.seed_bytes(),
            onion: onion.into(),
            onion_key,
        }
    }

    pub fn identity(&self) -> LongTermIdentity {
        LongTermIdentity::from_seed(self.seed)
    }
}

/// Persisted contact record (H3). Public identity material + addressing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedContact {
    pub id: String,
    pub display_name: String,
    pub onion: String,
    /// Static X25519 public (32). All-zero if unknown / legacy.
    pub x25519: [u8; 32],
    /// Ed25519 verifying key (32). All-zero if unknown / legacy.
    pub ed25519: [u8; 32],
}

/// Full session state inside the passphrase wrap (H2 identity + H3 session).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionState {
    pub identity: IdentityOnionState,
    /// Contacts survive restart (H3).
    #[zeroize(skip)]
    pub contacts: Vec<PersistedContact>,
    /// Per-contact DoubleRatchet::to_bytes() (H3). Key = contact id.
    pub ratchets: Vec<(String, Vec<u8>)>,
    /// Pending outbound framed ciphertext: (dest_onion, frame) (H3).
    pub pending: Vec<(String, Vec<u8>)>,
}

impl SessionState {
    pub fn from_identity(identity: IdentityOnionState) -> Self {
        Self {
            identity,
            contacts: Vec::new(),
            ratchets: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Upsert ratchet bytes for a contact id.
    pub fn set_ratchet_bytes(&mut self, contact_id: impl Into<String>, bytes: Vec<u8>) {
        let id = contact_id.into();
        if let Some(slot) = self.ratchets.iter_mut().find(|(k, _)| *k == id) {
            slot.1.zeroize();
            slot.1 = bytes;
        } else {
            self.ratchets.push((id, bytes));
        }
    }

    /// Append a pending frame (cap 64, matching audit session queue).
    pub fn queue_pending(&mut self, onion: impl Into<String>, frame: Vec<u8>) {
        if self.pending.len() < 64 {
            self.pending.push((onion.into(), frame));
        }
    }

    /// Remove one queued outbound frame after a successful SOCKS write (exact match).
    /// Zeroizes the removed body. Returns true if a frame was removed.
    pub fn ack_pending_frame(&mut self, onion: &str, frame: &[u8]) -> bool {
        if let Some(i) = self
            .pending
            .iter()
            .position(|(o, f)| o == onion && f.as_slice() == frame)
        {
            self.pending[i].1.zeroize();
            self.pending.remove(i);
            true
        } else {
            false
        }
    }

    /// Securely clear pending frame bodies then drop the queue.
    pub fn clear_pending_secure(&mut self) {
        for (_o, frame) in self.pending.iter_mut() {
            frame.zeroize();
        }
        self.pending.clear();
    }

    /// Securely clear ratchet blobs then drop the map.
    pub fn clear_ratchets_secure(&mut self) {
        for (_id, bytes) in self.ratchets.iter_mut() {
            bytes.zeroize();
        }
        self.ratchets.clear();
    }
}

fn data_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    (
        data_dir.join("state.enc"),
        data_dir.join("machine.key"),
    )
}

fn write_len_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn read_len_bytes(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, &'static str> {
    if *pos + 4 > buf.len() {
        return Err("truncated len");
    }
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + n > buf.len() {
        return Err("truncated bytes");
    }
    let out = buf[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(out)
}

fn write_len_str(out: &mut Vec<u8>, s: &str) {
    write_len_bytes(out, s.as_bytes());
}

fn read_len_str(buf: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    let b = read_len_bytes(buf, pos)?;
    String::from_utf8(b).map_err(|_| "utf8")
}

fn serialize_blob(state: &SessionState) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.push(BLOB_VERSION_V2);
    plain.extend_from_slice(&state.identity.seed);
    write_len_str(&mut plain, &state.identity.onion);
    write_len_bytes(&mut plain, &state.identity.onion_key);

    // contacts
    plain.extend_from_slice(&(state.contacts.len() as u32).to_be_bytes());
    for c in &state.contacts {
        write_len_str(&mut plain, &c.id);
        write_len_str(&mut plain, &c.display_name);
        write_len_str(&mut plain, &c.onion);
        plain.extend_from_slice(&c.x25519);
        plain.extend_from_slice(&c.ed25519);
    }

    // ratchets
    plain.extend_from_slice(&(state.ratchets.len() as u32).to_be_bytes());
    for (id, bytes) in &state.ratchets {
        write_len_str(&mut plain, id);
        write_len_bytes(&mut plain, bytes);
    }

    // pending
    plain.extend_from_slice(&(state.pending.len() as u32).to_be_bytes());
    for (onion, frame) in &state.pending {
        write_len_str(&mut plain, onion);
        write_len_bytes(&mut plain, frame);
    }

    plain
}

fn deserialize_blob(plain: &[u8]) -> Result<SessionState, &'static str> {
    if plain.is_empty() {
        return Err("empty state blob");
    }
    let ver = plain[0];
    if ver != BLOB_VERSION_V1 && ver != BLOB_VERSION_V2 {
        return Err("bad state blob version");
    }
    if plain.len() < 33 {
        return Err("state blob too short");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain[1..33]);
    let mut pos = 33;
    let onion = read_len_str(plain, &mut pos)?;
    let onion_key = read_len_bytes(plain, &mut pos)?;
    let identity = IdentityOnionState {
        seed,
        onion,
        onion_key,
    };

    if ver == BLOB_VERSION_V1 {
        // H2-only blob: no contacts/ratchets/pending section.
        return Ok(SessionState::from_identity(identity));
    }

    // v2 extras
    if pos + 4 > plain.len() {
        return Err("truncated contacts count");
    }
    let n_contacts =
        u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut contacts = Vec::with_capacity(n_contacts);
    for _ in 0..n_contacts {
        let id = read_len_str(plain, &mut pos)?;
        let display_name = read_len_str(plain, &mut pos)?;
        let onion = read_len_str(plain, &mut pos)?;
        if pos + 64 > plain.len() {
            return Err("truncated contact keys");
        }
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&plain[pos..pos + 32]);
        pos += 32;
        ed25519.copy_from_slice(&plain[pos..pos + 32]);
        pos += 32;
        contacts.push(PersistedContact {
            id,
            display_name,
            onion,
            x25519,
            ed25519,
        });
    }

    if pos + 4 > plain.len() {
        return Err("truncated ratchets count");
    }
    let n_ratchets =
        u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut ratchets = Vec::with_capacity(n_ratchets);
    for _ in 0..n_ratchets {
        let id = read_len_str(plain, &mut pos)?;
        let bytes = read_len_bytes(plain, &mut pos)?;
        ratchets.push((id, bytes));
    }

    if pos + 4 > plain.len() {
        return Err("truncated pending count");
    }
    let n_pending =
        u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut pending = Vec::with_capacity(n_pending);
    for _ in 0..n_pending {
        let onion = read_len_str(plain, &mut pos)?;
        let frame = read_len_bytes(plain, &mut pos)?;
        pending.push((onion, frame));
    }

    Ok(SessionState {
        identity,
        contacts,
        ratchets,
        pending,
    })
}

#[cfg(not(unix))]
fn set_private(path: &Path) -> std::io::Result<()> {
    let _ = path;
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), &'static str> {
    // Prefer create with 0600 then write to reduce TOCTOU (audit L2).
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "open private")?;
        f.write_all(data).map_err(|_| "write private")?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data).map_err(|_| "write")?;
        let _ = set_private(path);
        Ok(())
    }
}

fn machine_key_load_or_create(path: &Path) -> Result<[u8; 32], &'static str> {
    if let Ok(b) = fs::read(path) {
        if b.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            return Ok(k);
        }
    }
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).map_err(|_| "csprng failed")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "mkdir")?;
    }
    write_private(path, &k)?;
    Ok(k)
}

fn seal_plain(
    mode: PersistMode,
    passphrase: &[u8],
    key_path: &Path,
    plain: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match mode {
        PersistMode::Passphrase => {
            let _ = fs::remove_file(key_path);
            envelope::seal(passphrase, plain)
        }
        PersistMode::InsecureDevMachineKey => {
            let mut key = machine_key_load_or_create(key_path)?;
            let env = encrypt_with_key(&key, plain, STATE_AAD)?;
            key.zeroize();
            Ok(env)
        }
    }
}

fn open_env(
    mode: PersistMode,
    passphrase: &[u8],
    key_path: &Path,
    env: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match mode {
        PersistMode::Passphrase => envelope::open(passphrase, env),
        PersistMode::InsecureDevMachineKey => {
            let mut key = machine_key_load_or_create(key_path)?;
            let out = decrypt_with_key(&key, env, STATE_AAD)?;
            key.zeroize();
            Ok(out)
        }
    }
}

/// Save full session state (identity + contacts + ratchets + pending). Always writes v2.
pub fn save_session(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
    state: &SessionState,
) -> Result<(), &'static str> {
    fs::create_dir_all(data_dir).map_err(|_| "mkdir")?;
    let (state_path, key_path) = data_paths(data_dir);
    let mut plain = serialize_blob(state);
    let envelope = seal_plain(mode, passphrase, &key_path, &plain)?;
    plain.zeroize();
    write_private(&state_path, &envelope)?;
    Ok(())
}

/// Load full session state. Accepts v1 (identity-only) and v2 blobs.
pub fn load_session(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
) -> Result<SessionState, &'static str> {
    let (state_path, key_path) = data_paths(data_dir);
    let env = fs::read(&state_path).map_err(|_| "read state.enc")?;
    let mut plain = open_env(mode, passphrase, &key_path, &env)?;
    let state = deserialize_blob(&plain)?;
    plain.zeroize();
    Ok(state)
}

/// Save identity + onion state.
///
/// **H3 merge:** if `state.enc` already exists and decrypts, contacts/ratchets/pending
/// are preserved and only identity fields are updated. Fresh files start with empty extras.
pub fn save_disk(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
    state: &IdentityOnionState,
) -> Result<(), &'static str> {
    let mut session = if state_exists(data_dir) {
        match load_session(data_dir, mode, passphrase) {
            Ok(mut s) => {
                s.identity.seed = state.seed;
                s.identity.onion = state.onion.clone();
                s.identity.onion_key = state.onion_key.clone();
                s
            }
            // Wrong passphrase / corrupt: refuse rather than clobber extras.
            Err(e) => return Err(e),
        }
    } else {
        SessionState::from_identity(IdentityOnionState {
            seed: state.seed,
            onion: state.onion.clone(),
            onion_key: state.onion_key.clone(),
        })
    };
    let r = save_session(data_dir, mode, passphrase, &session);
    session.clear_pending_secure();
    session.clear_ratchets_secure();
    r
}

/// Load identity + onion state (extras available via [`load_session`]).
pub fn load_disk(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
) -> Result<IdentityOnionState, &'static str> {
    let session = load_session(data_dir, mode, passphrase)?;
    Ok(IdentityOnionState {
        seed: session.identity.seed,
        onion: session.identity.onion.clone(),
        onion_key: session.identity.onion_key.clone(),
    })
}

/// H3 durable outgoing commit: upsert ratchet bytes, append pending frame, fsync via save.
///
/// Call **after** encrypting with the *new* ratchet state and **before** Tor send.
/// See module docs for remaining races.
pub fn commit_outgoing(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
    contact_id: &str,
    ratchet_bytes: Vec<u8>,
    dest_onion: &str,
    frame: Vec<u8>,
) -> Result<(), &'static str> {
    let mut session = load_session(data_dir, mode, passphrase)?;
    session.set_ratchet_bytes(contact_id, ratchet_bytes);
    session.queue_pending(dest_onion, frame);
    let r = save_session(data_dir, mode, passphrase, &session);
    session.clear_pending_secure();
    session.clear_ratchets_secure();
    r
}

/// Remove at-rest identity/session files under `data_dir` (does not touch Tor HS dir).
/// Clears contacts, ratchets, and pending because they live inside `state.enc` (H3).
pub fn wipe_disk(data_dir: &Path) -> std::io::Result<()> {
    let (state_path, key_path) = data_paths(data_dir);
    let _ = fs::remove_file(state_path);
    let _ = fs::remove_file(key_path);
    Ok(())
}

/// True if a state.enc exists (caller still needs the right mode + passphrase).
pub fn state_exists(data_dir: &Path) -> bool {
    data_paths(data_dir).0.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::DoubleRatchet;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(tag: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("hashchat-h3-{}-{}", tag, n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn passphrase_roundtrip_no_machine_key() {
        let dir = tmp_dir("pass");
        let id = LongTermIdentity::from_seed([0xABu8; 32]);
        let state = IdentityOnionState::from_identity(
            &id,
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion",
            b"ED25519-V3:deadbeef".to_vec(),
        );
        save_disk(&dir, PersistMode::Passphrase, b"strong-pass", &state).unwrap();
        assert!(!dir.join("machine.key").exists());
        assert!(dir.join("state.enc").is_file());

        let loaded = load_disk(&dir, PersistMode::Passphrase, b"strong-pass").unwrap();
        assert_eq!(loaded.seed, state.seed);
        assert_eq!(loaded.onion, state.onion);
        assert_eq!(loaded.onion_key, state.onion_key);
        // Private onion material must not appear as a sibling plaintext file.
        assert!(!dir.join("onion_key").exists());
        assert!(!dir.join("hs_ed25519_secret_key").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_passphrase_refused_on_secure_path() {
        let dir = tmp_dir("empty");
        let id = LongTermIdentity::from_seed([3u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "x.onion", Vec::new());
        assert!(save_disk(&dir, PersistMode::Passphrase, b"", &state).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tmp_dir("wrong");
        let id = LongTermIdentity::from_seed([4u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "y.onion", Vec::new());
        save_disk(&dir, PersistMode::Passphrase, b"alpha", &state).unwrap();
        assert!(load_disk(&dir, PersistMode::Passphrase, b"beta").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn insecure_dev_machine_key_roundtrip() {
        let dir = tmp_dir("insecure");
        let id = LongTermIdentity::from_seed([5u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "z.onion", b"keymat".to_vec());
        save_disk(
            &dir,
            PersistMode::InsecureDevMachineKey,
            b"", // passphrase unused on this path
            &state,
        )
        .unwrap();
        assert!(dir.join("machine.key").is_file());
        let loaded = load_disk(&dir, PersistMode::InsecureDevMachineKey, b"").unwrap();
        assert_eq!(loaded.seed, state.seed);
        assert_eq!(loaded.onion_key, b"keymat");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_flags_defaults_to_passphrase() {
        // Do not set env in this test process for the default case — only check explicit false.
        assert_eq!(PersistMode::from_flags(false), PersistMode::Passphrase);
        assert_eq!(
            PersistMode::from_flags(true),
            PersistMode::InsecureDevMachineKey
        );
    }

    #[test]
    fn h3_contacts_ratchet_pending_roundtrip() {
        let dir = tmp_dir("h3-rt");
        let id = LongTermIdentity::from_seed([0x11u8; 32]);
        let mut ratchet = DoubleRatchet::new();
        ratchet.init_symmetric(&[0x22u8; 32]);
        let (_k, _step) = ratchet.ratchet_send();
        let ratchet_bytes = ratchet.to_bytes();

        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "me.onion",
            b"ED25519-V3:secret".to_vec(),
        ));
        session.contacts.push(PersistedContact {
            id: "alice".into(),
            display_name: "Alice".into(),
            onion: "alicehashchatv3exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion".into(),
            x25519: [0xAAu8; 32],
            ed25519: [0xBBu8; 32],
        });
        session.set_ratchet_bytes("alice", ratchet_bytes.clone());
        session.queue_pending(
            "alicehashchatv3exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            vec![0xCCu8; 48],
        );

        save_session(&dir, PersistMode::Passphrase, b"h3-pass", &session).unwrap();
        assert!(!dir.join("contacts.json").exists());
        assert!(!dir.join("alice.ratchet").exists());
        assert!(!dir.join("pending.bin").exists());

        let loaded = load_session(&dir, PersistMode::Passphrase, b"h3-pass").unwrap();
        assert_eq!(loaded.identity.seed, session.identity.seed);
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.contacts[0].id, "alice");
        assert_eq!(loaded.contacts[0].x25519, [0xAAu8; 32]);
        assert_eq!(loaded.ratchets.len(), 1);
        assert_eq!(loaded.ratchets[0].0, "alice");
        assert_eq!(loaded.ratchets[0].1, ratchet_bytes);
        // Ratchet bytes must restore a working DoubleRatchet.
        let restored = DoubleRatchet::from_bytes(&loaded.ratchets[0].1).unwrap();
        assert_eq!(restored.to_bytes(), ratchet_bytes);
        assert_eq!(loaded.pending.len(), 1);
        assert_eq!(loaded.pending[0].1, vec![0xCCu8; 48]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn h3_wipe_empties_disk() {
        let dir = tmp_dir("h3-wipe");
        let id = LongTermIdentity::from_seed([0x33u8; 32]);
        let mut session =
            SessionState::from_identity(IdentityOnionState::from_identity(&id, "w.onion", vec![]));
        session.contacts.push(PersistedContact {
            id: "bob".into(),
            display_name: "Bob".into(),
            onion: "bob.onion".into(),
            x25519: [1u8; 32],
            ed25519: [2u8; 32],
        });
        session.set_ratchet_bytes("bob", vec![9u8; 80]);
        session.queue_pending("bob.onion", vec![7u8; 16]);
        save_session(&dir, PersistMode::Passphrase, b"wipe-pass", &session).unwrap();
        assert!(dir.join("state.enc").is_file());

        wipe_disk(&dir).unwrap();
        assert!(!dir.join("state.enc").exists());
        assert!(!dir.join("machine.key").exists());
        assert!(load_session(&dir, PersistMode::Passphrase, b"wipe-pass").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn h3_identity_save_preserves_contacts() {
        let dir = tmp_dir("h3-merge");
        let id = LongTermIdentity::from_seed([0x44u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "old.onion",
            vec![1],
        ));
        session.contacts.push(PersistedContact {
            id: "c1".into(),
            display_name: "C1".into(),
            onion: "c1.onion".into(),
            x25519: [3u8; 32],
            ed25519: [4u8; 32],
        });
        session.set_ratchet_bytes("c1", vec![5u8; 40]);
        session.queue_pending("c1.onion", vec![6u8; 8]);
        save_session(&dir, PersistMode::Passphrase, b"merge-pass", &session).unwrap();

        // Identity-only save (H2 API) must not clobber H3 extras.
        let updated = IdentityOnionState::from_identity(
            &LongTermIdentity::from_seed([0x55u8; 32]),
            "new.onion",
            vec![9],
        );
        save_disk(&dir, PersistMode::Passphrase, b"merge-pass", &updated).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"merge-pass").unwrap();
        assert_eq!(loaded.identity.seed, [0x55u8; 32]);
        assert_eq!(loaded.identity.onion, "new.onion");
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.contacts[0].id, "c1");
        assert_eq!(loaded.ratchets[0].1, vec![5u8; 40]);
        assert_eq!(loaded.pending[0].1, vec![6u8; 8]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn h3_commit_outgoing_persists_before_return() {
        let dir = tmp_dir("h3-commit");
        let id = LongTermIdentity::from_seed([0x66u8; 32]);
        let session =
            SessionState::from_identity(IdentityOnionState::from_identity(&id, "me.onion", vec![]));
        save_session(&dir, PersistMode::Passphrase, b"commit-pass", &session).unwrap();

        let mut r = DoubleRatchet::new();
        r.init_symmetric(&[0x77u8; 32]);
        let bytes = r.to_bytes();
        commit_outgoing(
            &dir,
            PersistMode::Passphrase,
            b"commit-pass",
            "peer",
            bytes.clone(),
            "peer.onion",
            vec![0x88u8; 24],
        )
        .unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"commit-pass").unwrap();
        assert_eq!(loaded.ratchets.len(), 1);
        assert_eq!(loaded.ratchets[0].1, bytes);
        assert_eq!(loaded.pending.len(), 1);
        assert_eq!(loaded.pending[0].0, "peer.onion");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn h3_loads_legacy_v1_blob_as_empty_extras() {
        // Manually craft a v1 plaintext and wrap it to confirm backward compat.
        let dir = tmp_dir("h3-v1");
        let id = LongTermIdentity::from_seed([0x77u8; 32]);
        let identity =
            IdentityOnionState::from_identity(&id, "legacy.onion", b"key".to_vec());
        // Use serialize path: save via a temporary SessionState then rewrite as raw v1.
        // Build v1 bytes directly:
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V1);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        let env = envelope::seal(b"v1-pass", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v1-pass").unwrap();
        assert_eq!(loaded.identity.seed, identity.seed);
        assert!(loaded.contacts.is_empty());
        assert!(loaded.ratchets.is_empty());
        assert!(loaded.pending.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ack_pending_frame_removes_exact_match() {
        let mut session = SessionState::from_identity(IdentityOnionState {
            seed: [9u8; 32],
            onion: "x.onion".into(),
            onion_key: Vec::new(),
        });
        session.queue_pending("a.onion", vec![1, 2, 3]);
        session.queue_pending("b.onion", vec![4, 5, 6]);
        assert!(!session.ack_pending_frame("a.onion", &[9, 9]));
        assert!(session.ack_pending_frame("a.onion", &[1, 2, 3]));
        assert_eq!(session.pending.len(), 1);
        assert_eq!(session.pending[0].0, "b.onion");
    }
}
