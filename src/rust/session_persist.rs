//! Desktop identity + onion at-rest persistence (audit H2).
//!
//! **Default (paranoid):** passphrase → Argon2id → AES-256-GCM envelope written to
//! `hashchat_data/state.enc`. Empty passphrase is refused. No `machine.key` is created.
//!
//! **Insecure-dev only:** `PersistMode::InsecureDevMachineKey` (or env
//! `HASHCHAT_INSECURE_DEV_PERSIST=1`) uses a raw 32-byte `machine.key` (mode 0600)
//! to wrap the same blob. This recovers the pre-H2 behaviour for local CI/dev and
//! must never be the production default.
//!
//! Onion / identity private material lives only inside the AEAD blob — never as a
//! separate plaintext file under `hashchat_data/`.

use crate::envelope;
use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::{decrypt_with_key, encrypt_with_key};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AEAD domain separation for the insecure-dev machine-key wrap path.
const STATE_AAD: &[u8] = b"HashChat-v1-identity-onion-state";

/// On-disk plaintext blob version (inside the outer wrap).
const BLOB_VERSION: u8 = 1;

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
#[derive(Zeroize, ZeroizeOnDrop)]
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

fn data_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    (
        data_dir.join("state.enc"),
        data_dir.join("machine.key"),
    )
}

fn serialize_blob(state: &IdentityOnionState) -> Vec<u8> {
    let mut plain = Vec::with_capacity(1 + 32 + 8 + state.onion.len() + state.onion_key.len());
    plain.push(BLOB_VERSION);
    plain.extend_from_slice(&state.seed);
    write_len_bytes(&mut plain, state.onion.as_bytes());
    write_len_bytes(&mut plain, &state.onion_key);
    plain
}

fn deserialize_blob(plain: &[u8]) -> Result<IdentityOnionState, &'static str> {
    if plain.is_empty() || plain[0] != BLOB_VERSION {
        return Err("bad state blob version");
    }
    if plain.len() < 33 {
        return Err("state blob too short");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain[1..33]);
    let mut pos = 33;
    let onion_bytes = read_len_bytes(plain, &mut pos)?;
    let onion = String::from_utf8(onion_bytes).map_err(|_| "onion utf8")?;
    let onion_key = read_len_bytes(plain, &mut pos)?;
    Ok(IdentityOnionState {
        seed,
        onion,
        onion_key,
    })
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

/// Save identity + onion state. Passphrase required unless `InsecureDevMachineKey`.
pub fn save_disk(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
    state: &IdentityOnionState,
) -> Result<(), &'static str> {
    fs::create_dir_all(data_dir).map_err(|_| "mkdir")?;
    let (state_path, key_path) = data_paths(data_dir);
    let mut plain = serialize_blob(state);

    let envelope = match mode {
        PersistMode::Passphrase => {
            // Never leave a stale machine.key beside a passphrase-wrapped state.
            let _ = fs::remove_file(&key_path);
            envelope::seal(passphrase, &plain)?
        }
        PersistMode::InsecureDevMachineKey => {
            let mut key = machine_key_load_or_create(&key_path)?;
            let env = encrypt_with_key(&key, &plain, STATE_AAD)?;
            key.zeroize();
            env
        }
    };
    plain.zeroize();

    write_private(&state_path, &envelope)?;
    Ok(())
}

/// Load identity + onion state.
pub fn load_disk(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
) -> Result<IdentityOnionState, &'static str> {
    let (state_path, key_path) = data_paths(data_dir);
    let env = fs::read(&state_path).map_err(|_| "read state.enc")?;

    let mut plain = match mode {
        PersistMode::Passphrase => envelope::open(passphrase, &env)?,
        PersistMode::InsecureDevMachineKey => {
            let mut key = machine_key_load_or_create(&key_path)?;
            let out = decrypt_with_key(&key, &env, STATE_AAD)?;
            key.zeroize();
            out
        }
    };

    let state = deserialize_blob(&plain)?;
    plain.zeroize();
    Ok(state)
}

/// Remove at-rest identity files under `data_dir` (does not touch Tor HS dir).
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(tag: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("hashchat-h2-{}-{}", tag, n));
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
}
