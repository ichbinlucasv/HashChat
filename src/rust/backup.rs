//! Portable encrypted profile backup (SimpleX-parity item "encrypted local backup").
//!
//! A backup is a single file sealed with its own passphrase (Argon2id +
//! AES-256-GCM, the same [`crate::envelope`] used for `state.enc`), so it can be
//! stored off the machine without exposing the profile passphrase.
//!
//! File format: `MAGIC(4) | version(1) | envelope`, and the sealed plaintext is
//! `MAGIC(4) | version(1) | created_unix(u64 BE) | state blob`. The header is
//! repeated inside the AEAD so a tampered outer header is caught.
//!
//! What a backup carries: identity seed, onion address and key, contacts,
//! verified / blocked / muted lists and local preferences.
//!
//! What it deliberately leaves out:
//! - **Ratchet states.** Restoring an older ratchet would rewind the chain and
//!   could reuse message keys that were already spent, so contacts restored from a
//!   backup must start a fresh session (a new `:invite`) before chatting again.
//! - **Held outbound frames** (they were sealed under those ratchets).
//! - **Open one-time invites.** Their salts are spend-once; bringing them back
//!   would let a used invite be redeemed again.
//! - The save id and the wipe-settings record, which belong to the old machine.
//!
//! Extreme posture refuses to export: it keeps no contacts on disk, and a
//! backup file would be exactly the durable copy Extreme avoids.
//!
//! Honest limits: a backup file is as strong as its passphrase, and anyone who
//! has it and the passphrase holds your identity. Running two copies of one
//! identity at the same time confuses delivery; a backup is for recovery or
//! moving machines, not for a second live device.

use crate::envelope::{self, check_new_passphrase};
use crate::session_persist::{deserialize_blob, serialize_blob, SessionState};
use zeroize::Zeroize;

/// File magic for a HashChat backup.
pub const BACKUP_MAGIC: &[u8; 4] = b"HCBK";
/// Current backup format version.
pub const BACKUP_VERSION: u8 = 1;
/// Upper bound on a backup file read from disk (matches the profile cap order).
pub const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;

const HEADER_LEN: usize = 5;

/// Metadata read back from an opened backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupInfo {
    /// Unix time the backup was written (as the exporting clock read it).
    pub created_unix: u64,
    /// Number of contacts restored.
    pub contacts: usize,
}

/// Build the state a backup carries (see module docs for what is dropped).
fn backup_view(state: &SessionState) -> SessionState {
    let mut s = state.clone();
    s.clear_ratchets_secure();
    s.clear_pending_secure();
    s.pending_invites.zeroize();
    s.pending_invites.clear();
    s.save_id = None;
    s.wipe_settings = None;
    s
}

/// Seal `state` as a portable backup under `passphrase`.
///
/// The passphrase must pass the same strength check as a new profile
/// passphrase. Refused under Extreme posture.
pub fn export_backup(
    state: &SessionState,
    passphrase: &str,
    created_unix: u64,
) -> Result<Vec<u8>, &'static str> {
    if state.net.is_extreme() {
        return Err("extreme posture refuses backups (no durable contact copy)");
    }
    check_new_passphrase(passphrase, false)?;
    let view = backup_view(state);
    let mut blob = serialize_blob(&view);
    drop(view);
    let mut plain = Vec::with_capacity(HEADER_LEN + 8 + blob.len());
    plain.extend_from_slice(BACKUP_MAGIC);
    plain.push(BACKUP_VERSION);
    plain.extend_from_slice(&created_unix.to_be_bytes());
    plain.extend_from_slice(&blob);
    blob.zeroize();
    let sealed = envelope::seal(passphrase.as_bytes(), &plain);
    plain.zeroize();
    let sealed = sealed?;
    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.push(BACKUP_VERSION);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// True if `bytes` starts like a HashChat backup (no decryption).
pub fn looks_like_backup(bytes: &[u8]) -> bool {
    bytes.len() > HEADER_LEN && &bytes[..4] == BACKUP_MAGIC
}

/// Open a backup produced by [`export_backup`].
///
/// Wrong passphrase, tampering and truncation all fail closed with an opaque
/// reason. The returned state has no ratchets, held frames or open invites.
pub fn open_backup(
    bytes: &[u8],
    passphrase: &str,
) -> Result<(SessionState, BackupInfo), &'static str> {
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err("backup too large");
    }
    if !looks_like_backup(bytes) {
        return Err("not a HashChat backup");
    }
    if bytes[4] != BACKUP_VERSION {
        return Err("unsupported backup version");
    }
    if passphrase.is_empty() {
        return Err("empty passphrase refused");
    }
    let mut plain = envelope::open(passphrase.as_bytes(), &bytes[HEADER_LEN..])
        .map_err(|_| "backup did not open (wrong passphrase or damaged file)")?;
    let result = parse_inner(&plain);
    plain.zeroize();
    result
}

fn parse_inner(plain: &[u8]) -> Result<(SessionState, BackupInfo), &'static str> {
    if plain.len() < HEADER_LEN + 8 || &plain[..4] != BACKUP_MAGIC || plain[4] != BACKUP_VERSION {
        return Err("backup header mismatch");
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&plain[HEADER_LEN..HEADER_LEN + 8]);
    let created_unix = u64::from_be_bytes(ts);
    let state = deserialize_blob(&plain[HEADER_LEN + 8..])?;
    // Defence in depth: never hand back session material even if a crafted
    // (but correctly sealed) file carried it.
    let state = backup_view(&state);
    let info = BackupInfo {
        created_unix,
        contacts: state.contacts.len(),
    };
    Ok((state, info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_mode::PostureProfile;
    use crate::session_persist::IdentityOnionState;

    const PASS: &str = "correct horse battery staple";

    fn sample() -> SessionState {
        let mut s = SessionState::from_identity(IdentityOnionState {
            seed: [7u8; 32],
            onion: "a".repeat(56) + ".onion",
            onion_key: vec![1, 2, 3, 4],
        });
        s.set_ratchet_bytes("c1", vec![9u8; 40]);
        s.pending.push(("b.onion".into(), vec![5u8; 16]));
        s.pending_invites = vec![3u8; 24];
        s.verified_ids.push("c1".into());
        s.disappear_ttl_secs = 3600;
        s
    }

    #[test]
    fn roundtrip_keeps_identity_and_prefs() {
        let s = sample();
        let file = export_backup(&s, PASS, 1_700_000_000).unwrap();
        assert!(looks_like_backup(&file));
        let (r, info) = open_backup(&file, PASS).unwrap();
        assert_eq!(info.created_unix, 1_700_000_000);
        assert_eq!(r.identity.seed, [7u8; 32]);
        assert_eq!(r.identity.onion, s.identity.onion);
        assert_eq!(r.identity.onion_key, vec![1, 2, 3, 4]);
        assert_eq!(r.verified_ids, vec!["c1".to_string()]);
        assert_eq!(r.disappear_ttl_secs, 3600);
    }

    #[test]
    fn drops_ratchets_pending_and_invites() {
        let file = export_backup(&sample(), PASS, 1).unwrap();
        let (r, _) = open_backup(&file, PASS).unwrap();
        assert!(r.ratchets.is_empty());
        assert!(r.pending.is_empty());
        assert!(r.pending_invites.is_empty());
        assert!(r.save_id.is_none());
        assert!(r.wipe_settings.is_none());
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let file = export_backup(&sample(), PASS, 1).unwrap();
        assert!(open_backup(&file, "a different long passphrase").is_err());
        assert!(open_backup(&file, "").is_err());
    }

    #[test]
    fn tamper_and_truncation_fail() {
        let file = export_backup(&sample(), PASS, 1).unwrap();
        let mut bad = file.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open_backup(&bad, PASS).is_err());
        let mut ver = file.clone();
        ver[4] = 99;
        assert_eq!(
            open_backup(&ver, PASS).err().unwrap(),
            "unsupported backup version"
        );
        assert!(open_backup(&file[..file.len() / 2], PASS).is_err());
        assert_eq!(
            open_backup(b"nope", PASS).err().unwrap(),
            "not a HashChat backup"
        );
    }

    #[test]
    fn weak_passphrase_refused() {
        assert!(export_backup(&sample(), "short", 1).is_err());
    }

    #[test]
    fn extreme_refuses_export() {
        let mut s = sample();
        s.net.posture = PostureProfile::Extreme;
        assert!(export_backup(&s, PASS, 1).is_err());
    }
}
