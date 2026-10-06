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
//! Blob version: v1 = identity+onion only (H2); v2 = + contacts/ratchets/pending (H3);
//! v3 = + network prefs ([`crate::net_mode::NetConfig`]: mode / DNS / posture).
//! v4 = + disappearing TTL seconds (u32 BE; 0 = off). Local policy only — not on the wire.
//! v5 = + blocked / muted contact-id string lists (deny list; Standard durable).
//! v6 = + verified contact-id string list (SAS out-of-band trust gate; Standard durable).
//! v7 = + idle auto-lock timeout seconds (u32 BE; 0 = off; default 300 = 5m on missing).
//! v8 = + maximum send jitter seconds (u32 BE; 0 = off, the default on missing).
//! v9 = + clock mark (u64 BE): latest wall-clock time seen at save, rounded down
//! to ten minutes, used to warn about a clock set back ([`crate::clock_check`]).
//! Load accepts v1–v9; save always writes v9. Older blobs load empty deny lists;
//! pre-v6 contacts are treated as **verified** for continuity (new `:add-contact`
//! entries start unverified). Pre-v7 loads default idle lock to 5 minutes.
//!
//! ## File hygiene
//! `state.enc` and `machine.key` go through [`crate::private_fs`]: the data dir must
//! be a non-symlink directory owned by the effective uid (group/other bits are
//! cleared to 0700); files are opened `O_NOFOLLOW` and refused unless they are
//! regular, owner-owned, and carry no group/other bits. Writes are temp-file +
//! `fsync` + `rename`, so a crash cannot leave a truncated blob.
//!
//! ## Extreme disk policy (honest, fail-closed)
//! When [`crate::net_mode::PostureProfile::Extreme`] is set on the session's
//! [`NetConfig`], [`save_session`] persists **identity + onion + net prefs +
//! disappear TTL + idle lock timeout + send jitter only**. Contacts, ratchets, pending frames, blocked/muted, and
//! verified lists are written as empty vectors (blob stays v9). Trade-off: smaller
//! at-rest footprint and no multi-session contact/deny/verify continuity — the user
//! must re-add contacts (and re-block / re-verify if needed) after restart. Tor 1:1
//! messaging for the **current** process session is unchanged (in-memory
//! contacts/ratchets/queue/deny/verify lists still work until exit).
//!
//! **Load:** legacy Extreme blobs that still contain contacts/deny/verify lists are
//! loaded into memory for the current session; the next Extreme save strips them.
//! Standard posture keeps full H3 + deny-list + verified-set round-trip.
//!
//! Prefs are non-secret policy but live inside the wrapped blob so they cannot be
//! silently toggled by swapping a plaintext sibling file under `hashchat_data/`.
//! Missing prefs on v1/v2 load default to [`crate::net_mode::NetConfig::default`]
//! (Tor + standard); missing TTL on v1–v3 loads as `0` (off); missing deny lists
//! on v1–v4 load as empty; missing verified set on v1–v5 loads as all contact ids
//! verified (continuity); missing idle lock on v1–v6 loads as 300 seconds (5m).

use crate::disappearing::DEFAULT_LOCK_TIMEOUT_SECS;
use crate::clock_check::advance_clock_mark;
use crate::send_jitter::MAX_SEND_JITTER_SECS;
use crate::envelope::{self, StoreKey};
use crate::longterm_identity::LongTermIdentity;
use crate::net_mode::NetConfig;
use crate::private_fs::{self, PrivateFsError, MAX_PRIVATE_FILE_BYTES};
use crate::ratchet::{decrypt_with_key, encrypt_with_key};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AEAD domain separation for the insecure-dev machine-key wrap path.
const STATE_AAD: &[u8] = b"HashChat-v1-identity-onion-state";

/// On-disk plaintext blob versions (inside the outer wrap).
const BLOB_VERSION_V1: u8 = 1;
#[cfg(test)]
const BLOB_VERSION_V2: u8 = 2;
const BLOB_VERSION_V3: u8 = 3;
const BLOB_VERSION_V4: u8 = 4;
const BLOB_VERSION_V5: u8 = 5;
const BLOB_VERSION_V6: u8 = 6;
const BLOB_VERSION_V7: u8 = 7;
const BLOB_VERSION_V8: u8 = 8;
const BLOB_VERSION_V9: u8 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistMode {
    /// Production default: Argon2id(passphrase) wrap. Empty passphrase refused.
    Passphrase,
    /// Explicit insecure: raw machine.key wraps AES-GCM. Dev/CI only.
    InsecureDevMachineKey,
}

impl PersistMode {
    /// Resolve mode: insecure only when explicitly requested via flag or env.
    /// The env var must be exactly `1`; empty, `0` or any other value keeps the
    /// passphrase mode.
    pub fn from_flags(insecure_dev: bool) -> Self {
        let env_opt_in = |v: std::ffi::OsString| insecure_env_value_enables(&v);
        if insecure_dev || std::env::var_os("HASHCHAT_INSECURE_DEV_PERSIST").is_some_and(env_opt_in)
        {
            PersistMode::InsecureDevMachineKey
        } else {
            PersistMode::Passphrase
        }
    }
}

/// Only the exact value `1` opts in to insecure-dev persistence.
fn insecure_env_value_enables(v: &std::ffi::OsStr) -> bool {
    v == "1"
}

/// Maximum Unicode scalar count for a contact display name (`:rename`).
pub const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Upper bound on queued outbound frames kept in `state.enc`.
pub const MAX_PENDING_FRAMES: usize = 64;

/// Error text returned when a send is refused because the queue is full.
pub const ERR_QUEUE_FULL: &str = "outgoing queue full";

/// Validate a user-chosen contact display name.
///
/// Rules (fail-closed): non-empty after trim, at most [`MAX_DISPLAY_NAME_LEN`] chars,
/// no ASCII control characters / newlines, and must not look like a `hashchat://` link.
/// Returns the trimmed name on success.
pub fn validate_display_name(name: &str) -> Result<String, &'static str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("empty display name");
    }
    if trimmed.chars().count() > MAX_DISPLAY_NAME_LEN {
        return Err("display name too long");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("display name has control characters");
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("hashchat://") || lower.starts_with("hashchat:") {
        return Err("display name looks like a contact link");
    }
    Ok(trimmed.to_string())
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

/// Result of [`SessionState::upsert_contact_from_link`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactUpsert {
    pub id: String,
    pub was_update: bool,
    /// Onion, X25519 or Ed25519 differ from the stored record (SAS changed).
    pub identity_changed: bool,
    /// Record before the update (public material only).
    pub previous: Option<PersistedContact>,
    /// Verification state after the upsert.
    pub verified: bool,
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
    /// Network prefs (mode / DNS / posture). Non-secret policy; in-blob so a
    /// plaintext sibling cannot silently toggle them (v3+).
    #[zeroize(skip)]
    pub net: NetConfig,
    /// Local disappearing-message TTL in seconds (`0` = off). v4+; not sent on wire.
    #[zeroize(skip)]
    pub disappear_ttl_secs: u32,
    /// Contact ids refused for send + inbound decrypt/display (v5+; Standard durable).
    #[zeroize(skip)]
    pub blocked_ids: Vec<String>,
    /// Contact ids whose inbound plaintext is suppressed in UI after decrypt (v5+).
    /// Mute still advances the ratchet for sync; block does not decrypt.
    #[zeroize(skip)]
    pub muted_ids: Vec<String>,
    /// Contact ids marked SAS-verified out-of-band (v6+; Standard durable).
    /// Pre-v6 loads treat existing contacts as verified; new adds start unverified.
    /// This is a TOFU helper on top of Ed25519 link verify — not extra crypto binding.
    #[zeroize(skip)]
    pub verified_ids: Vec<String>,
    /// Idle auto-lock timeout in seconds (`0` = off). v7+; local UI defense only.
    /// Missing on pre-v7 load → [`DEFAULT_LOCK_TIMEOUT_SECS`] (5 minutes).
    #[zeroize(skip)]
    pub lock_timeout_secs: u32,
    /// Upper bound of the random delay before a send, in seconds (`0` = off). v8+.
    #[zeroize(skip)]
    pub send_jitter_secs: u32,
    /// Latest clock time recorded at a save (v9+; 0 = none yet). Each save
    /// raises it to the current time; it never goes down on its own.
    #[zeroize(skip)]
    pub clock_mark_unix: u64,
}

impl SessionState {
    pub fn from_identity(identity: IdentityOnionState) -> Self {
        Self {
            identity,
            contacts: Vec::new(),
            ratchets: Vec::new(),
            pending: Vec::new(),
            net: NetConfig::default(),
            disappear_ttl_secs: 0,
            blocked_ids: Vec::new(),
            muted_ids: Vec::new(),
            verified_ids: Vec::new(),
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            send_jitter_secs: 0,
            clock_mark_unix: 0,
        }
    }

    /// Fresh session seeded with caller prefs (new identity / cold create).
    pub fn from_identity_with_net(identity: IdentityOnionState, net: NetConfig) -> Self {
        Self {
            identity,
            contacts: Vec::new(),
            ratchets: Vec::new(),
            pending: Vec::new(),
            net,
            disappear_ttl_secs: 0,
            blocked_ids: Vec::new(),
            muted_ids: Vec::new(),
            verified_ids: Vec::new(),
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            send_jitter_secs: 0,
            clock_mark_unix: 0,
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

    /// Insert or update a contact from a verified signed link, applying the
    /// SAS trust rule:
    ///
    /// - A record matches if its onion **or** Ed25519 key equals the link's
    ///   (a record matching both is preferred).
    /// - If onion, X25519 and Ed25519 are all byte-identical, the record is a pure
    ///   re-import: verification and any `:rename` label are kept.
    /// - If any of the three differ, the SAS the user compared no longer applies:
    ///   the id is removed from `verified_ids` and the label is reset to
    ///   `default_label`, so neither trust nor a trusted name carries over to
    ///   new keys.
    /// - New records get an id not used by any contact or by the verified /
    ///   blocked / muted / ratchet lists, and always start unverified.
    ///
    /// The caller installs the ratchet for the returned id and persists.
    pub fn upsert_contact_from_link(
        &mut self,
        onion: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        default_label: &str,
    ) -> ContactUpsert {
        let both = self
            .contacts
            .iter()
            .position(|c| c.onion == onion && c.ed25519 == ed25519);
        let existing = both.or_else(|| {
            self.contacts
                .iter()
                .position(|c| c.onion == onion || c.ed25519 == ed25519)
        });
        if let Some(i) = existing {
            let previous = self.contacts[i].clone();
            let identity_changed = previous.onion != onion
                || previous.x25519 != x25519
                || previous.ed25519 != ed25519;
            let id = previous.id.clone();
            {
                let c = &mut self.contacts[i];
                c.onion = onion.to_string();
                c.x25519 = x25519;
                c.ed25519 = ed25519;
                if identity_changed || c.display_name.is_empty() {
                    c.display_name = default_label.to_string();
                }
            }
            if identity_changed {
                self.verified_ids.retain(|v| v != &id);
            }
            let verified = self.is_verified_id(&id);
            return ContactUpsert {
                id,
                was_update: true,
                identity_changed,
                previous: Some(previous),
                verified,
            };
        }
        let id = self.fresh_contact_id();
        self.verified_ids.retain(|v| v != &id);
        self.contacts.push(PersistedContact {
            id: id.clone(),
            display_name: default_label.to_string(),
            onion: onion.to_string(),
            x25519,
            ed25519,
        });
        ContactUpsert {
            id,
            was_update: false,
            identity_changed: false,
            previous: None,
            verified: false,
        }
    }

    /// `c<N>` not referenced by any contact or per-id list (avoids inheriting
    /// verification / block / mute / ratchet state after deletes).
    fn fresh_contact_id(&self) -> String {
        let used = |id: &str| {
            self.contacts.iter().any(|c| c.id == id)
                || self.verified_ids.iter().any(|v| v == id)
                || self.blocked_ids.iter().any(|v| v == id)
                || self.muted_ids.iter().any(|v| v == id)
                || self.ratchets.iter().any(|(k, _)| k == id)
        };
        let mut n = self.contacts.len() + 1;
        loop {
            let id = format!("c{n}");
            if !used(&id) {
                return id;
            }
            n += 1;
        }
    }

    /// Append a pending frame. Returns false and zeroizes `frame` when the
    /// queue already holds [`MAX_PENDING_FRAMES`]; callers must not treat the
    /// message as committed in that case.
    pub fn queue_pending(&mut self, onion: impl Into<String>, mut frame: Vec<u8>) -> bool {
        if self.pending.len() >= MAX_PENDING_FRAMES {
            frame.zeroize();
            return false;
        }
        self.pending.push((onion.into(), frame));
        true
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


    /// Resolve `:block` / `:mute` / `:rename` token to a contact id
    /// (exact id, onion, unique display-name / SAS / id prefix).
    /// Returns `None` if empty, ambiguous, or unknown — caller must refuse without guessing.
    pub fn resolve_deny_token(&self, token: &str) -> Option<String> {
        let t = token.trim();
        if t.is_empty() {
            return None;
        }
        if let Some(c) = self.contacts.iter().find(|c| c.id == t) {
            return Some(c.id.clone());
        }
        if let Some(c) = self
            .contacts
            .iter()
            .find(|c| c.onion == t || c.onion.eq_ignore_ascii_case(t))
        {
            return Some(c.id.clone());
        }
        let tl = t.to_ascii_lowercase();
        let matches: Vec<&PersistedContact> = self
            .contacts
            .iter()
            .filter(|c| {
                let label = if c.display_name.is_empty() {
                    c.id.as_str()
                } else {
                    c.display_name.as_str()
                };
                let sas = if c.ed25519 != [0u8; 32] && !c.onion.is_empty() {
                    Some(crate::contact_link::sas_fingerprint(
                        &c.ed25519,
                        &c.x25519,
                        &c.onion,
                    ))
                } else {
                    None
                };
                label.to_ascii_lowercase().starts_with(&tl)
                    || c.id.to_ascii_lowercase().starts_with(&tl)
                    || sas
                        .as_ref()
                        .map(|s| s.to_ascii_lowercase().starts_with(&tl))
                        .unwrap_or(false)
            })
            .collect();
        if matches.len() == 1 {
            Some(matches[0].id.clone())
        } else {
            None
        }
    }

    /// Set `display_name` for a contact id after [`validate_display_name`].
    /// Never modifies id / onion / keys. Extreme: in-RAM only until exit (`for_disk` strips).
    pub fn rename_contact_display_name(
        &mut self,
        contact_id: &str,
        new_name: &str,
    ) -> Result<(), &'static str> {
        let name = validate_display_name(new_name)?;
        let id = contact_id.trim();
        if id.is_empty() {
            return Err("unknown contact");
        }
        let c = self
            .contacts
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or("unknown contact")?;
        // Identity material stays put — label only.
        c.display_name = name;
        Ok(())
    }

    /// True if `contact_id` is on the durable block list.
    pub fn is_blocked_id(&self, contact_id: &str) -> bool {
        self.blocked_ids.iter().any(|id| id == contact_id)
    }

    /// True if `contact_id` is muted (UI suppress; decrypt still allowed).
    pub fn is_muted_id(&self, contact_id: &str) -> bool {
        self.muted_ids.iter().any(|id| id == contact_id)
    }

    /// Fail-closed send gate: Err when contact is blocked. No plaintext logging.
    pub fn refuse_send_if_blocked(&self, contact_id: &str) -> Result<(), &'static str> {
        if self.is_blocked_id(contact_id) {
            Err("blocked contact")
        } else {
            Ok(())
        }
    }

    /// True if `contact_id` is on the SAS-verified set.
    pub fn is_verified_id(&self, contact_id: &str) -> bool {
        self.verified_ids.iter().any(|id| id == contact_id)
    }

    /// Fail-closed send gate: Err when contact is not SAS-verified. No plaintext logging.
    pub fn refuse_send_if_unverified(&self, contact_id: &str) -> Result<(), &'static str> {
        if self.is_verified_id(contact_id) {
            Ok(())
        } else {
            Err("unverified contact")
        }
    }

    /// Mark contact id as SAS-verified (idempotent). Returns true if newly verified.
    pub fn verify_contact_id(&mut self, contact_id: impl Into<String>) -> bool {
        let id = contact_id.into();
        if self.verified_ids.iter().any(|v| v == &id) {
            return false;
        }
        self.verified_ids.push(id);
        true
    }

    /// Remove id from verified set (contact resolve or orphan token). Returns true if removed.
    pub fn unverify_contact_id(&mut self, token: &str) -> bool {
        let t = token.trim();
        if t.is_empty() {
            return false;
        }
        let before = self.verified_ids.len();
        if let Some(id) = self.resolve_deny_token(t) {
            self.verified_ids.retain(|v| v != &id);
        }
        let tl = t.to_ascii_lowercase();
        let list_matches: Vec<String> = self
            .verified_ids
            .iter()
            .filter(|v| v == &t || v.to_ascii_lowercase().starts_with(&tl))
            .cloned()
            .collect();
        if list_matches.len() == 1 {
            let id = &list_matches[0];
            self.verified_ids.retain(|v| v != id);
        } else if list_matches.iter().any(|v| v == t) {
            self.verified_ids.retain(|v| v != t);
        }
        self.verified_ids.len() < before
    }

    /// Inbound policy for a known contact id (after wire hint / ratchet match).
    pub fn inbound_deny_policy(&self, contact_id: &str) -> InboundDenyPolicy {
        if self.is_blocked_id(contact_id) {
            InboundDenyPolicy::DropNoDecrypt
        } else if self.is_muted_id(contact_id) {
            InboundDenyPolicy::DecryptNoDisplay
        } else {
            InboundDenyPolicy::Accept
        }
    }

    /// Add contact id to block list (idempotent). Removes mute for same id (block wins).
    /// Returns true if newly blocked.
    pub fn block_contact_id(&mut self, contact_id: impl Into<String>) -> bool {
        let id = contact_id.into();
        self.muted_ids.retain(|m| m != &id);
        if self.blocked_ids.iter().any(|b| b == &id) {
            return false;
        }
        self.blocked_ids.push(id);
        true
    }

    /// Remove id from block list. Also accepts exact token match against stored ids
    /// when the contact was already removed. Returns true if something was removed.
    pub fn unblock_contact_id(&mut self, token: &str) -> bool {
        let t = token.trim();
        if t.is_empty() {
            return false;
        }
        let before = self.blocked_ids.len();
        if let Some(id) = self.resolve_deny_token(t) {
            self.blocked_ids.retain(|b| b != &id);
        }
        // Orphan / Extreme-stripped ids: exact or unique prefix against the list itself.
        let tl = t.to_ascii_lowercase();
        let list_matches: Vec<String> = self
            .blocked_ids
            .iter()
            .filter(|b| b == &t || b.to_ascii_lowercase().starts_with(&tl))
            .cloned()
            .collect();
        if list_matches.len() == 1 {
            let id = &list_matches[0];
            self.blocked_ids.retain(|b| b != id);
        } else if list_matches.iter().any(|b| b == t) {
            self.blocked_ids.retain(|b| b != t);
        }
        self.blocked_ids.len() < before
    }

    /// Mute contact id (idempotent). No-op if already blocked (block supersedes).
    pub fn mute_contact_id(&mut self, contact_id: impl Into<String>) -> Result<bool, &'static str> {
        let id = contact_id.into();
        if self.is_blocked_id(&id) {
            return Err("contact is blocked (unblock first)");
        }
        if self.muted_ids.iter().any(|m| m == &id) {
            return Ok(false);
        }
        self.muted_ids.push(id);
        Ok(true)
    }

    /// Remove id from mute list (contact resolve or orphan token).
    pub fn unmute_contact_id(&mut self, token: &str) -> bool {
        let t = token.trim();
        if t.is_empty() {
            return false;
        }
        let before = self.muted_ids.len();
        if let Some(id) = self.resolve_deny_token(t) {
            self.muted_ids.retain(|m| m != &id);
        }
        let tl = t.to_ascii_lowercase();
        let list_matches: Vec<String> = self
            .muted_ids
            .iter()
            .filter(|m| m == &t || m.to_ascii_lowercase().starts_with(&tl))
            .cloned()
            .collect();
        if list_matches.len() == 1 {
            let id = &list_matches[0];
            self.muted_ids.retain(|m| m != id);
        } else if list_matches.iter().any(|m| m == t) {
            self.muted_ids.retain(|m| m != t);
        }
        self.muted_ids.len() < before
    }

    /// Remove one contact and securely wipe its ratchet, pending frames, and deny entries.
    ///
    /// Zeroizes ratchet bytes and pending ciphertext bodies for this contact before drop.
    /// Also removes matching blocked/muted ids and clears contact public-key fields.
    /// Does not touch identity or other contacts. Returns true if the contact id was found.
    ///
    /// Extreme: same in-RAM behavior; the next [`save_session`] still strips lists via
    /// [`Self::for_disk`] (no durable contact continuity under Extreme).
    pub fn delete_contact_secure(&mut self, contact_id: &str) -> bool {
        let id = contact_id.trim();
        if id.is_empty() {
            return false;
        }
        let Some(pos) = self.contacts.iter().position(|c| c.id == id) else {
            return false;
        };
        let onion = self.contacts[pos].onion.clone();
        {
            let c = &mut self.contacts[pos];
            c.x25519.zeroize();
            c.ed25519.zeroize();
            c.onion.clear();
            c.display_name.clear();
            c.id.clear();
        }
        self.contacts.remove(pos);

        let mut kept_ratchets: Vec<(String, Vec<u8>)> = Vec::with_capacity(self.ratchets.len());
        for (rid, mut bytes) in self.ratchets.drain(..) {
            if rid == id {
                bytes.zeroize();
            } else {
                kept_ratchets.push((rid, bytes));
            }
        }
        self.ratchets = kept_ratchets;

        if !onion.is_empty() {
            let mut kept_pending: Vec<(String, Vec<u8>)> = Vec::with_capacity(self.pending.len());
            for (dest, mut frame) in self.pending.drain(..) {
                if dest == onion || dest.eq_ignore_ascii_case(&onion) {
                    frame.zeroize();
                } else {
                    kept_pending.push((dest, frame));
                }
            }
            self.pending = kept_pending;
        }

        self.blocked_ids.retain(|b| b != id);
        self.muted_ids.retain(|m| m != id);
        self.verified_ids.retain(|v| v != id);
        true
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

    /// Build the on-disk view for the current posture.
    ///
    /// Under **Extreme**, contacts / ratchets / pending / blocked / muted / verified
    /// are empty so they are not durable across restart. Identity, onion material,
    /// net prefs, disappear TTL, and idle lock timeout are kept. Under **Standard**,
    /// returns a full clone (H3 + deny lists + verified set).
    ///
    /// The live in-memory session is unchanged; callers keep working state for the
    /// current Tor session and only the durable blob is minimized.
    pub fn for_disk(&self) -> SessionState {
        if !self.net.is_extreme() {
            return self.clone();
        }
        SessionState {
            identity: IdentityOnionState {
                seed: self.identity.seed,
                onion: self.identity.onion.clone(),
                onion_key: self.identity.onion_key.clone(),
            },
            contacts: Vec::new(),
            ratchets: Vec::new(),
            pending: Vec::new(),
            net: self.net.clone(),
            disappear_ttl_secs: self.disappear_ttl_secs,
            blocked_ids: Vec::new(),
            muted_ids: Vec::new(),
            verified_ids: Vec::new(),
            lock_timeout_secs: self.lock_timeout_secs,
            send_jitter_secs: self.send_jitter_secs,
            clock_mark_unix: self.clock_mark_unix,
        }
    }

    /// Nuclear in-RAM wipe for a loaded session (pending frames, ratchets, onion_key, seed).
    /// Does not touch disk — pair with [`wipe_disk`] / [`crate::wipe_local_sensitive`].
    ///
    /// Honest limits: cannot erase copies already swapped, core-dumped, or exfiltrated;
    /// cannot defeat a kernel implant. See THREATMODEL.md.
    pub fn wipe_memory_secure(&mut self) {
        self.clear_pending_secure();
        self.clear_ratchets_secure();
        self.contacts.clear();
        self.blocked_ids.clear();
        self.muted_ids.clear();
        self.verified_ids.clear();
        self.identity.seed.zeroize();
        self.identity.onion_key.zeroize();
        self.identity.onion_key.clear();
        // onion address is public routing material but still session residue — drop it.
        self.identity.onion.clear();
        self.net = NetConfig::default();
        self.disappear_ttl_secs = 0;
        self.lock_timeout_secs = 0;
        self.send_jitter_secs = 0;
        self.clock_mark_unix = 0;
    }
}

/// Inbound handling for deny lists (fail-closed for block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundDenyPolicy {
    /// Not denied — decrypt and display.
    Accept,
    /// Muted — decrypt (ratchet sync) but do not show plaintext in the UI.
    DecryptNoDisplay,
    /// Blocked — do not decrypt or display (refuse send separately).
    DropNoDecrypt,
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
    let end = pos.checked_add(n).ok_or("truncated bytes")?;
    if end > buf.len() {
        return Err("truncated bytes");
    }
    let out = buf[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

fn write_len_str(out: &mut Vec<u8>, s: &str) {
    write_len_bytes(out, s.as_bytes());
}

fn read_len_str(buf: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    let b = read_len_bytes(buf, pos)?;
    String::from_utf8(b).map_err(|_| "utf8")
}

fn write_string_list(out: &mut Vec<u8>, items: &[String]) {
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for s in items {
        write_len_str(out, s);
    }
}

fn read_string_list(buf: &[u8], pos: &mut usize) -> Result<Vec<String>, &'static str> {
    if *pos + 4 > buf.len() {
        return Err("truncated string list count");
    }
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    // Each string needs >= 4 length bytes; bound the prealloc.
    let mut out = Vec::with_capacity(n.min(buf.len().saturating_sub(*pos) / 4));
    for _ in 0..n {
        out.push(read_len_str(buf, pos)?);
    }
    Ok(out)
}

fn serialize_blob(state: &SessionState) -> Vec<u8> {
    serialize_blob_at(state, crate::deadman::unix_now())
}

fn serialize_blob_at(state: &SessionState, now_unix: u64) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.push(BLOB_VERSION_V9);
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

    // network prefs (v3+)
    let prefs = state.net.to_persist_bytes();
    write_len_bytes(&mut plain, &prefs);

    // disappearing TTL (v4+)
    plain.extend_from_slice(&state.disappear_ttl_secs.to_be_bytes());

    // deny lists (v5+)
    write_string_list(&mut plain, &state.blocked_ids);
    write_string_list(&mut plain, &state.muted_ids);

    // verified set (v6+)
    write_string_list(&mut plain, &state.verified_ids);

    // idle auto-lock timeout (v7+)
    plain.extend_from_slice(&state.lock_timeout_secs.to_be_bytes());

    // send jitter (v8+)
    plain.extend_from_slice(&state.send_jitter_secs.to_be_bytes());

    // clock mark (v9+)
    let mark = advance_clock_mark(state.clock_mark_unix, now_unix);
    plain.extend_from_slice(&mark.to_be_bytes());

    plain
}

fn deserialize_blob(plain: &[u8]) -> Result<SessionState, &'static str> {
    if plain.is_empty() {
        return Err("empty state blob");
    }
    let ver = plain[0];
    if !(BLOB_VERSION_V1..=BLOB_VERSION_V9).contains(&ver) {
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
        // H2-only blob: no contacts/ratchets/pending/prefs — defaults.
        return Ok(SessionState::from_identity(identity));
    }

    // v2 / v3 extras
    if pos + 4 > plain.len() {
        return Err("truncated contacts count");
    }
    let n_contacts =
        u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut contacts = Vec::with_capacity(n_contacts.min(plain.len().saturating_sub(pos) / 76));
    for _ in 0..n_contacts {
        let id = read_len_str(plain, &mut pos)?;
        let display_name = read_len_str(plain, &mut pos)?;
        let onion = read_len_str(plain, &mut pos)?;
        if plain.len().saturating_sub(pos) < 64 {
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
    let mut ratchets = Vec::with_capacity(n_ratchets.min(plain.len().saturating_sub(pos) / 8));
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
    let mut pending = Vec::with_capacity(n_pending.min(plain.len().saturating_sub(pos) / 8));
    for _ in 0..n_pending {
        let onion = read_len_str(plain, &mut pos)?;
        let frame = read_len_bytes(plain, &mut pos)?;
        pending.push((onion, frame));
    }

    let net = if ver >= BLOB_VERSION_V3 {
        let prefs = read_len_bytes(plain, &mut pos)?;
        NetConfig::from_persist_bytes(&prefs).map_err(|_| "bad net prefs")?
    } else {
        // v2: prefs absent → Tor + standard.
        NetConfig::default()
    };

    let disappear_ttl_secs = if ver >= BLOB_VERSION_V4 {
        if pos + 4 > plain.len() {
            return Err("truncated disappear ttl");
        }
        let ttl = u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap());
        pos += 4;
        ttl
    } else {
        0
    };

    let (blocked_ids, muted_ids) = if ver >= BLOB_VERSION_V5 {
        let blocked = read_string_list(plain, &mut pos)?;
        let muted = read_string_list(plain, &mut pos)?;
        (blocked, muted)
    } else {
        (Vec::new(), Vec::new())
    };

    // v6+: explicit verified set. Pre-v6: treat all loaded contacts as verified
    // so existing sessions are not suddenly blocked from sending.
    let verified_ids = if ver >= BLOB_VERSION_V6 {
        read_string_list(plain, &mut pos)?
    } else {
        contacts.iter().map(|c| c.id.clone()).collect()
    };

    // v7: idle lock timeout. Pre-v7: default 5 minutes (enable auto-lock for upgrades).
    let lock_timeout_secs = if ver >= BLOB_VERSION_V7 {
        if pos + 4 > plain.len() {
            return Err("truncated lock timeout");
        }
        let secs = u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap());
        pos += 4;
        secs
    } else {
        DEFAULT_LOCK_TIMEOUT_SECS
    };

    // v8: send jitter. Older blobs start with it off.
    let send_jitter_secs = if ver >= BLOB_VERSION_V8 {
        if pos + 4 > plain.len() {
            return Err("truncated send jitter");
        }
        let secs = u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap());
        pos += 4;
        secs.min(MAX_SEND_JITTER_SECS)
    } else {
        0
    };

    // v9: clock mark. Older blobs have none, so the first unlock cannot warn.
    let clock_mark_unix = if ver >= BLOB_VERSION_V9 {
        if pos + 8 > plain.len() {
            return Err("truncated clock mark");
        }
        let mark = u64::from_be_bytes(plain[pos..pos + 8].try_into().unwrap());
        pos += 8;
        mark
    } else {
        0
    };

    if pos != plain.len() {
        return Err("trailing junk in state blob");
    }

    Ok(SessionState {
        identity,
        contacts,
        ratchets,
        pending,
        net,
        disappear_ttl_secs,
        blocked_ids,
        muted_ids,
        verified_ids,
        lock_timeout_secs,
        send_jitter_secs,
        clock_mark_unix,
    })
}

const STATE_FILE: &str = "state.enc";
const MACHINE_KEY_FILE: &str = "machine.key";

/// Test helper: atomic owner-only write; `path` must be `dir/name`.
#[cfg(test)]
fn write_private(path: &Path, data: &[u8]) -> Result<(), &'static str> {
    let dir = path.parent().ok_or("invalid state path")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid state path")?;
    private_fs::write_private_file(dir, name, data).map_err(PrivateFsError::as_str)
}

fn machine_key_load_or_create(data_dir: &Path) -> Result<[u8; 32], &'static str> {
    match private_fs::read_private_file(data_dir, MACHINE_KEY_FILE, 32) {
        Ok(mut b) => {
            if b.len() != 32 {
                b.zeroize();
                // Refuse rather than regenerate: a new key would orphan state.enc.
                return Err("machine.key malformed");
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            b.zeroize();
            Ok(k)
        }
        Err(PrivateFsError::NotFound) => {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).map_err(|_| "csprng failed")?;
            private_fs::write_private_file(data_dir, MACHINE_KEY_FILE, &k)
                .map_err(PrivateFsError::as_str)?;
            Ok(k)
        }
        Err(e) => Err(e.as_str()),
    }
}

/// How a state blob is wrapped. Internal: public APIs pick one.
enum Wrap<'a> {
    Passphrase(&'a [u8]),
    InsecureDevMachineKey,
    Key(&'a StoreKey),
}

impl<'a> Wrap<'a> {
    fn from_mode(mode: PersistMode, passphrase: &'a [u8]) -> Self {
        match mode {
            PersistMode::Passphrase => Wrap::Passphrase(passphrase),
            PersistMode::InsecureDevMachineKey => Wrap::InsecureDevMachineKey,
        }
    }
}

fn seal_plain(wrap: &Wrap<'_>, data_dir: &Path, plain: &[u8]) -> Result<Vec<u8>, &'static str> {
    match wrap {
        Wrap::Passphrase(passphrase) => {
            let _ = fs::remove_file(data_paths(data_dir).1);
            envelope::seal(passphrase, plain)
        }
        Wrap::Key(k) => {
            let _ = fs::remove_file(data_paths(data_dir).1);
            envelope::seal_with_key(k, plain)
        }
        Wrap::InsecureDevMachineKey => {
            let mut key = machine_key_load_or_create(data_dir)?;
            let env = encrypt_with_key(&key, plain, STATE_AAD)?;
            key.zeroize();
            Ok(env)
        }
    }
}

fn open_env(wrap: &Wrap<'_>, data_dir: &Path, env: &[u8]) -> Result<Vec<u8>, &'static str> {
    match wrap {
        Wrap::Passphrase(passphrase) => envelope::open(passphrase, env),
        Wrap::Key(k) => envelope::open_with_key(k, env),
        Wrap::InsecureDevMachineKey => {
            let mut key = machine_key_load_or_create(data_dir)?;
            let out = decrypt_with_key(&key, env, STATE_AAD)?;
            key.zeroize();
            Ok(out)
        }
    }
}

fn save_session_wrapped(
    data_dir: &Path,
    wrap: &Wrap<'_>,
    state: &SessionState,
) -> Result<(), &'static str> {
    // Harden / refuse the directory before the (slow) KDF and before any write.
    private_fs::ensure_private_dir(data_dir).map_err(PrivateFsError::as_str)?;
    let disk = state.for_disk();
    let mut plain = serialize_blob(&disk);
    let envelope = seal_plain(wrap, data_dir, &plain);
    plain.zeroize();
    // `disk` ZeroizeOnDrop clears onion_key / ratchet / pending copies.
    drop(disk);
    private_fs::write_private_file(data_dir, STATE_FILE, &envelope?)
        .map_err(PrivateFsError::as_str)?;
    Ok(())
}

/// True if `passphrase` opens the current `state.enc`. One Argon2id run.
pub(crate) fn passphrase_opens_state(data_dir: &Path, passphrase: &[u8]) -> bool {
    let Ok(env) = read_state_envelope(data_dir) else {
        return false;
    };
    let Ok(key) = StoreKey::derive_for_envelope(passphrase, &env) else {
        return false;
    };
    match envelope::open_with_key(&key, &env) {
        Ok(mut plain) => {
            plain.zeroize();
            true
        }
        Err(_) => false,
    }
}

fn read_state_envelope(data_dir: &Path) -> Result<Vec<u8>, &'static str> {
    private_fs::read_private_file(data_dir, STATE_FILE, MAX_PRIVATE_FILE_BYTES)
        .map_err(PrivateFsError::as_str)
}

fn load_session_wrapped(data_dir: &Path, wrap: &Wrap<'_>) -> Result<SessionState, &'static str> {
    let env = read_state_envelope(data_dir)?;
    let mut plain = open_env(wrap, data_dir, &env)?;
    let state = deserialize_blob(&plain);
    plain.zeroize();
    state
}

/// Save session state. Always writes v7.
///
/// Under Extreme posture (`state.net.is_extreme()`), contacts / ratchets / pending /
/// blocked / muted / verified are stripped via [`SessionState::for_disk`] before sealing
/// (identity / onion / prefs / TTL / lock-timeout kept).
/// Standard keeps full H3 + deny lists + verified set.
pub fn save_session(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
    state: &SessionState,
) -> Result<(), &'static str> {
    save_session_wrapped(data_dir, &Wrap::from_mode(mode, passphrase), state)
}

/// Load full session state. Accepts v1–v7 blobs (deny lists empty before v5;
/// pre-v6 contacts default to verified).
///
/// Extreme policy: if a legacy blob still contains contacts/queue/deny/verify lists, they
/// are loaded into memory for this session; the next Extreme [`save_session`] strips them.
pub fn load_session(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
) -> Result<SessionState, &'static str> {
    load_session_wrapped(data_dir, &Wrap::from_mode(mode, passphrase))
}

/// Passphrase unlock that returns the derived [`StoreKey`] so the caller can
/// drop the passphrase and use [`save_session_with_key`] afterwards. Runs
/// Argon2id once. Same on-disk format as [`load_session`].
pub fn unlock_session(
    data_dir: &Path,
    passphrase: &[u8],
) -> Result<(SessionState, StoreKey), &'static str> {
    let env = read_state_envelope(data_dir)?;
    let key = StoreKey::derive_for_envelope(passphrase, &env)?;
    let mut plain = envelope::open_with_key(&key, &env)?;
    let state = deserialize_blob(&plain);
    plain.zeroize();
    Ok((state?, key))
}

/// Save with a key from [`unlock_session`] / [`StoreKey::derive_new`] (no KDF run).
pub fn save_session_with_key(
    data_dir: &Path,
    key: &StoreKey,
    state: &SessionState,
) -> Result<(), &'static str> {
    save_session_wrapped(data_dir, &Wrap::Key(key), state)
}

/// Load with a key from [`unlock_session`] (no KDF run).
pub fn load_session_with_key(data_dir: &Path, key: &StoreKey) -> Result<SessionState, &'static str> {
    load_session_wrapped(data_dir, &Wrap::Key(key))
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
    let queued = session.queue_pending(dest_onion, frame);
    let r = if queued {
        save_session(data_dir, mode, passphrase, &session)
    } else {
        Err(ERR_QUEUE_FULL)
    };
    session.clear_pending_secure();
    session.clear_ratchets_secure();
    r
}

/// [`commit_outgoing`] with a derived [`StoreKey`] instead of a passphrase.
pub fn commit_outgoing_with_key(
    data_dir: &Path,
    key: &StoreKey,
    contact_id: &str,
    ratchet_bytes: Vec<u8>,
    dest_onion: &str,
    frame: Vec<u8>,
) -> Result<(), &'static str> {
    let mut session = load_session_with_key(data_dir, key)?;
    session.set_ratchet_bytes(contact_id, ratchet_bytes);
    let queued = session.queue_pending(dest_onion, frame);
    let r = if queued {
        save_session_with_key(data_dir, key, &session)
    } else {
        Err(ERR_QUEUE_FULL)
    };
    session.clear_pending_secure();
    session.clear_ratchets_secure();
    r
}

/// Remove at-rest identity/session files under `data_dir` (does not touch Tor HS dir).
/// Clears contacts, ratchets, and pending because they live inside `state.enc` (H3).
pub fn wipe_disk(data_dir: &Path) -> std::io::Result<()> {
    let (state_path, key_path) = data_paths(data_dir);
    crate::shred::shred_file(&state_path);
    crate::shred::shred_file(&key_path);
    private_fs::remove_stale_temps(data_dir, STATE_FILE);
    private_fs::remove_stale_temps(data_dir, MACHINE_KEY_FILE);
    crate::duress::clear_duress(data_dir);
    crate::deadman::clear_deadman(data_dir);
    crate::failwipe::clear_failwipe(data_dir);
    Ok(())
}

/// True if anything exists at `state.enc` (caller still needs the right mode + passphrase).
///
/// Uses `lstat`: a symlink, dangling or not, counts as existing so the TUI goes
/// to the unlock path (where [`check_state_storage`] refuses it) instead of the
/// create path.
pub fn state_exists(data_dir: &Path) -> bool {
    fs::symlink_metadata(data_paths(data_dir).0).is_ok()
}

/// Validate the state directory and `state.enc` (type, owner, mode, size) without
/// decrypting. Missing dir/file is `Ok`. Also clears group/other bits on the
/// directory. Returns an opaque, path-free reason on refusal.
///
/// Call before unlock so a storage problem is reported as such and is not counted
/// as a wrong passphrase by the unlock backoff.
pub fn check_state_storage(data_dir: &Path) -> Result<(), &'static str> {
    if fs::symlink_metadata(data_dir).is_err() {
        return Ok(());
    }
    private_fs::check_private_file(data_dir, STATE_FILE).map_err(PrivateFsError::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::{take_zeroizing_vec, DoubleRatchet};
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

    #[cfg(unix)]
    #[test]
    fn saved_state_is_owner_only_and_loose_state_refused() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tmp_dir("perm");
        // tmp_dir creates the dir under the ambient umask (typically 0755).
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let id = LongTermIdentity::from_seed([6u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "p.onion", Vec::new());
        save_disk(&dir, PersistMode::Passphrase, b"alpha", &state).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(dir.join("state.enc")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(check_state_storage(&dir), Ok(()));

        fs::set_permissions(dir.join("state.enc"), fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_state_storage(&dir).unwrap_err();
        assert!(err.contains("group/other"));
        // Refused before decryption, even with the right passphrase.
        assert!(load_disk(&dir, PersistMode::Passphrase, b"alpha").is_err());

        fs::set_permissions(dir.join("state.enc"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_disk(&dir, PersistMode::Passphrase, b"alpha").unwrap().seed,
            state.seed
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_enc_refused_and_counts_as_existing() {
        let dir = tmp_dir("symstate");
        let other = tmp_dir("symstate-real");
        let id = LongTermIdentity::from_seed([7u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "q.onion", Vec::new());
        save_disk(&other, PersistMode::Passphrase, b"alpha", &state).unwrap();
        std::os::unix::fs::symlink(other.join("state.enc"), dir.join("state.enc")).unwrap();

        assert!(state_exists(&dir));
        assert!(check_state_storage(&dir).unwrap_err().contains("symlink"));
        assert!(load_disk(&dir, PersistMode::Passphrase, b"alpha").is_err());
        let s2 = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "q.onion",
            Vec::new(),
        ));
        assert!(save_session(&dir, PersistMode::Passphrase, b"alpha", &s2).is_err());

        // Dangling link: still "exists", so the TUI never takes the create path over it.
        fs::remove_file(dir.join("state.enc")).unwrap();
        std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("state.enc")).unwrap();
        assert!(state_exists(&dir));
        assert!(save_session(&dir, PersistMode::Passphrase, b"alpha", &s2).is_err());
        assert!(!dir.join("nowhere").exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&other);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_data_dir_refused() {
        let real = tmp_dir("symdir-real");
        let link = std::env::temp_dir().join(format!(
            "hashchat-h3-symdir-link-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let id = LongTermIdentity::from_seed([8u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "r.onion", Vec::new());
        assert!(save_disk(&link, PersistMode::Passphrase, b"alpha", &state).is_err());
        assert!(!real.join("state.enc").exists());
        save_disk(&real, PersistMode::Passphrase, b"alpha", &state).unwrap();
        assert!(check_state_storage(&link).unwrap_err().contains("symlink"));
        assert!(load_disk(&link, PersistMode::Passphrase, b"alpha").is_err());
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
    }

    #[cfg(unix)]
    #[test]
    fn machine_key_owner_only_and_malformed_key_not_regenerated() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tmp_dir("mkey");
        let id = LongTermIdentity::from_seed([9u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "s.onion", Vec::new());
        save_disk(&dir, PersistMode::InsecureDevMachineKey, b"", &state).unwrap();
        let kp = dir.join("machine.key");
        assert_eq!(fs::metadata(&kp).unwrap().mode() & 0o777, 0o600);

        fs::set_permissions(&kp, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_disk(&dir, PersistMode::InsecureDevMachineKey, b"").is_err());
        fs::set_permissions(&kp, fs::Permissions::from_mode(0o600)).unwrap();

        let before = fs::read(&kp).unwrap();
        write_private(&kp, &before[..31]).unwrap();
        assert!(load_disk(&dir, PersistMode::InsecureDevMachineKey, b"").is_err());
        assert_eq!(fs::read(&kp).unwrap().len(), 31, "short key must not be replaced");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_returns_key_and_key_saves_stay_passphrase_compatible() {
        let dir = tmp_dir("storekey");
        let id = LongTermIdentity::from_seed([21u8; 32]);
        let mut state = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "k.onion",
            b"onionkey".to_vec(),
        ));
        save_session(&dir, PersistMode::Passphrase, b"correct horse", &state).unwrap();
        let env1 = fs::read(dir.join("state.enc")).unwrap();

        assert!(unlock_session(&dir, b"wrong horse").is_err());
        let (loaded, key) = unlock_session(&dir, b"correct horse").unwrap();
        assert_eq!(loaded.identity.seed, state.identity.seed);

        // Save twice with the key: header salt kept, nonce fresh, no KDF needed.
        state.disappear_ttl_secs = 60;
        save_session_with_key(&dir, &key, &state).unwrap();
        let env2 = fs::read(dir.join("state.enc")).unwrap();
        save_session_with_key(&dir, &key, &state).unwrap();
        let env3 = fs::read(dir.join("state.enc")).unwrap();
        assert_eq!(env1[..17], env2[..17], "version + salt unchanged");
        assert_ne!(env2[17..29], env3[17..29], "nonce must differ per save");

        // Same format: the passphrase path still opens it.
        let via_pass = load_session(&dir, PersistMode::Passphrase, b"correct horse").unwrap();
        assert_eq!(via_pass.disappear_ttl_secs, 60);
        let via_key = load_session_with_key(&dir, &key).unwrap();
        assert_eq!(via_key.disappear_ttl_secs, 60);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_key_from_other_store_is_refused() {
        let a = tmp_dir("storekey-a");
        let b = tmp_dir("storekey-b");
        let id = LongTermIdentity::from_seed([22u8; 32]);
        let st = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "x.onion",
            Vec::new(),
        ));
        save_session(&a, PersistMode::Passphrase, b"same pass phrase", &st).unwrap();
        save_session(&b, PersistMode::Passphrase, b"same pass phrase", &st).unwrap();
        let (_, ka) = unlock_session(&a, b"same pass phrase").unwrap();
        // Different salt → different key, refused before AEAD.
        assert!(load_session_with_key(&b, &ka).is_err());
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }

    #[test]
    fn new_store_key_creates_loadable_store_and_commit_with_key() {
        let dir = tmp_dir("storekey-new");
        let id = LongTermIdentity::from_seed([23u8; 32]);
        let mut st = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "n.onion",
            Vec::new(),
        ));
        st.contacts.push(PersistedContact {
            id: "c1".into(),
            display_name: "C".into(),
            onion: "p.onion".into(),
            x25519: [1; 32],
            ed25519: [2; 32],
        });
        let key = StoreKey::derive_new(b"brand new passphrase").unwrap();
        save_session_with_key(&dir, &key, &st).unwrap();
        commit_outgoing_with_key(&dir, &key, "c1", vec![9, 9], "p.onion", vec![1, 2, 3]).unwrap();
        let back = load_session(&dir, PersistMode::Passphrase, b"brand new passphrase").unwrap();
        assert_eq!(back.pending.len(), 1);
        assert_eq!(back.ratchets.len(), 1);
        assert!(StoreKey::derive_new(b"").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    fn upsert_session() -> SessionState {
        let id = LongTermIdentity::from_seed([11u8; 32]);
        SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "me.onion",
            Vec::new(),
        ))
    }

    #[test]
    fn upsert_new_contact_starts_unverified() {
        let mut s = upsert_session();
        let up = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        assert!(!up.was_update && !up.identity_changed && !up.verified);
        assert!(s.refuse_send_if_unverified(&up.id).is_err());
    }

    #[test]
    fn identical_reimport_keeps_verification_and_label() {
        let mut s = upsert_session();
        let up = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        s.verify_contact_id(&up.id);
        s.rename_contact_display_name(&up.id, "Alice").unwrap();
        let again = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        assert_eq!(again.id, up.id);
        assert!(again.was_update && !again.identity_changed && again.verified);
        assert_eq!(s.contacts[0].display_name, "Alice");
        assert!(s.refuse_send_if_unverified(&up.id).is_ok());
    }

    #[test]
    fn key_change_on_same_onion_drops_verification_and_label() {
        let mut s = upsert_session();
        let up = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        s.verify_contact_id(&up.id);
        s.rename_contact_display_name(&up.id, "Alice").unwrap();

        // Same onion, different identity keys.
        let ch = s.upsert_contact_from_link("a.onion", [9; 32], [8; 32], "SAS-X");
        assert_eq!(ch.id, up.id);
        assert!(ch.was_update && ch.identity_changed && !ch.verified);
        assert!(s.refuse_send_if_unverified(&up.id).is_err());
        assert_eq!(s.contacts[0].display_name, "SAS-X");
        assert_eq!(s.contacts[0].ed25519, [8; 32]);
        let prev = ch.previous.unwrap();
        assert_eq!(prev.ed25519, [2; 32]);
        assert_eq!(prev.display_name, "Alice");
    }

    #[test]
    fn x25519_only_change_drops_verification() {
        let mut s = upsert_session();
        let up = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        s.verify_contact_id(&up.id);
        let ch = s.upsert_contact_from_link("a.onion", [3; 32], [2; 32], "SAS-B");
        assert!(ch.identity_changed && !ch.verified);
    }

    #[test]
    fn onion_change_with_same_ed25519_drops_verification() {
        let mut s = upsert_session();
        let up = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        s.verify_contact_id(&up.id);
        let ch = s.upsert_contact_from_link("b.onion", [1; 32], [2; 32], "SAS-C");
        assert_eq!(ch.id, up.id);
        assert!(ch.identity_changed && !ch.verified);
        assert_eq!(s.contacts[0].onion, "b.onion");
    }

    #[test]
    fn identity_change_is_persisted_as_unverified() {
        let dir = tmp_dir("upsert-persist");
        let mut s = upsert_session();
        let up = s.upsert_contact_from_link("a.onion", [1; 32], [2; 32], "SAS-A");
        s.verify_contact_id(&up.id);
        s.upsert_contact_from_link("a.onion", [5; 32], [6; 32], "SAS-Z");
        save_session(&dir, PersistMode::Passphrase, b"pw", &s).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"pw").unwrap();
        assert!(!loaded.is_verified_id(&up.id));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_id_never_reuses_a_verified_or_listed_id() {
        let mut s = upsert_session();
        let a = s.upsert_contact_from_link("a.onion", [1; 32], [1; 32], "A");
        let b = s.upsert_contact_from_link("b.onion", [2; 32], [2; 32], "B");
        s.verify_contact_id(&b.id);
        s.block_contact_id(&b.id);
        // Remove the first record only; b keeps its id ("c2") and state.
        s.contacts.retain(|c| c.id != a.id);
        let c = s.upsert_contact_from_link("c.onion", [3; 32], [3; 32], "C");
        assert_ne!(c.id, b.id);
        assert!(!c.verified);
        assert!(!s.is_blocked_id(&c.id));
        // Stale per-id list entries without a contact are not inherited either.
        s.verified_ids.push("c9".into());
        s.contacts.clear();
        s.ratchets.clear();
        s.blocked_ids.clear();
        s.verified_ids.retain(|v| v == "c9");
        for _ in 0..12 {
            let n = s.contacts.len();
            let up = s.upsert_contact_from_link(
                &format!("n{n}.onion"),
                [n as u8; 32],
                [n as u8 + 100; 32],
                "N",
            );
            assert_ne!(up.id, "c9");
            assert!(!up.verified);
        }
    }

    #[test]
    fn prefers_record_matching_both_onion_and_key() {
        let mut s = upsert_session();
        let a = s.upsert_contact_from_link("a.onion", [1; 32], [1; 32], "A");
        let b = s.upsert_contact_from_link("b.onion", [2; 32], [2; 32], "B");
        s.verify_contact_id(&b.id);
        let again = s.upsert_contact_from_link("b.onion", [2; 32], [2; 32], "B");
        assert_eq!(again.id, b.id);
        assert!(again.verified);
        assert_ne!(again.id, a.id);
    }

    #[test]
    fn wipe_disk_sweeps_stale_temp_files() {
        let dir = tmp_dir("wipetmp");
        let id = LongTermIdentity::from_seed([10u8; 32]);
        let state = IdentityOnionState::from_identity(&id, "t.onion", Vec::new());
        save_disk(&dir, PersistMode::Passphrase, b"alpha", &state).unwrap();
        fs::write(dir.join(".state.enc.tmp-0011223344556677"), b"x").unwrap();
        wipe_disk(&dir).unwrap();
        assert!(!state_exists(&dir));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
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
    fn insecure_env_requires_exact_one() {
        use std::ffi::OsStr;
        assert!(insecure_env_value_enables(OsStr::new("1")));
        for v in ["", "0", "false", "no", "11", " 1", "1 ", "true", "yes"] {
            assert!(!insecure_env_value_enables(OsStr::new(v)), "{v:?}");
        }
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
        session.set_ratchet_bytes("alice", take_zeroizing_vec(ratchet_bytes.clone()));
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
        assert_eq!(loaded.ratchets[0].1.as_slice(), ratchet_bytes.as_slice());
        // Ratchet bytes must restore a working DoubleRatchet.
        let restored = DoubleRatchet::from_bytes(&loaded.ratchets[0].1).unwrap();
        assert_eq!(restored.to_bytes().as_slice(), ratchet_bytes.as_slice());
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
            bytes.to_vec(),
            "peer.onion",
            vec![0x88u8; 24],
        )
        .unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"commit-pass").unwrap();
        assert_eq!(loaded.ratchets.len(), 1);
        assert_eq!(loaded.ratchets[0].1.as_slice(), bytes.as_slice());
        assert_eq!(loaded.pending.len(), 1);
        assert_eq!(loaded.pending[0].0, "peer.onion");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_pending_refuses_past_cap_and_zeroizes() {
        let id = LongTermIdentity::from_seed([0x41u8; 32]);
        let mut session =
            SessionState::from_identity(IdentityOnionState::from_identity(&id, "me.onion", vec![]));
        for i in 0..MAX_PENDING_FRAMES {
            assert!(session.queue_pending("peer.onion", vec![i as u8; 4]));
        }
        assert!(!session.queue_pending("peer.onion", vec![0xEE; 4]));
        assert_eq!(session.pending.len(), MAX_PENDING_FRAMES);
    }

    #[test]
    fn commit_outgoing_fails_when_queue_full_and_leaves_disk_alone() {
        let dir = tmp_dir("h3-queue-full");
        let id = LongTermIdentity::from_seed([0x42u8; 32]);
        let mut session =
            SessionState::from_identity(IdentityOnionState::from_identity(&id, "me.onion", vec![]));
        for _ in 0..MAX_PENDING_FRAMES {
            assert!(session.queue_pending("peer.onion", vec![1u8; 8]));
        }
        save_session(&dir, PersistMode::Passphrase, b"full-pass", &session).unwrap();

        let err = commit_outgoing(
            &dir,
            PersistMode::Passphrase,
            b"full-pass",
            "peer",
            vec![9u8; 80],
            "peer.onion",
            vec![2u8; 8],
        )
        .unwrap_err();
        assert_eq!(err, ERR_QUEUE_FULL);

        // The ratchet update must not have been written without its frame.
        let loaded = load_session(&dir, PersistMode::Passphrase, b"full-pass").unwrap();
        assert!(loaded.ratchets.is_empty());
        assert_eq!(loaded.pending.len(), MAX_PENDING_FRAMES);
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
        assert_eq!(loaded.net, NetConfig::default());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_memory_secure_clears_pending_ratchets_onion_key() {
        let mut session = SessionState::from_identity(IdentityOnionState {
            seed: [0xAAu8; 32],
            onion: "secret.onion".into(),
            onion_key: b"ED25519-V3:deadbeef".to_vec(),
        });
        session.contacts.push(PersistedContact {
            id: "bob".into(),
            display_name: "Bob".into(),
            onion: "bob.onion".into(),
            x25519: [1u8; 32],
            ed25519: [2u8; 32],
        });
        session.set_ratchet_bytes("bob", vec![0xBBu8; 64]);
        session.queue_pending("bob.onion", vec![0xCCu8; 32]);

        session.wipe_memory_secure();

        assert!(session.pending.is_empty());
        assert!(session.ratchets.is_empty());
        assert!(session.contacts.is_empty());
        assert!(session.identity.onion_key.is_empty());
        assert!(session.identity.onion.is_empty());
        assert_eq!(session.identity.seed, [0u8; 32]);
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

    #[test]
    fn v3_net_prefs_roundtrip_non_default() {
        use crate::net_mode::{DnsPreference, NetworkMode, PostureProfile};
        let dir = tmp_dir("v3-net");
        let id = LongTermIdentity::from_seed([0x88u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "me.onion",
            b"key".to_vec(),
        ));
        session.net.set_mode(NetworkMode::I2p).unwrap();
        session
            .net
            .set_dns(DnsPreference::Quad9, None)
            .unwrap();
        session.net.set_posture(PostureProfile::Standard);
        save_session(&dir, PersistMode::Passphrase, b"v3-pass", &session).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v3-pass").unwrap();
        assert_eq!(loaded.net.mode, NetworkMode::I2p);
        assert_eq!(loaded.net.dns, DnsPreference::Quad9);
        assert_eq!(loaded.net.posture, PostureProfile::Standard);
        assert_eq!(loaded.net, session.net);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v3_extreme_survives_restart_and_locks() {
        use crate::net_mode::{NetworkMode, PostureProfile};
        let dir = tmp_dir("v3-ext");
        let id = LongTermIdentity::from_seed([0x99u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "ext.onion",
            vec![],
        ));
        session.net.set_posture(PostureProfile::Extreme);
        save_session(&dir, PersistMode::Passphrase, b"ext-pass", &session).unwrap();

        let mut loaded = load_session(&dir, PersistMode::Passphrase, b"ext-pass").unwrap();
        assert_eq!(loaded.net.posture, PostureProfile::Extreme);
        assert_eq!(loaded.net.mode, NetworkMode::Tor);
        assert!(loaded
            .net
            .set_mode(NetworkMode::Clearnet)
            .is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_blob_loads_with_default_net_prefs() {
        // Craft a v2 plaintext (contacts/ratchets/pending, no prefs) and wrap it.
        let dir = tmp_dir("v2-compat");
        let id = LongTermIdentity::from_seed([0xAAu8; 32]);
        let identity =
            IdentityOnionState::from_identity(&id, "v2.onion", b"k".to_vec());
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V2);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        plain.extend_from_slice(&0u32.to_be_bytes()); // contacts
        plain.extend_from_slice(&0u32.to_be_bytes()); // ratchets
        plain.extend_from_slice(&0u32.to_be_bytes()); // pending
        let env = envelope::seal(b"v2-pass", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v2-pass").unwrap();
        assert_eq!(loaded.identity.seed, identity.seed);
        assert_eq!(loaded.net, NetConfig::default());
        // Re-save upgrades to v7.
        save_session(&dir, PersistMode::Passphrase, b"v2-pass", &loaded).unwrap();
        let again = load_session(&dir, PersistMode::Passphrase, b"v2-pass").unwrap();
        assert_eq!(again.net, NetConfig::default());
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn v4_disappear_ttl_roundtrip() {
        let dir = tmp_dir("v4_ttl");
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &LongTermIdentity::generate().unwrap(),
            "ttl.onion",
            vec![],
        ));
        session.disappear_ttl_secs = 300;
        save_session(&dir, PersistMode::Passphrase, b"ttl-pass", &session).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"ttl-pass").unwrap();
        assert_eq!(loaded.disappear_ttl_secs, 300);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v3_blob_loads_with_ttl_off() {
        // Craft a real v3 plaintext (net prefs, no TTL) and wrap — load defaults TTL=0.
        let dir = tmp_dir("v3_no_ttl");
        let id = LongTermIdentity::from_seed([0xBBu8; 32]);
        let identity =
            IdentityOnionState::from_identity(&id, "old.onion", b"k".to_vec());
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V3);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        plain.extend_from_slice(&0u32.to_be_bytes()); // contacts
        plain.extend_from_slice(&0u32.to_be_bytes()); // ratchets
        plain.extend_from_slice(&0u32.to_be_bytes()); // pending
        let prefs = NetConfig::default().to_persist_bytes();
        write_len_bytes(&mut plain, &prefs);
        let env = envelope::seal(b"v3pass", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v3pass").unwrap();
        assert_eq!(loaded.disappear_ttl_secs, 0);
        assert_eq!(loaded.net, NetConfig::default());
        // Re-save upgrades to v7; TTL stays off unless set.
        save_session(&dir, PersistMode::Passphrase, b"v3pass", &loaded).unwrap();
        let again = load_session(&dir, PersistMode::Passphrase, b"v3pass").unwrap();
        assert_eq!(again.disappear_ttl_secs, 0);

        let mut wiped = loaded;
        wiped.disappear_ttl_secs = 60;
        wiped.wipe_memory_secure();
        assert_eq!(wiped.disappear_ttl_secs, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extreme_save_strips_contacts_pending_on_reload() {
        use crate::net_mode::PostureProfile;
        let dir = tmp_dir("ext-min");
        let id = LongTermIdentity::from_seed([0xEEu8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "extmin.onion",
            b"ED25519-V3:ext".to_vec(),
        ));
        session.net.set_posture(PostureProfile::Extreme);
        session.disappear_ttl_secs = 3600;
        session.contacts.push(PersistedContact {
            id: "alice".into(),
            display_name: "Alice".into(),
            onion: "alice.onion".into(),
            x25519: [0xAAu8; 32],
            ed25519: [0xBBu8; 32],
        });
        session.set_ratchet_bytes("alice", vec![0x11u8; 48]);
        session.queue_pending("alice.onion", vec![0x22u8; 16]);
        session.block_contact_id("alice");
        session.muted_ids.push("other".into()); // orphan mute id
        session.verify_contact_id("alice");

        // In-memory for_disk preview is stripped; live session unchanged.
        let preview = session.for_disk();
        assert!(preview.contacts.is_empty());
        assert!(preview.ratchets.is_empty());
        assert!(preview.pending.is_empty());
        assert!(preview.blocked_ids.is_empty());
        assert!(preview.muted_ids.is_empty());
        assert!(preview.verified_ids.is_empty());
        assert_eq!(preview.identity.seed, session.identity.seed);
        assert_eq!(preview.disappear_ttl_secs, 3600);
        assert_eq!(session.contacts.len(), 1);
        assert_eq!(session.pending.len(), 1);
        assert_eq!(session.blocked_ids.len(), 1);

        save_session(&dir, PersistMode::Passphrase, b"ext-min-pass", &session).unwrap();
        // Live RAM still has session material for current Tor messaging.
        assert_eq!(session.contacts.len(), 1);
        assert_eq!(session.pending.len(), 1);
        assert_eq!(session.blocked_ids.len(), 1);

        let loaded = load_session(&dir, PersistMode::Passphrase, b"ext-min-pass").unwrap();
        assert_eq!(loaded.net.posture, PostureProfile::Extreme);
        assert_eq!(loaded.identity.seed, session.identity.seed);
        assert_eq!(loaded.identity.onion, "extmin.onion");
        assert_eq!(loaded.identity.onion_key, b"ED25519-V3:ext");
        assert_eq!(loaded.disappear_ttl_secs, 3600);
        assert!(loaded.contacts.is_empty());
        assert!(loaded.ratchets.is_empty());
        assert!(loaded.pending.is_empty());
        assert!(loaded.blocked_ids.is_empty());
        assert!(loaded.muted_ids.is_empty());
        assert!(loaded.verified_ids.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn standard_save_keeps_contacts_after_extreme_policy() {
        use crate::net_mode::PostureProfile;
        let dir = tmp_dir("std-keep");
        let id = LongTermIdentity::from_seed([0x53u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "std.onion",
            b"key".to_vec(),
        ));
        assert_eq!(session.net.posture, PostureProfile::Standard);
        session.contacts.push(PersistedContact {
            id: "bob".into(),
            display_name: "Bob".into(),
            onion: "bob.onion".into(),
            x25519: [1u8; 32],
            ed25519: [2u8; 32],
        });
        session.set_ratchet_bytes("bob", vec![3u8; 40]);
        session.queue_pending("bob.onion", vec![4u8; 8]);
        save_session(&dir, PersistMode::Passphrase, b"std-pass", &session).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"std-pass").unwrap();
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.contacts[0].id, "bob");
        assert_eq!(loaded.ratchets.len(), 1);
        assert_eq!(loaded.pending.len(), 1);
        assert_eq!(loaded.pending[0].1, vec![4u8; 8]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extreme_load_legacy_contacts_then_save_strips() {
        use crate::net_mode::PostureProfile;
        // Simulate a legacy Extreme blob that still had H3 extras (pre-minimization):
        // serialize_blob writes fields as-is; only save_session/for_disk strips.
        let dir = tmp_dir("ext-legacy");
        let id = LongTermIdentity::from_seed([0xCCu8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "legacy-ext.onion",
            vec![9],
        ));
        session.contacts.push(PersistedContact {
            id: "legacy".into(),
            display_name: "L".into(),
            onion: "l.onion".into(),
            x25519: [5u8; 32],
            ed25519: [6u8; 32],
        });
        session.set_ratchet_bytes("legacy", vec![7u8; 20]);
        session.queue_pending("l.onion", vec![8u8; 4]);
        session.net.set_posture(PostureProfile::Extreme);
        let plain = serialize_blob(&session);
        let env = envelope::seal(b"leg-pass", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"leg-pass").unwrap();
        assert_eq!(loaded.net.posture, PostureProfile::Extreme);
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.pending.len(), 1);
        // Extreme save strips durable extras; RAM for this session stays until drop.
        save_session(&dir, PersistMode::Passphrase, b"leg-pass", &loaded).unwrap();
        assert_eq!(loaded.contacts.len(), 1);
        let again = load_session(&dir, PersistMode::Passphrase, b"leg-pass").unwrap();
        assert_eq!(again.net.posture, PostureProfile::Extreme);
        assert!(again.contacts.is_empty());
        assert!(again.ratchets.is_empty());
        assert!(again.pending.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v5_blocked_muted_roundtrip_standard() {
        let dir = tmp_dir("v5-deny");
        let id = LongTermIdentity::from_seed([0xD1u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "deny.onion",
            vec![],
        ));
        session.contacts.push(PersistedContact {
            id: "c1".into(),
            display_name: "SASABCD".into(),
            onion: "peer.onion".into(),
            x25519: [9u8; 32],
            ed25519: [8u8; 32],
        });
        assert!(session.block_contact_id("c1"));
        assert_eq!(session.mute_contact_id("c1").unwrap_err(), "contact is blocked (unblock first)");
        session.contacts.push(PersistedContact {
            id: "c2".into(),
            display_name: "SASMUTE".into(),
            onion: "mute.onion".into(),
            x25519: [7u8; 32],
            ed25519: [6u8; 32],
        });
        assert_eq!(session.mute_contact_id("c2").unwrap(), true);
        save_session(&dir, PersistMode::Passphrase, b"deny-pass", &session).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"deny-pass").unwrap();
        assert_eq!(loaded.blocked_ids, vec!["c1".to_string()]);
        assert_eq!(loaded.muted_ids, vec!["c2".to_string()]);
        assert!(loaded.is_blocked_id("c1"));
        assert!(loaded.is_muted_id("c2"));
        assert_eq!(loaded.refuse_send_if_blocked("c1").unwrap_err(), "blocked contact");
        assert!(loaded.refuse_send_if_blocked("c2").is_ok());
        assert_eq!(
            loaded.inbound_deny_policy("c1"),
            InboundDenyPolicy::DropNoDecrypt
        );
        assert_eq!(
            loaded.inbound_deny_policy("c2"),
            InboundDenyPolicy::DecryptNoDisplay
        );
        assert_eq!(loaded.inbound_deny_policy("c3"), InboundDenyPolicy::Accept);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_refuse_helpers_resolve_sas_prefix() {
        let id = LongTermIdentity::from_seed([0xD2u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "me.onion",
            vec![],
        ));
        session.contacts.push(PersistedContact {
            id: "alice".into(),
            display_name: "SASXYZ12".into(),
            onion: "aliceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion".into(),
            x25519: [1u8; 32],
            ed25519: [2u8; 32],
        });
        assert_eq!(session.resolve_deny_token("SASXYZ").as_deref(), Some("alice"));
        assert_eq!(session.resolve_deny_token("alice").as_deref(), Some("alice"));
        // Unique SAS prefix is accepted (fail closed only when ambiguous/unknown).
        assert_eq!(session.resolve_deny_token("SAS").as_deref(), Some("alice"));
        assert!(session.resolve_deny_token("nope").is_none());
        assert!(session.block_contact_id(session.resolve_deny_token("SASXYZ").unwrap()));
        assert_eq!(session.refuse_send_if_blocked("alice").unwrap_err(), "blocked contact");
        assert!(session.unblock_contact_id("SASXYZ"));
        assert!(session.refuse_send_if_blocked("alice").is_ok());
    }

    #[test]
    fn delete_contact_secure_wipes_ratchet_pending_and_deny() {
        let id = LongTermIdentity::from_seed([0xD4u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "me.onion",
            vec![],
        ));
        session.contacts.push(PersistedContact {
            id: "bob".into(),
            display_name: "SASBOB".into(),
            onion: "bobonionaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion".into(),
            x25519: [0x11u8; 32],
            ed25519: [0x22u8; 32],
        });
        session.contacts.push(PersistedContact {
            id: "carol".into(),
            display_name: "SASCAROL".into(),
            onion: "carolonionaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion".into(),
            x25519: [0x33u8; 32],
            ed25519: [0x44u8; 32],
        });
        session.set_ratchet_bytes("bob", vec![0xBBu8; 48]);
        session.set_ratchet_bytes("carol", vec![0xCCu8; 48]);
        session.queue_pending(
            "bobonionaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            vec![0xDDu8; 16],
        );
        session.queue_pending(
            "carolonionaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            vec![0xEEu8; 16],
        );
        assert!(session.verify_contact_id("bob"));
        assert!(session.block_contact_id("bob"));
        assert_eq!(session.mute_contact_id("carol").unwrap(), true);

        assert!(session.delete_contact_secure("bob"));
        assert_eq!(session.contacts.len(), 1);
        assert_eq!(session.contacts[0].id, "carol");
        assert!(session.ratchets.iter().all(|(k, _)| k != "bob"));
        assert_eq!(session.ratchets.len(), 1);
        assert_eq!(session.ratchets[0].0, "carol");
        assert!(session
            .pending
            .iter()
            .all(|(o, _)| !o.starts_with("bobonion")));
        assert_eq!(session.pending.len(), 1);
        assert!(!session.is_blocked_id("bob"));
        assert!(!session.is_verified_id("bob"));
        assert!(session.is_muted_id("carol"));
        assert!(!session.delete_contact_secure("bob"));
        // Other contact material intact.
        assert_eq!(session.ratchets[0].1, vec![0xCCu8; 48]);
    }

    #[test]
    fn delete_contact_secure_extreme_ram_then_for_disk_empty() {
        use crate::net_mode::PostureProfile;
        let id = LongTermIdentity::from_seed([0xD5u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "ext.onion",
            vec![],
        ));
        session.net.set_posture(PostureProfile::Extreme);
        session.contacts.push(PersistedContact {
            id: "x".into(),
            display_name: "SASX".into(),
            onion: "xonionaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion".into(),
            x25519: [1u8; 32],
            ed25519: [2u8; 32],
        });
        session.set_ratchet_bytes("x", vec![0xAAu8; 32]);
        session.queue_pending(
            "xonionaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            vec![1, 2, 3],
        );
        assert!(session.delete_contact_secure("x"));
        assert!(session.contacts.is_empty());
        assert!(session.ratchets.is_empty());
        assert!(session.pending.is_empty());
        let disk = session.for_disk();
        assert!(disk.contacts.is_empty());
        assert!(disk.ratchets.is_empty());
        assert!(disk.pending.is_empty());
        assert!(disk.blocked_ids.is_empty());
        assert!(disk.muted_ids.is_empty());
        assert!(disk.verified_ids.is_empty());
    }

    #[test]
    fn v4_blob_loads_with_empty_deny_lists() {
        // Craft a real v4 plaintext (TTL, no deny lists) and wrap — load defaults empty lists.
        let dir = tmp_dir("v4_no_deny");
        let id = LongTermIdentity::from_seed([0xD3u8; 32]);
        let identity =
            IdentityOnionState::from_identity(&id, "oldv4.onion", b"k".to_vec());
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V4);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        plain.extend_from_slice(&0u32.to_be_bytes()); // contacts
        plain.extend_from_slice(&0u32.to_be_bytes()); // ratchets
        plain.extend_from_slice(&0u32.to_be_bytes()); // pending
        let prefs = NetConfig::default().to_persist_bytes();
        write_len_bytes(&mut plain, &prefs);
        plain.extend_from_slice(&120u32.to_be_bytes()); // ttl
        let env = envelope::seal(b"v4pass", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v4pass").unwrap();
        assert_eq!(loaded.disappear_ttl_secs, 120);
        assert!(loaded.blocked_ids.is_empty());
        assert!(loaded.muted_ids.is_empty());
        // Re-save upgrades to v7.
        save_session(&dir, PersistMode::Passphrase, b"v4pass", &loaded).unwrap();
        let again = load_session(&dir, PersistMode::Passphrase, b"v4pass").unwrap();
        assert_eq!(again.disappear_ttl_secs, 120);
        assert!(again.blocked_ids.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }



    #[test]
    fn v6_verified_roundtrip_and_refuse_send() {
        let dir = tmp_dir("v6-verify");
        let id = LongTermIdentity::from_seed([0x66u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "verify.onion",
            vec![],
        ));
        session.contacts.push(PersistedContact {
            id: "c1".into(),
            display_name: "SASNEW01".into(),
            onion: "peer.onion".into(),
            x25519: [9u8; 32],
            ed25519: [8u8; 32],
        });
        // New contact starts unverified — refuse send.
        assert!(!session.is_verified_id("c1"));
        assert_eq!(
            session.refuse_send_if_unverified("c1").unwrap_err(),
            "unverified contact"
        );
        assert!(session.verify_contact_id("c1"));
        assert!(!session.verify_contact_id("c1")); // idempotent
        assert!(session.refuse_send_if_unverified("c1").is_ok());
        save_session(&dir, PersistMode::Passphrase, b"v6-pass", &session).unwrap();
        let mut loaded = load_session(&dir, PersistMode::Passphrase, b"v6-pass").unwrap();
        assert_eq!(loaded.verified_ids, vec!["c1".to_string()]);
        assert!(loaded.is_verified_id("c1"));
        assert!(loaded.unverify_contact_id("SASNEW"));
        assert!(!loaded.is_verified_id("c1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_v6_contacts_load_as_verified_continuity() {
        // Craft a v5 blob with one contact and empty deny lists — load must mark verified.
        let dir = tmp_dir("v5_verified_cont");
        let id = LongTermIdentity::from_seed([0xC5u8; 32]);
        let identity =
            IdentityOnionState::from_identity(&id, "oldv5.onion", b"k".to_vec());
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V5);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        plain.extend_from_slice(&1u32.to_be_bytes()); // 1 contact
        write_len_str(&mut plain, "legacy");
        write_len_str(&mut plain, "SASLEG01");
        write_len_str(&mut plain, "peer.onion");
        plain.extend_from_slice(&[0xAAu8; 32]);
        plain.extend_from_slice(&[0xBBu8; 32]);
        plain.extend_from_slice(&0u32.to_be_bytes()); // ratchets
        plain.extend_from_slice(&0u32.to_be_bytes()); // pending
        let prefs = NetConfig::default().to_persist_bytes();
        write_len_bytes(&mut plain, &prefs);
        plain.extend_from_slice(&0u32.to_be_bytes()); // ttl
        write_string_list(&mut plain, &[]); // blocked
        write_string_list(&mut plain, &[]); // muted
        let env = envelope::seal(b"v5cont", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v5cont").unwrap();
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.contacts[0].id, "legacy");
        assert!(loaded.is_verified_id("legacy"));
        assert!(loaded.refuse_send_if_unverified("legacy").is_ok());
        // Re-save upgrades to v7 and keeps verified set.
        save_session(&dir, PersistMode::Passphrase, b"v5cont", &loaded).unwrap();
        let again = load_session(&dir, PersistMode::Passphrase, b"v5cont").unwrap();
        assert!(again.is_verified_id("legacy"));
        let _ = fs::remove_dir_all(&dir);
    }


    #[test]
    fn v7_lock_timeout_roundtrip() {
        let dir = tmp_dir("v7_lock");
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &LongTermIdentity::generate().unwrap(),
            "lock.onion",
            vec![],
        ));
        assert_eq!(session.lock_timeout_secs, DEFAULT_LOCK_TIMEOUT_SECS);
        session.lock_timeout_secs = 900; // 15m
        save_session(&dir, PersistMode::Passphrase, b"lock-pass", &session).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"lock-pass").unwrap();
        assert_eq!(loaded.lock_timeout_secs, 900);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_v7_loads_default_lock_timeout() {
        // Craft a v6 blob (verified list, no lock field) — load defaults lock to 5m.
        let dir = tmp_dir("v6_no_lock");
        let id = LongTermIdentity::from_seed([0x76u8; 32]);
        let identity =
            IdentityOnionState::from_identity(&id, "oldv6.onion", b"k".to_vec());
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V6);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        plain.extend_from_slice(&0u32.to_be_bytes()); // contacts
        plain.extend_from_slice(&0u32.to_be_bytes()); // ratchets
        plain.extend_from_slice(&0u32.to_be_bytes()); // pending
        let prefs = NetConfig::default().to_persist_bytes();
        write_len_bytes(&mut plain, &prefs);
        plain.extend_from_slice(&0u32.to_be_bytes()); // ttl
        write_string_list(&mut plain, &[]); // blocked
        write_string_list(&mut plain, &[]); // muted
        write_string_list(&mut plain, &[]); // verified
        let env = envelope::seal(b"v6lock", &plain).unwrap();
        fs::create_dir_all(&dir).unwrap();
        write_private(&dir.join("state.enc"), &env).unwrap();

        let loaded = load_session(&dir, PersistMode::Passphrase, b"v6lock").unwrap();
        assert_eq!(loaded.lock_timeout_secs, DEFAULT_LOCK_TIMEOUT_SECS);
        // Extreme for_disk keeps lock timeout.
        use crate::net_mode::PostureProfile;
        let mut extreme = loaded;
        extreme.net.set_posture(PostureProfile::Extreme);
        extreme.lock_timeout_secs = 60;
        let disk = extreme.for_disk();
        assert_eq!(disk.lock_timeout_secs, 60);
        let _ = fs::remove_dir_all(&dir);
    }

    fn v7_blob_bytes(identity: &IdentityOnionState, lock_secs: u32) -> Vec<u8> {
        let mut plain = Vec::new();
        plain.push(BLOB_VERSION_V7);
        plain.extend_from_slice(&identity.seed);
        write_len_str(&mut plain, &identity.onion);
        write_len_bytes(&mut plain, &identity.onion_key);
        plain.extend_from_slice(&0u32.to_be_bytes()); // contacts
        plain.extend_from_slice(&0u32.to_be_bytes()); // ratchets
        plain.extend_from_slice(&0u32.to_be_bytes()); // pending
        write_len_bytes(&mut plain, &NetConfig::default().to_persist_bytes());
        plain.extend_from_slice(&0u32.to_be_bytes()); // ttl
        write_string_list(&mut plain, &[]); // blocked
        write_string_list(&mut plain, &[]); // muted
        write_string_list(&mut plain, &[]); // verified
        plain.extend_from_slice(&lock_secs.to_be_bytes());
        plain
    }

    #[test]
    fn v8_send_jitter_roundtrip() {
        let dir = tmp_dir("v8_jitter");
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &LongTermIdentity::generate().unwrap(),
            "jitter.onion",
            vec![],
        ));
        assert_eq!(session.send_jitter_secs, 0);
        session.send_jitter_secs = 30;
        save_session(&dir, PersistMode::Passphrase, b"jitter-pass", &session).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"jitter-pass").unwrap();
        assert_eq!(loaded.send_jitter_secs, 30);
        assert_eq!(loaded.lock_timeout_secs, DEFAULT_LOCK_TIMEOUT_SECS);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v7_blob_loads_with_jitter_off() {
        let id = LongTermIdentity::from_seed([0x77u8; 32]);
        let identity = IdentityOnionState::from_identity(&id, "oldv7.onion", b"k".to_vec());
        let loaded = deserialize_blob(&v7_blob_bytes(&identity, 900)).unwrap();
        assert_eq!(loaded.lock_timeout_secs, 900);
        assert_eq!(loaded.send_jitter_secs, 0);
    }

    #[test]
    fn v8_blob_clamps_jitter_and_rejects_truncation() {
        let id = LongTermIdentity::from_seed([0x78u8; 32]);
        let identity = IdentityOnionState::from_identity(&id, "v8.onion", b"k".to_vec());
        let mut plain = v7_blob_bytes(&identity, 300);
        plain[0] = BLOB_VERSION_V8;
        assert!(deserialize_blob(&plain).is_err());
        plain.extend_from_slice(&100_000u32.to_be_bytes());
        let loaded = deserialize_blob(&plain).unwrap();
        assert_eq!(loaded.send_jitter_secs, MAX_SEND_JITTER_SECS);
        plain.push(0);
        assert!(deserialize_blob(&plain).is_err());
    }

    #[test]
    fn extreme_for_disk_keeps_send_jitter() {
        use crate::net_mode::PostureProfile;
        let id = LongTermIdentity::from_seed([0x79u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "extj.onion",
            vec![],
        ));
        session.net.set_posture(PostureProfile::Extreme);
        session.send_jitter_secs = 45;
        assert_eq!(session.for_disk().send_jitter_secs, 45);
        session.wipe_memory_secure();
        assert_eq!(session.send_jitter_secs, 0);
    }

    #[test]
    fn v9_clock_mark_only_moves_forward() {
        let id = LongTermIdentity::from_seed([0x7Au8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "clock.onion",
            vec![],
        ));
        let loaded = deserialize_blob(&serialize_blob_at(&session, 10_000)).unwrap();
        assert_eq!(loaded.clock_mark_unix, 9_600);

        // A save with the clock set back keeps the higher mark.
        session.clock_mark_unix = loaded.clock_mark_unix;
        let back = deserialize_blob(&serialize_blob_at(&session, 1_000)).unwrap();
        assert_eq!(back.clock_mark_unix, 9_600);

        let forward = deserialize_blob(&serialize_blob_at(&session, 50_000)).unwrap();
        assert_eq!(forward.clock_mark_unix, 49_800);
    }

    #[test]
    fn v9_clock_mark_survives_save_and_load() {
        let dir = tmp_dir("v9_clock");
        let session = SessionState::from_identity(IdentityOnionState::from_identity(
            &LongTermIdentity::generate().unwrap(),
            "clock2.onion",
            vec![],
        ));
        let before = crate::deadman::unix_now();
        save_session(&dir, PersistMode::Passphrase, b"clock-pass", &session).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"clock-pass").unwrap();
        assert!(loaded.clock_mark_unix + crate::clock_check::CLOCK_MARK_STEP_SECS > before);
        assert!(loaded.clock_mark_unix <= crate::deadman::unix_now());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v8_blob_loads_without_clock_mark() {
        let id = LongTermIdentity::from_seed([0x7Bu8; 32]);
        let identity = IdentityOnionState::from_identity(&id, "oldv8.onion", b"k".to_vec());
        let mut plain = v7_blob_bytes(&identity, 300);
        plain[0] = BLOB_VERSION_V8;
        plain.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(deserialize_blob(&plain).unwrap().clock_mark_unix, 0);

        plain[0] = BLOB_VERSION_V9;
        assert!(deserialize_blob(&plain).is_err(), "v9 without the mark is truncated");
        plain.extend_from_slice(&7_200u64.to_be_bytes());
        assert_eq!(deserialize_blob(&plain).unwrap().clock_mark_unix, 7_200);
    }

    #[test]
    fn extreme_for_disk_keeps_clock_mark_and_wipe_clears_it() {
        use crate::net_mode::PostureProfile;
        let id = LongTermIdentity::from_seed([0x7Cu8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "extc.onion",
            vec![],
        ));
        session.net.set_posture(PostureProfile::Extreme);
        session.clock_mark_unix = 123_000;
        assert_eq!(session.for_disk().clock_mark_unix, 123_000);
        session.wipe_memory_secure();
        assert_eq!(session.clock_mark_unix, 0);
    }

    #[test]
    fn extreme_for_disk_strips_verified_ids() {
        use crate::net_mode::PostureProfile;
        let id = LongTermIdentity::from_seed([0xEFu8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "extv.onion",
            vec![],
        ));
        session.net.set_posture(PostureProfile::Extreme);
        session.contacts.push(PersistedContact {
            id: "x".into(),
            display_name: "SASX".into(),
            onion: "x.onion".into(),
            x25519: [1u8; 32],
            ed25519: [2u8; 32],
        });
        session.verify_contact_id("x");
        let disk = session.for_disk();
        assert!(disk.verified_ids.is_empty());
        assert!(session.is_verified_id("x"));
    }

    #[test]
    fn validate_display_name_rules() {
        assert_eq!(validate_display_name("  Alice  ").unwrap(), "Alice");
        let max_ok = "a".repeat(MAX_DISPLAY_NAME_LEN);
        assert_eq!(
            validate_display_name(&max_ok).unwrap().chars().count(),
            MAX_DISPLAY_NAME_LEN
        );
        assert_eq!(
            validate_display_name("").unwrap_err(),
            "empty display name"
        );
        assert_eq!(
            validate_display_name("   ").unwrap_err(),
            "empty display name"
        );
        let too_long = "x".repeat(MAX_DISPLAY_NAME_LEN + 1);
        assert_eq!(
            validate_display_name(&too_long).unwrap_err(),
            "display name too long"
        );
        assert_eq!(
            validate_display_name("bad\nname").unwrap_err(),
            "display name has control characters"
        );
        assert_eq!(
            validate_display_name("nul\0byte").unwrap_err(),
            "display name has control characters"
        );
        assert_eq!(
            validate_display_name("hashchat://contact/v1/abc").unwrap_err(),
            "display name looks like a contact link"
        );
        assert_eq!(
            validate_display_name("HASHCHAT://x").unwrap_err(),
            "display name looks like a contact link"
        );
        assert_eq!(
            validate_display_name("hashchat:sneaky").unwrap_err(),
            "display name looks like a contact link"
        );
        // Normal punctuation OK
        assert!(validate_display_name("Bob (work)").is_ok());
    }

    #[test]
    fn rename_contact_display_name_updates_label_only() {
        let id = LongTermIdentity::from_seed([0xD5u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "me.onion",
            vec![],
        ));
        let onion = "aliceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
        session.contacts.push(PersistedContact {
            id: "c1".into(),
            display_name: "A1B2-C3D4".into(),
            onion: onion.to_string(),
            x25519: [9u8; 32],
            ed25519: [8u8; 32],
        });
        let before = session.contacts[0].clone();
        session
            .rename_contact_display_name("c1", "  Alice  ")
            .unwrap();
        let after = &session.contacts[0];
        assert_eq!(after.display_name, "Alice");
        assert_eq!(after.id, before.id);
        assert_eq!(after.onion, before.onion);
        assert_eq!(after.x25519, before.x25519);
        assert_eq!(after.ed25519, before.ed25519);
        // SAS prefix still resolves after rename (recomputed fingerprint).
        let sas = crate::contact_link::sas_fingerprint(&before.ed25519, &before.x25519, onion);
        let prefix: String = sas.chars().take(4).collect();
        assert_eq!(session.resolve_deny_token(&prefix).as_deref(), Some("c1"));
        assert_eq!(session.resolve_deny_token("Ali").as_deref(), Some("c1"));
        assert_eq!(
            session
                .rename_contact_display_name("c1", "hashchat://nope")
                .unwrap_err(),
            "display name looks like a contact link"
        );
        assert_eq!(session.contacts[0].display_name, "Alice");
        assert_eq!(
            session
                .rename_contact_display_name("missing", "X")
                .unwrap_err(),
            "unknown contact"
        );
    }

    #[test]
    fn rename_contact_standard_durable_extreme_ram_only() {
        use crate::net_mode::PostureProfile;
        let dir = tmp_dir("rename-persist");
        let id = LongTermIdentity::from_seed([0xD6u8; 32]);
        let mut session = SessionState::from_identity(IdentityOnionState::from_identity(
            &id,
            "r.onion",
            vec![],
        ));
        session.contacts.push(PersistedContact {
            id: "c1".into(),
            display_name: "OLD".into(),
            onion: "peer.onion".into(),
            x25519: [3u8; 32],
            ed25519: [4u8; 32],
        });
        session.rename_contact_display_name("c1", "Durable").unwrap();
        save_session(&dir, PersistMode::Passphrase, b"rn-pass", &session).unwrap();
        let loaded = load_session(&dir, PersistMode::Passphrase, b"rn-pass").unwrap();
        assert_eq!(loaded.contacts[0].display_name, "Durable");
        assert_eq!(loaded.contacts[0].id, "c1");
        assert_eq!(loaded.contacts[0].onion, "peer.onion");

        // Extreme: rename stays in RAM; for_disk / save strips contacts.
        session.net.set_posture(PostureProfile::Extreme);
        session.rename_contact_display_name("c1", "Ephemeral").unwrap();
        assert_eq!(session.contacts[0].display_name, "Ephemeral");
        let disk = session.for_disk();
        assert!(disk.contacts.is_empty());
        save_session(&dir, PersistMode::Passphrase, b"rn-pass", &session).unwrap();
        assert_eq!(session.contacts[0].display_name, "Ephemeral");
        let again = load_session(&dir, PersistMode::Passphrase, b"rn-pass").unwrap();
        assert!(again.contacts.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

}
