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
//! Load accepts v1–v5; save always writes v5. Older blobs load empty deny lists.
//!
//! ## Extreme disk policy (honest, fail-closed)
//! When [`crate::net_mode::PostureProfile::Extreme`] is set on the session's
//! [`NetConfig`], [`save_session`] persists **identity + onion + net prefs +
//! disappear TTL only**. Contacts, ratchets, pending frames, and blocked/muted
//! lists are written as empty vectors (blob stays v5). Trade-off: smaller at-rest
//! footprint and no multi-session contact/deny-list continuity — the user must
//! re-add contacts (and re-block if needed) after restart. Tor 1:1 messaging for
//! the **current** process session is unchanged (in-memory contacts/ratchets/queue
//! /deny lists still work until exit).
//!
//! **Load:** legacy Extreme blobs that still contain contacts/deny lists are
//! loaded into memory for the current session; the next Extreme save strips them.
//! Standard posture keeps full H3 + deny-list round-trip.
//!
//! Prefs are non-secret policy but live inside the wrapped blob so they cannot be
//! silently toggled by swapping a plaintext sibling file under `hashchat_data/`.
//! Missing prefs on v1/v2 load default to [`crate::net_mode::NetConfig::default`]
//! (Tor + standard); missing TTL on v1–v3 loads as `0` (off); missing deny lists
//! on v1–v4 load as empty.

use crate::envelope;
use crate::longterm_identity::LongTermIdentity;
use crate::net_mode::NetConfig;
use crate::ratchet::{decrypt_with_key, encrypt_with_key};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AEAD domain separation for the insecure-dev machine-key wrap path.
const STATE_AAD: &[u8] = b"HashChat-v1-identity-onion-state";

/// On-disk plaintext blob versions (inside the outer wrap).
const BLOB_VERSION_V1: u8 = 1;
const BLOB_VERSION_V2: u8 = 2;
const BLOB_VERSION_V3: u8 = 3;
const BLOB_VERSION_V4: u8 = 4;
const BLOB_VERSION_V5: u8 = 5;

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


    /// Resolve `:block` / `:mute` token to a contact id (exact id, onion, or unique SAS/id prefix).
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
                let sas = if c.display_name.is_empty() {
                    c.id.as_str()
                } else {
                    c.display_name.as_str()
                };
                sas.to_ascii_lowercase().starts_with(&tl)
                    || c.id.to_ascii_lowercase().starts_with(&tl)
            })
            .collect();
        if matches.len() == 1 {
            Some(matches[0].id.clone())
        } else {
            None
        }
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
    /// Under **Extreme**, contacts / ratchets / pending / blocked / muted are empty
    /// so they are not durable across restart. Identity, onion material, net prefs,
    /// and disappear TTL are kept. Under **Standard**, returns a full clone (H3 +
    /// deny lists).
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
        self.identity.seed.zeroize();
        self.identity.onion_key.zeroize();
        self.identity.onion_key.clear();
        // onion address is public routing material but still session residue — drop it.
        self.identity.onion.clear();
        self.net = NetConfig::default();
        self.disappear_ttl_secs = 0;
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
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(read_len_str(buf, pos)?);
    }
    Ok(out)
}

fn serialize_blob(state: &SessionState) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.push(BLOB_VERSION_V5);
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

    plain
}

fn deserialize_blob(plain: &[u8]) -> Result<SessionState, &'static str> {
    if plain.is_empty() {
        return Err("empty state blob");
    }
    let ver = plain[0];
    if ver != BLOB_VERSION_V1
        && ver != BLOB_VERSION_V2
        && ver != BLOB_VERSION_V3
        && ver != BLOB_VERSION_V4
        && ver != BLOB_VERSION_V5
    {
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

    let net = if ver == BLOB_VERSION_V3 || ver == BLOB_VERSION_V4 || ver == BLOB_VERSION_V5 {
        let prefs = read_len_bytes(plain, &mut pos)?;
        NetConfig::from_persist_bytes(&prefs).map_err(|_| "bad net prefs")?
    } else {
        // v2: prefs absent → Tor + standard.
        NetConfig::default()
    };

    let disappear_ttl_secs = if ver == BLOB_VERSION_V4 || ver == BLOB_VERSION_V5 {
        if pos + 4 > plain.len() {
            return Err("truncated disappear ttl");
        }
        let ttl = u32::from_be_bytes(plain[pos..pos + 4].try_into().unwrap());
        pos += 4;
        ttl
    } else {
        0
    };

    let (blocked_ids, muted_ids) = if ver == BLOB_VERSION_V5 {
        let blocked = read_string_list(plain, &mut pos)?;
        let muted = read_string_list(plain, &mut pos)?;
        (blocked, muted)
    } else {
        (Vec::new(), Vec::new())
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

/// Save session state. Always writes v5.
///
/// Under Extreme posture (`state.net.is_extreme()`), contacts / ratchets / pending /
/// blocked / muted are stripped via [`SessionState::for_disk`] before sealing.
/// Standard keeps full H3 + deny lists.
pub fn save_session(
    data_dir: &Path,
    mode: PersistMode,
    passphrase: &[u8],
    state: &SessionState,
) -> Result<(), &'static str> {
    fs::create_dir_all(data_dir).map_err(|_| "mkdir")?;
    let (state_path, key_path) = data_paths(data_dir);
    let disk = state.for_disk();
    let mut plain = serialize_blob(&disk);
    let envelope = seal_plain(mode, passphrase, &key_path, &plain)?;
    plain.zeroize();
    // `disk` ZeroizeOnDrop clears onion_key / ratchet / pending copies.
    drop(disk);
    write_private(&state_path, &envelope)?;
    Ok(())
}

/// Load full session state. Accepts v1–v5 blobs (deny lists empty before v5).
///
/// Extreme policy: if a legacy blob still contains contacts/queue/deny lists, they
/// are loaded into memory for this session; the next Extreme [`save_session`] strips them.
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
        // Re-save upgrades to v5.
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
        // Re-save upgrades to v5; TTL stays off unless set.
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

        // In-memory for_disk preview is stripped; live session unchanged.
        let preview = session.for_disk();
        assert!(preview.contacts.is_empty());
        assert!(preview.ratchets.is_empty());
        assert!(preview.pending.is_empty());
        assert!(preview.blocked_ids.is_empty());
        assert!(preview.muted_ids.is_empty());
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
        // Re-save upgrades to v5.
        save_session(&dir, PersistMode::Passphrase, b"v4pass", &loaded).unwrap();
        let again = load_session(&dir, PersistMode::Passphrase, b"v4pass").unwrap();
        assert_eq!(again.disappear_ttl_secs, 120);
        assert!(again.blocked_ids.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }


}
