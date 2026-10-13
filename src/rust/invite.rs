//! One-time invitation links that carry the bootstrap salt (audit M-1).
//!
//! A reusable contact link (`hashchat://contact/v1/...`) always yields the
//! same root key for the same two static keys. A one-time invite adds a fresh
//! 32-byte salt and a random invite id, signed by the inviter's long-term
//! key, so each accepted invite starts a session with a new root
//! ([`DoubleRatchet::init_directional_with_salt`]).
//!
//! # Wire format
//! ```text
//! hashchat://invite/v1/<onion>/<x25519>/<ed25519>/<invite-id>/<salt>/<expires>/<sig>[/<hs-sig>]
//! ```
//! - `<invite-id>`: 32 hex chars (16 random bytes), `<salt>`: 64 hex chars.
//! - `<expires>`: Unix seconds (decimal) after which the invite is refused.
//! - `<sig>`: Ed25519 over [`invite_payload`]; `<hs-sig>`: optional onion
//!   binding as in [`crate::contact_link`] (I-6).
//!
//! # One-time use
//! The inviter keeps the salt in [`PendingInvites`]; [`PendingInvites::redeem`]
//! hands it out exactly once and forgets it. The redeemer's side cannot be
//! forced to forget a link, so "one-time" is enforced by the inviter.
//!
//! Status: library only. The TUI still uses reusable contact links; wiring
//! `:invite` and carrying the invite id in the first frame is open.

use crate::contact_link::{
    hex_decode, hex_encode, parse_signed_contact_link, sas_fingerprint, ContactLinkError,
};
use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::DoubleRatchet;
use std::collections::BTreeMap;
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroize;

const PREFIX: &str = "hashchat://invite/v1/";
const PAYLOAD_TAG: &[u8] = b"hc-invite-v1";
/// Most open invites one profile keeps; older ones must be redeemed or expire.
pub const MAX_PENDING_INVITES: usize = 64;
/// Longest lifetime an invite may be issued with (7 days).
pub const MAX_INVITE_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteError {
    BadFormat,
    BadSignature,
    BadOnionBinding,
    Expired,
    UnknownOrUsed,
    TooManyPending,
    BadTtl,
    DhFailed,
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadFormat => "bad invite link format",
            Self::BadSignature => "invite signature verification failed",
            Self::BadOnionBinding => "onion key signature missing or does not match",
            Self::Expired => "invite has expired",
            Self::UnknownOrUsed => "invite is unknown or was already used",
            Self::TooManyPending => "too many open invites",
            Self::BadTtl => "invite lifetime out of range",
            Self::DhFailed => "static DH / ratchet init failed",
        };
        f.write_str(s)
    }
}

impl From<ContactLinkError> for InviteError {
    fn from(e: ContactLinkError) -> Self {
        match e {
            ContactLinkError::BadSignature => Self::BadSignature,
            ContactLinkError::BadOnionBinding => Self::BadOnionBinding,
            ContactLinkError::DhFailed => Self::DhFailed,
            _ => Self::BadFormat,
        }
    }
}

/// A parsed and verified invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Full onion including `.onion`.
    pub onion: String,
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub invite_id: [u8; 16],
    pub salt: [u8; 32],
    pub expires: u64,
    pub onion_bound: bool,
}

/// Exact bytes signed by the inviter's long-term Ed25519 key.
pub fn invite_payload(
    onion_bare: &str,
    x25519: &[u8; 32],
    invite_id: &[u8; 16],
    salt: &[u8; 32],
    expires: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD_TAG.len() + onion_bare.len() + 88);
    out.extend_from_slice(PAYLOAD_TAG);
    out.extend_from_slice(onion_bare.as_bytes());
    out.extend_from_slice(x25519);
    out.extend_from_slice(invite_id);
    out.extend_from_slice(salt);
    out.extend_from_slice(&expires.to_be_bytes());
    out
}

fn bare_onion(onion: &str) -> Result<(String, String), InviteError> {
    let o = onion.trim().to_lowercase();
    let bare = o.trim_end_matches(".onion").to_string();
    if bare.len() < 16 || !bare.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(InviteError::BadFormat);
    }
    Ok((format!("{bare}.onion"), bare))
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N], InviteError> {
    let v = hex_decode(s).map_err(|_| InviteError::BadFormat)?;
    v.try_into().map_err(|_| InviteError::BadFormat)
}

fn format_invite(
    id: &LongTermIdentity,
    onion: &str,
    onion_key: Option<&[u8]>,
    invite_id: &[u8; 16],
    salt: &[u8; 32],
    expires: u64,
) -> Result<String, InviteError> {
    let (full, bare) = bare_onion(onion)?;
    let x = id.x25519_public_bytes();
    let ed = id.ed25519_public_bytes();
    let sig = id
        .sign(&invite_payload(&bare, &x, invite_id, salt, expires))
        .to_bytes();
    let mut link = format!(
        "{PREFIX}{bare}/{}/{}/{}/{}/{expires}/{}",
        hex_encode(&x),
        hex_encode(&ed),
        hex_encode(invite_id),
        hex_encode(salt),
        hex_encode(&sig)
    );
    if let Some(key) = onion_key {
        let (hs_sig, pk) =
            crate::onion_binding::sign_binding(key, &ed, &x).ok_or(InviteError::BadOnionBinding)?;
        if crate::onion_binding::onion_public_key(&full) != Some(pk) {
            return Err(InviteError::BadOnionBinding);
        }
        link.push('/');
        link.push_str(&hex_encode(&hs_sig));
    }
    Ok(link)
}

/// Parse and verify an invite. `now` is Unix seconds; expired invites are refused.
pub fn parse_invite(raw: &str, now: u64) -> Result<Invite, InviteError> {
    let rest = raw
        .trim()
        .strip_prefix(PREFIX)
        .ok_or(InviteError::BadFormat)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 7 && parts.len() != 8 {
        return Err(InviteError::BadFormat);
    }
    if parts[0].contains('.') {
        return Err(InviteError::BadFormat);
    }
    let (full, bare) = bare_onion(parts[0])?;
    let x25519 = fixed::<32>(parts[1])?;
    let ed25519 = fixed::<32>(parts[2])?;
    let invite_id = fixed::<16>(parts[3])?;
    let salt = fixed::<32>(parts[4])?;
    if parts[5].is_empty() || !parts[5].bytes().all(|b| b.is_ascii_digit()) {
        return Err(InviteError::BadFormat);
    }
    let expires: u64 = parts[5].parse().map_err(|_| InviteError::BadFormat)?;
    let sig = fixed::<64>(parts[6])?;
    let payload = invite_payload(&bare, &x25519, &invite_id, &salt, expires);
    if !LongTermIdentity::verify(&ed25519, &payload, &sig) {
        return Err(InviteError::BadSignature);
    }
    let onion_bound = if parts.len() == 8 {
        let hs_sig = fixed::<64>(parts[7])?;
        if !crate::onion_binding::verify_binding(&full, &ed25519, &x25519, &hs_sig) {
            return Err(InviteError::BadOnionBinding);
        }
        true
    } else {
        false
    };
    if now >= expires {
        return Err(InviteError::Expired);
    }
    Ok(Invite {
        onion: full,
        x25519,
        ed25519,
        invite_id,
        salt,
        expires,
        onion_bound,
    })
}

fn salted_ratchet(
    local: &LongTermIdentity,
    peer_x25519: &[u8; 32],
    salt: &[u8; 32],
) -> Result<DoubleRatchet, InviteError> {
    let mut shared = local
        .x25519_dh_checked(&X25519Public::from(*peer_x25519))
        .ok_or(InviteError::DhFailed)?;
    let mut r = DoubleRatchet::new();
    r.init_directional_with_salt(&shared, &local.x25519_public_bytes(), peer_x25519, salt);
    shared.zeroize();
    Ok(r)
}

/// Redeemer side: verify the invite, then start a salted session.
/// Returns the ratchet, the SAS string and the parsed invite (whose
/// `invite_id` must reach the inviter with the redeemer's own contact link).
pub fn bootstrap_from_invite(
    local: &LongTermIdentity,
    link: &str,
    now: u64,
) -> Result<(DoubleRatchet, String, Invite), InviteError> {
    let inv = parse_invite(link, now)?;
    let r = salted_ratchet(local, &inv.x25519, &inv.salt)?;
    let sas = sas_fingerprint(&inv.ed25519, &inv.x25519, &inv.onion);
    Ok((r, sas, inv))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingEntry {
    salt: [u8; 32],
    expires: u64,
}

/// Inviter side: open invites waiting to be redeemed, each usable once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingInvites {
    open: BTreeMap<[u8; 16], PendingEntry>,
}

impl PendingInvites {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Drop invites whose lifetime has passed.
    pub fn purge_expired(&mut self, now: u64) {
        self.open.retain(|_, e| now < e.expires);
    }

    /// Issue a new invite link valid for `ttl_secs` (1 s to 7 days).
    /// `onion_key` adds the onion binding (I-6) when given.
    pub fn issue(
        &mut self,
        id: &LongTermIdentity,
        onion: &str,
        onion_key: Option<&[u8]>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<String, InviteError> {
        if ttl_secs == 0 || ttl_secs > MAX_INVITE_TTL_SECS {
            return Err(InviteError::BadTtl);
        }
        self.purge_expired(now);
        if self.open.len() >= MAX_PENDING_INVITES {
            return Err(InviteError::TooManyPending);
        }
        let mut invite_id = [0u8; 16];
        getrandom::getrandom(&mut invite_id).map_err(|_| InviteError::BadFormat)?;
        let salt = DoubleRatchet::fresh_bootstrap_salt();
        let expires = now.saturating_add(ttl_secs);
        let link = format_invite(id, onion, onion_key, &invite_id, &salt, expires)?;
        self.open.insert(invite_id, PendingEntry { salt, expires });
        Ok(link)
    }

    /// Withdraw an open invite without using it.
    pub fn revoke(&mut self, invite_id: &[u8; 16]) -> bool {
        self.open.remove(invite_id).is_some()
    }

    /// Hand out the salt for `invite_id` once. A second call, an unknown id or
    /// an expired invite is refused.
    pub fn redeem(&mut self, invite_id: &[u8; 16], now: u64) -> Result<[u8; 32], InviteError> {
        let entry = self
            .open
            .remove(invite_id)
            .ok_or(InviteError::UnknownOrUsed)?;
        if now >= entry.expires {
            return Err(InviteError::Expired);
        }
        Ok(entry.salt)
    }

    /// Inviter completes the session: redeem the invite once, verify the
    /// redeemer's signed contact link, then start the salted ratchet.
    /// The invite is consumed even if the contact link is bad, so a forged
    /// reply cannot be retried against the same invite.
    pub fn accept(
        &mut self,
        local: &LongTermIdentity,
        invite_id: &[u8; 16],
        peer_contact_link: &str,
        now: u64,
    ) -> Result<(DoubleRatchet, String), InviteError> {
        let mut salt = self.redeem(invite_id, now)?;
        let result = parse_signed_contact_link(peer_contact_link)
            .map_err(InviteError::from)
            .and_then(|peer| {
                let r = salted_ratchet(local, &peer.x25519, &salt)?;
                Ok((r, sas_fingerprint(&peer.ed25519, &peer.x25519, &peer.onion)))
            });
        salt.zeroize();
        result
    }

    /// Serialize for the encrypted profile state: per entry 16 B id, 32 B
    /// salt, 8 B big-endian expiry.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.open.len() * 56);
        for (id, e) in &self.open {
            out.extend_from_slice(id);
            out.extend_from_slice(&e.salt);
            out.extend_from_slice(&e.expires.to_be_bytes());
        }
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, InviteError> {
        if !raw.len().is_multiple_of(56) || raw.len() / 56 > MAX_PENDING_INVITES {
            return Err(InviteError::BadFormat);
        }
        let mut open = BTreeMap::new();
        for start in (0..raw.len()).step_by(56) {
            let chunk = &raw[start..start + 56];
            let mut id = [0u8; 16];
            id.copy_from_slice(&chunk[..16]);
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&chunk[16..48]);
            let mut exp = [0u8; 8];
            exp.copy_from_slice(&chunk[48..]);
            let expires = u64::from_be_bytes(exp);
            if open.insert(id, PendingEntry { salt, expires }).is_some() {
                return Err(InviteError::BadFormat);
            }
        }
        Ok(Self { open })
    }
}

impl Drop for PendingInvites {
    fn drop(&mut self) {
        for e in self.open.values_mut() {
            e.salt.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact_link::format_signed_contact_link;
    use crate::ratchet::encrypt_with_key;

    const NOW: u64 = 1_800_000_000;
    const ONION_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ONION_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn pair() -> (LongTermIdentity, LongTermIdentity) {
        (
            LongTermIdentity::from_seed([0xA1; 32]),
            LongTermIdentity::from_seed([0xB2; 32]),
        )
    }

    fn talk(sender: &mut DoubleRatchet, receiver: &mut DoubleRatchet) -> bool {
        let (key, _step) = sender.ratchet_send();
        let dh = *sender.public_key().as_bytes();
        let ct = encrypt_with_key(&key, b"hi", b"aad").unwrap();
        receiver
            .try_recv_decrypt(&X25519Public::from(dh), &ct, b"aad")
            .map(|(pt, _)| pt == b"hi")
            .unwrap_or(false)
    }

    #[test]
    fn invite_roundtrip_gives_matching_sessions_once() {
        let (bob, alice) = pair();
        let mut pending = PendingInvites::new();
        let link = pending.issue(&bob, ONION_B, None, NOW, 3600).unwrap();
        assert!(link.starts_with(PREFIX));

        let (mut r_alice, sas_a, inv) = bootstrap_from_invite(&alice, &link, NOW + 10).unwrap();
        assert!(!inv.onion_bound);
        let alice_link = format_signed_contact_link(&alice, ONION_A).unwrap();
        let (mut r_bob, _sas_b) = pending
            .accept(&bob, &inv.invite_id, &alice_link, NOW + 20)
            .unwrap();
        assert_eq!(
            sas_a,
            sas_fingerprint(
                &bob.ed25519_public_bytes(),
                &bob.x25519_public_bytes(),
                &format!("{ONION_B}.onion")
            )
        );
        assert!(talk(&mut r_alice, &mut r_bob));
        assert!(talk(&mut r_bob, &mut r_alice));

        // One-time: the same invite cannot be accepted again.
        assert_eq!(
            pending
                .accept(&bob, &inv.invite_id, &alice_link, NOW + 30)
                .err(),
            Some(InviteError::UnknownOrUsed)
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn two_invites_give_different_roots() {
        let (bob, alice) = pair();
        let mut pending = PendingInvites::new();
        let l1 = pending.issue(&bob, ONION_B, None, NOW, 60).unwrap();
        let l2 = pending.issue(&bob, ONION_B, None, NOW, 60).unwrap();
        assert_ne!(l1, l2);
        let (mut r1, _, _) = bootstrap_from_invite(&alice, &l1, NOW).unwrap();
        let (mut r2, _, _) = bootstrap_from_invite(&alice, &l2, NOW).unwrap();
        assert_ne!(r1.ratchet_send().0, r2.ratchet_send().0);
    }

    #[test]
    fn tampering_and_expiry_are_refused() {
        let (bob, _) = pair();
        let mut pending = PendingInvites::new();
        let link = pending.issue(&bob, ONION_B, None, NOW, 60).unwrap();
        let inv = parse_invite(&link, NOW).unwrap();

        // Swap in another salt: signature must fail.
        let other_salt = hex_encode(&[7u8; 32]);
        let tampered = link.replace(&hex_encode(&inv.salt), &other_salt);
        assert_eq!(
            parse_invite(&tampered, NOW).unwrap_err(),
            InviteError::BadSignature
        );
        // Stretch the expiry: signature must fail.
        let stretched = link.replace(
            &format!("/{}/", inv.expires),
            &format!("/{}/", inv.expires + 999),
        );
        assert_eq!(
            parse_invite(&stretched, NOW).unwrap_err(),
            InviteError::BadSignature
        );
        // Expired on the redeemer and the inviter side.
        assert_eq!(
            parse_invite(&link, NOW + 60).unwrap_err(),
            InviteError::Expired
        );
        assert_eq!(
            pending.redeem(&inv.invite_id, NOW + 61).unwrap_err(),
            InviteError::Expired
        );
        // Garbage.
        assert_eq!(
            parse_invite("hashchat://invite/v1/x", NOW).unwrap_err(),
            InviteError::BadFormat
        );
        assert_eq!(
            parse_invite(&format!("{link}/00/11"), NOW).unwrap_err(),
            InviteError::BadFormat
        );
    }

    #[test]
    fn bound_invite_and_forged_reply() {
        use crate::onion_binding::test_support::onion_and_key;
        let (bob, alice) = pair();
        let (onion, key) = onion_and_key(21);
        let mut pending = PendingInvites::new();
        let link = pending
            .issue(&bob, &onion, Some(key.as_bytes()), NOW, 60)
            .unwrap();
        let inv = parse_invite(&link, NOW).unwrap();
        assert!(inv.onion_bound);
        // A broken reply consumes the invite: no retry against it.
        assert!(pending
            .accept(&bob, &inv.invite_id, "hashchat://contact/v1/bad", NOW)
            .is_err());
        let good = format_signed_contact_link(&alice, ONION_A).unwrap();
        assert_eq!(
            pending.accept(&bob, &inv.invite_id, &good, NOW).err(),
            Some(InviteError::UnknownOrUsed)
        );
        let (_, other_key) = onion_and_key(22);
        assert_eq!(
            pending
                .issue(&bob, &onion, Some(other_key.as_bytes()), NOW, 60)
                .unwrap_err(),
            InviteError::BadOnionBinding
        );
    }

    #[test]
    fn limits_and_persistence() {
        let (bob, _) = pair();
        let mut pending = PendingInvites::new();
        assert_eq!(
            pending.issue(&bob, ONION_B, None, NOW, 0).unwrap_err(),
            InviteError::BadTtl
        );
        assert_eq!(
            pending
                .issue(&bob, ONION_B, None, NOW, MAX_INVITE_TTL_SECS + 1)
                .unwrap_err(),
            InviteError::BadTtl
        );
        for _ in 0..MAX_PENDING_INVITES {
            pending.issue(&bob, ONION_B, None, NOW, 10).unwrap();
        }
        assert_eq!(
            pending.issue(&bob, ONION_B, None, NOW, 10).unwrap_err(),
            InviteError::TooManyPending
        );
        let restored = PendingInvites::from_bytes(&pending.to_bytes()).unwrap();
        assert_eq!(restored, pending);
        // Expired entries are purged when a new invite is issued.
        pending.issue(&bob, ONION_B, None, NOW + 10, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(PendingInvites::from_bytes(&[0u8; 55]).is_err());
        let link = pending.issue(&bob, ONION_B, None, NOW + 10, 10).unwrap();
        let id = parse_invite(&link, NOW + 10).unwrap().invite_id;
        assert!(pending.revoke(&id));
        assert!(!pending.revoke(&id));
    }
}
