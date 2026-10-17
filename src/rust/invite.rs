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
//! # Reply
//! ```text
//! hashchat://invite-reply/v1/<invite-id>/<tag>/<contact-link body>
//! ```
//! The redeemer answers with its own signed contact link (the part after
//! `hashchat://contact/v1/`), the invite id and a 16-byte `<tag>`:
//! HMAC-SHA256 keyed by the invite salt over the id and the full contact link.
//! The tag proves the reply was made by someone holding the whole invite and
//! that the contact link was not swapped on the way. It cannot stop someone
//! who intercepted the invite itself; comparing the SAS out of band still
//! decides trust.
//!
//! # In-band reply (hello frame)
//! The redeemer can also carry the reply to the inviter's onion inside a
//! frame that has the shape of a sealed v3 frame
//! ([`crate::wire::frame_v3_sealed`]: empty hint, step 0, epoch 0):
//! `sender_dh` is a fresh ephemeral X25519 key, and the padded reply is sealed
//! with AES-256-GCM under
//! `HKDF-SHA256(ikm = DH(ephemeral, inviter static), salt = invite salt,
//! info = "hc-invite-hello-v1" || invite id)`, AAD = the v3 wire AAD.
//! Opening needs both the inviter's static key and an open invite's salt.
//! The inviter trial-opens against its open invites ([`PendingInvites::open_hello`]);
//! a frame that opens none of them spends nothing, so junk cannot burn invites.
//!
//! Status: the TUI issues invites (`:invite`), redeems them with
//! `:add-contact` (which queues the hello frame to the inviter's onion and
//! still prints the out-of-band reply as a fallback), accepts out-of-band
//! replies through `:add-contact` and accepts hello frames on receive.

use crate::contact_link::{
    hex_decode, hex_encode, is_v3_onion_label, parse_signed_contact_link, sas_fingerprint,
    ContactLinkError,
};
use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::DoubleRatchet;
use std::collections::BTreeMap;
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroize;

const PREFIX: &str = "hashchat://invite/v1/";
const REPLY_PREFIX: &str = "hashchat://invite-reply/v1/";
const CONTACT_PREFIX: &str = "hashchat://contact/v1/";
const REPLY_TAG_LABEL: &[u8] = b"hc-invite-reply-v1";
const REPLY_TAG_LEN: usize = 16;
const PAYLOAD_TAG: &[u8] = b"hc-invite-v1";
const HELLO_INFO: &[u8] = b"hc-invite-hello-v1";
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
    BadReplyTag,
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
            Self::BadReplyTag => "invite reply was not made from this invite",
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
    let bare = o.strip_suffix(".onion").unwrap_or(o.as_str());
    if !is_v3_onion_label(bare) {
        return Err(InviteError::BadFormat);
    }
    Ok((format!("{bare}.onion"), bare.to_string()))
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

fn reply_tag(salt: &[u8; 32], invite_id: &[u8; 16], contact_link: &str) -> [u8; REPLY_TAG_LEN] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(REPLY_TAG_LABEL);
    ctx.update(invite_id);
    ctx.update(contact_link.as_bytes());
    let full = ctx.sign();
    let mut out = [0u8; REPLY_TAG_LEN];
    out.copy_from_slice(&full.as_ref()[..REPLY_TAG_LEN]);
    out
}

/// Parse an invite lifetime such as `30m`, `12h` or `7d` (1 s to 7 days).
pub fn parse_invite_ttl(raw: &str) -> Option<u64> {
    let secs = u64::from(crate::disappearing::parse_ttl_token(raw).ok()?);
    (1..=MAX_INVITE_TTL_SECS).contains(&secs).then_some(secs)
}

/// True when `raw` looks like an invite link (not yet verified).
pub fn is_invite_link(raw: &str) -> bool {
    raw.trim().starts_with(PREFIX)
}

/// True when `raw` looks like an invite reply (not yet verified).
pub fn is_invite_reply(raw: &str) -> bool {
    raw.trim().starts_with(REPLY_PREFIX)
}

/// Redeemer side: the reply to send back to the inviter out of band.
/// `my_contact_link` must be this profile's signed contact link.
pub fn format_invite_reply(inv: &Invite, my_contact_link: &str) -> Result<String, InviteError> {
    let link = my_contact_link.trim();
    let body = link
        .strip_prefix(CONTACT_PREFIX)
        .ok_or(InviteError::BadFormat)?;
    let tag = reply_tag(&inv.salt, &inv.invite_id, link);
    Ok(format!(
        "{REPLY_PREFIX}{}/{}/{body}",
        hex_encode(&inv.invite_id),
        hex_encode(&tag)
    ))
}

/// Split a reply into invite id, tag and the redeemer's contact link.
/// Signatures are checked later, in [`PendingInvites::accept_reply`].
fn split_invite_reply(raw: &str) -> Result<([u8; 16], [u8; REPLY_TAG_LEN], String), InviteError> {
    let rest = raw
        .trim()
        .strip_prefix(REPLY_PREFIX)
        .ok_or(InviteError::BadFormat)?;
    let mut it = rest.splitn(3, '/');
    let id = fixed::<16>(it.next().ok_or(InviteError::BadFormat)?)?;
    let tag = fixed::<REPLY_TAG_LEN>(it.next().ok_or(InviteError::BadFormat)?)?;
    let body = it.next().ok_or(InviteError::BadFormat)?;
    if body.is_empty() || body.len() > 1024 {
        return Err(InviteError::BadFormat);
    }
    Ok((id, tag, format!("{CONTACT_PREFIX}{body}")))
}

/// Hello frame key: HKDF-SHA256 over the ephemeral-static DH, salted with
/// the invite salt and bound to the invite id.
fn hello_key(dh: &[u8; 32], salt: &[u8; 32], invite_id: &[u8; 16]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), dh);
    let mut info = Vec::with_capacity(HELLO_INFO.len() + 16);
    info.extend_from_slice(HELLO_INFO);
    info.extend_from_slice(invite_id);
    let mut okm = [0u8; 32];
    // 32 bytes is always a valid HKDF-SHA256 output length.
    hk.expand(&info, &mut okm)
        .expect("32-byte HKDF output is valid");
    okm
}

/// Redeemer side: seal the invite reply into a hello frame for the
/// inviter's onion. The frame has the sealed v3 shape (empty hint, step 0,
/// epoch 0) and a padded size class, so it looks like any other first frame.
pub fn invite_hello_frame(inv: &Invite, my_contact_link: &str) -> Result<Vec<u8>, InviteError> {
    let mut reply = format_invite_reply(inv, my_contact_link)?;
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&X25519Public::from(inv.x25519));
    if !shared.was_contributory() {
        reply.zeroize();
        return Err(InviteError::DhFailed);
    }
    let mut dh = shared.to_bytes();
    let mut key = hello_key(&dh, &inv.salt, &inv.invite_id);
    dh.zeroize();
    let padded = crate::padding::pad(reply.as_bytes());
    reply.zeroize();
    let mut padded = padded.map_err(|_| InviteError::BadFormat)?;
    let aad = crate::ratchet::build_wire_aad_v3(&[], 0, 0, &eph_pub);
    let ct = crate::ratchet::encrypt_with_key(&key, &padded, &aad);
    key.zeroize();
    padded.zeroize();
    let ct = ct.map_err(|_| InviteError::BadFormat)?;
    Ok(crate::wire::frame_v3_sealed(0, 0, &eph_pub, &ct))
}

/// True when a parsed v3 frame has the shape of a hello frame (sealed hint,
/// step 0, epoch 0). Ordinary first messages share this shape, so this is
/// only a cheap filter before [`PendingInvites::open_hello`].
pub fn looks_like_hello(frame: &crate::wire::FrameV3) -> bool {
    frame.hint.is_empty() && frame.step == 0 && frame.epoch_start == 0
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

    /// Inviter completes the session from a reply made by
    /// [`format_invite_reply`]. The invite is consumed first (one try per
    /// invite), then the salt-keyed tag is checked in constant time, then the
    /// contact link signature. Returns the ratchet, the peer's SAS and the
    /// peer's verified contact link fields.
    pub fn accept_reply(
        &mut self,
        local: &LongTermIdentity,
        reply: &str,
        now: u64,
    ) -> Result<(DoubleRatchet, String, crate::contact_link::SignedContact), InviteError> {
        let (invite_id, tag, link) = split_invite_reply(reply)?;
        let mut salt = self.redeem(&invite_id, now)?;
        let mut want = reply_tag(&salt, &invite_id, &link);
        let tag_ok: bool = subtle::ConstantTimeEq::ct_eq(&want[..], &tag[..]).into();
        want.zeroize();
        let result = if !tag_ok {
            Err(InviteError::BadReplyTag)
        } else {
            parse_signed_contact_link(&link)
                .map_err(InviteError::from)
                .and_then(|peer| {
                    let r = salted_ratchet(local, &peer.x25519, &salt)?;
                    let sas = sas_fingerprint(&peer.ed25519, &peer.x25519, &peer.onion);
                    Ok((r, sas, peer))
                })
        };
        salt.zeroize();
        result
    }

    /// Inviter side: try to open a hello frame against every open,
    /// unexpired invite. A frame that opens none of them returns
    /// [`InviteError::UnknownOrUsed`] and spends nothing. A frame that opens
    /// one spends that invite (through [`Self::accept_reply`]) whether or not
    /// the carried reply then verifies.
    pub fn open_hello(
        &mut self,
        local: &LongTermIdentity,
        frame: &crate::wire::FrameV3,
        now: u64,
    ) -> Result<(DoubleRatchet, String, crate::contact_link::SignedContact), InviteError> {
        if !looks_like_hello(frame) {
            return Err(InviteError::BadFormat);
        }
        self.purge_expired(now);
        if self.open.is_empty() {
            return Err(InviteError::UnknownOrUsed);
        }
        let mut dh = local
            .x25519_dh_checked(&X25519Public::from(frame.sender_dh))
            .ok_or(InviteError::DhFailed)?;
        let aad = crate::ratchet::build_wire_aad_v3(&[], 0, 0, &frame.sender_dh);
        let mut opened: Option<([u8; 16], Vec<u8>)> = None;
        for (id, e) in &self.open {
            let mut key = hello_key(&dh, &e.salt, id);
            let r = crate::ratchet::decrypt_with_key(&key, &frame.ciphertext, &aad);
            key.zeroize();
            if let Ok(pt) = r {
                opened = Some((*id, pt));
                break;
            }
        }
        dh.zeroize();
        let Some((id, mut padded)) = opened else {
            return Err(InviteError::UnknownOrUsed);
        };
        let unpadded = crate::padding::unpad(&padded);
        padded.zeroize();
        let reply = match unpadded.ok().and_then(|b| String::from_utf8(b).ok()) {
            Some(r) => zeroize::Zeroizing::new(r),
            None => {
                // Opened under this invite's key, so the invite is spent.
                self.revoke(&id);
                return Err(InviteError::BadFormat);
            }
        };
        // The reply must name the invite whose key opened the frame.
        match split_invite_reply(&reply) {
            Ok((rid, _, _)) if rid == id => {}
            _ => {
                self.revoke(&id);
                return Err(InviteError::BadReplyTag);
            }
        }
        self.accept_reply(local, &reply, now)
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
    fn reply_roundtrip_once_and_tag_binds_link() {
        let (bob, alice) = pair();
        let carol = LongTermIdentity::from_seed([0xC3; 32]);
        let mut pending = PendingInvites::new();
        let link = pending.issue(&bob, ONION_B, None, NOW, 3600).unwrap();
        assert!(is_invite_link(&link) && !is_invite_reply(&link));

        let (mut r_alice, _sas, inv) = bootstrap_from_invite(&alice, &link, NOW + 1).unwrap();
        let alice_link = format_signed_contact_link(&alice, ONION_A).unwrap();
        let reply = format_invite_reply(&inv, &alice_link).unwrap();
        assert!(is_invite_reply(&reply));
        assert!(format_invite_reply(&inv, "hashchat://other/v1/x").is_err());

        // A reply whose contact link was swapped (here: Carol's) fails the tag
        // and still burns the invite.
        let carol_link = format_signed_contact_link(&carol, ONION_A).unwrap();
        let mut pending2 = pending.clone();
        let (id_hex, rest) = reply
            .strip_prefix(REPLY_PREFIX)
            .unwrap()
            .split_once('/')
            .unwrap();
        let tag_hex = rest.split_once('/').unwrap().0;
        let swapped = format!(
            "{REPLY_PREFIX}{id_hex}/{tag_hex}/{}",
            carol_link.strip_prefix(CONTACT_PREFIX).unwrap()
        );
        assert_eq!(
            pending2.accept_reply(&bob, &swapped, NOW + 2).err(),
            Some(InviteError::BadReplyTag)
        );
        assert!(pending2.is_empty());

        let (mut r_bob, sas_b, peer) = pending.accept_reply(&bob, &reply, NOW + 2).unwrap();
        assert_eq!(peer.x25519, alice.x25519_public_bytes());
        assert_eq!(
            sas_b,
            sas_fingerprint(&peer.ed25519, &peer.x25519, &peer.onion)
        );
        assert!(talk(&mut r_alice, &mut r_bob));
        assert!(talk(&mut r_bob, &mut r_alice));
        assert_eq!(
            pending.accept_reply(&bob, &reply, NOW + 3).err(),
            Some(InviteError::UnknownOrUsed)
        );
    }

    #[test]
    fn invite_ttl_parsing() {
        assert_eq!(parse_invite_ttl("30m"), Some(1800));
        assert_eq!(parse_invite_ttl("7d"), Some(MAX_INVITE_TTL_SECS));
        assert_eq!(parse_invite_ttl("8d"), None);
        assert_eq!(parse_invite_ttl("off"), None);
        assert_eq!(parse_invite_ttl("soon"), None);
    }

    #[test]
    fn reply_parser_rejects_junk() {
        for bad in [
            "",
            "hashchat://invite-reply/v1/",
            "hashchat://invite-reply/v1/zz/00/x",
            "hashchat://invite-reply/v1/00000000000000000000000000000000/00",
            "hashchat://invite-reply/v1/00000000000000000000000000000000/00000000000000000000000000000000/",
        ] {
            assert!(split_invite_reply(bad).is_err(), "{bad}");
        }
        let long = format!(
            "{REPLY_PREFIX}{}/{}/{}",
            "0".repeat(32),
            "0".repeat(32),
            "a".repeat(1025)
        );
        assert!(split_invite_reply(&long).is_err());
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

    fn hello_setup() -> (
        LongTermIdentity,
        LongTermIdentity,
        PendingInvites,
        Invite,
        String,
    ) {
        let (bob, alice) = pair();
        let mut pending = PendingInvites::new();
        // A second open invite so trial-open has to pick the right one.
        pending.issue(&bob, ONION_B, None, NOW, 3600).unwrap();
        let link = pending.issue(&bob, ONION_B, None, NOW, 3600).unwrap();
        let (_r, _sas, inv) = bootstrap_from_invite(&alice, &link, NOW + 5).unwrap();
        let alice_link = format_signed_contact_link(&alice, ONION_A).unwrap();
        (bob, alice, pending, inv, alice_link)
    }

    #[test]
    fn hello_frame_carries_reply_in_band_once() {
        let (bob, alice, mut pending, inv, alice_link) = hello_setup();
        let (mut r_alice, _, _) = bootstrap_from_invite(
            &alice,
            &format_invite(&bob, ONION_B, None, &inv.invite_id, &inv.salt, inv.expires).unwrap(),
            NOW + 5,
        )
        .unwrap();
        let raw = invite_hello_frame(&inv, &alice_link).unwrap();
        let frame = crate::wire::unframe_v3(&raw).unwrap();
        assert!(looks_like_hello(&frame));
        // Padded to a size class: ciphertext = class + nonce + tag.
        assert!(crate::padding::SIZE_CLASSES
            .iter()
            .any(|c| frame.ciphertext.len() == c + 12 + 16));
        let (mut r_bob, sas, peer) = pending.open_hello(&bob, &frame, NOW + 10).unwrap();
        assert_eq!(peer.x25519, alice.x25519_public_bytes());
        assert_eq!(
            sas,
            sas_fingerprint(
                &alice.ed25519_public_bytes(),
                &alice.x25519_public_bytes(),
                &format!("{ONION_A}.onion")
            )
        );
        assert!(talk(&mut r_alice, &mut r_bob));
        assert!(talk(&mut r_bob, &mut r_alice));
        assert_eq!(pending.len(), 1, "only the opened invite is spent");
        assert_eq!(
            pending.open_hello(&bob, &frame, NOW + 11).err().unwrap(),
            InviteError::UnknownOrUsed
        );
    }

    #[test]
    fn hello_junk_or_wrong_inviter_spends_nothing() {
        let (bob, alice, mut pending, inv, alice_link) = hello_setup();
        let raw = invite_hello_frame(&inv, &alice_link).unwrap();
        let frame = crate::wire::unframe_v3(&raw).unwrap();
        // Someone else's static key cannot open it.
        let carol = LongTermIdentity::from_seed([0xC3; 32]);
        let mut carol_book = pending.clone();
        assert_eq!(
            carol_book
                .open_hello(&carol, &frame, NOW + 10)
                .err()
                .unwrap(),
            InviteError::UnknownOrUsed
        );
        // Flipped ciphertext byte: nothing opens, nothing spent.
        let mut bad = frame.clone();
        let last = bad.ciphertext.len() - 1;
        bad.ciphertext[last] ^= 1;
        assert_eq!(
            pending.open_hello(&bob, &bad, NOW + 10).err().unwrap(),
            InviteError::UnknownOrUsed
        );
        // Not hello-shaped (named hint) is refused before any crypto.
        let mut named = frame.clone();
        named.hint = alice.x25519_public_bytes().to_vec();
        assert_eq!(
            pending.open_hello(&bob, &named, NOW + 10).err().unwrap(),
            InviteError::BadFormat
        );
        assert_eq!(pending.len(), 2);
        // After expiry the genuine frame no longer opens.
        assert_eq!(
            pending.open_hello(&bob, &frame, inv.expires).err().unwrap(),
            InviteError::UnknownOrUsed
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn hello_frames_use_fresh_ephemeral_keys() {
        let (_bob, _alice, _pending, inv, alice_link) = hello_setup();
        let a = crate::wire::unframe_v3(&invite_hello_frame(&inv, &alice_link).unwrap()).unwrap();
        let b = crate::wire::unframe_v3(&invite_hello_frame(&inv, &alice_link).unwrap()).unwrap();
        assert_ne!(a.sender_dh, b.sender_dh);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
