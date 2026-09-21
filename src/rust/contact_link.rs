//! Signed contact bootstrap links (audit finding H1).
//!
//! # Wire format (v1 signed — required by default)
//! ```text
//! hashchat://contact/v1/<onion>/<x25519-hex>/<ed25519-hex>/<sig-hex>
//! ```
//! - `<onion>`: v3 onion **without** the `.onion` suffix (lowercase)
//! - `<x25519-hex>`: 64 lowercase hex chars (32-byte static DH public)
//! - `<ed25519-hex>`: 64 lowercase hex chars (32-byte identity verifying key)
//! - `<sig-hex>`: 128 lowercase hex chars (64-byte Ed25519 signature)
//!
//! # Canonical signed payload (exact bytes — do not change lightly)
//! ```text
//!   ASCII "v1"  ||  ASCII onion-without-.onion  ||  32 raw x25519 public bytes
//! ```
//! No length prefixes, no separators beyond the literal ASCII `v1`.
//! Signature = Ed25519.Sign(long-term ed25519 sk, payload) (detached).
//!
//! # Security model
//! Bootstrap is **signed static-DH + SAS**, not X3DH. Verify the signature
//! *before* computing DH / `init_symmetric`. Unsigned legacy links
//! (`…/v1/<onion>/<len:hex>`) are rejected by default (TOFU-insecure).

use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::DoubleRatchet;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519Public;

const PREFIX: &str = "hashchat://contact/v1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedContact {
    /// Full onion including `.onion` suffix.
    pub onion: String,
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactLinkError {
    BadFormat,
    BadHex,
    BadLength,
    BadOnion,
    BadSignature,
    UnsignedRejected,
    DhFailed,
}

impl std::fmt::Display for ContactLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContactLinkError::BadFormat => write!(f, "bad contact link format"),
            ContactLinkError::BadHex => write!(f, "invalid hex in contact link"),
            ContactLinkError::BadLength => write!(f, "unexpected field length"),
            ContactLinkError::BadOnion => write!(f, "onion looks invalid"),
            ContactLinkError::BadSignature => write!(f, "ed25519 signature verification failed"),
            ContactLinkError::UnsignedRejected => {
                write!(f, "unsigned contact link rejected (TOFU-insecure); use signed v1 or :add-contact-insecure")
            }
            ContactLinkError::DhFailed => write!(f, "static DH / ratchet init failed"),
        }
    }
}

/// Exact bytes signed by the long-term ed25519 key.
pub fn canonical_payload(onion_no_suffix: &str, x25519: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + onion_no_suffix.len() + 32);
    out.extend_from_slice(b"v1");
    out.extend_from_slice(onion_no_suffix.as_bytes());
    out.extend_from_slice(x25519);
    out
}

fn normalize_onion_parts(onion: &str) -> Result<(String /*full*/, String /*no suffix*/), ContactLinkError> {
    let o = onion.trim().to_lowercase();
    let (full, bare) = if o.ends_with(".onion") {
        let bare = o.trim_end_matches(".onion").to_string();
        (o, bare)
    } else {
        (format!("{o}.onion"), o.clone())
    };
    // Tor v3 onion hostnames are 56 base32 chars + ".onion"
    if bare.len() < 16 || bare.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return Err(ContactLinkError::BadOnion);
    }
    Ok((full, bare))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, ContactLinkError> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ContactLinkError::BadHex);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ContactLinkError::BadHex))
        .collect()
}

fn hex_decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], ContactLinkError> {
    let v = hex_decode(s)?;
    if v.len() != N {
        return Err(ContactLinkError::BadLength);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Short SAS / fingerprint for manual compare (voice / out-of-band).
/// SHA-256(ed25519 || x25519 || onion_full) → first 4 bytes as `XXXX-XXXX` (uppercase hex).
pub fn sas_fingerprint(ed25519: &[u8; 32], x25519: &[u8; 32], onion_full: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ed25519);
    hasher.update(x25519);
    hasher.update(onion_full.as_bytes());
    let dig = hasher.finalize();
    format!(
        "{:02X}{:02X}-{:02X}{:02X}",
        dig[0], dig[1], dig[2], dig[3]
    )
}

/// Build a signed contact link from a long-term identity + onion.
pub fn format_signed_contact_link(id: &LongTermIdentity, onion: &str) -> Result<String, ContactLinkError> {
    let (full, bare) = normalize_onion_parts(onion)?;
    let x = id.x25519_public_bytes();
    let ed = id.ed25519_public_bytes();
    let payload = canonical_payload(&bare, &x);
    let sig = id.sign(&payload);
    let sig_bytes = sig.to_bytes();
    let _ = full; // encoded without suffix in the URI
    Ok(format!(
        "{}{}/{}/{}/{}",
        PREFIX,
        bare,
        hex_encode(&x),
        hex_encode(&ed),
        hex_encode(&sig_bytes)
    ))
}

/// Parse + verify a signed contact link. Rejects unsigned / tampered input.
pub fn parse_signed_contact_link(raw: &str) -> Result<SignedContact, ContactLinkError> {
    let s = raw.trim();
    let rest = s
        .strip_prefix(PREFIX)
        .ok_or(ContactLinkError::BadFormat)?;

    let parts: Vec<&str> = rest.split('/').collect();
    match parts.len() {
        // Legacy unsigned: <onion>/<len:hex>  → reject by default
        2 => Err(ContactLinkError::UnsignedRejected),
        4 => {
            let (full, bare) = normalize_onion_parts(parts[0])?;
            if parts[0] != bare && parts[0] != full {
                // accept either bare or full in the path; we normalized
            }
            // Path must use bare onion (no .onion) per format
            if parts[0].contains('.') {
                return Err(ContactLinkError::BadFormat);
            }
            let x25519 = hex_decode_fixed::<32>(parts[1])?;
            let ed25519 = hex_decode_fixed::<32>(parts[2])?;
            let sig = hex_decode_fixed::<64>(parts[3])?;

            let payload = canonical_payload(&bare, &x25519);
            if !LongTermIdentity::verify(&ed25519, &payload, &sig) {
                return Err(ContactLinkError::BadSignature);
            }
            Ok(SignedContact {
                onion: full,
                x25519,
                ed25519,
                sig,
            })
        }
        _ => Err(ContactLinkError::BadFormat),
    }
}

/// Explicit insecure path for old unsigned links (TOFU). Loudly separate API.
pub fn parse_unsigned_contact_link_insecure(
    raw: &str,
) -> Result<(String, [u8; 32]), ContactLinkError> {
    let s = raw.trim();
    let rest = s
        .strip_prefix(PREFIX)
        .ok_or(ContactLinkError::BadFormat)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 {
        return Err(ContactLinkError::BadFormat);
    }
    let (full, _) = normalize_onion_parts(parts[0])?;
    // Old format: <len>:<hex> or raw 64-hex
    let key_part = parts[1];
    let hex = if let Some((len_str, hex)) = key_part.split_once(':') {
        let len: usize = len_str.parse().map_err(|_| ContactLinkError::BadFormat)?;
        if hex.len() != len * 2 {
            return Err(ContactLinkError::BadLength);
        }
        hex
    } else {
        key_part
    };
    let key = hex_decode_fixed::<32>(hex)?;
    Ok((full, key))
}

/// Verify signature, static-DH, then `init_symmetric` on a fresh ratchet.
/// Returns (ratchet, SAS string). Never DH before verify.
pub fn bootstrap_ratchet_from_signed_link(
    local: &LongTermIdentity,
    link: &str,
) -> Result<(DoubleRatchet, String), ContactLinkError> {
    let peer = parse_signed_contact_link(link)?;
    let peer_pub = X25519Public::from(peer.x25519);
    let shared = local.x25519_dh(&peer_pub);
    let mut r = DoubleRatchet::new();
    r.init_symmetric(&shared);
    let sas = sas_fingerprint(&peer.ed25519, &peer.x25519, &peer.onion);
    Ok((r, sas))
}

pub fn sas_for_signed(contact: &SignedContact) -> String {
    sas_fingerprint(&contact.ed25519, &contact.x25519, &contact.onion)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn demo_onion() -> &'static str {
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd"
    }

    #[test]
    fn valid_signed_link_accepts_and_bootstraps() {
        let alice = LongTermIdentity::from_seed([0xA1; 32]);
        let bob = LongTermIdentity::from_seed([0xB2; 32]);
        let link = format_signed_contact_link(&bob, demo_onion()).unwrap();
        assert!(link.starts_with(PREFIX));
        let parsed = parse_signed_contact_link(&link).expect("valid signed");
        assert!(parsed.onion.ends_with(".onion"));
        let (_ra, sas_a) = bootstrap_ratchet_from_signed_link(&alice, &link).unwrap();
        assert_eq!(sas_a, sas_for_signed(&parsed));
        let sa = alice.x25519_dh(&bob.x25519_public());
        let sb = bob.x25519_dh(&alice.x25519_public());
        assert_eq!(sa, sb);
    }

    #[test]
    fn tampered_sig_rejects() {
        let id = LongTermIdentity::from_seed([3u8; 32]);
        let link = format_signed_contact_link(&id, demo_onion()).unwrap();
        let mut bytes = link.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let link = String::from_utf8(bytes).unwrap();
        assert_eq!(
            parse_signed_contact_link(&link).unwrap_err(),
            ContactLinkError::BadSignature
        );
        assert!(bootstrap_ratchet_from_signed_link(&id, &link).is_err());
    }

    #[test]
    fn tampered_onion_rejects() {
        let id = LongTermIdentity::from_seed([4u8; 32]);
        let link = format_signed_contact_link(&id, demo_onion()).unwrap();
        let bad = link.replacen(demo_onion(), "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 1);
        assert_eq!(
            parse_signed_contact_link(&bad).unwrap_err(),
            ContactLinkError::BadSignature
        );
    }

    #[test]
    fn tampered_x25519_rejects() {
        let id = LongTermIdentity::from_seed([5u8; 32]);
        let link = format_signed_contact_link(&id, demo_onion()).unwrap();
        let rest = link.strip_prefix(PREFIX).unwrap();
        let parts: Vec<&str> = rest.split('/').collect();
        assert_eq!(parts.len(), 4);
        let mut x = parts[1].to_string();
        let flipped = if &x[0..2] == "00" { "01" } else { "00" };
        x.replace_range(0..2, flipped);
        let bad = format!("{}{}/{}/{}/{}", PREFIX, parts[0], x, parts[2], parts[3]);
        assert_eq!(
            parse_signed_contact_link(&bad).unwrap_err(),
            ContactLinkError::BadSignature
        );
    }

    #[test]
    fn unsigned_legacy_rejected_by_default() {
        let onion = demo_onion();
        let legacy = format!(
            "hashchat://contact/v1/{}/32:{}",
            onion,
            hex_encode(&[0xABu8; 32])
        );
        assert_eq!(
            parse_signed_contact_link(&legacy).unwrap_err(),
            ContactLinkError::UnsignedRejected
        );
        let (o, k) = parse_unsigned_contact_link_insecure(&legacy).unwrap();
        assert!(o.ends_with(".onion"));
        assert_eq!(k, [0xABu8; 32]);
    }

    #[test]
    fn sas_stable() {
        let ed = [9u8; 32];
        let x = [8u8; 32];
        let a = sas_fingerprint(&ed, &x, "abc.onion");
        let b = sas_fingerprint(&ed, &x, "abc.onion");
        assert_eq!(a, b);
        assert_eq!(a.len(), 9);
        assert!(a.contains('-'));
    }
}
