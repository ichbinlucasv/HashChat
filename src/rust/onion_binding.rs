//! Binding between a contact link and the onion service it names (audit I-6).
//!
//! A v3 onion address is the service's Ed25519 public key. A link signed only
//! by the identity key lets anyone claim someone else's onion. Here the onion
//! service key also signs the identity and static DH keys, and the receiver
//! checks that signature against the key encoded in the onion address. A link
//! is then valid only if its author controls the onion.
//!
//! The signed bytes are `"HashChat-onion-binding-v1" || onion_pubkey ||
//! identity_ed25519 || x25519`. Tor keeps the service key as a 64-byte
//! expanded secret key, so signing goes through dalek's hazmat API.

use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::Sha512;
use zeroize::Zeroize;

const LABEL: &[u8] = b"HashChat-onion-binding-v1";
const KEY_PREFIX: &str = "ED25519-V3:";

/// The 32-byte service public key inside a v3 onion hostname (with or without
/// the `.onion` suffix). The two checksum bytes are not checked: the signature
/// check against the key itself is what matters here.
pub fn onion_public_key(onion: &str) -> Option<[u8; 32]> {
    let host = onion.trim().to_ascii_lowercase();
    let host = host.strip_suffix(".onion").unwrap_or(&host);
    if host.len() != 56 {
        return None;
    }
    let raw = base32_decode(host)?;
    if raw.len() != 35 || raw[34] != 3 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[..32]);
    Some(key)
}

fn binding_message(onion_key: &[u8; 32], ed25519: &[u8; 32], x25519: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(LABEL.len() + 96);
    m.extend_from_slice(LABEL);
    m.extend_from_slice(onion_key);
    m.extend_from_slice(ed25519);
    m.extend_from_slice(x25519);
    m
}

/// Sign with the stored Tor key (`ED25519-V3:<base64>`). Returns the signature
/// and the onion public key it belongs to.
pub fn sign_binding(
    onion_key_spec: &[u8],
    ed25519: &[u8; 32],
    x25519: &[u8; 32],
) -> Option<([u8; 64], [u8; 32])> {
    let spec = std::str::from_utf8(onion_key_spec).ok()?;
    let b64 = spec.trim().strip_prefix(KEY_PREFIX)?;
    let mut raw = base64_decode(b64)?;
    if raw.len() != 64 {
        raw.zeroize();
        return None;
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&raw);
    raw.zeroize();
    let esk = ExpandedSecretKey::from_bytes(&arr);
    arr.zeroize();
    let vk = VerifyingKey::from(&esk);
    let pk = vk.to_bytes();
    let sig = raw_sign::<Sha512>(&esk, &binding_message(&pk, ed25519, x25519), &vk);
    Some((sig.to_bytes(), pk))
}

/// True if `sig` is the onion key's signature over these link keys.
pub fn verify_binding(
    onion: &str,
    ed25519: &[u8; 32],
    x25519: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    let Some(pk) = onion_public_key(onion) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(&binding_message(&pk, ed25519, x25519), &Signature::from_bytes(sig))
        .is_ok()
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Test helpers: build an onion and a Tor-style key spec from a seed.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use sha2::Digest;

    fn base32_encode(data: &[u8]) -> String {
        const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut out = String::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for &b in data {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((acc >> bits) & 31) as usize] as char);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    fn base64_encode(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
        out
    }

    /// (bare onion hostname, `ED25519-V3:` key spec) for a seed.
    pub(crate) fn onion_and_key(seed: u8) -> (String, String) {
        let h = Sha512::digest([seed; 32]);
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&h);
        let esk = ExpandedSecretKey::from_bytes(&arr);
        let pk = VerifyingKey::from(&esk).to_bytes();
        let mut raw = pk.to_vec();
        raw.extend_from_slice(&[0, 0, 3]);
        (
            base32_encode(&raw),
            format!("{KEY_PREFIX}{}", base64_encode(&arr)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::onion_and_key;
    use super::*;

    #[test]
    fn test_onion_has_the_v3_shape() {
        let (onion, _) = onion_and_key(1);
        assert_eq!(onion.len(), 56);
        assert!(onion_public_key(&onion).is_some());
        assert!(onion_public_key(&format!("{onion}.onion")).is_some());
        assert!(onion_public_key("short").is_none());
        assert!(onion_public_key(&"1".repeat(56)).is_none());
    }

    #[test]
    fn signature_binds_onion_to_both_link_keys() {
        let (onion, spec) = onion_and_key(2);
        let (ed, x) = ([7u8; 32], [8u8; 32]);
        let (sig, pk) = sign_binding(spec.as_bytes(), &ed, &x).unwrap();
        assert_eq!(Some(pk), onion_public_key(&onion));
        assert!(verify_binding(&onion, &ed, &x, &sig));
        assert!(!verify_binding(&onion, &[9u8; 32], &x, &sig), "other identity key");
        assert!(!verify_binding(&onion, &ed, &[9u8; 32], &sig), "other DH key");
        let (other, _) = onion_and_key(3);
        assert!(!verify_binding(&other, &ed, &x, &sig), "someone else's onion");
    }

    #[test]
    fn sign_rejects_malformed_key_specs() {
        let (ed, x) = ([1u8; 32], [2u8; 32]);
        assert!(sign_binding(b"", &ed, &x).is_none());
        assert!(sign_binding(b"ED25519-V3:AAAA", &ed, &x).is_none());
        assert!(sign_binding(b"RSA1024:AAAA", &ed, &x).is_none());
        assert!(sign_binding(&[0xff, 0xfe], &ed, &x).is_none());
    }
}
