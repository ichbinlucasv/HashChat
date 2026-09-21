//! Wire frame v2 (matches Haskell `frameForWire` / `unframeFromWire`).
//!
//! Layout: `version(1)=2 | hintLen(1) | hint | step(4 BE) | sender_dh(32) | ctLen(4 BE) | ciphertext`
//! Desktop receive rejects version ≠ 2 and missing sender_dh (audit M4).

use crate::ratchet::WIRE_VERSION_V2;

/// Encode a v2 wire frame.
pub fn frame_v2(hint: &[u8], step: u32, sender_dh: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    let hint = if hint.len() > 32 { &hint[..32] } else { hint };
    let mut out = Vec::with_capacity(2 + hint.len() + 4 + 32 + 4 + ciphertext.len());
    out.push(WIRE_VERSION_V2);
    out.push(hint.len() as u8);
    out.extend_from_slice(hint);
    out.extend_from_slice(&step.to_be_bytes());
    out.extend_from_slice(sender_dh);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// Parse a v2 wire frame. Rejects v1 / wrong lengths.
pub fn unframe_v2(bs: &[u8]) -> Result<(Vec<u8>, u32, [u8; 32], Vec<u8>), &'static str> {
    if bs.len() < 2 + 4 + 32 + 4 {
        return Err("frame too short");
    }
    if bs[0] != WIRE_VERSION_V2 {
        return Err("unsupported wire version");
    }
    let hl = bs[1] as usize;
    if bs.len() < 2 + hl + 4 + 32 + 4 {
        return Err("frame truncated");
    }
    let mut pos = 2;
    let hint = bs[pos..pos + hl].to_vec();
    pos += hl;
    let step = u32::from_be_bytes(bs[pos..pos + 4].try_into().map_err(|_| "step")?);
    pos += 4;
    let mut dh = [0u8; 32];
    dh.copy_from_slice(&bs[pos..pos + 32]);
    pos += 32;
    let cl = u32::from_be_bytes(bs[pos..pos + 4].try_into().map_err(|_| "ctlen")?) as usize;
    pos += 4;
    if bs.len() != pos + cl {
        return Err("ciphertext length mismatch");
    }
    let ct = bs[pos..].to_vec();
    Ok((hint, step, dh, ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let dh = [7u8; 32];
        let framed = frame_v2(b"alice", 3, &dh, b"ciphertext-blob");
        let (h, step, d, ct) = unframe_v2(&framed).unwrap();
        assert_eq!(h, b"alice");
        assert_eq!(step, 3);
        assert_eq!(d, dh);
        assert_eq!(ct, b"ciphertext-blob");
    }

    #[test]
    fn rejects_v1() {
        let mut bad = frame_v2(b"x", 1, &[0u8; 32], b"ct");
        bad[0] = 1;
        assert!(unframe_v2(&bad).is_err());
    }
}
