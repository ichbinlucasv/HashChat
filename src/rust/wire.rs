//! Wire frame v2 (matches Haskell `frameForWire` / `unframeFromWire`).
//!
//! Layout: `version(1)=2 | hintLen(1) | hint | step(4 BE) | sender_dh(32) | ctLen(4 BE) | ciphertext`
//! Desktop receive rejects version ≠ 2 and missing sender_dh (audit M4).
//!
//! Outbound plaintext is also gated by [`MAX_PLAINTEXT_SEND_BYTES`] so huge pastes
//! cannot balloon memory or Tor frames before ratchet encrypt (local UX limit).

use crate::hidden_service::MAX_HS_INBOUND_FRAME;
use crate::ratchet::{WIRE_VERSION_V2, WIRE_VERSION_V3};

/// AES-256-GCM ciphertext blob overhead on the wire: nonce(12) ‖ ciphertext ‖ tag(16).
const AEAD_CIPHERTEXT_OVERHEAD: usize = 12 + 16;

/// Maximum wire-v2 header size when `hint` is truncated to 32 bytes in [`frame_v2`].
/// `version(1) + hintLen(1) + hint(32) + step(4) + sender_dh(32) + ctLen(4)`.
const WIRE_V2_HEADER_MAX: usize = 1 + 1 + 32 + 4 + 32 + 4;

/// Default maximum UTF-8 plaintext bytes the Rust TUI may encrypt/send in one message.
///
/// **8 KiB** keeps AES-GCM ciphertext + wire-v2 framing well under
/// [`MAX_HS_INBOUND_FRAME`] (16 KiB) with headroom for Tor framed transport.
/// Configurable compile-time constant — not a runtime setting.
///
/// **Honest scope:** local UX / memory gate only. Not a wire-protocol version bump;
/// inbound still enforces the transport frame cap independently.
pub const MAX_PLAINTEXT_SEND_BYTES: usize = 8 * 1024;

/// Worst-case framed ciphertext size for a plaintext of [`MAX_PLAINTEXT_SEND_BYTES`].
pub const MAX_FRAMED_SEND_BYTES: usize =
    MAX_PLAINTEXT_SEND_BYTES + AEAD_CIPHERTEXT_OVERHEAD + WIRE_V2_HEADER_MAX;

const _: () = assert!(MAX_FRAMED_SEND_BYTES <= MAX_HS_INBOUND_FRAME);

/// Fail-closed size check for outbound UTF-8 plaintext **before** ratchet encrypt.
///
/// Returns `Err` when `plaintext_utf8.len() > MAX_PLAINTEXT_SEND_BYTES`.
/// Callers must not echo the body in status/logs.
pub fn check_plaintext_send_size(plaintext_utf8: &[u8]) -> Result<(), &'static str> {
    if plaintext_utf8.len() > MAX_PLAINTEXT_SEND_BYTES {
        Err("plaintext exceeds max send size")
    } else {
        Ok(())
    }
}

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
    // Honest frame_v2 truncates hints to 32; reject oversize hintLen so extra
    // bytes cannot be accepted then dropped from AEAD AAD (L-9).
    if hl > 32 {
        return Err("hint too long");
    }
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

/// Wire frame v3 header fields. Differs from v2 by one field: `epoch_start`,
/// the step of the first message under the sender's current DH key, which
/// lets the receiver skip exactly the unseen tail of the previous chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameV3 {
    pub hint: Vec<u8>,
    pub step: u32,
    pub epoch_start: u32,
    pub sender_dh: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Largest v3 frame: header with a 32-byte hint plus the biggest padded class sealed.
pub const MAX_FRAMED_V3_BYTES: usize = 1 + 1 + 32 + 4 + 4 + 32 + 4
    + crate::padding::SIZE_CLASSES[crate::padding::SIZE_CLASSES.len() - 1]
    + AEAD_CIPHERTEXT_OVERHEAD;

const _: () = assert!(MAX_FRAMED_V3_BYTES <= MAX_HS_INBOUND_FRAME);

/// Encode a v3 wire frame: `3 | hintLen | hint | step | epoch_start | sender_dh | ctLen | ct`.
pub fn frame_v3(
    hint: &[u8],
    step: u32,
    epoch_start: u32,
    sender_dh: &[u8; 32],
    ciphertext: &[u8],
) -> Vec<u8> {
    let hint = if hint.len() > 32 { &hint[..32] } else { hint };
    let mut out = Vec::with_capacity(2 + hint.len() + 8 + 32 + 4 + ciphertext.len());
    out.push(WIRE_VERSION_V3);
    out.push(hint.len() as u8);
    out.extend_from_slice(hint);
    out.extend_from_slice(&step.to_be_bytes());
    out.extend_from_slice(&epoch_start.to_be_bytes());
    out.extend_from_slice(sender_dh);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// Parse a v3 wire frame. Rejects other versions, long hints, bad lengths and
/// an `epoch_start` after `step`.
pub fn unframe_v3(bs: &[u8]) -> Result<FrameV3, &'static str> {
    if bs.len() < 2 + 8 + 32 + 4 {
        return Err("frame too short");
    }
    if bs[0] != WIRE_VERSION_V3 {
        return Err("unsupported wire version");
    }
    let hl = bs[1] as usize;
    if hl > 32 {
        return Err("hint too long");
    }
    if bs.len() < 2 + hl + 8 + 32 + 4 {
        return Err("frame truncated");
    }
    let mut pos = 2;
    let hint = bs[pos..pos + hl].to_vec();
    pos += hl;
    let step = u32::from_be_bytes(bs[pos..pos + 4].try_into().map_err(|_| "step")?);
    pos += 4;
    let epoch_start = u32::from_be_bytes(bs[pos..pos + 4].try_into().map_err(|_| "epoch")?);
    pos += 4;
    if epoch_start > step {
        return Err("epoch after step");
    }
    let mut sender_dh = [0u8; 32];
    sender_dh.copy_from_slice(&bs[pos..pos + 32]);
    pos += 32;
    let cl = u32::from_be_bytes(bs[pos..pos + 4].try_into().map_err(|_| "ctlen")?) as usize;
    pos += 4;
    if bs.len() != pos + cl {
        return Err("ciphertext length mismatch");
    }
    Ok(FrameV3 {
        hint,
        step,
        epoch_start,
        sender_dh,
        ciphertext: bs[pos..].to_vec(),
    })
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

    #[test]
    fn plaintext_send_size_accepts_at_limit() {
        let ok = vec![b'a'; MAX_PLAINTEXT_SEND_BYTES];
        assert!(check_plaintext_send_size(&ok).is_ok());
        assert!(check_plaintext_send_size(b"").is_ok());
        assert!(check_plaintext_send_size(b"hello").is_ok());
    }

    #[test]
    fn plaintext_send_size_rejects_over_limit() {
        let over = vec![b'x'; MAX_PLAINTEXT_SEND_BYTES + 1];
        assert_eq!(
            check_plaintext_send_size(&over).unwrap_err(),
            "plaintext exceeds max send size"
        );
    }

    #[test]
    fn max_plaintext_framed_fits_inbound_cap() {
        // Synthetic worst-case: max plaintext + AEAD overhead + max v2 header.
        assert!(MAX_FRAMED_SEND_BYTES <= MAX_HS_INBOUND_FRAME);
        assert_eq!(MAX_PLAINTEXT_SEND_BYTES, 8 * 1024);
        let ct_len = MAX_PLAINTEXT_SEND_BYTES + AEAD_CIPHERTEXT_OVERHEAD;
        let framed = frame_v2(&[0u8; 32], 1, &[0u8; 32], &vec![0u8; ct_len]);
        assert!(framed.len() <= MAX_HS_INBOUND_FRAME);
        assert_eq!(framed.len(), MAX_FRAMED_SEND_BYTES);
    }

    #[test]
    fn unframe_rejects_hint_len_over_32() {
        // Craft a frame advertising hintLen=33 with enough trailing bytes so
        // a parser that only checked remaining length would accept it.
        let dh = [9u8; 32];
        let ct = b"ct-blob";
        let mut framed = Vec::new();
        framed.push(WIRE_VERSION_V2);
        framed.push(33); // oversize hintLen
        framed.extend_from_slice(&[b'h'; 33]);
        framed.extend_from_slice(&3u32.to_be_bytes());
        framed.extend_from_slice(&dh);
        framed.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        framed.extend_from_slice(ct);
        assert_eq!(unframe_v2(&framed).unwrap_err(), "hint too long");

        // Mutate a valid frame's hintLen byte upward and pad the hint region.
        let mut good = frame_v2(b"alice", 1, &dh, ct);
        assert!(unframe_v2(&good).is_ok());
        let orig_hl = good[1] as usize;
        assert_eq!(orig_hl, 5);
        good[1] = 33;
        for _ in 0..(33 - orig_hl) {
            good.insert(2 + orig_hl, b'X');
        }
        assert_eq!(unframe_v2(&good).unwrap_err(), "hint too long");
    }

    #[test]
    fn unframe_accepts_hint_lens_0_through_32() {
        let dh = [3u8; 32];
        let ct = b"roundtrip-ct";
        for hl in 0usize..=32 {
            let hint: Vec<u8> = (0..hl).map(|i| (i as u8).wrapping_add(0x41)).collect();
            let framed = frame_v2(&hint, hl as u32, &dh, ct);
            let (h, step, d, out_ct) = unframe_v2(&framed).expect("valid hintLen must parse");
            assert_eq!(h, hint);
            assert_eq!(step, hl as u32);
            assert_eq!(d, dh);
            assert_eq!(out_ct, ct);
        }
    }

    #[test]
    fn v3_roundtrip_and_limits() {
        let dh = [5u8; 32];
        let framed = frame_v3(b"alice", 9, 5, &dh, b"ct-blob");
        let f = unframe_v3(&framed).unwrap();
        assert_eq!(f.hint, b"alice");
        assert_eq!((f.step, f.epoch_start), (9, 5));
        assert_eq!(f.sender_dh, dh);
        assert_eq!(f.ciphertext, b"ct-blob");
        // v2 and v3 frames are not interchangeable.
        assert!(unframe_v3(&frame_v2(b"a", 1, &dh, b"ct")).is_err());
        assert!(unframe_v2(&framed).is_err());
    }

    #[test]
    fn v3_rejects_epoch_after_step_and_trailing_bytes() {
        let dh = [5u8; 32];
        assert_eq!(
            unframe_v3(&frame_v3(b"a", 3, 4, &dh, b"ct")).unwrap_err(),
            "epoch after step"
        );
        let mut framed = frame_v3(b"a", 3, 3, &dh, b"ct");
        framed.push(0);
        assert!(unframe_v3(&framed).is_err());
    }

    #[test]
    fn v3_largest_frame_fits_inbound_cap() {
        let ct = vec![0u8; crate::padding::SIZE_CLASSES[4] + AEAD_CIPHERTEXT_OVERHEAD];
        let framed = frame_v3(&[0u8; 32], 1, 0, &[0u8; 32], &ct);
        assert_eq!(framed.len(), MAX_FRAMED_V3_BYTES);
        assert!(framed.len() <= MAX_HS_INBOUND_FRAME);
    }
}
