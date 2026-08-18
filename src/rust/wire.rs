//! Wire framing shared by the Rust TUI and (later) the Android JNI.
//! Format: version(1) | hintLen(1) | hint | step(4 BE) | ctLen(4 BE) | ciphertext

pub const WIRE_VERSION: u8 = 1;

pub fn frame_for_wire(hint: &[u8], step: u32, ciphertext: &[u8]) -> Vec<u8> {
    let hint = if hint.len() > 32 { &hint[..32] } else { hint };
    let mut out = Vec::with_capacity(2 + hint.len() + 8 + ciphertext.len());
    out.push(WIRE_VERSION);
    out.push(hint.len() as u8);
    out.extend_from_slice(hint);
    out.extend_from_slice(&step.to_be_bytes());
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

pub fn unframe_from_wire(buf: &[u8]) -> Option<(Vec<u8>, u32, Vec<u8>)> {
    if buf.len() < 2 + 8 {
        return None;
    }
    if buf[0] != WIRE_VERSION {
        return None;
    }
    let hl = buf[1] as usize;
    if buf.len() < 2 + hl + 8 {
        return None;
    }
    let hint = buf[2..2 + hl].to_vec();
    let step_off = 2 + hl;
    let step = u32::from_be_bytes(buf[step_off..step_off + 4].try_into().ok()?);
    let cl = u32::from_be_bytes(buf[step_off + 4..step_off + 8].try_into().ok()?) as usize;
    let ct_off = step_off + 8;
    if buf.len() != ct_off + cl {
        return None;
    }
    Some((hint, step, buf[ct_off..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = frame_for_wire(b"alicehint", 7, b"ciphertext-here");
        let (h, step, ct) = unframe_from_wire(&frame).expect("frame");
        assert_eq!(h, b"alicehint");
        assert_eq!(step, 7);
        assert_eq!(ct, b"ciphertext-here");
    }

    #[test]
    fn rejects_bad_version() {
        let mut frame = frame_for_wire(b"x", 0, b"y");
        frame[0] = 9;
        assert!(unframe_from_wire(&frame).is_none());
    }
}
