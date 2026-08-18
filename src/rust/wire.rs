//! Wire framing.
//! v1: version | hintLen | hint | step(4) | ctLen(4) | ct
//! v2: version | hintLen | hint | step(4) | sender_dh(32) | ctLen(4) | ct

pub const WIRE_VERSION: u8 = 2;
pub const WIRE_VERSION_V1: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub hint: Vec<u8>,
    pub step: u32,
    pub sender_dh: Option<[u8; 32]>,
    pub ciphertext: Vec<u8>,
}

pub fn frame_for_wire(hint: &[u8], step: u32, ciphertext: &[u8]) -> Vec<u8> {
    frame_v2(hint, step, &[0u8; 32], ciphertext)
}

pub fn frame_v2(hint: &[u8], step: u32, sender_dh: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    let hint = if hint.len() > 32 { &hint[..32] } else { hint };
    let mut out = Vec::with_capacity(2 + hint.len() + 4 + 32 + 4 + ciphertext.len());
    out.push(WIRE_VERSION);
    out.push(hint.len() as u8);
    out.extend_from_slice(hint);
    out.extend_from_slice(&step.to_be_bytes());
    out.extend_from_slice(sender_dh);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

pub fn unframe_from_wire(buf: &[u8]) -> Option<(Vec<u8>, u32, Vec<u8>)> {
    unframe(buf).map(|f| (f.hint, f.step, f.ciphertext))
}

pub fn unframe(buf: &[u8]) -> Option<WireFrame> {
    if buf.len() < 2 + 8 {
        return None;
    }
    let ver = buf[0];
    let hl = buf[1] as usize;
    if buf.len() < 2 + hl + 8 {
        return None;
    }
    let hint = buf[2..2 + hl].to_vec();
    let step_off = 2 + hl;
    let step = u32::from_be_bytes(buf[step_off..step_off + 4].try_into().ok()?);
    match ver {
        WIRE_VERSION_V1 => {
            let cl = u32::from_be_bytes(buf[step_off + 4..step_off + 8].try_into().ok()?) as usize;
            let ct_off = step_off + 8;
            if buf.len() != ct_off + cl {
                return None;
            }
            Some(WireFrame {
                hint,
                step,
                sender_dh: None,
                ciphertext: buf[ct_off..].to_vec(),
            })
        }
        WIRE_VERSION => {
            if buf.len() < step_off + 4 + 32 + 4 {
                return None;
            }
            let mut dh = [0u8; 32];
            dh.copy_from_slice(&buf[step_off + 4..step_off + 36]);
            let cl = u32::from_be_bytes(buf[step_off + 36..step_off + 40].try_into().ok()?) as usize;
            let ct_off = step_off + 40;
            if buf.len() != ct_off + cl {
                return None;
            }
            Some(WireFrame {
                hint,
                step,
                sender_dh: Some(dh),
                ciphertext: buf[ct_off..].to_vec(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_v2_roundtrip() {
        let dh = [3u8; 32];
        let raw = frame_v2(b"alicehint", 7, &dh, b"ciphertext-here");
        let f = unframe(&raw).expect("frame");
        assert_eq!(f.hint, b"alicehint");
        assert_eq!(f.step, 7);
        assert_eq!(f.sender_dh, Some(dh));
        assert_eq!(f.ciphertext, b"ciphertext-here");
    }

    #[test]
    fn still_reads_v1() {
        let hint = b"x";
        let mut v1 = vec![1u8, 1];
        v1.extend_from_slice(hint);
        v1.extend_from_slice(&4u32.to_be_bytes());
        v1.extend_from_slice(&3u32.to_be_bytes());
        v1.extend_from_slice(b"abc");
        let f = unframe(&v1).unwrap();
        assert_eq!(f.ciphertext, b"abc");
        assert!(f.sender_dh.is_none());
    }

    #[test]
    fn rejects_bad_version() {
        let mut frame = frame_v2(b"x", 0, &[0u8; 32], b"y");
        frame[0] = 9;
        assert!(unframe(&frame).is_none());
    }
}
