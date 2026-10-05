//! Fixed size classes for message plaintext.
//!
//! The plaintext is padded before AEAD sealing so the ciphertext length only
//! reveals which class a message falls in, not its exact length. Layout:
//! `len(2, BE) | data | zero padding`, with the total equal to a class size.
//!
//! This hides message length from the network and from anyone who sees the
//! frame, not the fact that a message was sent or when.

/// Allowed padded plaintext sizes, smallest first. The last class holds the
/// largest message the TUI will send (`MAX_PLAINTEXT_SEND_BYTES` plus the
/// two length bytes).
pub const SIZE_CLASSES: [usize; 5] = [512, 1024, 2048, 4096, 8448];

const LEN_PREFIX: usize = 2;

/// Largest data length that fits in the biggest class.
#[cfg(test)]
pub const MAX_PADDED_DATA: usize = SIZE_CLASSES[SIZE_CLASSES.len() - 1] - LEN_PREFIX;

/// Smallest class that holds `data_len` bytes plus the length prefix.
pub fn class_for(data_len: usize) -> Option<usize> {
    SIZE_CLASSES
        .iter()
        .copied()
        .find(|&c| data_len + LEN_PREFIX <= c)
}

/// Pad `data` to its size class. The result is wrapped for zeroizing by the caller.
pub fn pad(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let class = class_for(data.len()).ok_or("message too long to pad")?;
    let mut out = vec![0u8; class];
    out[..LEN_PREFIX].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[LEN_PREFIX..LEN_PREFIX + data.len()].copy_from_slice(data);
    Ok(out)
}

/// Remove padding. Rejects a size that is not a class, a length that does not
/// fit, and non-zero padding bytes.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !SIZE_CLASSES.contains(&padded.len()) {
        return Err("bad padded size");
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if LEN_PREFIX + len > padded.len() {
        return Err("bad padded length");
    }
    // The sender uses the smallest class that fits.
    if class_for(len) != Some(padded.len()) {
        return Err("oversized padding class");
    }
    if padded[LEN_PREFIX + len..].iter().any(|&b| b != 0) {
        return Err("nonzero padding");
    }
    Ok(padded[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_at_class_boundaries() {
        for &c in &SIZE_CLASSES {
            for len in [c - LEN_PREFIX - 1, c - LEN_PREFIX] {
                let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
                let padded = pad(&data).unwrap();
                assert_eq!(padded.len(), class_for(len).unwrap());
                assert_eq!(unpad(&padded).unwrap(), data);
            }
        }
    }

    #[test]
    fn empty_and_short_messages_share_a_class() {
        assert_eq!(pad(b"").unwrap().len(), 512);
        assert_eq!(pad(b"hi").unwrap().len(), 512);
        assert_eq!(pad(&[1u8; 510]).unwrap().len(), 512);
        assert_eq!(pad(&[1u8; 511]).unwrap().len(), 1024);
        assert_eq!(unpad(&pad(b"").unwrap()).unwrap(), b"");
    }

    #[test]
    fn largest_send_fits_and_one_more_does_not() {
        assert_eq!(MAX_PADDED_DATA, 8446);
        assert!(MAX_PADDED_DATA >= crate::wire::MAX_PLAINTEXT_SEND_BYTES);
        assert!(pad(&vec![1u8; MAX_PADDED_DATA]).is_ok());
        assert!(pad(&vec![1u8; MAX_PADDED_DATA + 1]).is_err());
    }

    #[test]
    fn unpad_rejects_malformed_input() {
        assert!(unpad(&[0u8; 100]).is_err(), "not a class size");
        let mut p = pad(b"abc").unwrap();
        p[300] = 1;
        assert_eq!(unpad(&p).unwrap_err(), "nonzero padding");
        let mut p = pad(b"abc").unwrap();
        p[..2].copy_from_slice(&600u16.to_be_bytes());
        assert!(unpad(&p).is_err(), "length beyond buffer");
        // Valid layout but a larger class than the sender would pick.
        let mut big = vec![0u8; 1024];
        big[..2].copy_from_slice(&3u16.to_be_bytes());
        big[2..5].copy_from_slice(b"abc");
        assert_eq!(unpad(&big).unwrap_err(), "oversized padding class");
    }
}
