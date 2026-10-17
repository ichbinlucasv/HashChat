//! Chat message list owned by Rust (Android maximum-Rust migration).
//!
//! The Android shell used to keep the transcript as a Kotlin `List<String>`
//! and guessed "sent by me" from a `You:` prefix. This module owns the list
//! instead: each entry has a stable id, a direction flag, a delivery state and
//! an optional disappearing deadline. Text is sanitised (control and bidi
//! characters neutralised) and capped on the way in, the list is bounded, and
//! removed text is zeroized.
//!
//! [`MessageBook::export`] gives a plaintext encoding for the platform to
//! wrap (Android Keystore); it is never written to disk by this crate. An
//! ephemeral book (Extreme / strict) exports nothing.
//!
//! # Encoding (v1)
//! ```text
//! "HCMB1" | count(u32 BE) | entries
//! entry = id(u64) | flags(u8: bit0 = mine) | delivery(u8) | sent_at(u64)
//!         | expires_at(u64, 0 = never) | len(u32) | utf-8 text
//! ```

use std::collections::VecDeque;
use zeroize::Zeroize;

const MAGIC: &[u8] = b"HCMB1";
/// Most messages kept; the oldest are dropped (and zeroized) beyond this.
pub const MAX_MESSAGES: usize = 2000;
/// Longest text kept per message, in bytes (cut at a char boundary).
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
/// Largest encoded book [`MessageBook::load`] will parse.
pub const MAX_ENCODED_BYTES: usize = MAX_MESSAGES * (MAX_TEXT_BYTES + 30) + 16;

/// Delivery state of an outgoing message (display only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Incoming messages and system lines.
    None,
    Queued,
    Sent,
    Failed,
}

impl Delivery {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Queued => 1,
            Self::Sent => 2,
            Self::Failed => 3,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Queued,
            2 => Self::Sent,
            3 => Self::Failed,
            _ => return None,
        })
    }
}

/// One transcript line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEntry {
    pub id: u64,
    pub mine: bool,
    pub delivery: Delivery,
    pub sent_at: u64,
    /// Unix seconds after which the entry is purged; `None` keeps it.
    pub expires_at: Option<u64>,
    pub text: String,
}

impl Drop for MessageEntry {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

/// Why a [`MessageBook::load`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageBookError {
    Malformed,
    TooLarge,
}

impl MessageBookError {
    pub fn label(self) -> &'static str {
        match self {
            Self::Malformed => "message list is malformed",
            Self::TooLarge => "message list is too large",
        }
    }
}

/// Sanitise and cap one message text.
fn clean_text(raw: &str) -> String {
    let safe = crate::term_sanitize::sanitize_for_terminal(raw);
    let mut s = safe.into_owned();
    if s.len() > MAX_TEXT_BYTES {
        let mut cut = MAX_TEXT_BYTES;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        // Zeroize the tail before shortening the string.
        let mut tail = s.split_off(cut);
        tail.zeroize();
    }
    s
}

/// Bounded in-memory transcript.
#[derive(Debug, Default)]
pub struct MessageBook {
    entries: VecDeque<MessageEntry>,
    next_id: u64,
    ephemeral: bool,
}

impl MessageBook {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            ..Self::default()
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &MessageEntry> {
        self.entries.iter()
    }

    /// Ephemeral books (Extreme / strict) keep messages in memory only:
    /// [`Self::export`] returns an empty book.
    pub fn set_ephemeral(&mut self, on: bool) {
        self.ephemeral = on;
    }

    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Append a message; `ttl_secs` 0 means it does not disappear.
    /// Returns the new id. The oldest entry is dropped beyond [`MAX_MESSAGES`].
    pub fn add(&mut self, mine: bool, text: &str, now: u64, ttl_secs: u64) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = id.wrapping_add(1).max(1);
        let expires_at = (ttl_secs > 0).then(|| now.saturating_add(ttl_secs));
        self.entries.push_back(MessageEntry {
            id,
            mine,
            delivery: if mine {
                Delivery::Queued
            } else {
                Delivery::None
            },
            sent_at: now,
            expires_at,
            text: clean_text(text),
        });
        while self.entries.len() > MAX_MESSAGES {
            self.entries.pop_front();
        }
        id
    }

    /// Update the delivery state of an outgoing message.
    pub fn set_delivery(&mut self, id: u64, d: Delivery) -> bool {
        match self.entries.iter_mut().find(|e| e.id == id && e.mine) {
            Some(e) => {
                e.delivery = d;
                true
            }
            None => false,
        }
    }

    /// Remove one message (text zeroized on drop).
    pub fn delete(&mut self, id: u64) -> bool {
        match self.entries.iter().position(|e| e.id == id) {
            Some(i) => {
                self.entries.remove(i);
                true
            }
            None => false,
        }
    }

    /// Remove every message (text zeroized on drop).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drop messages whose disappearing deadline has passed. Returns how many.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.expires_at.is_none_or(|t| now < t));
        before - self.entries.len()
    }

    /// Plaintext encoding for platform wrapping. Empty book when ephemeral.
    pub fn export(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        if self.ephemeral {
            out.extend_from_slice(&0u32.to_be_bytes());
            return out;
        }
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.id.to_be_bytes());
            out.push(u8::from(e.mine));
            out.push(e.delivery.to_u8());
            out.extend_from_slice(&e.sent_at.to_be_bytes());
            out.extend_from_slice(&e.expires_at.unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&(e.text.len() as u32).to_be_bytes());
            out.extend_from_slice(e.text.as_bytes());
        }
        out
    }

    /// Replace the book with an encoding from [`Self::export`]. Entries that
    /// expired by `now` are dropped; text is sanitised again. On error the
    /// book is left unchanged. The ephemeral flag is kept.
    pub fn load(&mut self, raw: &[u8], now: u64) -> Result<(), MessageBookError> {
        if raw.len() > MAX_ENCODED_BYTES {
            return Err(MessageBookError::TooLarge);
        }
        let mut r = Reader { raw, pos: 0 };
        if r.take(MAGIC.len())? != MAGIC {
            return Err(MessageBookError::Malformed);
        }
        let count = r.u32()? as usize;
        if count > MAX_MESSAGES {
            return Err(MessageBookError::TooLarge);
        }
        let mut entries = VecDeque::with_capacity(count);
        let mut max_id = 0u64;
        for _ in 0..count {
            let id = r.u64()?;
            let flags = r.u8()?;
            if flags > 1 || id == 0 {
                return Err(MessageBookError::Malformed);
            }
            let delivery = Delivery::from_u8(r.u8()?).ok_or(MessageBookError::Malformed)?;
            let sent_at = r.u64()?;
            let exp = r.u64()?;
            let len = r.u32()? as usize;
            if len > MAX_TEXT_BYTES {
                return Err(MessageBookError::TooLarge);
            }
            let text =
                std::str::from_utf8(r.take(len)?).map_err(|_| MessageBookError::Malformed)?;
            if entries.iter().any(|e: &MessageEntry| e.id == id) {
                return Err(MessageBookError::Malformed);
            }
            max_id = max_id.max(id);
            let expires_at = (exp != 0).then_some(exp);
            if expires_at.is_some_and(|t| now >= t) {
                continue;
            }
            entries.push_back(MessageEntry {
                id,
                mine: flags == 1,
                delivery,
                sent_at,
                expires_at,
                text: clean_text(text),
            });
        }
        if r.pos != raw.len() {
            return Err(MessageBookError::Malformed);
        }
        self.entries = entries;
        self.next_id = max_id.wrapping_add(1).max(1);
        Ok(())
    }
}

struct Reader<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MessageBookError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.raw.len())
            .ok_or(MessageBookError::Malformed)?;
        let s = &self.raw[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, MessageBookError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, MessageBookError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, MessageBookError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn add_delivery_delete_and_roundtrip() {
        let mut b = MessageBook::new();
        let a = b.add(true, "hello", NOW, 0);
        let c = b.add(false, "hi back", NOW + 1, 60);
        assert_ne!(a, c);
        assert_eq!(b.entries().next().unwrap().delivery, Delivery::Queued);
        assert!(b.set_delivery(a, Delivery::Sent));
        // Incoming messages have no delivery state to change.
        assert!(!b.set_delivery(c, Delivery::Sent));
        let raw = b.export();
        let mut restored = MessageBook::new();
        restored.load(&raw, NOW + 2).unwrap();
        let got: Vec<_> = restored.entries().cloned().collect();
        let want: Vec<_> = b.entries().cloned().collect();
        assert_eq!(got, want);
        // New ids continue after the restored ones.
        assert!(restored.add(true, "x", NOW, 0) > c);
        assert!(b.delete(a));
        assert!(!b.delete(a));
        assert_eq!(b.len(), 1);
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn disappearing_entries_purge_and_are_dropped_on_load() {
        let mut b = MessageBook::new();
        b.add(false, "keep", NOW, 0);
        b.add(false, "gone soon", NOW, 30);
        let raw = b.export();
        assert_eq!(b.purge_expired(NOW + 29), 0);
        assert_eq!(b.purge_expired(NOW + 30), 1);
        assert_eq!(b.len(), 1);
        let mut late = MessageBook::new();
        late.load(&raw, NOW + 31).unwrap();
        assert_eq!(late.len(), 1);
        assert_eq!(late.entries().next().unwrap().text, "keep");
    }

    #[test]
    fn text_is_sanitised_capped_and_list_bounded() {
        let mut b = MessageBook::new();
        b.add(false, "evil\u{1b}[2Jtext\u{202e}", NOW, 0);
        let t = &b.entries().next().unwrap().text;
        assert!(crate::term_sanitize::is_terminal_safe(t));
        let long = "é".repeat(MAX_TEXT_BYTES);
        b.add(true, &long, NOW, 0);
        let t = &b.entries().nth(1).unwrap().text;
        assert!(t.len() <= MAX_TEXT_BYTES && t.len() >= MAX_TEXT_BYTES - 1);
        for i in 0..MAX_MESSAGES + 5 {
            b.add(false, &format!("m{i}"), NOW, 0);
        }
        assert_eq!(b.len(), MAX_MESSAGES);
        assert_eq!(b.entries().next().unwrap().text, "m5");
    }

    #[test]
    fn ephemeral_exports_nothing() {
        let mut b = MessageBook::new();
        b.set_ephemeral(true);
        b.add(true, "secret", NOW, 0);
        let raw = b.export();
        let mut r = MessageBook::new();
        r.load(&raw, NOW).unwrap();
        assert!(r.is_empty());
        assert!(!raw.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn malformed_input_is_refused_and_book_unchanged() {
        let mut b = MessageBook::new();
        b.add(false, "stay", NOW, 0);
        let mut good = MessageBook::new();
        good.add(true, "x", NOW, 0);
        let raw = good.export();
        for bad in [
            &b"HCMB0\0\0\0\0"[..],
            &raw[..raw.len() - 1],
            &[raw.as_slice(), b"!"].concat(),
            b"",
        ] {
            assert!(b.load(bad, NOW).is_err());
        }
        // Duplicate ids.
        let mut dup = MessageBook::new();
        dup.add(true, "a", NOW, 0);
        let one = dup.export();
        let body = &one[MAGIC.len() + 4..];
        let mut two = MAGIC.to_vec();
        two.extend_from_slice(&2u32.to_be_bytes());
        two.extend_from_slice(body);
        two.extend_from_slice(body);
        assert_eq!(b.load(&two, NOW), Err(MessageBookError::Malformed));
        // Count over the cap.
        let mut huge = MAGIC.to_vec();
        huge.extend_from_slice(&(MAX_MESSAGES as u32 + 1).to_be_bytes());
        assert_eq!(b.load(&huge, NOW), Err(MessageBookError::TooLarge));
        assert_eq!(b.entries().next().unwrap().text, "stay");
    }
}
