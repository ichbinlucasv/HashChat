//! Bounded queue of inbound voice chunks (Android maximum-Rust).
//!
//! The shell used to keep an unbounded queue of frames and called a JNI
//! symbol that had no Rust body, so the receive thread aborted on the first
//! chunk. Chunks live here instead. The queue holds a fixed count, each
//! chunk is capped at one Tor inbound frame, and the bytes are zeroized when
//! the chunk is taken, the queue is cleared, or this value is dropped.
//!
//! Push does not decrypt and does not frame. Extreme refuses the whole
//! surface, matching the other gated voice paths. A full queue refuses the
//! new chunk: dropping an older one would leave a hole in the recording, and
//! growing without a bound would let a sender pin memory.

use std::collections::VecDeque;

use zeroize::{Zeroize, Zeroizing};

use crate::hidden_service::MAX_HS_INBOUND_FRAME;

/// How many chunks the queue will hold.
pub const MAX_VOICE_CHUNKS: usize = 32;

/// One chunk cannot be larger than a Tor inbound frame.
pub const MAX_VOICE_CHUNK_BYTES: usize = MAX_HS_INBOUND_FRAME;

/// Why a chunk was not queued. The bytes are not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceQueueRefusal {
    /// Extreme builds have no voice path.
    Extreme,
    /// Zero-length input is not a chunk.
    Empty,
    /// Longer than [`MAX_VOICE_CHUNK_BYTES`].
    TooLarge,
    /// [`MAX_VOICE_CHUNKS`] are already waiting.
    Full,
}

/// In-memory queue for one Android process. Not written to disk.
pub struct VoiceChunkQueue {
    chunks: VecDeque<Zeroizing<Vec<u8>>>,
}

impl VoiceChunkQueue {
    pub const fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Copy `chunk` onto the tail. The caller's buffer is not cleared.
    pub fn push(&mut self, extreme: bool, chunk: &[u8]) -> Result<(), VoiceQueueRefusal> {
        if extreme {
            return Err(VoiceQueueRefusal::Extreme);
        }
        if chunk.is_empty() {
            return Err(VoiceQueueRefusal::Empty);
        }
        if chunk.len() > MAX_VOICE_CHUNK_BYTES {
            return Err(VoiceQueueRefusal::TooLarge);
        }
        if self.chunks.len() >= MAX_VOICE_CHUNKS {
            return Err(VoiceQueueRefusal::Full);
        }
        self.chunks.push_back(Zeroizing::new(chunk.to_vec()));
        Ok(())
    }

    /// Oldest chunk, or nothing when the queue is empty.
    ///
    /// The returned buffer zeroizes on drop.
    pub fn pop(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.chunks.pop_front()
    }

    /// Drop every chunk. Each buffer is zeroized.
    pub fn clear(&mut self) {
        while let Some(mut chunk) = self.chunks.pop_front() {
            chunk.zeroize();
        }
    }
}

impl Default for VoiceChunkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VoiceChunkQueue {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_and_a_copy_is_independent_of_the_caller() {
        let mut q = VoiceChunkQueue::new();
        assert!(q.is_empty());
        let mut first = b"one".to_vec();
        q.push(false, &first).unwrap();
        first[0] = 0;
        q.push(false, b"two").unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(&q.pop().unwrap()[..], b"one");
        assert_eq!(&q.pop().unwrap()[..], b"two");
        assert!(q.pop().is_none());
        assert!(q.is_empty());
    }

    #[test]
    fn empty_oversized_and_full_are_refused() {
        let mut q = VoiceChunkQueue::new();
        assert_eq!(q.push(false, b""), Err(VoiceQueueRefusal::Empty));
        let too_big = vec![0x56u8; MAX_VOICE_CHUNK_BYTES + 1];
        assert_eq!(q.push(false, &too_big), Err(VoiceQueueRefusal::TooLarge));
        assert!(q.is_empty());

        let maxed = vec![0x11u8; MAX_VOICE_CHUNK_BYTES];
        q.push(false, &maxed).unwrap();
        assert_eq!(q.pop().unwrap().len(), MAX_VOICE_CHUNK_BYTES);

        let chunk = [0x56u8; 4];
        for _ in 0..MAX_VOICE_CHUNKS {
            q.push(false, &chunk).unwrap();
        }
        assert_eq!(q.push(false, &chunk), Err(VoiceQueueRefusal::Full));
        assert_eq!(q.len(), MAX_VOICE_CHUNKS);
        q.pop().unwrap();
        q.push(false, b"after").unwrap();
        assert_eq!(q.len(), MAX_VOICE_CHUNKS);
    }

    #[test]
    fn extreme_refuses_and_does_not_keep_the_bytes() {
        let mut q = VoiceChunkQueue::new();
        q.push(false, b"kept").unwrap();
        assert_eq!(
            q.push(true, b"voice-secret"),
            Err(VoiceQueueRefusal::Extreme)
        );
        assert_eq!(q.len(), 1);
        assert_eq!(&q.pop().unwrap()[..], b"kept");
    }

    #[test]
    fn clear_drops_every_chunk() {
        let mut q = VoiceChunkQueue::new();
        q.push(false, b"a").unwrap();
        q.push(false, b"b").unwrap();
        q.clear();
        assert!(q.is_empty());
        assert!(q.pop().is_none());
    }
}
