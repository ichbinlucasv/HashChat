//! Per-chunk voice chain and recording frames.
//!
//! A recording is split into fixed-size pieces. Each piece is padded to one
//! size and sealed under its own message key. The next chunk uses the next
//! chain key. That is the symmetric half of a double ratchet: a stolen
//! message key does not open the next chunk. There is no DH ratchet here.
//! The text session still owns DH.
//!
//! The chain seed is the secret. A fresh random stream id (public, in the
//! frame) mixes into the first chain key, so two recordings under one seed
//! do not share keys. The seed is not written by this module. A process that
//! only keeps it in memory cannot open a recording after a restart, and a
//! second device cannot open it until some later step carries the seed
//! inside an established contact session. This module does not do that.
//!
//! All-zero seeds and the keys that used to be hardcoded in the Android
//! shell are refused. Extreme refuses the whole surface. A frame that does
//! not open does not move the chain.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::hidden_service::MAX_HS_INBOUND_FRAME;
use crate::ratchet::{decrypt_with_key, encrypt_with_key};

/// Frame version. Unknown versions are refused.
pub const VOICE_VERSION: u8 = 1;

/// Public id mixed into the stream chain. Not a secret.
pub const STREAM_ID_LEN: usize = 16;

/// Padded plaintext of every chunk. The network sees this size, not the
/// length of the audio piece inside it.
pub const VOICE_PAD: usize = 4096;

const LEN_PREFIX: usize = 2;

/// Audio bytes carried in one chunk, before padding.
pub const VOICE_PAYLOAD: usize = VOICE_PAD - LEN_PREFIX;

/// Most chunks one recording may contain.
pub const MAX_VOICE_CHUNKS: usize = 256;

/// Most audio bytes [`VoiceChain::seal_recording`] will accept.
pub const MAX_RECORDING_BYTES: usize = MAX_VOICE_CHUNKS * VOICE_PAYLOAD;

/// Most finished or abandoned streams remembered, so a replay cannot re-open
/// them. When this is full, a new stream is refused instead of forgetting an
/// old id.
pub const MAX_SEEN_STREAMS: usize = 256;

/// Most chain steps one frame may skip. A step past this is refused before
/// the KDF runs in a loop. The header step is also capped at
/// [`MAX_VOICE_CHUNKS`], so this bound is the whole recording.
pub const MAX_VOICE_SKIP: u32 = (MAX_VOICE_CHUNKS as u32) - 1;

const HEADER_LEN: usize = 1 + STREAM_ID_LEN + 4 + 2;
const AEAD_OVERHEAD: usize = 12 + 16;

/// On-wire size of one voice frame. Fixed, so the length does not leak which
/// piece was short.
pub const VOICE_FRAME_LEN: usize = HEADER_LEN + VOICE_PAD + AEAD_OVERHEAD;

const BUNDLE_MAGIC: &[u8; 4] = b"HVB1";

/// Largest bundle [`VoiceChain::seal_recording`] emits.
pub const MAX_BUNDLE_BYTES: usize = 4 + 2 + MAX_VOICE_CHUNKS * (2 + VOICE_FRAME_LEN);

/// `0` means the call produced its bytes. `1` means a chunk opened and the
/// rest of the recording has not arrived. Refusals are negative.
pub const VOICE_STATUS_OK: i32 = 0;
pub const VOICE_STATUS_PENDING: i32 = 1;

const _: () = assert!(VOICE_FRAME_LEN <= MAX_HS_INBOUND_FRAME);
const _: () = assert!(VOICE_PAYLOAD > 0);
const _: () = assert!(MAX_VOICE_SKIP as usize + 1 == MAX_VOICE_CHUNKS);

const STREAM_INFO: &[u8] = b"HashChat-Voice-Stream-v1";
const CHUNK_INFO: &[u8] = b"HashChat-Voice-Chunk-Key-v1";
const NEXT_INFO: &[u8] = b"HashChat-Voice-Next-Chain-v1";

/// Why a seal or open was refused. The bytes are not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceRefusal {
    /// Extreme builds have no voice path.
    Extreme,
    /// No audio bytes.
    Empty,
    /// Longer than [`MAX_RECORDING_BYTES`].
    TooLarge,
    /// All-zero, all-ones, or a key that used to be written in the shell.
    WeakSeed,
    /// The frame or bundle did not parse, or the AEAD did not open.
    BadFrame,
    /// This step, or this stream, was already accepted.
    Replay,
    /// The step would skip more keys than [`MAX_VOICE_SKIP`].
    TooManySkips,
    /// [`MAX_SEEN_STREAMS`] recordings are already remembered.
    TooMany,
    /// The system random source failed.
    Rng,
    /// [`VoiceChain::wipe`] has run.
    Wiped,
    /// The Android environment check refused voice. The shared chain does
    /// not inspect the device; the shell passes this in.
    Strict,
}

impl VoiceRefusal {
    pub fn code(self) -> i32 {
        match self {
            Self::Extreme => -1,
            Self::Empty => -2,
            Self::TooLarge => -3,
            Self::WeakSeed => -4,
            Self::BadFrame => -5,
            Self::Replay => -6,
            Self::TooManySkips => -7,
            Self::TooMany => -8,
            Self::Rng => -9,
            Self::Wiped => -10,
            Self::Strict => -11,
        }
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -1 => Some(Self::Extreme),
            -2 => Some(Self::Empty),
            -3 => Some(Self::TooLarge),
            -4 => Some(Self::WeakSeed),
            -5 => Some(Self::BadFrame),
            -6 => Some(Self::Replay),
            -7 => Some(Self::TooManySkips),
            -8 => Some(Self::TooMany),
            -9 => Some(Self::Rng),
            -10 => Some(Self::Wiped),
            -11 => Some(Self::Strict),
            _ => None,
        }
    }

    /// Short toast text. Never echoes audio, a seed, or a frame.
    pub fn label(self) -> &'static str {
        match self {
            Self::Extreme => "Voice is off in Extreme mode.",
            Self::Empty => "Voice recording was empty.",
            Self::TooLarge => "Voice recording is too long.",
            Self::WeakSeed => "Voice key was refused.",
            Self::BadFrame => "Voice frame was refused.",
            Self::Replay => "Voice frame was already opened.",
            Self::TooManySkips => "Voice frame is too far ahead.",
            Self::TooMany => "Voice recording limit for this process was reached.",
            Self::Rng => "Voice key could not be generated.",
            Self::Wiped => "Voice keys were wiped.",
            Self::Strict => "Voice is refused in this environment.",
        }
    }
}

/// Label for a status code from [`VoiceRefusal::code`], [`VOICE_STATUS_OK`],
/// or [`VOICE_STATUS_PENDING`]. Unknown codes get a generic refusal.
pub fn status_label(code: i32) -> &'static str {
    match VoiceRefusal::from_code(code) {
        Some(r) => r.label(),
        None => match code {
            VOICE_STATUS_OK | VOICE_STATUS_PENDING => "",
            _ => "Voice was refused.",
        },
    }
}

/// One direction of voice for one process. The seed stays here.
pub struct VoiceChain {
    seed: [u8; 32],
    dead: bool,
    seen: Vec<[u8; STREAM_ID_LEN]>,
    flight: Option<InFlight>,
}

struct InFlight {
    stream_id: [u8; STREAM_ID_LEN],
    count: u16,
    parts: Vec<Option<Zeroizing<Vec<u8>>>>,
    chain_key: [u8; 32],
    recv_next: u32,
    skipped: BTreeMap<u32, [u8; 32]>,
}

impl InFlight {
    fn snapshot(&self) -> Self {
        Self {
            stream_id: self.stream_id,
            count: self.count,
            parts: self
                .parts
                .iter()
                .map(|p| p.as_ref().map(|z| Zeroizing::new(z.to_vec())))
                .collect(),
            chain_key: self.chain_key,
            recv_next: self.recv_next,
            skipped: self.skipped.clone(),
        }
    }

    fn wipe(&mut self) {
        self.stream_id.zeroize();
        self.chain_key.zeroize();
        self.recv_next = 0;
        self.count = 0;
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
        self.skipped.clear();
        for part in &mut self.parts {
            if let Some(buf) = part {
                buf.zeroize();
            }
            *part = None;
        }
        self.parts.clear();
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.wipe();
    }
}

struct FrameView<'a> {
    stream_id: [u8; STREAM_ID_LEN],
    step: u32,
    count: u16,
    body: &'a [u8],
}

impl VoiceChain {
    /// Random seed from the system CSPRNG. Refuses a weak draw.
    pub fn generate() -> Result<Self, VoiceRefusal> {
        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() {
            seed.zeroize();
            return Err(VoiceRefusal::Rng);
        }
        let chain = Self::from_seed(&seed);
        seed.zeroize();
        chain
    }

    /// Chain for a seed the caller already holds. The array is copied.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, VoiceRefusal> {
        if is_weak_seed(seed) {
            return Err(VoiceRefusal::WeakSeed);
        }
        Ok(Self {
            seed: *seed,
            dead: false,
            seen: Vec::new(),
            flight: None,
        })
    }

    /// Drop the seed, the open recording, and the replay set.
    pub fn wipe(&mut self) {
        self.seed.zeroize();
        self.dead = true;
        self.seen.clear();
        if let Some(mut flight) = self.flight.take() {
            flight.wipe();
        }
    }

    fn live(&self) -> Result<(), VoiceRefusal> {
        if self.dead {
            Err(VoiceRefusal::Wiped)
        } else {
            Ok(())
        }
    }

    /// Split `audio`, pad each piece, and seal a bundle.
    ///
    /// Does not move the opener. `extreme` refuses before the seed is used.
    pub fn seal_recording(&self, extreme: bool, audio: &[u8]) -> Result<Vec<u8>, VoiceRefusal> {
        if extreme {
            return Err(VoiceRefusal::Extreme);
        }
        self.live()?;
        if audio.is_empty() {
            return Err(VoiceRefusal::Empty);
        }
        if audio.len() > MAX_RECORDING_BYTES {
            return Err(VoiceRefusal::TooLarge);
        }

        let mut stream_id = [0u8; STREAM_ID_LEN];
        if getrandom::getrandom(&mut stream_id).is_err() {
            return Err(VoiceRefusal::Rng);
        }
        let count_usize = audio.len().div_ceil(VOICE_PAYLOAD);
        let count = u16::try_from(count_usize).map_err(|_| VoiceRefusal::TooLarge)?;
        let mut chain = stream_chain(&self.seed, &stream_id);
        let mut frames: Vec<Vec<u8>> = Vec::with_capacity(count_usize);
        let mut off = 0usize;
        let mut step = 0u32;
        while off < audio.len() {
            let end = (off + VOICE_PAYLOAD).min(audio.len());
            let piece = &audio[off..end];
            if step + 1 != u32::from(count) && piece.len() != VOICE_PAYLOAD {
                wipe_frames(&mut frames);
                chain.zeroize();
                return Err(VoiceRefusal::BadFrame);
            }
            match seal_one(&mut chain, &stream_id, step, count, piece) {
                Ok(frame) => frames.push(frame),
                Err(e) => {
                    wipe_frames(&mut frames);
                    chain.zeroize();
                    return Err(e);
                }
            }
            off = end;
            step = step.saturating_add(1);
        }
        chain.zeroize();
        let bundle = encode_bundle(&frames);
        wipe_frames(&mut frames);
        Ok(bundle)
    }

    /// Open one frame. `Ok(None)` means this chunk is stored and the
    /// recording is not complete yet. `Ok(Some)` is the whole recording.
    ///
    /// A new stream id abandons an unfinished recording and remembers that
    /// id, so its chunks cannot be resumed. A frame that fails AEAD does
    /// not move the chain.
    pub fn open_frame(
        &mut self,
        extreme: bool,
        frame: &[u8],
    ) -> Result<Option<Vec<u8>>, VoiceRefusal> {
        if extreme {
            return Err(VoiceRefusal::Extreme);
        }
        self.live()?;
        let view = parse_frame(frame)?;
        self.open_view(view)
    }

    /// Open a bundle from [`Self::seal_recording`]. Either the whole
    /// recording comes back or the opener is left as it was.
    pub fn open_bundle(&mut self, extreme: bool, bundle: &[u8]) -> Result<Vec<u8>, VoiceRefusal> {
        if extreme {
            return Err(VoiceRefusal::Extreme);
        }
        self.live()?;
        let saved_flight = self.flight.as_ref().map(InFlight::snapshot);
        let saved_seen = self.seen.len();
        match self.open_bundle_commit(bundle) {
            Ok(audio) => {
                if let Some(mut old) = saved_flight {
                    old.wipe();
                }
                Ok(audio)
            }
            Err(e) => {
                self.rollback(saved_flight, saved_seen);
                Err(e)
            }
        }
    }

    fn open_bundle_commit(&mut self, bundle: &[u8]) -> Result<Vec<u8>, VoiceRefusal> {
        let n = bundle_count(bundle)?;
        let mut owned: Vec<Vec<u8>> = Vec::with_capacity(usize::from(n));
        for i in 0..n {
            owned.push(bundle_frame(bundle, i)?.to_vec());
        }
        if let Err(e) = bundle_shape(&owned, n) {
            wipe_frames(&mut owned);
            return Err(e);
        }
        let mut audio = None;
        for frame in &owned {
            match self.open_frame(false, frame) {
                Ok(Some(buf)) => audio = Some(buf),
                Ok(None) => {}
                Err(e) => {
                    wipe_frames(&mut owned);
                    return Err(e);
                }
            }
        }
        wipe_frames(&mut owned);
        audio.ok_or(VoiceRefusal::BadFrame)
    }

    fn rollback(&mut self, saved: Option<InFlight>, seen_len: usize) {
        if let Some(mut cur) = self.flight.take() {
            cur.wipe();
        }
        self.flight = saved;
        self.seen.truncate(seen_len);
    }

    fn open_view(&mut self, view: FrameView<'_>) -> Result<Option<Vec<u8>>, VoiceRefusal> {
        let continuing = self
            .flight
            .as_ref()
            .is_some_and(|f| f.stream_id == view.stream_id);
        if !continuing {
            if self.seen.contains(&view.stream_id) {
                return Err(VoiceRefusal::Replay);
            }
            // One slot for this stream when it finishes. A second slot is
            // required when an unfinished recording has to be remembered too.
            // Refuse before the KDF so a bad frame cannot discard that recording.
            let need = if self.flight.is_some() { 2 } else { 1 };
            if self.seen.len().saturating_add(need) > MAX_SEEN_STREAMS {
                return Err(VoiceRefusal::TooMany);
            }
        } else {
            let flight = self.flight.as_ref().ok_or(VoiceRefusal::BadFrame)?;
            if flight.count != view.count {
                return Err(VoiceRefusal::BadFrame);
            }
            if flight
                .parts
                .get(view.step as usize)
                .is_some_and(Option::is_some)
            {
                return Err(VoiceRefusal::Replay);
            }
        }

        let (mut chain, mut recv_next, mut skipped) = if continuing {
            let flight = self.flight.as_ref().ok_or(VoiceRefusal::BadFrame)?;
            (flight.chain_key, flight.recv_next, flight.skipped.clone())
        } else {
            (
                stream_chain(&self.seed, &view.stream_id),
                0u32,
                BTreeMap::new(),
            )
        };

        let mut msg_key = match message_key_for(&mut chain, &mut recv_next, &mut skipped, view.step)
        {
            Ok(k) => k,
            Err(e) => {
                chain.zeroize();
                wipe_skipped(&mut skipped);
                return Err(e);
            }
        };
        let header = frame_header(&view.stream_id, view.step, view.count);
        let opened = decrypt_with_key(&msg_key, view.body, &header);
        msg_key.zeroize();
        let mut plain = match opened {
            Ok(buf) => buf,
            Err(_) => {
                chain.zeroize();
                wipe_skipped(&mut skipped);
                return Err(VoiceRefusal::BadFrame);
            }
        };
        let mut audio = match unpad(&plain) {
            Ok(buf) => buf,
            Err(e) => {
                plain.zeroize();
                chain.zeroize();
                wipe_skipped(&mut skipped);
                return Err(e);
            }
        };
        plain.zeroize();
        let last = view.step + 1 == u32::from(view.count);
        if !last && audio.len() != VOICE_PAYLOAD {
            audio.zeroize();
            chain.zeroize();
            wipe_skipped(&mut skipped);
            return Err(VoiceRefusal::BadFrame);
        }

        if !continuing {
            if let Some(mut flight) = self.flight.take() {
                let old = flight.stream_id;
                flight.wipe();
                self.seen.push(old);
            }
            self.flight = Some(InFlight {
                stream_id: view.stream_id,
                count: view.count,
                parts: (0..view.count).map(|_| None).collect(),
                chain_key: [0u8; 32],
                recv_next: 0,
                skipped: BTreeMap::new(),
            });
        }
        let flight = self.flight.as_mut().ok_or(VoiceRefusal::BadFrame)?;
        flight.chain_key.zeroize();
        flight.chain_key = chain;
        flight.recv_next = recv_next;
        wipe_skipped(&mut flight.skipped);
        flight.skipped = skipped;
        let slot = usize::try_from(view.step).map_err(|_| VoiceRefusal::BadFrame)?;
        match flight.parts.get_mut(slot) {
            Some(part) => *part = Some(Zeroizing::new(audio)),
            None => {
                audio.zeroize();
                return Err(VoiceRefusal::BadFrame);
            }
        }
        if flight.parts.iter().all(Option::is_some) {
            let mut done = self.flight.take().ok_or(VoiceRefusal::BadFrame)?;
            let id = done.stream_id;
            let assembled = assemble(&mut done);
            done.wipe();
            self.seen.push(id);
            Ok(Some(assembled))
        } else {
            Ok(None)
        }
    }
}

impl Drop for VoiceChain {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn assemble(flight: &mut InFlight) -> Vec<u8> {
    let mut out = Vec::new();
    for part in &mut flight.parts {
        if let Some(buf) = part {
            out.extend_from_slice(buf);
            buf.zeroize();
        }
        *part = None;
    }
    out
}

fn message_key_for(
    chain: &mut [u8; 32],
    recv_next: &mut u32,
    skipped: &mut BTreeMap<u32, [u8; 32]>,
    step: u32,
) -> Result<[u8; 32], VoiceRefusal> {
    if step < *recv_next {
        return skipped.remove(&step).ok_or(VoiceRefusal::Replay);
    }
    let gap = step - *recv_next;
    if gap > MAX_VOICE_SKIP {
        return Err(VoiceRefusal::TooManySkips);
    }
    if skipped
        .len()
        .saturating_add(usize::try_from(gap).unwrap_or(usize::MAX))
        > MAX_VOICE_CHUNKS
    {
        return Err(VoiceRefusal::TooManySkips);
    }
    for i in 0..gap {
        let at = recv_next.saturating_add(i);
        let msg = advance(chain);
        skipped.insert(at, msg);
    }
    let msg = advance(chain);
    *recv_next = step.saturating_add(1);
    Ok(msg)
}

fn advance(chain: &mut [u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, chain);
    let mut msg = [0u8; 32];
    let mut next = [0u8; 32];
    hk.expand(CHUNK_INFO, &mut msg)
        .expect("voice chunk key is 32 bytes");
    hk.expand(NEXT_INFO, &mut next)
        .expect("voice chain key is 32 bytes");
    chain.copy_from_slice(&next);
    next.zeroize();
    msg
}

fn stream_chain(seed: &[u8; 32], stream_id: &[u8; STREAM_ID_LEN]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(stream_id), seed);
    let mut out = [0u8; 32];
    hk.expand(STREAM_INFO, &mut out)
        .expect("voice stream key is 32 bytes");
    out
}

fn seal_one(
    chain: &mut [u8; 32],
    stream_id: &[u8; STREAM_ID_LEN],
    step: u32,
    count: u16,
    piece: &[u8],
) -> Result<Vec<u8>, VoiceRefusal> {
    let mut padded = pad_chunk(piece)?;
    let mut msg = advance(chain);
    let header = frame_header(stream_id, step, count);
    let body = match encrypt_with_key(&msg, &padded, &header) {
        Ok(buf) => buf,
        Err(_) => {
            msg.zeroize();
            padded.zeroize();
            return Err(VoiceRefusal::Rng);
        }
    };
    msg.zeroize();
    padded.zeroize();
    if body.len() != VOICE_PAD + AEAD_OVERHEAD {
        return Err(VoiceRefusal::BadFrame);
    }
    let mut frame = Vec::with_capacity(VOICE_FRAME_LEN);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn frame_header(stream_id: &[u8; STREAM_ID_LEN], step: u32, count: u16) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0] = VOICE_VERSION;
    header[1..1 + STREAM_ID_LEN].copy_from_slice(stream_id);
    header[1 + STREAM_ID_LEN..1 + STREAM_ID_LEN + 4].copy_from_slice(&step.to_be_bytes());
    header[1 + STREAM_ID_LEN + 4..].copy_from_slice(&count.to_be_bytes());
    header
}

fn parse_frame(frame: &[u8]) -> Result<FrameView<'_>, VoiceRefusal> {
    if frame.len() != VOICE_FRAME_LEN {
        return Err(VoiceRefusal::BadFrame);
    }
    if frame[0] != VOICE_VERSION {
        return Err(VoiceRefusal::BadFrame);
    }
    let mut stream_id = [0u8; STREAM_ID_LEN];
    stream_id.copy_from_slice(&frame[1..1 + STREAM_ID_LEN]);
    let step = u32::from_be_bytes(
        frame[1 + STREAM_ID_LEN..1 + STREAM_ID_LEN + 4]
            .try_into()
            .map_err(|_| VoiceRefusal::BadFrame)?,
    );
    let count = u16::from_be_bytes(
        frame[1 + STREAM_ID_LEN + 4..HEADER_LEN]
            .try_into()
            .map_err(|_| VoiceRefusal::BadFrame)?,
    );
    if count == 0 || usize::from(count) > MAX_VOICE_CHUNKS || step >= u32::from(count) {
        return Err(VoiceRefusal::BadFrame);
    }
    let body = &frame[HEADER_LEN..];
    if body.len() != VOICE_PAD + AEAD_OVERHEAD {
        return Err(VoiceRefusal::BadFrame);
    }
    Ok(FrameView {
        stream_id,
        step,
        count,
        body,
    })
}

fn pad_chunk(piece: &[u8]) -> Result<[u8; VOICE_PAD], VoiceRefusal> {
    if piece.is_empty() || piece.len() > VOICE_PAYLOAD {
        return Err(VoiceRefusal::BadFrame);
    }
    let mut out = [0u8; VOICE_PAD];
    let n = u16::try_from(piece.len()).map_err(|_| VoiceRefusal::BadFrame)?;
    out[..LEN_PREFIX].copy_from_slice(&n.to_be_bytes());
    out[LEN_PREFIX..LEN_PREFIX + piece.len()].copy_from_slice(piece);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, VoiceRefusal> {
    if padded.len() != VOICE_PAD {
        return Err(VoiceRefusal::BadFrame);
    }
    let n = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if n == 0 || n > VOICE_PAYLOAD {
        return Err(VoiceRefusal::BadFrame);
    }
    if padded[LEN_PREFIX + n..].iter().any(|&b| b != 0) {
        return Err(VoiceRefusal::BadFrame);
    }
    Ok(padded[LEN_PREFIX..LEN_PREFIX + n].to_vec())
}

/// How many frames a bundle claims. Does not decrypt.
pub fn bundle_count(bundle: &[u8]) -> Result<u16, VoiceRefusal> {
    if bundle.len() < 6 || !bundle.starts_with(BUNDLE_MAGIC) {
        return Err(VoiceRefusal::BadFrame);
    }
    let n = u16::from_be_bytes([bundle[4], bundle[5]]);
    if n == 0 || usize::from(n) > MAX_VOICE_CHUNKS {
        return Err(VoiceRefusal::BadFrame);
    }
    // Walk the lengths so a short or padded buffer is refused here.
    let mut pos = 6usize;
    for _ in 0..n {
        if pos + 2 > bundle.len() {
            return Err(VoiceRefusal::BadFrame);
        }
        let len = u16::from_be_bytes([bundle[pos], bundle[pos + 1]]) as usize;
        pos += 2;
        if len != VOICE_FRAME_LEN || pos + len > bundle.len() {
            return Err(VoiceRefusal::BadFrame);
        }
        pos += len;
    }
    if pos != bundle.len() {
        return Err(VoiceRefusal::BadFrame);
    }
    Ok(n)
}

/// One frame inside a bundle, by index. Does not decrypt.
pub fn bundle_frame(bundle: &[u8], index: u16) -> Result<&[u8], VoiceRefusal> {
    let n = bundle_count(bundle)?;
    if index >= n {
        return Err(VoiceRefusal::BadFrame);
    }
    let mut pos = 6usize;
    for i in 0..n {
        let len = u16::from_be_bytes([bundle[pos], bundle[pos + 1]]) as usize;
        pos += 2;
        if i == index {
            return Ok(&bundle[pos..pos + len]);
        }
        pos += len;
    }
    Err(VoiceRefusal::BadFrame)
}

fn encode_bundle(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    let n = u16::try_from(frames.len()).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    for frame in frames {
        let len = u16::try_from(frame.len()).unwrap_or(0);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(frame);
    }
    out
}

fn bundle_shape(frames: &[Vec<u8>], n: u16) -> Result<(), VoiceRefusal> {
    if frames.len() != usize::from(n) {
        return Err(VoiceRefusal::BadFrame);
    }
    let first = parse_frame(&frames[0])?;
    if first.count != n {
        return Err(VoiceRefusal::BadFrame);
    }
    let mut saw = vec![false; usize::from(n)];
    for frame in frames {
        let view = parse_frame(frame)?;
        if view.stream_id != first.stream_id || view.count != n {
            return Err(VoiceRefusal::BadFrame);
        }
        let slot = usize::try_from(view.step).map_err(|_| VoiceRefusal::BadFrame)?;
        if saw.get(slot).copied().unwrap_or(true) {
            return Err(VoiceRefusal::BadFrame);
        }
        saw[slot] = true;
    }
    if saw.iter().any(|s| !*s) {
        return Err(VoiceRefusal::BadFrame);
    }
    Ok(())
}

fn wipe_frames(frames: &mut Vec<Vec<u8>>) {
    for frame in frames.iter_mut() {
        frame.zeroize();
    }
    frames.clear();
}

fn wipe_skipped(skipped: &mut BTreeMap<u32, [u8; 32]>) {
    for key in skipped.values_mut() {
        key.zeroize();
    }
    skipped.clear();
}

fn is_weak_seed(seed: &[u8; 32]) -> bool {
    let mut bad = seed.ct_eq(&[0u8; 32]);
    bad |= seed.ct_eq(&[0xffu8; 32]);
    bad |= seed.ct_eq(&demo_mul_add(7, 11));
    bad |= seed.ct_eq(&demo_index());
    bad |= seed.ct_eq(&demo_plus(7));
    bool::from(bad)
}

const fn demo_mul_add(mul: u8, add: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (i as u8).wrapping_mul(mul).wrapping_add(add);
        i += 1;
    }
    out
}

const fn demo_index() -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = i as u8;
        i += 1;
    }
    out
}

const fn demo_plus(add: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (i as u8).wrapping_add(add);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> VoiceChain {
        let mut seed = [0u8; 32];
        seed[0] = 0x5a;
        seed[31] = 0xa5;
        VoiceChain::from_seed(&seed).unwrap()
    }

    #[test]
    fn short_and_split_recordings_roundtrip() {
        let send = chain();
        let mut recv = chain();
        let one = send.seal_recording(false, b"hello-voice").unwrap();
        assert_eq!(bundle_count(&one).unwrap(), 1);
        assert_eq!(recv.open_bundle(false, &one).unwrap(), b"hello-voice");

        let mut audio = vec![0x11u8; VOICE_PAYLOAD];
        audio.push(0x22);
        let two = send.seal_recording(false, &audio).unwrap();
        assert_eq!(bundle_count(&two).unwrap(), 2);
        assert_eq!(bundle_frame(&two, 0).unwrap().len(), VOICE_FRAME_LEN);
        assert_eq!(recv.open_bundle(false, &two).unwrap(), audio);
    }

    #[test]
    fn chunks_out_of_order_assemble_once() {
        let send = chain();
        let mut recv = chain();
        let audio = vec![0x44u8; VOICE_PAYLOAD + 3];
        let bundle = send.seal_recording(false, &audio).unwrap();
        let second = bundle_frame(&bundle, 1).unwrap().to_vec();
        let first = bundle_frame(&bundle, 0).unwrap().to_vec();
        assert!(recv.open_frame(false, &second).unwrap().is_none());
        let got = recv.open_frame(false, &first).unwrap().unwrap();
        assert_eq!(got, audio);
        assert_eq!(
            recv.open_frame(false, &first).unwrap_err(),
            VoiceRefusal::Replay
        );
        assert_eq!(
            recv.open_bundle(false, &bundle).unwrap_err(),
            VoiceRefusal::Replay
        );
    }

    #[test]
    fn tamper_does_not_move_the_chain_and_a_bundle_rolls_back() {
        let send = chain();
        let mut recv = chain();
        let audio = vec![0x66u8; VOICE_PAYLOAD + 8];
        let mut bundle = send.seal_recording(false, &audio).unwrap();
        let last = bundle.len() - 1;
        bundle[last] ^= 0x5a;
        assert_eq!(
            recv.open_bundle(false, &bundle).unwrap_err(),
            VoiceRefusal::BadFrame
        );
        bundle[last] ^= 0x5a;
        assert_eq!(recv.open_bundle(false, &bundle).unwrap(), audio);

        let fresh = send.seal_recording(false, b"after-rollback").unwrap();
        let mut bad = bundle_frame(&fresh, 0).unwrap().to_vec();
        bad[VOICE_FRAME_LEN - 1] ^= 0xff;
        assert_eq!(
            recv.open_frame(false, &bad).unwrap_err(),
            VoiceRefusal::BadFrame
        );
        assert_eq!(recv.open_bundle(false, &fresh).unwrap(), b"after-rollback");
    }

    #[test]
    fn a_different_seed_and_a_wiped_chain_refuse() {
        let send = chain();
        let bundle = send.seal_recording(false, b"secret-audio").unwrap();
        let mut other_seed = [9u8; 32];
        other_seed[0] = 1;
        let mut other = VoiceChain::from_seed(&other_seed).unwrap();
        assert_eq!(
            other.open_bundle(false, &bundle).unwrap_err(),
            VoiceRefusal::BadFrame
        );
        other.wipe();
        assert_eq!(
            other.seal_recording(false, b"x").unwrap_err(),
            VoiceRefusal::Wiped
        );
        assert_eq!(
            other.open_bundle(false, &bundle).unwrap_err(),
            VoiceRefusal::Wiped
        );
    }

    #[test]
    fn weak_empty_extreme_and_oversize_are_refused() {
        assert!(matches!(
            VoiceChain::from_seed(&[0u8; 32]),
            Err(VoiceRefusal::WeakSeed)
        ));
        assert!(matches!(
            VoiceChain::from_seed(&[0xffu8; 32]),
            Err(VoiceRefusal::WeakSeed)
        ));
        assert!(matches!(
            VoiceChain::from_seed(&demo_mul_add(7, 11)),
            Err(VoiceRefusal::WeakSeed)
        ));
        assert!(matches!(
            VoiceChain::from_seed(&demo_index()),
            Err(VoiceRefusal::WeakSeed)
        ));
        assert!(matches!(
            VoiceChain::from_seed(&demo_plus(7)),
            Err(VoiceRefusal::WeakSeed)
        ));
        let send = chain();
        assert_eq!(
            send.seal_recording(false, b"").unwrap_err(),
            VoiceRefusal::Empty
        );
        assert_eq!(
            send.seal_recording(true, b"audio").unwrap_err(),
            VoiceRefusal::Extreme
        );
        let huge = vec![1u8; MAX_RECORDING_BYTES + 1];
        assert_eq!(
            send.seal_recording(false, &huge).unwrap_err(),
            VoiceRefusal::TooLarge
        );
        let mut recv = chain();
        assert_eq!(
            recv.open_frame(true, &[0u8; VOICE_FRAME_LEN]).unwrap_err(),
            VoiceRefusal::Extreme
        );
        assert!(recv.open_bundle(false, b"HVB1").is_err());
        assert_eq!(
            status_label(VoiceRefusal::Extreme.code()),
            VoiceRefusal::Extreme.label()
        );
        assert_eq!(status_label(VOICE_STATUS_PENDING), "");
        assert_eq!(status_label(99), "Voice was refused.");
    }

    #[test]
    fn a_bad_frame_does_not_discard_an_unfinished_recording() {
        let send = chain();
        let mut recv = chain();
        let audio = vec![0x21u8; VOICE_PAYLOAD + 1];
        let bundle = send.seal_recording(false, &audio).unwrap();
        assert!(recv
            .open_frame(false, bundle_frame(&bundle, 0).unwrap())
            .unwrap()
            .is_none());
        let mut junk = bundle_frame(&bundle, 1).unwrap().to_vec();
        junk[1] ^= 0xff;
        junk[VOICE_FRAME_LEN - 1] ^= 0xff;
        assert_eq!(
            recv.open_frame(false, &junk).unwrap_err(),
            VoiceRefusal::BadFrame
        );
        let got = recv
            .open_frame(false, bundle_frame(&bundle, 1).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(got, audio);
    }

    #[test]
    fn a_new_stream_abandons_an_unfinished_one() {
        let send = chain();
        let mut recv = chain();
        let first = vec![0x21u8; VOICE_PAYLOAD + 1];
        let second = b"second-recording".to_vec();
        let bundle_a = send.seal_recording(false, &first).unwrap();
        let bundle_b = send.seal_recording(false, &second).unwrap();
        assert!(recv
            .open_frame(false, bundle_frame(&bundle_a, 0).unwrap())
            .unwrap()
            .is_none());
        assert_eq!(recv.open_bundle(false, &bundle_b).unwrap(), second);
        assert_eq!(
            recv.open_bundle(false, &bundle_a).unwrap_err(),
            VoiceRefusal::Replay
        );
    }

    #[test]
    fn seen_cap_refuses_a_new_stream() {
        let send = chain();
        let mut recv = chain();
        for i in 0..MAX_SEEN_STREAMS {
            let audio = [u8::try_from(i).unwrap_or(1)];
            let audio = if audio[0] == 0 { [1u8] } else { audio };
            let bundle = send.seal_recording(false, &audio).unwrap();
            assert_eq!(recv.open_bundle(false, &bundle).unwrap(), audio);
        }
        let extra = send.seal_recording(false, b"overflow").unwrap();
        assert_eq!(
            recv.open_bundle(false, &extra).unwrap_err(),
            VoiceRefusal::TooMany
        );
    }

    #[test]
    fn generated_chains_do_not_open_each_other() {
        let a = VoiceChain::generate().unwrap();
        let b = VoiceChain::generate().unwrap();
        let bundle = a.seal_recording(false, b"from-a").unwrap();
        let mut b = b;
        assert!(b.open_bundle(false, &bundle).is_err());
    }
}
