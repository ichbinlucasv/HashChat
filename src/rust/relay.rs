//! Self-hosted store-and-forward relay (one mailbox per recipient).
//!
//! People run this themselves. It holds fixed-size slots of ciphertext for
//! offline peers. There are no accounts and no request log. The operator can
//! see mailbox ids, token hashes, ciphertext, and deposit times. They cannot
//! see plaintext: the slot is an opaque padded frame from the ratchet.
//!
//! The public listener accepts only put, get, and ack. It binds `127.0.0.1`
//! and is meant to be published as a Tor v3 onion (`Port=80` to that
//! listener). Creating or deleting a mailbox is an in-process operator
//! action, so it is not reachable through the onion.
//!
//! A profile may use several relays. Deposit tries a contact's cards in the
//! order they were stored and stops at the first that accepts the slot.
//! Fetch walks the profile's own inboxes in that same kind of order. This is
//! failover, not a copy on every relay.
//!
//! What this is not: cover traffic, a background poll, or a promise that the
//! operator is honest. A relay can drop frames, refuse the queue, or record
//! timing. A relay that answers FULL or REFUSED has already seen the slot.
//! If a reply is lost after the relay stored the frame, the next relay may
//! store a second copy. Delivery is best-effort. Frames expire. The sender
//! keeps a local copy until a direct Tor send works.
//!
//! Disk, when a directory is configured, holds ciphertext and token hashes
//! in owner-only files. The tokens themselves are not written. Wiping
//! removes mailbox files and leaves `onion.key` in place; deleting the
//! directory removes the onion key as well. Overwrite is unreliable on SSDs
//! and copy-on-write filesystems.

use crate::hidden_service::MAX_HS_INBOUND_FRAME;
use crate::tor_socks::{is_onion_destination, socks5_connect, SocksIsolationCreds};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Fixed slot size. Every stored frame and every public response body uses
/// this length, so a slot does not reveal which plaintext size class it holds.
pub const RELAY_SLOT_BYTES: usize = 16 * 1024;

/// Mailboxes one process will hold.
pub const MAX_MAILBOXES: usize = 128;

/// Frames queued for one mailbox. A full mailbox refuses the put.
pub const MAX_FRAMES_PER_MAILBOX: usize = 32;

/// Default lifetime of one deposited frame (72 hours).
pub const DEFAULT_TTL_SECS: u64 = 72 * 60 * 60;

/// Shortest and longest lifetime the command line will accept.
pub const MIN_TTL_SECS: u64 = 60 * 60;
pub const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Deposit targets stored in one profile.
pub const MAX_RELAY_TARGETS: usize = 64;

/// Relay cards for one contact. Tried in stored order; the first accept wins.
pub const MAX_RELAYS_PER_CONTACT: usize = 4;

/// Inboxes one profile fetches. Same cap: more relays means more operators
/// who can see ciphertext and timing.
pub const MAX_RELAY_INBOXES: usize = 4;

/// Stored inbox book. A single inbox written by an older profile is version 1.
const INBOX_BOOK_VERSION: u8 = 2;

const MAX_INBOX_STORED: usize = 1024;

const MAGIC: &[u8; 4] = b"HCRL";
const VERSION: u8 = 1;
const OP_PUT: u8 = 1;
const OP_GET: u8 = 2;
const OP_ACK: u8 = 3;

const ST_OK: u8 = 0;
const ST_REFUSED: u8 = 1;
const ST_FULL: u8 = 2;
const ST_EMPTY: u8 = 3;

const REQ_BODY: usize = 4 + 1 + 1 + 32 + 32 + RELAY_SLOT_BYTES;
const RESP_BODY: usize = 4 + 1 + 1 + RELAY_SLOT_BYTES;

const _: () = assert!(REQ_BODY <= u16::MAX as usize);
const _: () = assert!(RESP_BODY <= u16::MAX as usize);
const _: () = assert!(RELAY_SLOT_BYTES - 2 >= 8 * 1024);

const LABEL_PULL: &[u8] = b"HashChat-relay-pull-v1";
const LABEL_PUSH: &[u8] = b"HashChat-relay-push-v1";
const FILE_MAGIC: &[u8; 4] = b"HCMB";
const FILE_VER: u8 = 1;
const FILE_HEADER: usize = 4 + 1 + 32 + 32 + 2;
const CONN_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CONNS: usize = 16;
const MAX_OPERATOR_LINE: usize = 256;

const DUMMY_TOKEN: [u8; 32] = [0xA5; 32];

fn token_hash(label: &[u8], token: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(token);
    h.finalize().into()
}

fn slot_hash(slot: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HashChat-relay-slot-v1");
    h.update(slot);
    h.finalize().into()
}

/// Id of a frame already handed to a relay, so a later retry does not fill
/// the mailbox with the same ciphertext.
pub fn frame_deposit_id(frame: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HashChat-relay-deposit-v1");
    h.update(frame);
    h.finalize().into()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_exact<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    let text = text.trim();
    if text.len() != N * 2 {
        return Err("bad relay token");
    }
    let raw = text.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let Ok(hi) = hex_val(raw[i * 2]) else {
            out.zeroize();
            return Err("bad relay token");
        };
        let Ok(lo) = hex_val(raw[i * 2 + 1]) else {
            out.zeroize();
            return Err("bad relay token");
        };
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

fn pack_slot(frame: &[u8]) -> Result<Vec<u8>, &'static str> {
    if frame.is_empty() || frame.len() > RELAY_SLOT_BYTES - 2 || frame.len() > MAX_HS_INBOUND_FRAME
    {
        return Err("frame does not fit a relay slot");
    }
    let mut slot = vec![0u8; RELAY_SLOT_BYTES];
    let n = u16::try_from(frame.len()).map_err(|_| "frame does not fit a relay slot")?;
    slot[..2].copy_from_slice(&n.to_be_bytes());
    slot[2..2 + frame.len()].copy_from_slice(frame);
    Ok(slot)
}

fn unpack_slot(slot: &[u8]) -> Result<Vec<u8>, &'static str> {
    if slot.len() != RELAY_SLOT_BYTES {
        return Err("bad relay slot");
    }
    let n = u16::from_be_bytes([slot[0], slot[1]]) as usize;
    if n == 0 || n > RELAY_SLOT_BYTES - 2 || n > MAX_HS_INBOUND_FRAME {
        return Err("bad relay slot");
    }
    if slot[2 + n..].iter().any(|&b| b != 0) {
        return Err("bad relay slot");
    }
    Ok(slot[2..2 + n].to_vec())
}

fn check_onion(onion: &str) -> Result<String, &'static str> {
    let onion = onion.trim().to_ascii_lowercase();
    if onion.len() > 62 || onion.contains(':') || !is_onion_destination(&onion) {
        return Err("relay onion refused");
    }
    Ok(onion)
}

fn check_contact_id(id: &str) -> Result<&str, &'static str> {
    let id = id.trim();
    if id.is_empty()
        || id.len() > 128
        || id.bytes().any(|b| b < 0x20 || b == 0x7f)
        || id.to_ascii_lowercase().contains("hashchat://")
    {
        return Err("bad relay contact");
    }
    Ok(id)
}

/// Text that holds mailbox secrets. Zeroized on drop. Printing it is the
/// one intentional reveal; the terminal scrollback keeps a copy after that.
pub struct Revealed {
    inner: String,
}

impl Revealed {
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Display for Revealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.inner)
    }
}

impl Drop for Revealed {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Tokens returned once, when the operator creates a mailbox.
///
/// `pull_token` stays with the recipient. `push_token` is what senders are
/// given. Neither is written to the relay's disk.
#[derive(Clone, Zeroize)]
pub struct MailboxSecrets {
    pub id: [u8; 32],
    pub pull_token: [u8; 32],
    pub push_token: [u8; 32],
}

impl Drop for MailboxSecrets {
    fn drop(&mut self) {
        self.id.zeroize();
        self.pull_token.zeroize();
        self.push_token.zeroize();
    }
}

impl MailboxSecrets {
    /// `inbox <hex>` and `card <hex>` for the operator to hand out.
    ///
    /// The hex is `id || pull` and `id || push`. The relay onion is not in
    /// either line: say it separately, and check it out of band. The card
    /// does not bind the onion.
    pub fn reveal(&self) -> Revealed {
        let mut inbox_pair = self.pair(&self.pull_token);
        let mut card_pair = self.pair(&self.push_token);
        let mut inbox = encode_hex(&inbox_pair);
        let mut card = encode_hex(&card_pair);
        inbox_pair.zeroize();
        card_pair.zeroize();
        let text = format!("inbox {inbox}\ncard {card}");
        inbox.zeroize();
        card.zeroize();
        Revealed { inner: text }
    }

    fn pair(&self, token: &[u8; 32]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.id);
        out[32..].copy_from_slice(token);
        out
    }
}

/// This profile's mailbox: where to fetch frames addressed to us.
#[derive(Clone, Zeroize)]
pub struct Inbox {
    onion: String,
    id: [u8; 32],
    pull_token: [u8; 32],
}

impl Drop for Inbox {
    fn drop(&mut self) {
        self.onion.zeroize();
        self.id.zeroize();
        self.pull_token.zeroize();
    }
}

impl Inbox {
    pub fn parse(onion: &str, inbox_hex: &str) -> Result<Self, &'static str> {
        let onion = check_onion(onion)?;
        let mut pair = decode_hex_exact::<64>(inbox_hex)?;
        let mut id = [0u8; 32];
        let mut pull = [0u8; 32];
        id.copy_from_slice(&pair[..32]);
        pull.copy_from_slice(&pair[32..]);
        pair.zeroize();
        Ok(Self {
            onion,
            id,
            pull_token: pull,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let o = self.onion.as_bytes();
        let mut out = Vec::with_capacity(2 + o.len() + 64);
        out.push(VERSION);
        out.push(u8::try_from(o.len()).unwrap_or(0));
        out.extend_from_slice(o);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.pull_token);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 2 + 64 || bytes.len() > 2 + 62 + 64 {
            return Err("bad relay inbox");
        }
        if bytes[0] != VERSION {
            return Err("bad relay inbox");
        }
        let n = bytes[1] as usize;
        if bytes.len() != 2 + n + 64 {
            return Err("bad relay inbox");
        }
        let onion = std::str::from_utf8(&bytes[2..2 + n]).map_err(|_| "bad relay inbox")?;
        let onion = check_onion(onion)?;
        let mut id = [0u8; 32];
        let mut pull = [0u8; 32];
        let rest = &bytes[2 + n..];
        id.copy_from_slice(&rest[..32]);
        pull.copy_from_slice(&rest[32..]);
        Ok(Self {
            onion,
            id,
            pull_token: pull,
        })
    }

    pub fn onion(&self) -> &str {
        &self.onion
    }

    /// Fetch the oldest frame. `Empty` means the mailbox had nothing live.
    ///
    /// A slot that is not a valid frame is acked and reported as refused, so
    /// junk cannot sit at the head forever. A valid frame is not acked here:
    /// call [`Inbox::ack`] after the local decrypt attempt.
    pub fn fetch(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        isolation: Option<&SocksIsolationCreds>,
    ) -> Result<Fetched, &'static str> {
        let mut req = request(
            OP_GET,
            &self.id,
            &self.pull_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        let reply = exchange_onion(proxy_host, proxy_port, &self.onion, &req, isolation);
        req.zeroize();
        let reply = reply?;
        match reply.status {
            ST_EMPTY => Ok(Fetched::Empty),
            ST_OK => {
                let hash = slot_hash(&reply.slot);
                match unpack_slot(&reply.slot) {
                    Ok(frame) => Ok(Fetched::Frame {
                        frame,
                        ack: Ack {
                            hash,
                            id: self.id,
                            pull_token: self.pull_token,
                            onion: self.onion.clone(),
                        },
                    }),
                    Err(_) => {
                        let _ = ack_at(
                            proxy_host,
                            proxy_port,
                            &self.onion,
                            &self.id,
                            &self.pull_token,
                            &hash,
                            isolation,
                        );
                        Err("relay refused")
                    }
                }
            }
            _ => Err("relay refused"),
        }
    }

    pub fn ack(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        ack: &Ack,
        isolation: Option<&SocksIsolationCreds>,
    ) -> Result<(), &'static str> {
        if ack.id != self.id || ack.onion != self.onion {
            return Err("relay refused");
        }
        ack_at(
            proxy_host,
            proxy_port,
            &self.onion,
            &self.id,
            &self.pull_token,
            &ack.hash,
            isolation,
        )
    }
}

/// Proof of which slot was fetched, so ack cannot delete a newer head.
#[derive(Clone, Zeroize)]
pub struct Ack {
    hash: [u8; 32],
    id: [u8; 32],
    pull_token: [u8; 32],
    onion: String,
}

impl Drop for Ack {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.id.zeroize();
        self.pull_token.zeroize();
        self.onion.zeroize();
    }
}

/// One fetched relay frame, or an empty mailbox.
pub enum Fetched {
    Empty,
    Frame { frame: Vec<u8>, ack: Ack },
}

/// What a deposit attempt did.
///
/// `Deposited` is the first relay that accepted the slot. Later relays are
/// not contacted. `Unreachable` means every tried relay failed before a
/// reply, or was already known down. `Refused` means at least one relay
/// answered and none accepted. `Skipped` means there was no card to try.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositHop {
    Skipped,
    Deposited,
    Unreachable,
    Refused,
}

/// Where to deposit frames for one contact, on one relay.
#[derive(Clone, Zeroize)]
pub struct Target {
    contact_id: String,
    onion: String,
    id: [u8; 32],
    push_token: [u8; 32],
}

impl Drop for Target {
    fn drop(&mut self) {
        self.contact_id.zeroize();
        self.onion.zeroize();
        self.id.zeroize();
        self.push_token.zeroize();
    }
}

impl Target {
    pub fn contact_id(&self) -> &str {
        &self.contact_id
    }

    pub fn onion(&self) -> &str {
        &self.onion
    }

    /// Put one frame. The relay sees the fixed slot, not the plaintext.
    pub fn deposit(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        frame: &[u8],
        isolation: Option<&SocksIsolationCreds>,
    ) -> Result<(), &'static str> {
        let mut slot = pack_slot(frame)?;
        let mut req = request(OP_PUT, &self.id, &self.push_token, &slot);
        let reply = exchange_onion(proxy_host, proxy_port, &self.onion, &req, isolation);
        slot.zeroize();
        req.zeroize();
        let reply = reply?;
        match reply.status {
            ST_OK => Ok(()),
            ST_FULL => Err("relay full"),
            _ => Err("relay refused"),
        }
    }

    /// Loopback deposit for tests. Refuses any address that is not loopback.
    #[cfg(test)]
    fn deposit_addr(&self, addr: SocketAddr, frame: &[u8]) -> Result<(), &'static str> {
        let mut slot = pack_slot(frame)?;
        let mut req = request(OP_PUT, &self.id, &self.push_token, &slot);
        let reply = exchange_public(addr, &req);
        slot.zeroize();
        req.zeroize();
        let reply = reply?;
        match reply.status {
            ST_OK => Ok(()),
            ST_FULL => Err("relay full"),
            _ => Err("relay refused"),
        }
    }
}

/// Try `targets` in order. `down` holds relay onions that already failed to
/// connect during this batch; those are skipped and not contacted again.
///
/// The onion strings in `down` are copies. The caller zeroizes that list
/// when the batch ends. This function does not log them.
pub fn failover_deposit<F>(targets: &[Target], down: &mut Vec<String>, mut try_one: F) -> DepositHop
where
    F: FnMut(&Target) -> Result<(), &'static str>,
{
    if targets.is_empty() {
        return DepositHop::Skipped;
    }
    let mut refused = false;
    for target in targets {
        if down.iter().any(|onion| onion == target.onion()) {
            continue;
        }
        match try_one(target) {
            Ok(()) => return DepositHop::Deposited,
            Err("relay unreachable") => {
                let onion = target.onion().to_string();
                if !down.iter().any(|known| known == &onion) {
                    down.push(onion);
                }
            }
            Err(_) => refused = true,
        }
    }
    if refused {
        DepositHop::Refused
    } else {
        DepositHop::Unreachable
    }
}

/// Deposit targets kept inside the encrypted profile.
#[derive(Clone, Default)]
pub struct TargetBook {
    targets: Vec<Target>,
}

impl TargetBook {
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// First card for this contact. Failover uses [`TargetBook::cards_for_ids`].
    pub fn get(&self, contact_id: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.contact_id == contact_id)
    }

    /// Cards whose contact id is in `ids`, in failover order (first stored, first tried).
    ///
    /// The queued frame is addressed to the contact's own onion. These cards
    /// carry the relay onion, which is a different host. Matching the two
    /// onions would skip every real relay.
    pub fn cards_for_ids(&self, ids: &[&str]) -> Vec<Target> {
        self.targets
            .iter()
            .filter(|target| ids.iter().any(|id| *id == target.contact_id))
            .cloned()
            .collect()
    }

    pub fn insert(
        &mut self,
        contact_id: &str,
        onion: &str,
        card_hex: &str,
    ) -> Result<(), &'static str> {
        let contact_id = check_contact_id(contact_id)?.to_string();
        let onion = check_onion(onion)?;
        let mut pair = decode_hex_exact::<64>(card_hex)?;
        let mut id = [0u8; 32];
        let mut push = [0u8; 32];
        id.copy_from_slice(&pair[..32]);
        push.copy_from_slice(&pair[32..]);
        pair.zeroize();
        if let Some(pos) = self
            .targets
            .iter()
            .position(|t| t.contact_id == contact_id && t.onion == onion)
        {
            self.targets[pos] = Target {
                contact_id,
                onion,
                id,
                push_token: push,
            };
            return Ok(());
        }
        let for_contact = self
            .targets
            .iter()
            .filter(|t| t.contact_id == contact_id)
            .count();
        if for_contact >= MAX_RELAYS_PER_CONTACT || self.targets.len() >= MAX_RELAY_TARGETS {
            id.zeroize();
            push.zeroize();
            return Err(if for_contact >= MAX_RELAYS_PER_CONTACT {
                "too many relays"
            } else {
                "relay targets full"
            });
        }
        self.targets.push(Target {
            contact_id,
            onion,
            id,
            push_token: push,
        });
        Ok(())
    }

    /// Drop every card for this contact.
    pub fn remove(&mut self, contact_id: &str) -> bool {
        let before = self.targets.len();
        self.targets.retain(|t| t.contact_id != contact_id);
        self.targets.len() != before
    }

    /// Drop one card. The onion is the relay, not the contact.
    pub fn remove_onion(&mut self, contact_id: &str, onion: &str) -> Result<bool, &'static str> {
        let contact_id = check_contact_id(contact_id)?;
        let onion = check_onion(onion)?;
        let Some(pos) = self
            .targets
            .iter()
            .position(|t| t.contact_id == contact_id && t.onion == onion)
        else {
            return Ok(false);
        };
        self.targets.remove(pos);
        Ok(true)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.targets.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        out.push(VERSION);
        out.extend_from_slice(&(u16::try_from(self.targets.len()).unwrap_or(0)).to_be_bytes());
        for t in &self.targets {
            push_str(&mut out, &t.contact_id);
            push_str(&mut out, &t.onion);
            out.extend_from_slice(&t.id);
            out.extend_from_slice(&t.push_token);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Ok(Self {
                targets: Vec::new(),
            });
        }
        if bytes.len() < 3 || bytes[0] != VERSION {
            return Err("bad relay targets");
        }
        let n = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if n > MAX_RELAY_TARGETS {
            return Err("bad relay targets");
        }
        let mut pos = 3;
        let mut targets: Vec<Target> = Vec::with_capacity(n);
        for _ in 0..n {
            let contact_id = take_str(bytes, &mut pos)?;
            let contact_id = check_contact_id(contact_id)?.to_string();
            let onion = check_onion(take_str(bytes, &mut pos)?)?;
            if pos + 64 > bytes.len() {
                return Err("bad relay targets");
            }
            let mut id = [0u8; 32];
            let mut push = [0u8; 32];
            id.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            push.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            if targets
                .iter()
                .any(|t| t.contact_id == contact_id && t.onion == onion)
            {
                return Err("bad relay targets");
            }
            if targets
                .iter()
                .filter(|t| t.contact_id == contact_id)
                .count()
                >= MAX_RELAYS_PER_CONTACT
            {
                return Err("bad relay targets");
            }
            targets.push(Target {
                contact_id,
                onion,
                id,
                push_token: push,
            });
        }
        if pos != bytes.len() {
            return Err("bad relay targets");
        }
        Ok(Self { targets })
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.push(u8::try_from(b.len()).unwrap_or(255));
    out.extend_from_slice(b);
}

fn take_str<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a str, &'static str> {
    if *pos >= bytes.len() {
        return Err("bad relay targets");
    }
    let n = bytes[*pos] as usize;
    *pos += 1;
    let end = pos.checked_add(n).ok_or("bad relay targets")?;
    if end > bytes.len() {
        return Err("bad relay targets");
    }
    let s = std::str::from_utf8(&bytes[*pos..end]).map_err(|_| "bad relay targets")?;
    *pos = end;
    Ok(s)
}

/// Inboxes this profile fetches, in the order they were added.
#[derive(Clone, Default)]
pub struct InboxBook {
    inboxes: Vec<Inbox>,
}

impl InboxBook {
    pub fn len(&self) -> usize {
        self.inboxes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inboxes.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Inbox> {
        self.inboxes.iter()
    }

    /// Add an inbox, or replace the pull token when that relay onion is already stored.
    pub fn insert(&mut self, onion: &str, inbox_hex: &str) -> Result<(), &'static str> {
        let inbox = Inbox::parse(onion, inbox_hex)?;
        if let Some(pos) = self.inboxes.iter().position(|i| i.onion() == inbox.onion()) {
            self.inboxes[pos] = inbox;
            return Ok(());
        }
        if self.inboxes.len() >= MAX_RELAY_INBOXES {
            return Err("too many relays");
        }
        self.inboxes.push(inbox);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.inboxes.clear();
    }

    pub fn remove_onion(&mut self, onion: &str) -> Result<bool, &'static str> {
        let onion = check_onion(onion)?;
        let Some(pos) = self.inboxes.iter().position(|i| i.onion() == onion) else {
            return Ok(false);
        };
        self.inboxes.remove(pos);
        Ok(true)
    }

    /// Empty input is an empty book. Version 1 is one inbox from an older profile.
    /// Version 2 is this book.
    pub fn from_stored(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Ok(Self {
                inboxes: Vec::new(),
            });
        }
        if bytes.len() > MAX_INBOX_STORED {
            return Err("bad relay inbox");
        }
        match bytes[0] {
            VERSION => {
                let inbox = Inbox::from_bytes(bytes)?;
                Ok(Self {
                    inboxes: vec![inbox],
                })
            }
            INBOX_BOOK_VERSION => parse_inbox_book(bytes),
            _ => Err("bad relay inbox"),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.inboxes.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let count = u8::try_from(self.inboxes.len()).unwrap_or(0);
        out.push(INBOX_BOOK_VERSION);
        out.push(count);
        for inbox in &self.inboxes {
            let body = inbox.to_bytes();
            let n = u16::try_from(body.len()).unwrap_or(0);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&body);
        }
        out
    }
}

fn parse_inbox_book(bytes: &[u8]) -> Result<InboxBook, &'static str> {
    if bytes.len() < 2 || bytes[0] != INBOX_BOOK_VERSION {
        return Err("bad relay inbox");
    }
    let n = bytes[1] as usize;
    if n == 0 || n > MAX_RELAY_INBOXES {
        return Err("bad relay inbox");
    }
    let mut pos = 2usize;
    let mut inboxes = Vec::with_capacity(n);
    for _ in 0..n {
        if pos + 2 > bytes.len() {
            return Err("bad relay inbox");
        }
        let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if len == 0 {
            return Err("bad relay inbox");
        }
        let end = pos.checked_add(len).ok_or("bad relay inbox")?;
        if end > bytes.len() {
            return Err("bad relay inbox");
        }
        let inbox = Inbox::from_bytes(&bytes[pos..end])?;
        pos = end;
        if inboxes
            .iter()
            .any(|have: &Inbox| have.onion() == inbox.onion())
        {
            return Err("bad relay inbox");
        }
        inboxes.push(inbox);
    }
    if pos != bytes.len() {
        return Err("bad relay inbox");
    }
    Ok(InboxBook { inboxes })
}

struct Reply {
    status: u8,
    slot: Vec<u8>,
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.slot.zeroize();
    }
}

fn request(op: u8, id: &[u8; 32], token: &[u8; 32], slot: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; REQ_BODY];
    body[..4].copy_from_slice(MAGIC);
    body[4] = VERSION;
    body[5] = op;
    body[6..38].copy_from_slice(id);
    body[38..70].copy_from_slice(token);
    let n = slot.len().min(RELAY_SLOT_BYTES);
    body[70..70 + n].copy_from_slice(&slot[..n]);
    body
}

fn encode_response(status: u8, slot: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; RESP_BODY];
    body[..4].copy_from_slice(MAGIC);
    body[4] = VERSION;
    body[5] = status;
    let n = slot.len().min(RELAY_SLOT_BYTES);
    body[6..6 + n].copy_from_slice(&slot[..n]);
    body
}

fn parse_response(body: &[u8]) -> Result<Reply, &'static str> {
    if body.len() != RESP_BODY || &body[..4] != MAGIC || body[4] != VERSION {
        return Err("relay refused");
    }
    let status = body[5];
    if !matches!(status, ST_OK | ST_REFUSED | ST_FULL | ST_EMPTY) {
        return Err("relay refused");
    }
    Ok(Reply {
        status,
        slot: body[6..].to_vec(),
    })
}

fn write_body(stream: &mut TcpStream, body: &[u8]) -> Result<(), ()> {
    if body.len() > u16::MAX as usize {
        return Err(());
    }
    let len = (body.len() as u16).to_be_bytes();
    stream.write_all(&len).map_err(|_| ())?;
    stream.write_all(body).map_err(|_| ())?;
    stream.flush().map_err(|_| ())
}

fn read_exact_body(stream: &mut TcpStream, exact: usize) -> Result<Vec<u8>, ()> {
    let mut ln = [0u8; 2];
    stream.read_exact(&mut ln).map_err(|_| ())?;
    let n = u16::from_be_bytes(ln) as usize;
    if n != exact {
        return Err(());
    }
    let mut buf = vec![0u8; n];
    if stream.read_exact(&mut buf).is_err() {
        buf.zeroize();
        return Err(());
    }
    Ok(buf)
}

fn exchange_stream(stream: &mut TcpStream, req: &[u8]) -> Result<Reply, &'static str> {
    let _ = stream.set_read_timeout(Some(CONN_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONN_TIMEOUT));
    write_body(stream, req).map_err(|_| "relay refused")?;
    let mut body = read_exact_body(stream, RESP_BODY).map_err(|_| "relay refused")?;
    let reply = parse_response(&body);
    body.zeroize();
    reply
}

fn exchange_onion(
    proxy_host: &str,
    proxy_port: u16,
    onion: &str,
    req: &[u8],
    isolation: Option<&SocksIsolationCreds>,
) -> Result<Reply, &'static str> {
    let onion = check_onion(onion)?;
    let mut stream = socks5_connect(proxy_host, proxy_port, &onion, 80, isolation)
        .map_err(|_| "relay unreachable")?;
    exchange_stream(&mut stream, req)
}

#[cfg(test)]
fn exchange_public(addr: SocketAddr, req: &[u8]) -> Result<Reply, &'static str> {
    if !addr.ip().is_loopback() {
        return Err("relay address refused");
    }
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|_| "relay unreachable")?;
    exchange_stream(&mut stream, req)
}

fn ack_at(
    proxy_host: &str,
    proxy_port: u16,
    onion: &str,
    id: &[u8; 32],
    pull: &[u8; 32],
    hash: &[u8; 32],
    isolation: Option<&SocksIsolationCreds>,
) -> Result<(), &'static str> {
    let mut slot = vec![0u8; RELAY_SLOT_BYTES];
    slot[..32].copy_from_slice(hash);
    let mut req = request(OP_ACK, id, pull, &slot);
    slot.zeroize();
    let reply = exchange_onion(proxy_host, proxy_port, onion, &req, isolation);
    req.zeroize();
    let reply = reply?;
    if reply.status == ST_OK {
        Ok(())
    } else {
        Err("relay refused")
    }
}

struct Mailbox {
    id: [u8; 32],
    pull_hash: [u8; 32],
    push_hash: [u8; 32],
    frames: VecDeque<(u64, Vec<u8>)>,
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        self.id.zeroize();
        self.pull_hash.zeroize();
        self.push_hash.zeroize();
        for (_, slot) in self.frames.iter_mut() {
            slot.zeroize();
        }
    }
}

struct Store {
    mailboxes: Vec<Mailbox>,
    ttl_secs: u64,
    max_mailboxes: usize,
    max_frames: usize,
    dir: Option<PathBuf>,
}

impl Store {
    fn open(
        dir: Option<PathBuf>,
        ttl_secs: u64,
        max_mailboxes: usize,
        max_frames: usize,
    ) -> Result<Self, &'static str> {
        let ttl_secs = ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let mut store = Self {
            mailboxes: Vec::new(),
            ttl_secs,
            max_mailboxes,
            max_frames,
            dir,
        };
        if let Some(dir) = store.dir.clone() {
            prepare_dir(&dir)?;
            store.load(&dir)?;
        }
        Ok(store)
    }

    fn load(&mut self, dir: &Path) -> Result<(), &'static str> {
        let entries = fs::read_dir(dir).map_err(|_| "relay directory refused")?;
        for entry in entries {
            let entry = entry.map_err(|_| "relay directory refused")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "relay directory refused")?;
            if name == crate::hidden_service::ONION_KEY_FILE || name.contains(".tmp-") {
                continue;
            }
            let Some(hex_id) = name.strip_prefix("m-") else {
                return Err("relay directory refused");
            };
            if hex_id.len() != 64
                || !hex_id
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err("relay directory refused");
            }
            let id = decode_hex_exact::<32>(hex_id).map_err(|_| "relay directory refused")?;
            let mut bytes = crate::private_fs::read_private_file(
                dir,
                &name,
                (FILE_HEADER + self.max_frames * (8 + RELAY_SLOT_BYTES)) as u64,
            )
            .map_err(|_| "relay mailbox file refused")?;
            let parsed = parse_mailbox_file(&id, &bytes, self.max_frames);
            bytes.zeroize();
            self.mailboxes.push(parsed?);
        }
        if self.mailboxes.len() > self.max_mailboxes {
            return Err("relay directory refused");
        }
        Ok(())
    }

    fn create(&mut self) -> Result<MailboxSecrets, &'static str> {
        if self.mailboxes.len() >= self.max_mailboxes {
            return Err("relay full");
        }
        let mut id = [0u8; 32];
        let mut pull = [0u8; 32];
        let mut push = [0u8; 32];
        if getrandom::getrandom(&mut id).is_err()
            || getrandom::getrandom(&mut pull).is_err()
            || getrandom::getrandom(&mut push).is_err()
        {
            id.zeroize();
            pull.zeroize();
            push.zeroize();
            return Err("relay refused");
        }
        let mailbox = Mailbox {
            id,
            pull_hash: token_hash(LABEL_PULL, &pull),
            push_hash: token_hash(LABEL_PUSH, &push),
            frames: VecDeque::new(),
        };
        self.mailboxes.push(mailbox);
        if let Err(e) = self.persist(&id) {
            self.remove_memory(&id);
            id.zeroize();
            pull.zeroize();
            push.zeroize();
            return Err(e);
        }
        Ok(MailboxSecrets {
            id,
            pull_token: pull,
            push_token: push,
        })
    }

    fn delete(&mut self, id: &[u8; 32]) -> Result<(), &'static str> {
        let Some(pos) = self.index_of(id) else {
            return Err("relay refused");
        };
        self.mailboxes.remove(pos);
        self.remove_file(id);
        Ok(())
    }

    fn wipe(&mut self) {
        let ids: Vec<[u8; 32]> = self.mailboxes.iter().map(|m| m.id).collect();
        self.mailboxes.clear();
        for id in ids {
            self.remove_file(&id);
        }
    }

    fn put(&mut self, id: &[u8; 32], token: &[u8; 32], slot: &[u8], now: u64) -> u8 {
        if unpack_slot(slot).is_err() {
            return ST_REFUSED;
        }
        let Some(pos) = self.gate(id, LABEL_PUSH, token, |m| &m.push_hash) else {
            return ST_REFUSED;
        };
        self.gc(pos, now);
        if self.mailboxes[pos].frames.len() >= self.max_frames {
            return ST_FULL;
        }
        let exp = now.saturating_add(self.ttl_secs);
        self.mailboxes[pos].frames.push_back((exp, slot.to_vec()));
        if self.persist(id).is_err() {
            if let Some((_, mut rolled)) = self.mailboxes[pos].frames.pop_back() {
                rolled.zeroize();
            }
            return ST_REFUSED;
        }
        ST_OK
    }

    fn get(&mut self, id: &[u8; 32], token: &[u8; 32], now: u64) -> (u8, Vec<u8>) {
        let Some(pos) = self.gate(id, LABEL_PULL, token, |m| &m.pull_hash) else {
            return (ST_REFUSED, vec![0u8; RELAY_SLOT_BYTES]);
        };
        self.gc(pos, now);
        let _ = self.persist(id);
        match self.mailboxes[pos].frames.front() {
            Some((_, slot)) => (ST_OK, slot.clone()),
            None => (ST_EMPTY, vec![0u8; RELAY_SLOT_BYTES]),
        }
    }

    fn ack(&mut self, id: &[u8; 32], token: &[u8; 32], hash: &[u8; 32], now: u64) -> u8 {
        let Some(pos) = self.gate(id, LABEL_PULL, token, |m| &m.pull_hash) else {
            return ST_REFUSED;
        };
        self.gc(pos, now);
        let matches = self.mailboxes[pos].frames.front().is_some_and(|(_, slot)| {
            let got = slot_hash(slot);
            let eq: bool = got.ct_eq(hash).into();
            eq
        });
        if !matches {
            return ST_REFUSED;
        }
        if let Some((exp, mut slot)) = self.mailboxes[pos].frames.pop_front() {
            if self.persist(id).is_err() {
                self.mailboxes[pos].frames.push_front((exp, slot));
                return ST_REFUSED;
            }
            slot.zeroize();
        }
        ST_OK
    }

    fn gate(
        &self,
        id: &[u8; 32],
        label: &[u8],
        token: &[u8; 32],
        which: impl Fn(&Mailbox) -> &[u8; 32],
    ) -> Option<usize> {
        let hash = token_hash(label, token);
        let dummy = token_hash(label, &DUMMY_TOKEN);
        let pos = self.index_of(id);
        let against = match pos {
            Some(i) => *which(&self.mailboxes[i]),
            None => dummy,
        };
        let eq: bool = hash.ct_eq(&against).into();
        if pos.is_some() && eq {
            pos
        } else {
            None
        }
    }

    fn index_of(&self, id: &[u8; 32]) -> Option<usize> {
        let mut found = None;
        for (i, m) in self.mailboxes.iter().enumerate() {
            let eq: bool = m.id.ct_eq(id).into();
            if eq {
                found = Some(i);
            }
        }
        found
    }

    fn gc(&mut self, pos: usize, now: u64) {
        let frames = &mut self.mailboxes[pos].frames;
        while frames.front().is_some_and(|(exp, _)| *exp <= now) {
            if let Some((_, mut slot)) = frames.pop_front() {
                slot.zeroize();
            }
        }
    }

    fn persist(&self, id: &[u8; 32]) -> Result<(), &'static str> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let Some(pos) = self.index_of(id) else {
            return Ok(());
        };
        let name = mailbox_file_name(id);
        let bytes = encode_mailbox(&self.mailboxes[pos]);
        crate::private_fs::write_private_file(dir, &name, &bytes).map_err(|_| "relay not saved")
    }

    fn remove_memory(&mut self, id: &[u8; 32]) {
        if let Some(pos) = self.index_of(id) {
            self.mailboxes.remove(pos);
        }
    }

    fn remove_file(&self, id: &[u8; 32]) {
        let Some(dir) = &self.dir else {
            return;
        };
        crate::shred::shred_file(&dir.join(mailbox_file_name(id)));
    }

    fn counts(&self) -> (u32, u32) {
        let frames = self
            .mailboxes
            .iter()
            .map(|m| m.frames.len())
            .fold(0usize, usize::saturating_add);
        (
            u32::try_from(self.mailboxes.len()).unwrap_or(u32::MAX),
            u32::try_from(frames).unwrap_or(u32::MAX),
        )
    }
}

fn mailbox_file_name(id: &[u8; 32]) -> String {
    format!("m-{}", encode_hex(id))
}

fn encode_mailbox(m: &Mailbox) -> Vec<u8> {
    let mut out = Vec::with_capacity(FILE_HEADER + m.frames.len() * (8 + RELAY_SLOT_BYTES));
    out.extend_from_slice(FILE_MAGIC);
    out.push(FILE_VER);
    out.extend_from_slice(&m.pull_hash);
    out.extend_from_slice(&m.push_hash);
    let n = u16::try_from(m.frames.len()).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    for (exp, slot) in &m.frames {
        out.extend_from_slice(&exp.to_be_bytes());
        out.extend_from_slice(slot);
    }
    out
}

fn parse_mailbox_file(
    id: &[u8; 32],
    bytes: &[u8],
    max_frames: usize,
) -> Result<Mailbox, &'static str> {
    if bytes.len() < FILE_HEADER || &bytes[..4] != FILE_MAGIC || bytes[4] != FILE_VER {
        return Err("relay mailbox file refused");
    }
    let mut pull_hash = [0u8; 32];
    let mut push_hash = [0u8; 32];
    pull_hash.copy_from_slice(&bytes[5..37]);
    push_hash.copy_from_slice(&bytes[37..69]);
    let n = u16::from_be_bytes([bytes[69], bytes[70]]) as usize;
    if n > max_frames {
        return Err("relay mailbox file refused");
    }
    let mut pos = FILE_HEADER;
    let mut frames = VecDeque::with_capacity(n);
    for _ in 0..n {
        if pos + 8 + RELAY_SLOT_BYTES > bytes.len() {
            return Err("relay mailbox file refused");
        }
        let mut exp_b = [0u8; 8];
        exp_b.copy_from_slice(&bytes[pos..pos + 8]);
        let exp = u64::from_be_bytes(exp_b);
        pos += 8;
        let slot = bytes[pos..pos + RELAY_SLOT_BYTES].to_vec();
        pos += RELAY_SLOT_BYTES;
        if unpack_slot(&slot).is_err() {
            return Err("relay mailbox file refused");
        }
        frames.push_back((exp, slot));
    }
    if pos != bytes.len() {
        return Err("relay mailbox file refused");
    }
    Ok(Mailbox {
        id: *id,
        pull_hash,
        push_hash,
        frames,
    })
}

fn prepare_dir(dir: &Path) -> Result<(), &'static str> {
    if dir.as_os_str().is_empty() {
        return Err("relay directory refused");
    }
    fs::create_dir_all(dir).map_err(|_| "relay directory refused")?;
    // Tightens ownership and mode, and refuses a final-component symlink.
    crate::private_fs::check_private_file(dir, crate::hidden_service::ONION_KEY_FILE)
        .map_err(|_| "relay directory refused")
}

/// Counts only. No mailbox ids and no ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayStatus {
    pub mailboxes: u32,
    pub frames: u32,
}

/// Public listener plus the operator actions on the store.
pub struct RelayServer {
    public_addr: SocketAddr,
    store: Arc<Mutex<Store>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RelayServer {
    pub fn start(dir: Option<PathBuf>, ttl_secs: u64) -> Result<Self, &'static str> {
        Self::start_limited(dir, ttl_secs, MAX_MAILBOXES, MAX_FRAMES_PER_MAILBOX)
    }

    fn start_limited(
        dir: Option<PathBuf>,
        ttl_secs: u64,
        max_mailboxes: usize,
        max_frames: usize,
    ) -> Result<Self, &'static str> {
        let store = Store::open(dir, ttl_secs, max_mailboxes, max_frames)?;
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|_| "relay bind failed")?;
        let public_addr = listener.local_addr().map_err(|_| "relay bind failed")?;
        if !public_addr.ip().is_loopback() {
            return Err("relay bind failed");
        }
        let store = Arc::new(Mutex::new(store));
        let stop = Arc::new(AtomicBool::new(false));
        let store_t = Arc::clone(&store);
        let stop_t = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("hashchat-relay".into())
            .spawn(move || accept_loop(listener, store_t, stop_t))
            .map_err(|_| "relay bind failed")?;
        Ok(Self {
            public_addr,
            store,
            stop,
            thread: Some(thread),
        })
    }

    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    pub fn create_mailbox(&self) -> Result<MailboxSecrets, &'static str> {
        self.with_store(|s| s.create())
    }

    pub fn delete_mailbox(&self, id: &[u8; 32]) -> Result<(), &'static str> {
        self.with_store(|s| s.delete(id))
    }

    pub fn wipe(&self) -> Result<(), &'static str> {
        self.with_store(|s| {
            s.wipe();
            Ok(())
        })
    }

    pub fn status(&self) -> Result<RelayStatus, &'static str> {
        let (mailboxes, frames) = self.with_store(|s| Ok(s.counts()))?;
        Ok(RelayStatus { mailboxes, frames })
    }

    fn with_store<T>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let mut guard = self.store.lock().map_err(|_| "relay refused")?;
        f(&mut guard)
    }

    pub fn shutdown(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = TcpStream::connect_timeout(&self.public_addr, Duration::from_millis(500));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(listener: TcpListener, store: Arc<Mutex<Store>>, stop: Arc<AtomicBool>) {
    let live = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = incoming else {
            continue;
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let Some(slot) = reserve_conn(&live, MAX_CONNS) else {
            continue;
        };
        let store = Arc::clone(&store);
        let _ = thread::Builder::new()
            .name("hashchat-relay-conn".into())
            .spawn(move || {
                let _slot = slot;
                handle_conn(stream, &store);
            });
    }
}

struct ConnSlot(Arc<AtomicUsize>);

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_conn(live: &Arc<AtomicUsize>, max: usize) -> Option<ConnSlot> {
    let mut cur = live.load(Ordering::Acquire);
    loop {
        if cur >= max {
            return None;
        }
        match live.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(ConnSlot(Arc::clone(live))),
            Err(now) => cur = now,
        }
    }
}

fn handle_conn(mut stream: TcpStream, store: &Mutex<Store>) {
    let _ = stream.set_read_timeout(Some(CONN_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONN_TIMEOUT));
    let Ok(mut body) = read_exact_body(&mut stream, REQ_BODY) else {
        return;
    };
    let mut response = dispatch(&body, store);
    body.zeroize();
    let _ = write_body(&mut stream, &response);
    response.zeroize();
}

fn dispatch(body: &[u8], store: &Mutex<Store>) -> Vec<u8> {
    if body.len() != REQ_BODY || &body[..4] != MAGIC || body[4] != VERSION {
        return encode_response(ST_REFUSED, &[]);
    }
    let op = body[5];
    let mut id = [0u8; 32];
    let mut token = [0u8; 32];
    id.copy_from_slice(&body[6..38]);
    token.copy_from_slice(&body[38..70]);
    let slot = &body[70..];
    let now = crate::deadman::unix_now();
    let Ok(mut guard) = store.lock() else {
        id.zeroize();
        token.zeroize();
        return encode_response(ST_REFUSED, &[]);
    };
    let (status, out_slot) = match op {
        OP_PUT => {
            let status = guard.put(&id, &token, slot, now);
            (status, vec![0u8; RELAY_SLOT_BYTES])
        }
        OP_GET => {
            if slot.iter().any(|&b| b != 0) {
                (ST_REFUSED, vec![0u8; RELAY_SLOT_BYTES])
            } else {
                guard.get(&id, &token, now)
            }
        }
        OP_ACK => {
            if slot[32..].iter().any(|&b| b != 0) {
                (ST_REFUSED, vec![0u8; RELAY_SLOT_BYTES])
            } else {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&slot[..32]);
                let status = guard.ack(&id, &token, &hash, now);
                hash.zeroize();
                (status, vec![0u8; RELAY_SLOT_BYTES])
            }
        }
        _ => (ST_REFUSED, vec![0u8; RELAY_SLOT_BYTES]),
    };
    id.zeroize();
    token.zeroize();
    let encoded = encode_response(status, &out_slot);
    // out_slot may hold ciphertext on GET; drop zeroizes only if we clear it.
    let mut out_slot = out_slot;
    out_slot.zeroize();
    encoded
}

/// What the operator typed on the relay's stdin.
pub enum OperatorCommand {
    Create,
    Delete([u8; 32]),
    Status,
    Wipe,
    Help,
    Quit,
}

pub fn parse_operator_line(line: &str) -> Result<OperatorCommand, &'static str> {
    if line.len() > MAX_OPERATOR_LINE {
        return Err("line refused");
    }
    let line = line.trim();
    if !line.is_ascii() || line.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("line refused");
    }
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else {
        return Err("line refused");
    };
    let cmd = cmd.to_ascii_lowercase();
    match cmd.as_str() {
        "create" => {
            if parts.next().is_some() {
                return Err("line refused");
            }
            Ok(OperatorCommand::Create)
        }
        "status" => {
            if parts.next().is_some() {
                return Err("line refused");
            }
            Ok(OperatorCommand::Status)
        }
        "help" => {
            if parts.next().is_some() {
                return Err("line refused");
            }
            Ok(OperatorCommand::Help)
        }
        "quit" => {
            if parts.next().is_some() {
                return Err("line refused");
            }
            Ok(OperatorCommand::Quit)
        }
        "delete" => {
            let Some(hex_id) = parts.next() else {
                return Err("line refused");
            };
            if parts.next().is_some() {
                return Err("line refused");
            }
            let id = decode_hex_exact::<32>(hex_id)?;
            Ok(OperatorCommand::Delete(id))
        }
        "wipe" => {
            let Some(word) = parts.next() else {
                return Err("line refused");
            };
            if parts.next().is_some() || !word.eq_ignore_ascii_case("confirm") {
                return Err("line refused");
            }
            Ok(OperatorCommand::Wipe)
        }
        _ => Err("line refused"),
    }
}

/// One stdin read. Overlong lines are refused and consumed up to a cap;
/// past that cap the caller should stop, so the tail cannot become a command.
pub enum LineRead {
    Eof,
    Line(String),
    Refused,
    Stopped,
}

pub fn next_operator_line(reader: &mut impl BufRead) -> LineRead {
    let mut buf = Vec::new();
    let mut overlong = false;
    let mut extra = 0usize;
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => {
                if buf.is_empty() && !overlong {
                    return LineRead::Eof;
                }
                break;
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if buf.len() >= MAX_OPERATOR_LINE {
                    overlong = true;
                    extra = extra.saturating_add(1);
                    if extra > 65_536 {
                        buf.zeroize();
                        return LineRead::Stopped;
                    }
                } else {
                    buf.push(byte[0]);
                }
            }
            Err(_) => {
                buf.zeroize();
                return LineRead::Stopped;
            }
        }
    }
    if overlong {
        buf.zeroize();
        return LineRead::Refused;
    }
    while buf.last().is_some_and(|b| *b == b'\r') {
        buf.pop();
    }
    match String::from_utf8(buf) {
        Ok(s) => LineRead::Line(s),
        Err(e) => {
            let mut bad = e.into_bytes();
            bad.zeroize();
            LineRead::Refused
        }
    }
}

/// Command-line arguments after the program name.
pub enum CliRequest {
    Help,
    Run(RelayCli),
}

pub struct RelayCli {
    pub memory_only: bool,
    pub loopback_only: bool,
    pub ttl_secs: u64,
    pub dir: Option<PathBuf>,
}

pub const RELAY_HELP: &str = "\
hashchat-relay — store-and-forward ciphertext for offline peers

Binds 127.0.0.1 only. With Tor's ControlPort up, publishes that listener
as a v3 onion. Without --loopback-only, startup fails if Tor refuses.

  hashchat-relay [--dir PATH] [--memory] [--loopback-only] [--ttl-hours N]

stdin, one command a line:
  create            print an inbox line and a card line (secrets; once)
  delete HEXID      remove one mailbox
  status            mailbox and frame counts
  wipe confirm      destroy queued ciphertext (onion key stays)
  help
  quit

The inbox line stays with you. The card line is what a contact is given,
together with the onion, which you check out of band. The card does not
bind the onion. A contact may hold cards for several relays; this process
is one relay. There is no account and no request log. The process sees
ciphertext. --memory keeps the queue and the onion only until exit.
";

pub fn parse_cli<S: AsRef<str>>(args: &[S]) -> Result<CliRequest, &'static str> {
    if args.len() == 1 && matches!(args[0].as_ref(), "--help" | "-h" | "help") {
        return Ok(CliRequest::Help);
    }
    let mut memory_only = false;
    let mut loopback_only = false;
    let mut ttl_hours: u64 = 72;
    let mut dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_ref();
        if !arg.is_ascii() || arg.contains('\0') {
            return Err("relay option refused");
        }
        match arg {
            "--memory" => memory_only = true,
            "--loopback-only" => loopback_only = true,
            "--dir" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    return Err("relay option refused");
                };
                let path = path.as_ref();
                if path.is_empty() || path.contains('\0') || path.len() > 4096 {
                    return Err("relay option refused");
                }
                dir = Some(PathBuf::from(path));
            }
            "--ttl-hours" => {
                i += 1;
                let Some(n) = args.get(i) else {
                    return Err("relay option refused");
                };
                let n = n.as_ref();
                if n.len() > 4 || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("relay ttl refused");
                }
                let hours: u64 = n.parse().map_err(|_| "relay ttl refused")?;
                let secs = hours.saturating_mul(3600);
                if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&secs) {
                    return Err("relay ttl refused");
                }
                ttl_hours = hours;
            }
            _ => return Err("relay option refused"),
        }
        i += 1;
    }
    if memory_only && dir.is_some() {
        return Err("relay option refused");
    }
    let dir = if memory_only {
        None
    } else {
        Some(dir.unwrap_or_else(|| PathBuf::from("hashchat_relay")))
    };
    Ok(CliRequest::Run(RelayCli {
        memory_only,
        loopback_only,
        ttl_secs: ttl_hours.saturating_mul(3600),
        dir,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_binding::test_support::onion_and_key;
    use std::io::Cursor;

    fn onion(seed: u8) -> String {
        let (bare, _) = onion_and_key(seed);
        format!("{bare}.onion")
    }

    fn small_server(dir: Option<PathBuf>) -> RelayServer {
        RelayServer::start_limited(dir, MIN_TTL_SECS, 4, 2).unwrap()
    }

    fn put_get_ack(addr: SocketAddr, secrets: &MailboxSecrets, frame: &[u8]) {
        let slot = pack_slot(frame).unwrap();
        let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
        let reply = exchange_public(addr, &put).unwrap();
        assert_eq!(reply.status, ST_OK);
        let get = request(
            OP_GET,
            &secrets.id,
            &secrets.pull_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        let reply = exchange_public(addr, &get).unwrap();
        assert_eq!(reply.status, ST_OK);
        assert_eq!(unpack_slot(&reply.slot).unwrap(), frame);
        let hash = slot_hash(&reply.slot);
        let mut ack_slot = vec![0u8; RELAY_SLOT_BYTES];
        ack_slot[..32].copy_from_slice(&hash);
        let ack = request(OP_ACK, &secrets.id, &secrets.pull_token, &ack_slot);
        let reply = exchange_public(addr, &ack).unwrap();
        assert_eq!(reply.status, ST_OK);
        let reply = exchange_public(addr, &get).unwrap();
        assert_eq!(reply.status, ST_EMPTY);
    }

    #[test]
    fn put_get_ack_roundtrip_and_push_cannot_fetch() {
        let server = small_server(None);
        let secrets = server.create_mailbox().unwrap();
        put_get_ack(server.public_addr(), &secrets, b"sealed-frame");
        let slot = pack_slot(b"nope").unwrap();
        let get = request(
            OP_GET,
            &secrets.id,
            &secrets.push_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        assert_eq!(
            exchange_public(server.public_addr(), &get).unwrap().status,
            ST_REFUSED
        );
        let put = request(OP_PUT, &secrets.id, &secrets.pull_token, &slot);
        assert_eq!(
            exchange_public(server.public_addr(), &put).unwrap().status,
            ST_REFUSED
        );
    }

    #[test]
    fn unknown_mailbox_and_bad_token_share_a_status() {
        let server = small_server(None);
        let secrets = server.create_mailbox().unwrap();
        let slot = pack_slot(b"x").unwrap();
        let bad_token = request(OP_PUT, &secrets.id, &[9u8; 32], &slot);
        let unknown = request(OP_PUT, &[7u8; 32], &secrets.push_token, &slot);
        let a = exchange_public(server.public_addr(), &bad_token).unwrap();
        let b = exchange_public(server.public_addr(), &unknown).unwrap();
        assert_eq!(a.status, ST_REFUSED);
        assert_eq!(a.status, b.status);
    }

    #[test]
    fn public_listener_refuses_create_shaped_and_bad_length() {
        let server = small_server(None);
        let mut body = request(OP_PUT, &[0u8; 32], &[0u8; 32], &vec![0u8; RELAY_SLOT_BYTES]);
        body[5] = 9;
        assert_eq!(
            exchange_public(server.public_addr(), &body).unwrap().status,
            ST_REFUSED
        );
        let mut stream = TcpStream::connect(server.public_addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&1u16.to_be_bytes()).unwrap();
        let mut buf = [0u8; 8];
        assert!(stream.read(&mut buf).ok().unwrap_or(0) == 0 || stream.read(&mut buf).is_err());
    }

    #[test]
    fn full_mailbox_refuses_without_dropping_the_head() {
        let server = small_server(None);
        let secrets = server.create_mailbox().unwrap();
        let addr = server.public_addr();
        for frame in [b"one".as_slice(), b"two".as_slice()] {
            let slot = pack_slot(frame).unwrap();
            let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
            assert_eq!(exchange_public(addr, &put).unwrap().status, ST_OK);
        }
        let slot = pack_slot(b"three").unwrap();
        let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
        assert_eq!(exchange_public(addr, &put).unwrap().status, ST_FULL);
        let get = request(
            OP_GET,
            &secrets.id,
            &secrets.pull_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        let reply = exchange_public(addr, &get).unwrap();
        assert_eq!(unpack_slot(&reply.slot).unwrap(), b"one");
    }

    #[test]
    fn nonzero_padding_and_wrong_ack_do_not_store_or_delete() {
        let server = small_server(None);
        let secrets = server.create_mailbox().unwrap();
        let addr = server.public_addr();
        let mut slot = pack_slot(b"kept").unwrap();
        let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
        assert_eq!(exchange_public(addr, &put).unwrap().status, ST_OK);
        slot[RELAY_SLOT_BYTES - 1] = 1;
        let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
        assert_eq!(exchange_public(addr, &put).unwrap().status, ST_REFUSED);
        let mut ack_slot = vec![0u8; RELAY_SLOT_BYTES];
        ack_slot[..32].copy_from_slice(&[1u8; 32]);
        let ack = request(OP_ACK, &secrets.id, &secrets.pull_token, &ack_slot);
        assert_eq!(exchange_public(addr, &ack).unwrap().status, ST_REFUSED);
        let get = request(
            OP_GET,
            &secrets.id,
            &secrets.pull_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        assert_eq!(
            unpack_slot(&exchange_public(addr, &get).unwrap().slot).unwrap(),
            b"kept"
        );
    }

    #[test]
    fn expired_frame_is_not_returned() {
        let mut store = Store::open(None, MIN_TTL_SECS, 4, 4).unwrap();
        let secrets = store.create().unwrap();
        let slot = pack_slot(b"old").unwrap();
        assert_eq!(
            store.put(&secrets.id, &secrets.push_token, &slot, 1_000),
            ST_OK
        );
        let (status, _) = store.get(&secrets.id, &secrets.pull_token, 1_000 + MIN_TTL_SECS);
        assert_eq!(status, ST_EMPTY);
    }

    #[test]
    fn disk_roundtrip_stores_hashes_not_tokens_and_wipe_keeps_onion_key() {
        let dir = std::env::temp_dir().join(format!(
            "hashchat-relay-{}-{}",
            std::process::id(),
            encode_hex(&rand_bytes())
        ));
        let _ = fs::remove_dir_all(&dir);
        let (_, spec) = onion_and_key(4);
        crate::hidden_service::write_onion_key_file(&dir, spec.as_bytes()).unwrap();
        let secrets = {
            let server = small_server(Some(dir.clone()));
            let secrets = server.create_mailbox().unwrap();
            let slot = pack_slot(b"queued").unwrap();
            let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
            assert_eq!(
                exchange_public(server.public_addr(), &put).unwrap().status,
                ST_OK
            );
            secrets
        };
        let name = mailbox_file_name(&secrets.id);
        let bytes = crate::private_fs::read_private_file(&dir, &name, 2_000_000).unwrap();
        assert!(!bytes.windows(32).any(|w| w == secrets.pull_token));
        assert!(!bytes.windows(32).any(|w| w == secrets.push_token));
        let server = small_server(Some(dir.clone()));
        let get = request(
            OP_GET,
            &secrets.id,
            &secrets.pull_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        let reply = exchange_public(server.public_addr(), &get).unwrap();
        assert_eq!(unpack_slot(&reply.slot).unwrap(), b"queued");
        server.wipe().unwrap();
        drop(server);
        assert!(!dir.join(&name).exists());
        let key = crate::hidden_service::read_onion_key_file(&dir).unwrap();
        assert!(key.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unexpected_mailbox_name_refuses_the_directory() {
        let dir = std::env::temp_dir().join(format!(
            "hashchat-relay-name-{}-{}",
            std::process::id(),
            encode_hex(&rand_bytes())
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("m-{}", "AB".repeat(32))), b"nope").unwrap();
        match RelayServer::start(Some(dir.clone()), DEFAULT_TTL_SECS) {
            Err(e) => assert_eq!(e, "relay directory refused"),
            Ok(_) => panic!("unexpected mailbox name was accepted"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn loopback_exchange_refuses_a_public_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1);
        let req = request(OP_GET, &[0u8; 32], &[0u8; 32], &vec![0u8; RELAY_SLOT_BYTES]);
        match exchange_public(addr, &req) {
            Err(e) => assert_eq!(e, "relay address refused"),
            Ok(_) => panic!("public address was accepted"),
        }
    }

    #[test]
    fn inbox_and_card_roundtrip_and_backup_shape() {
        let o = onion(9);
        let server = small_server(None);
        let secrets = server.create_mailbox().unwrap();
        let revealed = secrets.reveal();
        let mut lines = revealed.as_str().lines();
        let inbox_hex = lines.next().unwrap().strip_prefix("inbox ").unwrap();
        let card_hex = lines.next().unwrap().strip_prefix("card ").unwrap();
        let inbox = Inbox::parse(&o, inbox_hex).unwrap();
        assert_eq!(inbox.onion(), o);
        let back = Inbox::from_bytes(&inbox.to_bytes()).unwrap();
        assert_eq!(back.id, secrets.id);
        assert_eq!(back.pull_token, secrets.pull_token);
        let mut book = TargetBook::default();
        book.insert("contact-1", &o, card_hex).unwrap();
        let stored = book.to_bytes();
        let loaded = TargetBook::from_bytes(&stored).unwrap();
        assert_eq!(
            loaded.get("contact-1").unwrap().push_token,
            secrets.push_token
        );
        assert!(TargetBook::from_bytes(&[]).unwrap().is_empty());
        assert!(Inbox::parse("example.com", inbox_hex).is_err());
        assert!(book.insert("contact-1", "not-an-onion", card_hex).is_err());
    }

    #[test]
    fn operator_lines_and_cli_fail_closed() {
        assert!(matches!(
            parse_operator_line("create").unwrap(),
            OperatorCommand::Create
        ));
        match parse_operator_line("wipe") {
            Err(e) => assert_eq!(e, "line refused"),
            Ok(_) => panic!("bare wipe was accepted"),
        }
        assert!(matches!(
            parse_operator_line("wipe confirm").unwrap(),
            OperatorCommand::Wipe
        ));
        assert!(parse_operator_line("delete zz").is_err());
        assert!(parse_operator_line("create now").is_err());
        assert!(matches!(parse_cli(&["--help"]).unwrap(), CliRequest::Help));
        let cli = match parse_cli(&["--memory", "--loopback-only", "--ttl-hours", "1"]).unwrap() {
            CliRequest::Run(c) => c,
            CliRequest::Help => panic!("run"),
        };
        assert!(cli.memory_only && cli.loopback_only && cli.dir.is_none());
        assert_eq!(cli.ttl_secs, 3600);
        assert!(parse_cli(&["--memory", "--dir", "/tmp/x"]).is_err());
        assert!(parse_cli(&["--ttl-hours", "0"]).is_err());
        assert!(parse_cli(&["--ttl-hours", "999"]).is_err());
        assert!(parse_cli(&["--surprise"]).is_err());
        let mut cursor = Cursor::new(b"create\nthis line is fine\n".to_vec());
        assert!(matches!(next_operator_line(&mut cursor), LineRead::Line(s) if s == "create"));
        let huge = vec![b'a'; 300];
        let mut cursor = Cursor::new(huge);
        assert!(matches!(next_operator_line(&mut cursor), LineRead::Refused));
    }

    fn card_hex(secrets: &MailboxSecrets) -> String {
        let revealed = secrets.reveal();
        revealed
            .as_str()
            .lines()
            .nth(1)
            .unwrap()
            .strip_prefix("card ")
            .unwrap()
            .to_string()
    }

    fn fill_mailbox(addr: SocketAddr, secrets: &MailboxSecrets, frames: &[&[u8]]) {
        for frame in frames {
            let slot = pack_slot(frame).unwrap();
            let put = request(OP_PUT, &secrets.id, &secrets.push_token, &slot);
            assert_eq!(exchange_public(addr, &put).unwrap().status, ST_OK);
        }
    }

    fn head_frame(addr: SocketAddr, secrets: &MailboxSecrets) -> Vec<u8> {
        let get = request(
            OP_GET,
            &secrets.id,
            &secrets.pull_token,
            &vec![0u8; RELAY_SLOT_BYTES],
        );
        unpack_slot(&exchange_public(addr, &get).unwrap().slot).unwrap()
    }

    #[test]
    fn several_relays_keep_order_and_a_new_card_does_not_drop_the_others() {
        let o1 = onion(1);
        let o2 = onion(2);
        let o3 = onion(3);
        let mut book = TargetBook::default();
        book.insert("c", &o1, &"ab".repeat(64)).unwrap();
        book.insert("c", &o2, &"cd".repeat(64)).unwrap();
        book.insert("c", &o1, &"ef".repeat(64)).unwrap();
        let cards = book.cards_for_ids(&["c"]);
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].onion(), o1);
        assert_eq!(cards[1].onion(), o2);
        assert_eq!(cards[0].push_token, [0xef; 32]);
        assert_ne!(cards[0].onion(), "contact.onion");
        book.insert("c", &o3, &"11".repeat(64)).unwrap();
        book.insert("other", &o1, &"22".repeat(64)).unwrap();
        assert_eq!(book.cards_for_ids(&["c"]).len(), 3);
        assert!(book.remove_onion("c", &o2).unwrap());
        assert!(!book.remove_onion("c", &o2).unwrap());
        assert_eq!(
            book.cards_for_ids(&["c"])
                .iter()
                .map(|t| t.onion().to_string())
                .collect::<Vec<_>>(),
            vec![o1.clone(), o3]
        );
        assert!(book.remove("c"));
        assert_eq!(book.len(), 1);
        assert!(book.get("other").is_some());

        for n in 4u8..=7 {
            book.insert("c", &onion(n), &"33".repeat(64)).unwrap();
        }
        assert_eq!(
            book.insert("c", &onion(8), &"33".repeat(64)),
            Err("too many relays")
        );
        assert_eq!(book.cards_for_ids(&["c"]).len(), MAX_RELAYS_PER_CONTACT);

        let mut full = TargetBook::default();
        for n in 0..MAX_RELAY_TARGETS as u8 {
            full.insert(&format!("p{n}"), &onion(n), &"44".repeat(64))
                .unwrap();
        }
        assert_eq!(
            full.insert("overflow", &onion(200), &"44".repeat(64)),
            Err("relay targets full")
        );

        let stored = book.to_bytes();
        let loaded = TargetBook::from_bytes(&stored).unwrap();
        assert_eq!(loaded.cards_for_ids(&["c"]).len(), MAX_RELAYS_PER_CONTACT);
        let mut single = TargetBook::default();
        single.insert("c", &o1, &"ab".repeat(64)).unwrap();
        let raw = single.to_bytes();
        let mut dup = raw.clone();
        dup[2] = 2;
        dup.extend_from_slice(&raw[3..]);
        assert!(TargetBook::from_bytes(&dup).is_err());
    }

    #[test]
    fn legacy_inbox_loads_and_a_book_caps_at_four() {
        let o1 = onion(20);
        let legacy = Inbox::parse(&o1, &"ab".repeat(64)).unwrap().to_bytes();
        assert_eq!(legacy[0], VERSION);
        let book = InboxBook::from_stored(&legacy).unwrap();
        assert_eq!(book.len(), 1);
        assert_eq!(book.iter().next().unwrap().onion(), o1);
        let mut book = InboxBook::from_stored(&[]).unwrap();
        book.insert(&o1, &"ab".repeat(64)).unwrap();
        book.insert(&o1, &"cd".repeat(64)).unwrap();
        assert_eq!(book.len(), 1);
        assert_eq!(book.iter().next().unwrap().pull_token, [0xcd; 32]);
        for n in 21..24 {
            book.insert(&onion(n), &"11".repeat(64)).unwrap();
        }
        assert_eq!(book.len(), MAX_RELAY_INBOXES);
        assert_eq!(
            book.insert(&onion(24), &"11".repeat(64)),
            Err("too many relays")
        );
        let stored = book.to_bytes();
        assert_eq!(stored[0], INBOX_BOOK_VERSION);
        let loaded = InboxBook::from_stored(&stored).unwrap();
        assert_eq!(loaded.len(), MAX_RELAY_INBOXES);
        assert_eq!(loaded.iter().next().unwrap().pull_token, [0xcd; 32]);
        let mut short = stored.clone();
        short.pop();
        assert!(InboxBook::from_stored(&short).is_err());
        let mut extra = stored.clone();
        extra.push(0);
        assert!(InboxBook::from_stored(&extra).is_err());
        assert!(InboxBook::from_stored(&[INBOX_BOOK_VERSION, 0]).is_err());
        assert!(InboxBook::from_stored(&[9, 1]).is_err());
        assert!(book.remove_onion(&onion(21)).unwrap());
        assert_eq!(book.len(), 3);
        book.clear();
        assert!(book.is_empty());
        assert!(book.to_bytes().is_empty());
    }

    #[test]
    fn failover_uses_the_next_relay_when_the_first_is_full_or_down() {
        let primary = small_server(None);
        let backup = small_server(None);
        let primary_secrets = primary.create_mailbox().unwrap();
        let backup_secrets = backup.create_mailbox().unwrap();
        let o1 = onion(30);
        let o2 = onion(31);
        let mut book = TargetBook::default();
        book.insert("c", &o1, &card_hex(&primary_secrets)).unwrap();
        book.insert("c", &o2, &card_hex(&backup_secrets)).unwrap();
        let targets = book.cards_for_ids(&["c"]);

        fill_mailbox(
            primary.public_addr(),
            &primary_secrets,
            &[b"old-1", b"old-2"],
        );
        let mut calls = Vec::new();
        let hop = failover_deposit(&targets, &mut Vec::new(), |target| {
            calls.push(target.onion().to_string());
            let addr = if target.onion() == o1 {
                primary.public_addr()
            } else {
                backup.public_addr()
            };
            target.deposit_addr(addr, b"moved")
        });
        assert_eq!(hop, DepositHop::Deposited);
        assert_eq!(calls, vec![o1.clone(), o2.clone()]);
        assert_eq!(
            head_frame(primary.public_addr(), &primary_secrets),
            b"old-1"
        );
        assert_eq!(head_frame(backup.public_addr(), &backup_secrets), b"moved");

        let mut saw_second = false;
        let hop = failover_deposit(&targets, &mut Vec::new(), |target| {
            if target.onion() == o2 {
                saw_second = true;
            }
            Ok(())
        });
        assert_eq!(hop, DepositHop::Deposited);
        assert!(!saw_second);

        let closed = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let o0 = onion(32);
        let mut book = TargetBook::default();
        book.insert("c", &o0, &"ab".repeat(64)).unwrap();
        book.insert("c", &o2, &card_hex(&backup_secrets)).unwrap();
        let targets = book.cards_for_ids(&["c"]);
        let mut down = Vec::new();
        let mut calls = Vec::new();
        let hop = failover_deposit(&targets, &mut down, |target| {
            calls.push(target.onion().to_string());
            if target.onion() == o0 {
                target.deposit_addr(closed, b"via-backup")
            } else {
                target.deposit_addr(backup.public_addr(), b"via-backup")
            }
        });
        assert_eq!(hop, DepositHop::Deposited);
        assert_eq!(calls, vec![o0.clone(), o2.clone()]);
        assert_eq!(down, vec![o0.clone()]);
        let mut later = 0usize;
        let hop = failover_deposit(&targets, &mut down, |target| {
            later += 1;
            assert_eq!(target.onion(), o2);
            Err("relay full")
        });
        assert_eq!(later, 1);
        assert_eq!(hop, DepositHop::Refused);
        assert!(down.iter().any(|onion| onion == &o0));

        let mut down = Vec::new();
        assert_eq!(
            failover_deposit(&targets, &mut down, |_| Err("relay unreachable")),
            DepositHop::Unreachable
        );
        assert_eq!(down.len(), 2);
        let mut skipped = 0usize;
        assert_eq!(
            failover_deposit(&targets, &mut down, |_| {
                skipped += 1;
                Ok(())
            }),
            DepositHop::Unreachable
        );
        assert_eq!(skipped, 0);
        assert_eq!(
            failover_deposit(&[], &mut Vec::new(), |_| Ok(())),
            DepositHop::Skipped
        );
        assert_eq!(
            failover_deposit(&targets, &mut Vec::new(), |target| {
                if target.onion() == o0 {
                    Err("relay unreachable")
                } else {
                    Err("relay refused")
                }
            }),
            DepositHop::Refused
        );
    }

    fn rand_bytes() -> [u8; 4] {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).unwrap();
        b
    }
}
