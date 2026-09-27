//! Tor v3 hidden service via ControlPort + local framed TCP listener.
//!
//! M1: Cookie `AUTHENTICATE` only — never bare `AUTHENTICATE`. Fail closed if
//! COOKIEFILE is missing or the cookie is unreadable. Cookie bytes are never logged.
//!
//! ControlPort peer authentication (SAFECOOKIE):
//! - Whatever answers on the loopback control port is not trusted until it proves
//!   knowledge of the cookie. We use `AUTHCHALLENGE SAFECOOKIE` and check the
//!   server HMAC (constant time) **before** sending our own; the cookie itself
//!   never leaves the process.
//! - The `COOKIEFILE` path advertised in `PROTOCOLINFO` is only accepted if it
//!   resolves to a known system Tor cookie location, or to the path in
//!   `HASHCHAT_TOR_COOKIE_FILE` when that is set (then it is the only accepted
//!   path). Without this, a listener that is not Tor could name a cookie file it
//!   wrote itself and pass the HMAC check.
//! - The cookie file must be a regular file of exactly 32 bytes, opened without
//!   following a final symlink; size is checked before reading.
//! - Control replies are bounded (line length and line count).
//! - `ADD_ONION` (which carries the stored onion key) is only sent after the
//!   above succeeds.
//!
//! The control TCP connection is kept open: Tor drops ephemeral onions when it closes.
//! When `ADD_ONION` returns `PrivateKey=`, callers must persist it only inside the
//! passphrase-wrapped session blob (H2 `onion_key`).

use crate::tor_socks::{is_loopback_host, MAX_SOCKS_FRAME};
use ring::hmac;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Max wait for the next frame header on an open connection.
const MAX_ACCEPT_IDLE_SECS: u64 = 30;

/// Once a frame header has arrived, the whole body must arrive within this
/// many seconds in total (not per read call), so trickled bytes cannot keep a
/// connection busy indefinitely.
const MAX_FRAME_BODY_SECS: u64 = 20;

/// Hard cap on one inbound connection's lifetime.
const MAX_CONN_LIFETIME_SECS: u64 = 120;

/// Connections served concurrently (one thread each). Extra connections are
/// closed at accept and counted; they never wait behind a slow peer.
pub const HS_MAX_CONCURRENT_CONNS: usize = 16;

/// Tor control cookies are exactly 32 bytes (control-spec, COOKIE / SAFECOOKIE).
const TOR_COOKIE_LEN: usize = 32;

/// Env override naming the only acceptable cookie path (absolute).
pub const TOR_COOKIE_FILE_ENV: &str = "HASHCHAT_TOR_COOKIE_FILE";

/// System Tor cookie locations accepted when no override is set. Compared after
/// canonicalisation, so `/var/run` → `/run` aliases match.
const DEFAULT_COOKIE_PATHS: &[&str] = &[
    "/run/tor/control.authcookie",
    "/var/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
    "/var/lib/tor/control.authcookie",
];

const SAFECOOKIE_SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const SAFECOOKIE_CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// Bounds on a single control reply.
const MAX_CONTROL_LINE: usize = 4096;
const MAX_CONTROL_LINES: usize = 256;

/// Strict max inbound HS transport frame body (bytes), **≤** [`MAX_SOCKS_FRAME`].
///
/// Wire-v2 chat frames are far smaller; 16 KiB caps per-read allocation under
/// a malicious length prefix while staying above realistic ciphertext sizes.
/// Oversize → close that stream; body is not read and not queued.
pub const MAX_HS_INBOUND_FRAME: usize = 16 * 1024;

/// Bounded inbound mpsc capacity. When full, new frames are dropped (counted)
/// — the queue never grows unbounded.
pub const HS_INBOUND_QUEUE_CAP: usize = 64;

/// Soft per-connection frame budget within the accept idle window. Excess
/// closes that stream only (simple local DoS brake; not a Tor-level defense).
const MAX_FRAMES_PER_CONN: u32 = 64;

const _: () = assert!(MAX_HS_INBOUND_FRAME <= MAX_SOCKS_FRAME);

pub struct HiddenService {
    pub onion: String,
    pub local_port: u16,
    rx: Receiver<Vec<u8>>,
    /// Frames dropped because the inbound queue was full (no contents logged).
    drops: Arc<AtomicU64>,
    /// Connections closed at accept because the concurrency cap was reached.
    refused: Arc<AtomicU64>,
    /// Must stay open or Tor forgets a non-persisted onion.
    _control: TcpStream,
}

impl HiddenService {
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }

    /// Count of inbound frames dropped under backpressure (never includes bytes).
    pub fn dropped_frame_count(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Count of inbound connections refused at the concurrency cap.
    pub fn refused_connection_count(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}

/// Publish (or re-attach) a v3 onion mapped to an ephemeral local listener.
///
/// `existing_key` is the Tor private-key blob (`ED25519-V3:…`) from a prior
/// `ADD_ONION`, stored in the wrapped session. Returns `(service, private_key_bytes)`.
/// On `NEW`, `private_key_bytes` holds the returned `PrivateKey=`; on replay it is
/// typically empty (caller should keep the existing key).
pub fn start_hidden_service_with_key(
    control_host: &str,
    control_port: u16,
    existing_key: Option<&[u8]>,
) -> Result<(HiddenService, Vec<u8>), String> {
    if !is_loopback_host(control_host) {
        return Err("ControlPort host refused (not loopback)".into());
    }

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "local bind failed".to_string())?;
    let local_port = listener
        .local_addr()
        .map_err(|_| "local addr failed".to_string())?
        .port();

    let mut control = connect_control(control_host, control_port)?;
    let cookie_override = std::env::var_os(TOR_COOKIE_FILE_ENV).map(PathBuf::from);
    authenticate_cookie_only(&mut control, cookie_override.as_deref())?;
    let existing_str = existing_key.and_then(|b| std::str::from_utf8(b).ok());
    let (onion, privkey) = add_onion(&mut control, local_port, existing_str)?;

    let (tx, rx) = mpsc::sync_channel(HS_INBOUND_QUEUE_CAP);
    let drops = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let counters = HsCounters {
        drops: Arc::clone(&drops),
        refused: Arc::clone(&refused),
    };
    thread::Builder::new()
        .name("hashchat-hs".into())
        .spawn(move || accept_loop(listener, tx, counters, HsLimits::default()))
        .map_err(|_| "listener thread failed".to_string())?;

    Ok((
        HiddenService {
            onion,
            local_port,
            rx,
            drops,
            refused,
            _control: control,
        },
        privkey,
    ))
}

/// Timing / concurrency limits for the inbound listener (tests shrink them).
#[derive(Clone, Copy, Debug)]
struct HsLimits {
    idle: Duration,
    frame_body: Duration,
    conn_lifetime: Duration,
    max_conns: usize,
    max_frames_per_conn: u32,
}

impl Default for HsLimits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(MAX_ACCEPT_IDLE_SECS),
            frame_body: Duration::from_secs(MAX_FRAME_BODY_SECS),
            conn_lifetime: Duration::from_secs(MAX_CONN_LIFETIME_SECS),
            max_conns: HS_MAX_CONCURRENT_CONNS,
            max_frames_per_conn: MAX_FRAMES_PER_CONN,
        }
    }
}

#[derive(Clone)]
struct HsCounters {
    drops: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
}

/// Decrements the live-connection count when a handler exits (incl. panic).
struct ConnSlot(Arc<AtomicUsize>);

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserve a connection slot, or `None` if `max` are already in use.
fn try_reserve_slot(live: &Arc<AtomicUsize>, max: usize) -> Option<ConnSlot> {
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

fn accept_loop(
    listener: TcpListener,
    tx: SyncSender<Vec<u8>>,
    counters: HsCounters,
    limits: HsLimits,
) {
    let live = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        let Some(slot) = try_reserve_slot(&live, limits.max_conns) else {
            // At capacity: close immediately rather than queue behind slow peers.
            counters.refused.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        };
        let tx = tx.clone();
        let drops = Arc::clone(&counters.drops);
        let spawned = thread::Builder::new()
            .name("hashchat-hs-conn".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let _slot = slot;
                serve_connection(stream, &tx, &drops, limits);
            });
        if spawned.is_err() {
            // Thread spawn failed: the closure (stream + slot) was dropped.
            counters.refused.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Read frames from one connection under idle, per-frame and lifetime deadlines.
/// Returns when the peer closes, misbehaves, or a limit is hit.
fn serve_connection(
    mut stream: TcpStream,
    tx: &SyncSender<Vec<u8>>,
    drops: &AtomicU64,
    limits: HsLimits,
) {
    let conn_deadline = Instant::now() + limits.conn_lifetime;
    let mut frames: u32 = 0;
    while frames < limits.max_frames_per_conn {
        match read_frame_with_deadlines(&mut stream, MAX_HS_INBOUND_FRAME, &limits, conn_deadline) {
            Ok(frame) => {
                frames = frames.saturating_add(1);
                match tx.try_send(frame) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_dropped)) => {
                        // Backpressure: drop frame, never grow queue; no contents logged.
                        drops.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_dropped)) => return,
                }
            }
            Err(()) => return, // oversize / timeout / EOF → close stream
        }
    }
}

/// Fill `buf` completely before `deadline`. The socket read timeout is reset to
/// the remaining time before each read, so the bound is on total time.
fn read_exact_by(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<(), ()> {
    let mut filled = 0;
    while filled < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(());
        }
        let remaining = (deadline - now).max(Duration::from_millis(1));
        stream.set_read_timeout(Some(remaining)).map_err(|_| ())?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Same framing as [`crate::tor_socks::read_framed_u16_max`] (2-byte BE length + body), with
/// deadlines: header within `idle`, body within `frame_body` of the header,
/// everything within the connection deadline.
fn read_frame_with_deadlines(
    stream: &mut TcpStream,
    max_len: usize,
    limits: &HsLimits,
    conn_deadline: Instant,
) -> Result<Vec<u8>, ()> {
    let cap = max_len.min(MAX_SOCKS_FRAME);
    let header_deadline = (Instant::now() + limits.idle).min(conn_deadline);
    let mut ln = [0u8; 2];
    read_exact_by(stream, &mut ln, header_deadline)?;
    let n = u16::from_be_bytes(ln) as usize;
    if n == 0 || n > cap {
        // Do not allocate or drain the claimed body — close the connection.
        return Err(());
    }
    let body_deadline = (Instant::now() + limits.frame_body).min(conn_deadline);
    let mut buf = vec![0u8; n];
    if read_exact_by(stream, &mut buf, body_deadline).is_err() {
        buf.zeroize();
        return Err(());
    }
    Ok(buf)
}

fn connect_control(host: &str, port: u16) -> Result<TcpStream, String> {
    let addr = format!("{host}:{port}")
        .parse()
        .map_err(|_| "bad control address".to_string())?;
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|_| format!("ControlPort {host}:{port} unreachable"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(8)));
    Ok(s)
}

/// M1: cookie AUTHENTICATE only. Never send bare AUTHENTICATE.
///
/// SAFECOOKIE handshake; see module docs for the trust argument.
fn authenticate_cookie_only(
    s: &mut TcpStream,
    cookie_override: Option<&Path>,
) -> Result<(), String> {
    let info = control_cmd(s, "PROTOCOLINFO 1")?;
    if !protocolinfo_offers_safecookie(&info) {
        return Err(
            "Tor control: SAFECOOKIE not offered (fail-closed; refusing bare AUTHENTICATE)".into(),
        );
    }
    let advertised = cookie_path_from_protocolinfo(&info).ok_or_else(|| {
        "Tor control: no COOKIEFILE in PROTOCOLINFO (fail-closed; refusing bare AUTHENTICATE)"
            .to_string()
    })?;
    let path = resolve_cookie_path(&advertised, cookie_override)?;
    let mut cookie = read_tor_cookie(&path)?;

    let mut client_nonce = [0u8; 32];
    if getrandom::getrandom(&mut client_nonce).is_err() {
        cookie.zeroize();
        return Err("csprng failed".into());
    }
    let result = safecookie_exchange(s, &cookie, &client_nonce);
    cookie.zeroize();
    result
}

fn safecookie_exchange(
    s: &mut TcpStream,
    cookie: &[u8; TOR_COOKIE_LEN],
    client_nonce: &[u8; 32],
) -> Result<(), String> {
    let chal = control_cmd(
        s,
        &format!("AUTHCHALLENGE SAFECOOKIE {}", hex_lower(client_nonce)),
    )?;
    let (server_hash, server_nonce) = parse_authchallenge(&chal)
        .ok_or_else(|| "Tor control: bad AUTHCHALLENGE reply (fail-closed)".to_string())?;

    let mut expected = safecookie_hmac(SAFECOOKIE_SERVER_KEY, cookie, client_nonce, &server_nonce);
    let ok: bool = expected.ct_eq(&server_hash).into();
    expected.zeroize();
    if !ok {
        // The peer does not know the cookie: it is not our Tor. Send nothing more.
        return Err("Tor control: ControlPort failed SAFECOOKIE proof (fail-closed)".into());
    }

    let mut client_hash =
        safecookie_hmac(SAFECOOKIE_CLIENT_KEY, cookie, client_nonce, &server_nonce);
    let mut hex = hex_lower(&client_hash);
    client_hash.zeroize();
    // OPSEC: hex is sent to ControlPort only — never logged.
    let resp = control_cmd(s, &format!("AUTHENTICATE {hex}"));
    hex.zeroize();
    let resp = resp?;
    if resp.len() == 1 && resp[0] == "250 OK" {
        Ok(())
    } else {
        Err("Tor cookie authentication failed".into())
    }
}

/// HMAC-SHA256(key, cookie ‖ client_nonce ‖ server_nonce) per control-spec SAFECOOKIE.
fn safecookie_hmac(
    key: &[u8],
    cookie: &[u8; TOR_COOKIE_LEN],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(cookie);
    ctx.update(client_nonce);
    ctx.update(server_nonce);
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0f) as usize] as char);
    }
    s
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

/// `250 AUTHCHALLENGE SERVERHASH=<64 hex> SERVERNONCE=<64 hex>` → (hash, nonce).
fn parse_authchallenge(lines: &[String]) -> Option<([u8; 32], [u8; 32])> {
    if lines.len() != 1 {
        return None;
    }
    let rest = lines[0].strip_prefix("250 AUTHCHALLENGE ")?;
    let mut hash = None;
    let mut nonce = None;
    for tok in rest.split_ascii_whitespace() {
        if let Some(v) = tok.strip_prefix("SERVERHASH=") {
            if hash.is_some() {
                return None;
            }
            hash = Some(hex32(v)?);
        } else if let Some(v) = tok.strip_prefix("SERVERNONCE=") {
            if nonce.is_some() {
                return None;
            }
            nonce = Some(hex32(v)?);
        }
    }
    Some((hash?, nonce?))
}

/// True if the `250-AUTH METHODS=` list contains `SAFECOOKIE`.
fn protocolinfo_offers_safecookie(lines: &[String]) -> bool {
    lines.iter().any(|line| {
        line.strip_prefix("250-AUTH ")
            .and_then(|rest| {
                rest.split_ascii_whitespace()
                    .find_map(|t| t.strip_prefix("METHODS="))
            })
            .map(|m| m.split(',').any(|x| x == "SAFECOOKIE"))
            .unwrap_or(false)
    })
}

/// Accept the advertised cookie path only if it resolves to an allowed location.
/// Errors never include the path.
fn resolve_cookie_path(
    advertised: &str,
    cookie_override: Option<&Path>,
) -> Result<PathBuf, String> {
    let refused = || {
        format!(
            "Tor control: COOKIEFILE not at an expected location (fail-closed; set {TOR_COOKIE_FILE_ENV})"
        )
    };
    let adv = Path::new(advertised);
    if !adv.is_absolute() {
        return Err(refused());
    }
    let canon = std::fs::canonicalize(adv)
        .map_err(|_| "Tor control cookie unreadable (fail-closed)".to_string())?;
    let allowed: Vec<PathBuf> = match cookie_override {
        Some(p) => {
            if !p.is_absolute() {
                return Err(format!("{TOR_COOKIE_FILE_ENV} must be an absolute path"));
            }
            vec![p.to_path_buf()]
        }
        None => DEFAULT_COOKIE_PATHS.iter().map(PathBuf::from).collect(),
    };
    for a in allowed {
        if let Ok(ca) = std::fs::canonicalize(&a) {
            if ca == canon {
                return Ok(canon);
            }
        }
    }
    Err(refused())
}

/// Read a Tor cookie: regular file, exactly 32 bytes, no final-component symlink.
fn read_tor_cookie(path: &Path) -> Result<[u8; TOR_COOKIE_LEN], String> {
    let unreadable = || "Tor control cookie unreadable (fail-closed)".to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let f = opts.open(path).map_err(|_| unreadable())?;
    let md = f.metadata().map_err(|_| unreadable())?;
    if !md.is_file() || md.len() != TOR_COOKIE_LEN as u64 {
        return Err("Tor control cookie malformed (fail-closed)".into());
    }
    let mut cookie = [0u8; TOR_COOKIE_LEN];
    let mut f = f.take(TOR_COOKIE_LEN as u64 + 1);
    if f.read_exact(&mut cookie).is_err() {
        cookie.zeroize();
        return Err(unreadable());
    }
    let mut extra = [0u8; 1];
    if matches!(f.read(&mut extra), Ok(n) if n > 0) {
        cookie.zeroize();
        return Err("Tor control cookie malformed (fail-closed)".into());
    }
    Ok(cookie)
}

/// Parse `COOKIEFILE="…"` from PROTOCOLINFO lines (unit-tested).
pub fn cookie_path_from_protocolinfo(lines: &[String]) -> Option<String> {
    for line in lines {
        if !line.starts_with("250-AUTH ") {
            continue;
        }
        if let Some(idx) = line.find("COOKIEFILE=") {
            let rest = &line[idx + "COOKIEFILE=".len()..];
            let rest = rest.trim_start_matches('"');
            let end = rest.find('"').unwrap_or(rest.len());
            let p = rest[..end].trim();
            if !p.is_empty() {
                return Some(p.to_string());
            }
        }
    }
    None
}

fn add_onion(
    s: &mut TcpStream,
    local_port: u16,
    existing_key: Option<&str>,
) -> Result<(String, Vec<u8>), String> {
    let spec = match existing_key {
        Some(k) if !k.trim().is_empty() => {
            let k = k.trim();
            if !is_valid_onion_key_spec(k) {
                return Err("stored onion key malformed (refused)".into());
            }
            k.to_string()
        }
        _ => "NEW:ED25519-V3".to_string(),
    };
    // Intentionally no DiscardPK: we persist PrivateKey inside the wrapped blob (H2).
    let mut cmd = format!("ADD_ONION {spec} Port=80,127.0.0.1:{local_port}");
    let mut spec = spec;
    let resp = control_cmd(s, &cmd);
    cmd.zeroize();
    spec.zeroize();
    let mut resp = resp?;
    let mut onion = None;
    let mut privkey = Vec::new();
    for line in &resp {
        if let Some(id) = line.strip_prefix("250-ServiceID=") {
            onion = Some(format!("{}.onion", id.trim()));
        }
        if let Some(pk) = line.strip_prefix("250-PrivateKey=") {
            privkey = pk.trim().as_bytes().to_vec();
        }
    }
    let rejected = resp.iter().any(|l| l.starts_with('5'));
    for l in resp.iter_mut() {
        l.zeroize();
    }
    match onion {
        Some(o) => Ok((o, privkey)),
        None => {
            if rejected {
                Err("ADD_ONION rejected by Tor".into())
            } else {
                Err("ADD_ONION failed (no ServiceID)".into())
            }
        }
    }
}

/// `ED25519-V3:<base64>` only; no whitespace or control bytes can reach the command line.
fn is_valid_onion_key_spec(k: &str) -> bool {
    match k.strip_prefix("ED25519-V3:") {
        Some(b64) => {
            !b64.is_empty()
                && b64.len() <= 128
                && b64
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
        }
        None => false,
    }
}

fn control_cmd(s: &mut TcpStream, cmd: &str) -> Result<Vec<String>, String> {
    s.write_all(cmd.as_bytes())
        .map_err(|_| "control write failed".to_string())?;
    s.write_all(b"\r\n")
        .map_err(|_| "control write failed".to_string())?;
    s.flush().map_err(|_| "control flush failed".to_string())?;
    let reader = BufReader::new(
        s.try_clone()
            .map_err(|_| "control clone failed".to_string())?,
    );
    read_control_reply(reader)
}

/// Read one control reply with bounded line length and count.
fn read_control_reply<R: BufRead>(mut reader: R) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    loop {
        if lines.len() >= MAX_CONTROL_LINES {
            return Err("control reply too long".into());
        }
        let mut raw = Vec::new();
        let n = (&mut reader)
            .take(MAX_CONTROL_LINE as u64 + 1)
            .read_until(b'\n', &mut raw)
            .map_err(|_| "control read failed".to_string())?;
        if n == 0 {
            break;
        }
        if raw.len() > MAX_CONTROL_LINE {
            raw.zeroize();
            return Err("control line too long".into());
        }
        let t = match String::from_utf8(raw) {
            Ok(mut s) => {
                let end = s.trim_end_matches(['\r', '\n']).len();
                s.truncate(end);
                s
            }
            Err(e) => {
                let mut b = e.into_bytes();
                b.zeroize();
                return Err("control reply not UTF-8".into());
            }
        };
        let done = t.starts_with("250 ") || t.starts_with('5');
        lines.push(t);
        if done {
            break;
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor_socks::{read_framed_u16_max, write_framed_u16};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Duration;

    // ---- SAFECOOKIE / cookie-path tests (local fake ControlPort, no Tor) ----

    fn tmp_dir(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("hashchat-ctl-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[derive(Clone, Copy, PartialEq)]
    enum ServerMode {
        /// Real Tor behaviour: knows the cookie.
        Honest,
        /// Impostor: does not know the cookie, sends a made-up SERVERHASH.
        Impostor,
    }

    /// Minimal fake ControlPort. Returns (addr, handle yielding received command lines).
    fn fake_control(
        cookie_path: String,
        cookie: [u8; 32],
        methods: &'static str,
        mode: ServerMode,
    ) -> (std::net::SocketAddr, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let h = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut got = Vec::new();
            let mut client_nonce = [0u8; 32];
            let server_nonce = [0x5au8; 32];
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                got.push(line.clone());
                if line == "PROTOCOLINFO 1" {
                    write!(
                        w,
                        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods} COOKIEFILE=\"{cookie_path}\"\r\n250-VERSION Tor=\"0.4.8.0\"\r\n250 OK\r\n"
                    )
                    .unwrap();
                } else if let Some(n) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                    client_nonce = hex32(n).unwrap();
                    let sh = match mode {
                        ServerMode::Honest => safecookie_hmac(
                            SAFECOOKIE_SERVER_KEY,
                            &cookie,
                            &client_nonce,
                            &server_nonce,
                        ),
                        ServerMode::Impostor => [0x11u8; 32],
                    };
                    write!(
                        w,
                        "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                        hex_lower(&sh),
                        hex_lower(&server_nonce)
                    )
                    .unwrap();
                } else if let Some((_, h)) = line.split_once(' ') {
                    // Only other command the client sends: the SAFECOOKIE client hash.
                    let want = safecookie_hmac(
                        SAFECOOKIE_CLIENT_KEY,
                        &cookie,
                        &client_nonce,
                        &server_nonce,
                    );
                    if hex32(h) == Some(want) {
                        write!(w, "250 OK\r\n").unwrap();
                    } else {
                        write!(w, "515 Authentication failed\r\n").unwrap();
                    }
                } else {
                    write!(w, "510 Unrecognized command\r\n").unwrap();
                }
                w.flush().unwrap();
            }
            got
        });
        (addr, h)
    }

    fn write_cookie(dir: &Path, bytes: &[u8]) -> PathBuf {
        let p = dir.join("control_auth_cookie");
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn run_auth(addr: std::net::SocketAddr, cookie_override: Option<&Path>) -> Result<(), String> {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let r = authenticate_cookie_only(&mut s, cookie_override);
        drop(s);
        r
    }

    #[test]
    fn safecookie_succeeds_with_honest_server_and_allowed_path() {
        let dir = tmp_dir("ok");
        let cookie = [0xA7u8; 32];
        let path = write_cookie(&dir, &cookie);
        let (addr, h) = fake_control(
            path.to_string_lossy().into_owned(),
            cookie,
            "COOKIE,SAFECOOKIE",
            ServerMode::Honest,
        );
        run_auth(addr, Some(&path)).unwrap();
        let got = h.join().unwrap();
        assert!(got
            .iter()
            .any(|l| l.starts_with("AUTHCHALLENGE SAFECOOKIE ")));
        // Raw cookie hex is never sent.
        let cookie_hex = hex_lower(&cookie);
        assert!(got.iter().all(|l| !l.contains(&cookie_hex)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn impostor_server_gets_no_authenticate() {
        let dir = tmp_dir("impostor");
        let cookie = [0x42u8; 32];
        let path = write_cookie(&dir, &cookie);
        let (addr, h) = fake_control(
            path.to_string_lossy().into_owned(),
            cookie,
            "COOKIE,SAFECOOKIE",
            ServerMode::Impostor,
        );
        let err = run_auth(addr, Some(&path)).unwrap_err();
        assert!(err.contains("SAFECOOKIE proof"), "{err}");
        let got = h.join().unwrap();
        // Only PROTOCOLINFO + AUTHCHALLENGE; nothing after the failed proof.
        assert_eq!(got.len(), 2, "client must not answer an unproven server");
        assert!(got[1].starts_with("AUTHCHALLENGE SAFECOOKIE "));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unexpected_cookiefile_path_refused_before_reading() {
        let dir = tmp_dir("path");
        let cookie = [0x33u8; 32];
        let planted = write_cookie(&dir, &cookie);
        let expected = dir.join("expected_cookie");
        std::fs::write(&expected, [0u8; 32]).unwrap();
        // Server names a file it controls; the user configured a different one.
        let (addr, h) = fake_control(
            planted.to_string_lossy().into_owned(),
            cookie,
            "COOKIE,SAFECOOKIE",
            ServerMode::Honest,
        );
        let err = run_auth(addr, Some(&expected)).unwrap_err();
        assert!(err.contains("expected location"), "{err}");
        assert!(
            !err.contains(dir.to_string_lossy().as_ref()),
            "no path in errors"
        );
        let got = h.join().unwrap();
        assert!(got.iter().all(|l| !l.starts_with("AUTH")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_allowlist_rejects_arbitrary_user_file() {
        let dir = tmp_dir("default");
        let p = write_cookie(&dir, &[1u8; 32]);
        let err = resolve_cookie_path(p.to_str().unwrap(), None).unwrap_err();
        assert!(err.contains("expected location"));
        assert!(resolve_cookie_path("relative/cookie", None).is_err());
        assert!(resolve_cookie_path(p.to_str().unwrap(), Some(Path::new("rel"))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_safecookie_method_refused() {
        let dir = tmp_dir("methods");
        let cookie = [9u8; 32];
        let path = write_cookie(&dir, &cookie);
        let (addr, h) = fake_control(
            path.to_string_lossy().into_owned(),
            cookie,
            "COOKIE",
            ServerMode::Honest,
        );
        let err = run_auth(addr, Some(&path)).unwrap_err();
        assert!(err.contains("SAFECOOKIE not offered"), "{err}");
        let got = h.join().unwrap();
        assert!(got.iter().all(|l| !l.starts_with("AUTH")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cookie_must_be_exactly_32_regular_bytes() {
        let dir = tmp_dir("size");
        for len in [0usize, 31, 33, 4096] {
            let p = dir.join(format!("c{len}"));
            std::fs::write(&p, vec![7u8; len]).unwrap();
            assert!(read_tor_cookie(&p).is_err(), "len {len}");
        }
        let ok = dir.join("ok");
        std::fs::write(&ok, [7u8; 32]).unwrap();
        assert_eq!(read_tor_cookie(&ok).unwrap(), [7u8; 32]);
        assert!(read_tor_cookie(&dir).is_err(), "directory refused");
        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&ok, &link).unwrap();
            assert!(read_tor_cookie(&link).is_err(), "final symlink refused");
            if Path::new("/dev/zero").exists() {
                assert!(read_tor_cookie(Path::new("/dev/zero")).is_err());
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safecookie_hmac_known_answer() {
        // Reference values computed independently (HMAC-SHA256, constant string as key).
        let (c, cn, sn) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(
            hex_lower(&safecookie_hmac(SAFECOOKIE_SERVER_KEY, &c, &cn, &sn)),
            "1830d2de6e061e60adfa2c0c2a9257b7126e51b074f39bd4519d89229df08827"
        );
        assert_eq!(
            hex_lower(&safecookie_hmac(SAFECOOKIE_CLIENT_KEY, &c, &cn, &sn)),
            "8d81b806c8314911da68057896783b1f28f640a588c9a2cfe902d371806bbf1a"
        );
    }

    #[test]
    fn authchallenge_parser_is_strict() {
        let h = "ab".repeat(32);
        let n = "cd".repeat(32);
        let good = vec![format!("250 AUTHCHALLENGE SERVERHASH={h} SERVERNONCE={n}")];
        assert!(parse_authchallenge(&good).is_some());
        for bad in [
            format!("250 AUTHCHALLENGE SERVERHASH={h}"),
            format!("250 AUTHCHALLENGE SERVERNONCE={n}"),
            format!("250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={n}", &h[..62]),
            format!("250 AUTHCHALLENGE SERVERHASH={h}zz SERVERNONCE={n}"),
            format!("250 AUTHCHALLENGE SERVERHASH={h} SERVERHASH={h} SERVERNONCE={n}"),
            format!("250 OK SERVERHASH={h} SERVERNONCE={n}"),
            "515 nope".to_string(),
        ] {
            assert!(parse_authchallenge(&[bad.clone()]).is_none(), "{bad}");
        }
    }

    #[test]
    fn safecookie_methods_parsed_from_auth_line_only() {
        let yes = vec!["250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/x\"".to_string()];
        let no = vec!["250-AUTH METHODS=COOKIE COOKIEFILE=\"/x\"".to_string()];
        let spoof = vec!["250-VERSION Tor=\"METHODS=SAFECOOKIE\"".to_string()];
        assert!(protocolinfo_offers_safecookie(&yes));
        assert!(!protocolinfo_offers_safecookie(&no));
        assert!(!protocolinfo_offers_safecookie(&spoof));
    }

    #[test]
    fn control_reply_bounded() {
        let long = format!("250 {}\r\n", "a".repeat(MAX_CONTROL_LINE + 10));
        assert!(read_control_reply(std::io::Cursor::new(long.into_bytes())).is_err());
        let many = "250-x\r\n".repeat(MAX_CONTROL_LINES + 5);
        assert!(read_control_reply(std::io::Cursor::new(many.into_bytes())).is_err());
        let ok = "250-a\r\n250 OK\r\n";
        assert_eq!(
            read_control_reply(std::io::Cursor::new(ok.as_bytes().to_vec())).unwrap(),
            vec!["250-a".to_string(), "250 OK".to_string()]
        );
    }

    #[test]
    fn stored_onion_key_spec_validated() {
        let good = format!("ED25519-V3:{}", "A".repeat(86) + "==");
        assert!(is_valid_onion_key_spec(&good));
        for bad in [
            "",
            "ED25519-V3:",
            "RSA1024:abc",
            "ED25519-V3:abc def",
            "ED25519-V3:abc\r\nGETINFO x",
            "NEW:ED25519-V3",
        ] {
            assert!(!is_valid_onion_key_spec(bad), "{bad:?}");
        }
    }

    #[test]
    fn parses_cookiefile_quoted() {
        let lines = vec![
            "250-PROTOCOLINFO 1".into(),
            "250-AUTH METHODS=COOKIE,HASHEDPASSWORD COOKIEFILE=\"/run/tor/control.authcookie\""
                .into(),
            "250 OK".into(),
        ];
        assert_eq!(
            cookie_path_from_protocolinfo(&lines).as_deref(),
            Some("/run/tor/control.authcookie")
        );
    }

    #[test]
    fn parses_cookiefile_absent() {
        let lines = vec![
            "250-PROTOCOLINFO 1".into(),
            "250-AUTH METHODS=NULL".into(),
            "250 OK".into(),
        ];
        assert!(cookie_path_from_protocolinfo(&lines).is_none());
    }

    #[test]
    fn control_host_non_loopback_refused() {
        let err = match start_hidden_service_with_key("8.8.8.8", 9051, None) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err.contains("loopback"));
    }

    #[test]
    fn max_hs_inbound_frame_at_or_below_socks_cap() {
        assert!(MAX_HS_INBOUND_FRAME > 0);
        assert!(MAX_HS_INBOUND_FRAME <= MAX_SOCKS_FRAME);
        assert!(HS_INBOUND_QUEUE_CAP >= 32 && HS_INBOUND_QUEUE_CAP <= 64);
    }

    #[test]
    fn hs_oversize_length_rejected_closes_without_queue() {
        // Local TCP only — no Tor. Advertise length > MAX_HS_INBOUND_FRAME.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(HS_INBOUND_QUEUE_CAP);
        let drops = Arc::new(AtomicU64::new(0));
        let counters = HsCounters {
            drops: Arc::clone(&drops),
            refused: Arc::new(AtomicU64::new(0)),
        };
        thread::spawn(move || accept_loop(listener, tx, counters, HsLimits::default()));

        let mut s = TcpStream::connect(addr).unwrap();
        let over = ((MAX_HS_INBOUND_FRAME as u16).saturating_add(1)).to_be_bytes();
        // If MAX_HS were u16::MAX this would wrap; assert we stay strictly below.
        assert!(MAX_HS_INBOUND_FRAME < u16::MAX as usize);
        s.write_all(&over).unwrap();
        s.flush().unwrap();
        // Give accept thread a moment; oversize must not enqueue.
        thread::sleep(Duration::from_millis(80));
        assert!(rx.try_recv().is_err(), "oversize frame must not be queued");
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    // ---- accept-loop concurrency / deadline tests (local TCP, short limits) ----

    fn spawn_listener(
        limits: HsLimits,
        cap: usize,
    ) -> (
        std::net::SocketAddr,
        Receiver<Vec<u8>>,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(cap);
        let drops = Arc::new(AtomicU64::new(0));
        let refused = Arc::new(AtomicU64::new(0));
        let counters = HsCounters {
            drops: Arc::clone(&drops),
            refused: Arc::clone(&refused),
        };
        thread::spawn(move || accept_loop(listener, tx, counters, limits));
        (addr, rx, drops, refused)
    }

    fn short_limits() -> HsLimits {
        HsLimits {
            idle: Duration::from_millis(1500),
            frame_body: Duration::from_millis(400),
            conn_lifetime: Duration::from_secs(3),
            max_conns: 4,
            max_frames_per_conn: MAX_FRAMES_PER_CONN,
        }
    }

    fn recv_within(rx: &Receiver<Vec<u8>>, ms: u64) -> Option<Vec<u8>> {
        rx.recv_timeout(Duration::from_millis(ms)).ok()
    }

    /// True once the server has closed `s` (EOF or reset) within `ms`.
    fn closed_within(s: &mut TcpStream, ms: u64) -> bool {
        use std::io::Read;
        s.set_read_timeout(Some(Duration::from_millis(ms))).unwrap();
        let mut b = [0u8; 1];
        match s.read(&mut b) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }

    #[test]
    fn stalled_client_does_not_block_other_peers() {
        let (addr, rx, _, _) = spawn_listener(short_limits(), 8);
        // Slow peer: header promising 100 bytes, then nothing.
        let mut slow = TcpStream::connect(addr).unwrap();
        slow.write_all(&100u16.to_be_bytes()).unwrap();
        slow.write_all(&[1u8; 3]).unwrap();
        slow.flush().unwrap();
        thread::sleep(Duration::from_millis(50));
        // Honest peer is served immediately, not after the slow one times out.
        let mut ok = TcpStream::connect(addr).unwrap();
        write_framed_u16(&mut ok, b"hello").unwrap();
        let got = recv_within(&rx, 300).expect("honest frame must not wait");
        assert_eq!(got, b"hello");
        drop(slow);
    }

    #[test]
    fn trickled_body_hits_total_frame_deadline() {
        let (addr, rx, _, _) = spawn_listener(short_limits(), 8);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&50u16.to_be_bytes()).unwrap();
        // One byte every 100 ms: each read is quick, but the frame is not.
        let start = Instant::now();
        let mut closed = false;
        for _ in 0..40 {
            if s.write_all(&[7u8]).is_err() {
                closed = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !closed {
            closed = closed_within(&mut s, 500);
        }
        assert!(closed, "server must close a trickling connection");
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(rx.try_recv().is_err(), "partial frame must not be queued");
    }

    #[test]
    fn idle_connection_closed_after_idle_limit() {
        let (addr, _rx, _, _) = spawn_listener(short_limits(), 8);
        let mut s = TcpStream::connect(addr).unwrap();
        let start = Instant::now();
        assert!(closed_within(&mut s, 3000));
        let el = start.elapsed();
        assert!(
            el >= Duration::from_millis(1200) && el < Duration::from_millis(2800),
            "{el:?}"
        );
    }

    #[test]
    fn connection_lifetime_is_capped() {
        let mut lim = short_limits();
        lim.idle = Duration::from_millis(900);
        lim.conn_lifetime = Duration::from_millis(1500);
        let (addr, rx, _, _) = spawn_listener(lim, 64);
        let mut s = TcpStream::connect(addr).unwrap();
        let start = Instant::now();
        // Keep sending valid frames well inside the idle window.
        let mut closed = false;
        for i in 0..40u8 {
            if write_framed_u16(&mut s, &[i]).is_err() {
                closed = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !closed {
            closed = closed_within(&mut s, 1000);
        }
        assert!(closed, "lifetime cap must close an active connection");
        assert!(start.elapsed() < Duration::from_secs(5));
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        assert!(n >= 1 && n < 40, "some frames served before cap: {n}");
    }

    #[test]
    fn excess_connections_refused_and_slots_released() {
        let (addr, rx, _, refused) = spawn_listener(short_limits(), 8);
        // Fill all slots with idle connections.
        let mut idle: Vec<TcpStream> = (0..4).map(|_| TcpStream::connect(addr).unwrap()).collect();
        thread::sleep(Duration::from_millis(100));
        let mut extra = TcpStream::connect(addr).unwrap();
        assert!(
            closed_within(&mut extra, 500),
            "over-cap connection must be closed"
        );
        assert!(refused.load(Ordering::Relaxed) >= 1);
        // Free the slots; a new peer is served again.
        idle.clear();
        thread::sleep(Duration::from_millis(200));
        let mut ok = TcpStream::connect(addr).unwrap();
        write_framed_u16(&mut ok, b"again").unwrap();
        assert_eq!(recv_within(&rx, 500).as_deref(), Some(&b"again"[..]));
    }

    #[test]
    fn slot_reservation_respects_cap() {
        let live = Arc::new(AtomicUsize::new(0));
        let a = try_reserve_slot(&live, 2).unwrap();
        let b = try_reserve_slot(&live, 2).unwrap();
        assert!(try_reserve_slot(&live, 2).is_none());
        drop(a);
        let c = try_reserve_slot(&live, 2).unwrap();
        assert_eq!(live.load(Ordering::Relaxed), 2);
        drop((b, c));
        assert_eq!(live.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn hs_inbound_queue_full_drops_not_unbounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Tiny cap so we can fill without many frames.
        let cap = 2usize;
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(cap);
        let drops = Arc::new(AtomicU64::new(0));
        let drops_t = Arc::clone(&drops);
        // Inline mini accept-loop with same backpressure semantics as production.
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                loop {
                    match read_framed_u16_max(&mut stream, MAX_HS_INBOUND_FRAME) {
                        Ok(frame) => match tx.try_send(frame) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                drops_t.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => return,
                        },
                        Err(_) => break,
                    }
                }
            }
        });

        let mut s = TcpStream::connect(addr).unwrap();
        for i in 0u8..8 {
            write_framed_u16(&mut s, &[i, i, i, i]).unwrap();
        }
        thread::sleep(Duration::from_millis(120));

        let mut queued = 0usize;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert!(queued <= cap, "queued={queued} cap={cap}");
        assert!(
            drops.load(Ordering::Relaxed) >= 1,
            "expected drops under backpressure"
        );
    }

    #[test]
    fn read_framed_respects_hs_max_constant() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            read_framed_u16_max(&mut client, MAX_HS_INBOUND_FRAME)
        });
        let mut s = TcpStream::connect(addr).unwrap();
        let over = ((MAX_HS_INBOUND_FRAME as u16) + 1).to_be_bytes();
        s.write_all(&over).unwrap();
        s.flush().unwrap();
        let err = handle.join().unwrap().unwrap_err();
        assert!(err.contains("bad frame length"), "unexpected: {err}");
    }
}
