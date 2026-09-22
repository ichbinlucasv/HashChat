//! Tor v3 hidden service via ControlPort + local framed TCP listener.
//!
//! M1: Cookie `AUTHENTICATE` only — never bare `AUTHENTICATE`. Fail closed if
//! COOKIEFILE is missing or the cookie is unreadable. Cookie bytes are never logged.
//!
//! The control TCP connection is kept open: Tor drops ephemeral onions when it closes.
//! When `ADD_ONION` returns `PrivateKey=`, callers must persist it only inside the
//! passphrase-wrapped session blob (H2 `onion_key`).

use crate::tor_socks::{is_loopback_host, read_framed_u16_max, MAX_SOCKS_FRAME};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_ACCEPT_IDLE_SECS: u64 = 30;

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
    authenticate_cookie_only(&mut control)?;
    let existing_str = existing_key.and_then(|b| std::str::from_utf8(b).ok());
    let (onion, privkey) = add_onion(&mut control, local_port, existing_str)?;

    let (tx, rx) = mpsc::sync_channel(HS_INBOUND_QUEUE_CAP);
    let drops = Arc::new(AtomicU64::new(0));
    let drops_thread = Arc::clone(&drops);
    thread::Builder::new()
        .name("hashchat-hs".into())
        .spawn(move || accept_loop(listener, tx, drops_thread))
        .map_err(|_| "listener thread failed".to_string())?;

    Ok((
        HiddenService {
            onion,
            local_port,
            rx,
            drops,
            _control: control,
        },
        privkey,
    ))
}

fn accept_loop(listener: TcpListener, tx: SyncSender<Vec<u8>>, drops: Arc<AtomicU64>) {
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(MAX_ACCEPT_IDLE_SECS)));
        let mut frames_this_conn: u32 = 0;
        loop {
            if frames_this_conn >= MAX_FRAMES_PER_CONN {
                // Soft per-connection budget exhausted — close stream.
                break;
            }
            match read_framed_u16_max(&mut stream, MAX_HS_INBOUND_FRAME) {
                Ok(frame) => {
                    frames_this_conn = frames_this_conn.saturating_add(1);
                    match tx.try_send(frame) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_dropped)) => {
                            // Backpressure: drop frame, never grow queue; no contents logged.
                            drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(TrySendError::Disconnected(_dropped)) => return,
                    }
                }
                Err(_) => break, // includes oversize / idle timeout / EOF → close stream
            }
        }
    }
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
fn authenticate_cookie_only(s: &mut TcpStream) -> Result<(), String> {
    let info = control_cmd(s, "PROTOCOLINFO 1")?;
    let path = cookie_path_from_protocolinfo(&info).ok_or_else(|| {
        "Tor control: no COOKIEFILE in PROTOCOLINFO (fail-closed; refusing bare AUTHENTICATE)"
            .to_string()
    })?;
    let raw = std::fs::read(&path).map_err(|_| {
        format!("Tor control cookie unreadable (fail-closed)")
    })?;
    if raw.is_empty() {
        return Err("Tor control cookie empty (fail-closed)".into());
    }
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    // OPSEC: hex is sent to ControlPort only — never logged.
    let resp = control_cmd(s, &format!("AUTHENTICATE {hex}"))?;
    if resp.iter().any(|l| l.starts_with("250")) {
        Ok(())
    } else {
        Err("Tor cookie authentication failed".into())
    }
}

/// Parse `COOKIEFILE="…"` from PROTOCOLINFO lines (unit-tested).
pub fn cookie_path_from_protocolinfo(lines: &[String]) -> Option<String> {
    for line in lines {
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
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => "NEW:ED25519-V3".to_string(),
    };
    // Intentionally no DiscardPK: we persist PrivateKey inside the wrapped blob (H2).
    let cmd = format!("ADD_ONION {spec} Port=80,127.0.0.1:{local_port}");
    let resp = control_cmd(s, &cmd)?;
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
    match onion {
        Some(o) => Ok((o, privkey)),
        None => {
            if resp.iter().any(|l| l.starts_with('5')) {
                Err("ADD_ONION rejected by Tor".into())
            } else {
                Err("ADD_ONION failed (no ServiceID)".into())
            }
        }
    }
}

fn control_cmd(s: &mut TcpStream, cmd: &str) -> Result<Vec<String>, String> {
    s.write_all(cmd.as_bytes())
        .map_err(|_| "control write failed".to_string())?;
    s.write_all(b"\r\n")
        .map_err(|_| "control write failed".to_string())?;
    s.flush()
        .map_err(|_| "control flush failed".to_string())?;
    let mut reader = BufReader::new(s.try_clone().map_err(|_| "control clone failed".to_string())?);
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|_| "control read failed".to_string())?;
        if n == 0 {
            break;
        }
        let t = line.trim_end_matches(['\r', '\n']).to_string();
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
    use std::time::Duration;

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
        let drops_t = Arc::clone(&drops);
        thread::spawn(move || accept_loop(listener, tx, drops_t));

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
