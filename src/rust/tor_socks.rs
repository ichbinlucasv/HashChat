//! Tor SOCKS5 client with fail-closed anonymity policy (audit H4).
//!
//! - Proxy host must be loopback only (`127.0.0.0/8`, `::1`, `localhost`).
//! - Destination must be a Tor v3 `.onion` (length-checked).
//! - Outbound CONNECT may use RFC1929 username/password (default on) so Tor
//!   `IsolateSOCKSAuth` isolates circuits per contact; optional off via prefs.
//! - No clearnet fallback. Does not start Tor. Credentials are never logged.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Max payload for the 2-byte length-prefixed transport frame (matches Haskell Tor.hs).
pub const MAX_SOCKS_FRAME: usize = u16::MAX as usize;

/// H4: SOCKS proxy must be loopback only.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h == "localhost" || h == "::1" || h == "[::1]" {
        return true;
    }
    // IPv4 127.0.0.0/8
    if let Some(rest) = h.strip_prefix("127.") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    }
    false
}

/// H4: outbound destinations must be Tor v3 onions (host part before optional `:port`).
pub fn is_onion_destination(dest: &str) -> bool {
    let host = dest
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(dest)
        .trim()
        .to_ascii_lowercase();
    // v3 onion: 56 base32 chars + ".onion" => 62
    host.ends_with(".onion") && host.len() >= 62 && host.len() <= 70
}

#[derive(Clone, Debug)]
pub struct TorProbe {
    pub socks_ok: bool,
    pub control_ok: bool,
    pub note: String,
}

/// Best-effort reachability probe (does not authenticate).
pub fn probe(socks_host: &str, socks_port: u16, control_port: u16) -> TorProbe {
    let socks_ok = if is_loopback_host(socks_host) {
        tcp_up(socks_host, socks_port, 400)
    } else {
        false
    };
    let control_ok = if is_loopback_host(socks_host) {
        tcp_up(socks_host, control_port, 400)
    } else {
        false
    };
    let note = match (socks_ok, control_ok) {
        (true, true) => "Tor SOCKS + ControlPort reachable".into(),
        (true, false) => "SOCKS up; ControlPort down (send may work; :listen needs control)".into(),
        (false, true) => "ControlPort up; SOCKS down".into(),
        (false, false) => "Tor not reachable on loopback SOCKS/ControlPort".into(),
    };
    TorProbe {
        socks_ok,
        control_ok,
        note,
    }
}

fn tcp_up(host: &str, port: u16, ms: u64) -> bool {
    let addr = match format!("{host}:{port}").to_socket_addrs() {
        Ok(mut a) => match a.next() {
            Some(x) => x,
            None => return false,
        },
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(ms)).is_ok()
}

/// Opaque SOCKS5 RFC1929 tags for Tor `IsolateSOCKSAuth`.
///
/// Not a shared secret and not suitable as authentication. `Debug` redacts
/// values so credentials never appear in logs or panic output.
#[derive(Clone, PartialEq, Eq)]
pub struct SocksIsolationCreds {
    username: String,
    password: String,
}

impl SocksIsolationCreds {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    fn from_digest(dig: &[u8]) -> Self {
        // 8+8 bytes → 16+16 hex chars (well under SOCKS5 255-byte limit).
        Self {
            username: hex_lower(&dig[0..8]),
            password: hex_lower(&dig[8..16]),
        }
    }
}

impl std::fmt::Debug for SocksIsolationCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SocksIsolationCreds { username: [REDACTED], password: [REDACTED] }")
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn isol_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for p in parts {
        hasher.update(p);
    }
    let dig = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

/// Domain-separated isolation tags from contact id + local identity seed.
///
/// Seed is mixed in so predictable local ids (`c1`, `c2`, …) do not collide
/// across identities. Callers must never log seed or the returned credentials.
pub fn socks_isolation_for_contact(contact_id: &str, local_seed: &[u8; 32]) -> SocksIsolationCreds {
    let dig = isol_digest(
        b"hashchat-socks-isol-v1\0contact\0",
        &[local_seed.as_slice(), contact_id.as_bytes()],
    );
    SocksIsolationCreds::from_digest(&dig)
}

/// Fallback isolation tags from destination v3 onion (pending-queue retries).
///
/// Prefer [`socks_isolation_for_contact`] when contact id + seed are available.
/// Fails closed if `dest` is not a v3 `.onion`.
pub fn socks_isolation_for_onion(dest: &str) -> Result<SocksIsolationCreds, String> {
    if !is_onion_destination(dest) {
        return Err("destination refused (need v3 .onion)".into());
    }
    let host = dest
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(dest)
        .trim()
        .to_ascii_lowercase();
    let dig = isol_digest(b"hashchat-socks-isol-v1\0onion\0", &[host.as_bytes()]);
    Ok(SocksIsolationCreds::from_digest(&dig))
}

/// Alias kept for callers/tests that pass a destination onion.
pub fn socks_isolation_credentials(dest: &str) -> Result<(String, String), String> {
    let c = socks_isolation_for_onion(dest)?;
    Ok((c.username.clone(), c.password.clone()))
}

/// SOCKS5 CONNECT through a loopback Tor client to a `.onion` destination.
///
/// When `isolation` is `Some`, negotiates RFC1929 username/password so Tor
/// `IsolateSOCKSAuth` (default SocksPort) opens a distinct circuit. When
/// `None`, uses no-auth (shared circuit pool). Fail-closed: refuses
/// non-loopback proxies and non-onion destinations before any handshake.
pub fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    isolation: Option<&SocksIsolationCreds>,
) -> Result<TcpStream, String> {
    match isolation {
        Some(c) => socks5_connect_with_auth(
            proxy_host,
            proxy_port,
            dest_host,
            dest_port,
            c.username.as_bytes(),
            c.password.as_bytes(),
        ),
        None => socks5_connect_no_auth(proxy_host, proxy_port, dest_host, dest_port),
    }
}

/// SOCKS5 CONNECT with no-auth method `0x00` (isolation off).
pub fn socks5_connect_no_auth(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
) -> Result<TcpStream, String> {
    socks5_handshake(proxy_host, proxy_port, dest_host, dest_port, None)
}

/// SOCKS5 CONNECT with explicit RFC1929 credentials (loopback + onion only).
///
/// Prefer [`socks5_connect`] for messenger sends. This entry point exists for
/// tests and callers that already hold isolation tags. Credentials must be
/// 1..=255 bytes each; they are never written to logs here.
pub fn socks5_connect_with_auth(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    username: &[u8],
    password: &[u8],
) -> Result<TcpStream, String> {
    if username.is_empty() || username.len() > 255 || password.is_empty() || password.len() > 255 {
        return Err("SOCKS isolation credentials length invalid".into());
    }
    socks5_handshake(
        proxy_host,
        proxy_port,
        dest_host,
        dest_port,
        Some((username, password)),
    )
}

fn socks5_handshake(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    userpass: Option<(&[u8], &[u8])>,
) -> Result<TcpStream, String> {
    if !is_loopback_host(proxy_host) {
        return Err("SOCKS proxy refused (not loopback)".into());
    }
    if !is_onion_destination(dest_host) {
        return Err("destination refused (need v3 .onion)".into());
    }

    let addr = format!("{proxy_host}:{proxy_port}")
        .to_socket_addrs()
        .map_err(|_| "SOCKS resolve failed".to_string())?
        .next()
        .ok_or_else(|| "SOCKS resolve empty".to_string())?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .map_err(|_| "SOCKS connect failed".to_string())?;
    // Onion circuits can be slow on first use.
    let _ = s.set_write_timeout(Some(Duration::from_secs(45)));
    let _ = s.set_read_timeout(Some(Duration::from_secs(45)));

    match userpass {
        Some((username, password)) => {
            // Offer username/password only (0x02) so Tor must select IsolateSOCKSAuth path.
            s.write_all(&[0x05, 0x01, 0x02])
                .map_err(|_| "SOCKS greet write failed".to_string())?;
            let mut greet = [0u8; 2];
            s.read_exact(&mut greet)
                .map_err(|_| "SOCKS greet read failed".to_string())?;
            if greet[0] != 0x05 || greet[1] != 0x02 {
                return Err("SOCKS auth negotiation failed".into());
            }
            // RFC1929 sub-negotiation (version 0x01). Credentials never logged.
            let mut auth = Vec::with_capacity(3 + username.len() + password.len());
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            s.write_all(&auth)
                .map_err(|_| "SOCKS auth write failed".to_string())?;
            let mut auth_rep = [0u8; 2];
            s.read_exact(&mut auth_rep)
                .map_err(|_| "SOCKS auth read failed".to_string())?;
            if auth_rep[0] != 0x01 || auth_rep[1] != 0x00 {
                return Err("SOCKS auth rejected".into());
            }
        }
        None => {
            s.write_all(&[0x05, 0x01, 0x00])
                .map_err(|_| "SOCKS greet write failed".to_string())?;
            let mut greet = [0u8; 2];
            s.read_exact(&mut greet)
                .map_err(|_| "SOCKS greet read failed".to_string())?;
            if greet[0] != 0x05 || greet[1] != 0x00 {
                return Err("SOCKS auth negotiation failed".into());
            }
        }
    }

    let host = dest_host
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(dest_host)
        .as_bytes();
    if host.is_empty() || host.len() > 255 {
        return Err("onion host length invalid".into());
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&dest_port.to_be_bytes());
    s.write_all(&req)
        .map_err(|_| "SOCKS CONNECT write failed".to_string())?;

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)
        .map_err(|_| "SOCKS CONNECT reply failed".to_string())?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err("SOCKS CONNECT rejected".into());
    }
    match hdr[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest)
                .map_err(|_| "SOCKS reply addr failed".to_string())?;
        }
        0x03 => {
            let mut ln = [0u8; 1];
            s.read_exact(&mut ln)
                .map_err(|_| "SOCKS reply addr failed".to_string())?;
            let mut skip = vec![0u8; ln[0] as usize + 2];
            s.read_exact(&mut skip)
                .map_err(|_| "SOCKS reply addr failed".to_string())?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            s.read_exact(&mut rest)
                .map_err(|_| "SOCKS reply addr failed".to_string())?;
        }
        _ => return Err("SOCKS reply ATYP unknown".into()),
    }
    Ok(s)
}

/// Write a 2-byte BE length-prefixed frame (Haskell Tor.hs compatible).
pub fn write_framed_u16(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_SOCKS_FRAME {
        return Err("frame too large".into());
    }
    let len = (payload.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|_| "frame length write failed".to_string())?;
    stream
        .write_all(payload)
        .map_err(|_| "frame body write failed".to_string())?;
    stream
        .flush()
        .map_err(|_| "frame flush failed".to_string())
}

/// Read a 2-byte BE length-prefixed frame with an explicit max body length.
///
/// On oversize / zero length: returns `Err` **without** reading the body
/// (caller should close the stream). `max_len` should be ≤ `MAX_SOCKS_FRAME`.
pub fn read_framed_u16_max(stream: &mut TcpStream, max_len: usize) -> Result<Vec<u8>, String> {
    let cap = max_len.min(MAX_SOCKS_FRAME);
    let mut ln = [0u8; 2];
    stream
        .read_exact(&mut ln)
        .map_err(|_| "frame length read failed".to_string())?;
    let n = u16::from_be_bytes(ln) as usize;
    if n == 0 || n > cap {
        // Do not allocate or drain the claimed body — close the connection.
        return Err("bad frame length".into());
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|_| "frame body read failed".to_string())?;
    Ok(buf)
}

/// Read a 2-byte BE length-prefixed frame (cap = `MAX_SOCKS_FRAME`).
pub fn read_framed_u16(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    read_framed_u16_max(stream, MAX_SOCKS_FRAME)
}

/// CONNECT via SOCKS then send one length-prefixed ciphertext blob.
///
/// Pass `Some(creds)` for per-contact Tor circuit isolation; `None` for no-auth.
pub fn socks5_send(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    payload: &[u8],
    isolation: Option<&SocksIsolationCreds>,
) -> Result<(), String> {
    let mut s = socks5_connect(proxy_host, proxy_port, dest_host, dest_port, isolation)?;
    write_framed_u16(&mut s, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_accepted() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
    }

    #[test]
    fn non_loopback_hosts_refused() {
        assert!(!is_loopback_host("8.8.8.8"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("socks.example.com"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host(""));
    }

    #[test]
    fn onion_destination_checks() {
        let v3 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        assert!(is_onion_destination(v3));
        assert!(is_onion_destination(&format!("{v3}:80")));
        assert!(!is_onion_destination("example.com"));
        assert!(!is_onion_destination("short.onion"));
        assert!(!is_onion_destination("not-an-onion"));
    }

    #[test]
    fn socks_send_refuses_non_loopback_without_connect() {
        let err = socks5_send(
            "8.8.8.8",
            9050,
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion",
            80,
            b"x",
            None,
        )
        .unwrap_err();
        assert!(err.contains("loopback"));
    }

    #[test]
    fn socks_send_refuses_clearnet_dest() {
        let err = socks5_send("127.0.0.1", 9050, "example.com", 80, b"x", None).unwrap_err();
        assert!(err.contains(".onion"));
    }

    #[test]
    fn socks_connect_refuses_non_onion_ip_without_connect() {
        // Must fail closed on clearnet IP before any SOCKS handshake / network use.
        let err = socks5_connect("127.0.0.1", 9050, "8.8.8.8", 443, None).unwrap_err();
        assert!(err.contains(".onion"), "unexpected: {err}");
    }

    #[test]
    fn onion_destination_refuses_clearnet_and_short_onion() {
        assert!(!is_onion_destination("1.2.3.4"));
        assert!(!is_onion_destination("1.2.3.4:443"));
        assert!(!is_onion_destination("example.org:443"));
        // Too short to be v3 even with .onion suffix.
        assert!(!is_onion_destination("abcd.onion"));
        assert!(!is_onion_destination("abcd.onion:80"));
    }

    #[test]
    fn framed_u16_tcp_roundtrip() {
        use std::net::TcpListener;
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = b"wire-v2-ciphertext-blob".to_vec();
        let handle = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            read_framed_u16(&mut client).unwrap()
        });
        let mut s = TcpStream::connect(addr).unwrap();
        write_framed_u16(&mut s, &payload).unwrap();
        assert_eq!(handle.join().unwrap(), payload);
    }

    #[test]
    fn framed_u16_max_rejects_oversize_without_body_alloc() {
        use std::net::TcpListener;
        use std::thread;
        // Cap far below u16::MAX so we can advertise an oversize length.
        const CAP: usize = 64;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            read_framed_u16_max(&mut client, CAP)
        });
        let mut s = TcpStream::connect(addr).unwrap();
        // Length = CAP+1; no body bytes written — reader must reject before read_exact body.
        let over = ((CAP as u16) + 1).to_be_bytes();
        s.write_all(&over).unwrap();
        s.flush().unwrap();
        let err = handle.join().unwrap().unwrap_err();
        assert!(err.contains("bad frame length"), "unexpected: {err}");
    }

    #[test]
    fn framed_u16_max_rejects_zero_length() {
        use std::net::TcpListener;
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            read_framed_u16_max(&mut client, 1024)
        });
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&0u16.to_be_bytes()).unwrap();
        s.flush().unwrap();
        let err = handle.join().unwrap().unwrap_err();
        assert!(err.contains("bad frame length"), "unexpected: {err}");
    }

    #[test]
    fn socks_isolation_for_contact_stable_and_distinct() {
        let seed_a = [0x11u8; 32];
        let seed_b = [0x22u8; 32];
        let c1 = socks_isolation_for_contact("c1", &seed_a);
        let c1b = socks_isolation_for_contact("c1", &seed_a);
        let c2 = socks_isolation_for_contact("c2", &seed_a);
        let c1_other = socks_isolation_for_contact("c1", &seed_b);
        assert_eq!(c1, c1b);
        assert_ne!(c1, c2);
        assert_ne!(c1, c1_other);
        assert_eq!(c1.username().len(), 16);
        assert_eq!(c1.password().len(), 16);
        // Debug must never leak credential bytes.
        let dbg = format!("{c1:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(c1.username()));
        assert!(!dbg.contains(c1.password()));
    }

    #[test]
    fn socks_isolation_credentials_deterministic_and_distinct() {
        let a = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        let b = "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.onion";
        let ca = socks_isolation_for_onion(a).unwrap();
        let ca2 = socks_isolation_for_onion(a).unwrap();
        let cb = socks_isolation_for_onion(b).unwrap();
        assert_eq!(ca, ca2);
        assert_ne!(ca, cb);
        let ca_p = socks_isolation_for_onion(&format!("{a}:80")).unwrap();
        assert_eq!(ca_p, ca);
        let (ua, pa) = socks_isolation_credentials(a).unwrap();
        assert_eq!(ua, ca.username());
        assert_eq!(pa, ca.password());
    }

    #[test]
    fn socks_isolation_credentials_refuse_clearnet() {
        let err = socks_isolation_for_onion("example.com").unwrap_err();
        assert!(err.contains(".onion"), "unexpected: {err}");
    }

    #[test]
    fn socks5_connect_with_auth_refuses_empty_credentials_without_connect() {
        let onion = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        let err = socks5_connect_with_auth("127.0.0.1", 9050, onion, 80, b"", b"x").unwrap_err();
        assert!(err.contains("credentials"), "unexpected: {err}");
    }

    #[test]
    fn socks5_isolated_handshake_against_local_mock() {
        use std::net::TcpListener;
        use std::thread;
        let onion = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        let creds = socks_isolation_for_onion(onion).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expect_user = creds.username().to_string();
        let expect_pass = creds.password().to_string();
        let handle = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut greet = [0u8; 3];
            client.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x02]);
            client.write_all(&[0x05, 0x02]).unwrap();
            let mut ver = [0u8; 1];
            client.read_exact(&mut ver).unwrap();
            assert_eq!(ver[0], 0x01);
            let mut ulen = [0u8; 1];
            client.read_exact(&mut ulen).unwrap();
            let mut ubuf = vec![0u8; ulen[0] as usize];
            client.read_exact(&mut ubuf).unwrap();
            let mut plen = [0u8; 1];
            client.read_exact(&mut plen).unwrap();
            let mut pbuf = vec![0u8; plen[0] as usize];
            client.read_exact(&mut pbuf).unwrap();
            assert_eq!(ubuf, expect_user.as_bytes());
            assert_eq!(pbuf, expect_pass.as_bytes());
            client.write_all(&[0x01, 0x00]).unwrap();
            // CONNECT: VER CMD RSV ATYP
            let mut hdr = [0u8; 4];
            client.read_exact(&mut hdr).unwrap();
            assert_eq!(&[0x05, 0x01, 0x00, 0x03], &hdr);
            let mut ln = [0u8; 1];
            client.read_exact(&mut ln).unwrap();
            let mut hostport = vec![0u8; ln[0] as usize + 2];
            client.read_exact(&mut hostport).unwrap();
            // Success + IPv4 0.0.0.0:0
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            "ok".to_string()
        });
        let stream = socks5_connect("127.0.0.1", addr.port(), onion, 80, Some(&creds)).unwrap();
        drop(stream);
        assert_eq!(handle.join().unwrap(), "ok");
    }

    #[test]
    fn socks5_no_auth_handshake_against_local_mock() {
        use std::net::TcpListener;
        use std::thread;
        let onion = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut greet = [0u8; 3];
            client.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00]);
            client.write_all(&[0x05, 0x00]).unwrap();
            let mut hdr = [0u8; 4];
            client.read_exact(&mut hdr).unwrap();
            assert_eq!(&[0x05, 0x01, 0x00, 0x03], &hdr);
            let mut ln = [0u8; 1];
            client.read_exact(&mut ln).unwrap();
            let mut hostport = vec![0u8; ln[0] as usize + 2];
            client.read_exact(&mut hostport).unwrap();
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            "ok".to_string()
        });
        let stream = socks5_connect("127.0.0.1", addr.port(), onion, 80, None).unwrap();
        drop(stream);
        assert_eq!(handle.join().unwrap(), "ok");
    }
}
