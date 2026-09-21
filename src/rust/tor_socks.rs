//! Tor SOCKS5 client with fail-closed anonymity policy (audit H4).
//!
//! - Proxy host must be loopback only (`127.0.0.0/8`, `::1`, `localhost`).
//! - Destination must be a Tor v3 `.onion` (length-checked).
//! - No clearnet fallback. Does not start Tor.

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

/// SOCKS5 CONNECT (no-auth) through a loopback Tor client to a `.onion` destination.
pub fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
) -> Result<TcpStream, String> {
    if !is_loopback_host(proxy_host) {
        return Err(format!("SOCKS proxy refused (not loopback)"));
    }
    if !is_onion_destination(dest_host) {
        return Err("destination refused (need v3 .onion)".into());
    }

    let addr = format!("{proxy_host}:{proxy_port}")
        .to_socket_addrs()
        .map_err(|_| "SOCKS resolve failed".to_string())?
        .next()
        .ok_or_else(|| "SOCKS resolve empty".to_string())?;
    let mut s =
        TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|_| "SOCKS connect failed".to_string())?;
    // Onion circuits can be slow on first use.
    let _ = s.set_write_timeout(Some(Duration::from_secs(45)));
    let _ = s.set_read_timeout(Some(Duration::from_secs(45)));

    s.write_all(&[0x05, 0x01, 0x00])
        .map_err(|_| "SOCKS greet write failed".to_string())?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)
        .map_err(|_| "SOCKS greet read failed".to_string())?;
    if greet[0] != 0x05 || greet[1] != 0x00 {
        return Err("SOCKS auth negotiation failed".into());
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

/// Read a 2-byte BE length-prefixed frame.
pub fn read_framed_u16(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut ln = [0u8; 2];
    stream
        .read_exact(&mut ln)
        .map_err(|_| "frame length read failed".to_string())?;
    let n = u16::from_be_bytes(ln) as usize;
    if n == 0 || n > MAX_SOCKS_FRAME {
        return Err("bad frame length".into());
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|_| "frame body read failed".to_string())?;
    Ok(buf)
}

/// CONNECT via SOCKS then send one length-prefixed ciphertext blob.
pub fn socks5_send(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let mut s = socks5_connect(proxy_host, proxy_port, dest_host, dest_port)?;
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
        let err = socks5_send("8.8.8.8", 9050, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion", 80, b"x")
            .unwrap_err();
        assert!(err.contains("loopback"));
    }

    #[test]
    fn socks_send_refuses_clearnet_dest() {
        let err = socks5_send("127.0.0.1", 9050, "example.com", 80, b"x").unwrap_err();
        assert!(err.contains(".onion"));
    }
}
