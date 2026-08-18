//! Best-effort Tor SOCKS5 client + control-port probe.
//! Does not start Tor. Extreme mode should keep 127.0.0.1:9050 only.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct TorStatus {
    pub socks_ok: bool,
    pub control_ok: bool,
    pub note: String,
}

pub fn probe(socks_host: &str, socks_port: u16, control_port: u16) -> TorStatus {
    let socks_ok = TcpStream::connect_timeout(
        &format!("{socks_host}:{socks_port}")
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .unwrap_or_else(|| "127.0.0.1:9050".parse().unwrap()),
        Duration::from_millis(400),
    )
    .is_ok();
    let control_ok = TcpStream::connect_timeout(
        &format!("{socks_host}:{control_port}")
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .unwrap_or_else(|| "127.0.0.1:9051".parse().unwrap()),
        Duration::from_millis(400),
    )
    .is_ok();
    let note = match (socks_ok, control_ok) {
        (true, true) => "Tor SOCKS + control reachable".into(),
        (true, false) => "SOCKS up, control down (send may work)".into(),
        (false, _) => "Tor not reachable on 9050 — start tor before sending over the network".into(),
    };
    TorStatus {
        socks_ok,
        control_ok,
        note,
    }
}

/// SOCKS5 CONNECT through a local Tor client. `dest` is a hostname (v3 onion or DNS).
pub fn socks5_send(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let addr = format!("{proxy_host}:{proxy_port}")
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("proxy resolve")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;

    // greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    s.write_all(&[0x05, 0x01, 0x00]).map_err(|e| e.to_string())?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).map_err(|e| e.to_string())?;
    if greet[0] != 0x05 || greet[1] != 0x00 {
        return Err(format!("socks greet {:x?}", greet));
    }

    let host = dest_host.as_bytes();
    if host.len() > 255 {
        return Err("dest too long".into());
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&dest_port.to_be_bytes());
    s.write_all(&req).map_err(|e| e.to_string())?;

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).map_err(|e| e.to_string())?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(format!("socks connect rejected {:x?}", hdr));
    }
    match hdr[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut ln = [0u8; 1];
            s.read_exact(&mut ln).map_err(|e| e.to_string())?;
            let mut skip = vec![0u8; ln[0] as usize + 2];
            s.read_exact(&mut skip).map_err(|e| e.to_string())?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            s.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        _ => return Err("socks atyp".into()),
    }

    s.write_all(payload).map_err(|e| e.to_string())?;
    Ok(())
}
