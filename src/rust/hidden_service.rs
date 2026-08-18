//! Tor v3 hidden service via the control port + a local framed TCP listener.
//! The control connection is kept open: Tor drops ephemeral onions when it closes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const MAX_FRAME: usize = 256 * 1024;

pub struct HiddenService {
    pub onion: String,
    pub local_port: u16,
    rx: Receiver<Vec<u8>>,
    /// Must stay open or Tor forgets the onion.
    _control: TcpStream,
}

impl HiddenService {
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }
}

pub fn start_hidden_service(control_host: &str, control_port: u16) -> Result<HiddenService, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener
        .set_nonblocking(false)
        .map_err(|e| e.to_string())?;
    let local_port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let mut control = connect_control(control_host, control_port)?;
    authenticate(&mut control)?;
    let onion = add_onion(&mut control, local_port)?;

    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("hashchat-hs".into())
        .spawn(move || accept_loop(listener, tx))
        .map_err(|e| e.to_string())?;

    Ok(HiddenService {
        onion,
        local_port,
        rx,
        _control: control,
    })
}

pub fn write_framed(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_FRAME {
        return Err("frame too large".into());
    }
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| e.to_string())?;
    stream.write_all(payload).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

pub fn read_framed(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut ln = [0u8; 4];
    stream.read_exact(&mut ln).map_err(|e| e.to_string())?;
    let n = u32::from_be_bytes(ln) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(format!("bad frame len {n}"));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn accept_loop(listener: TcpListener, tx: mpsc::Sender<Vec<u8>>) {
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        loop {
            match read_framed(&mut stream) {
                Ok(frame) => {
                    if tx.send(frame).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn connect_control(host: &str, port: u16) -> Result<TcpStream, String> {
    let s = TcpStream::connect_timeout(
        &format!("{host}:{port}").parse().map_err(|e| format!("{e}"))?,
        Duration::from_secs(2),
    )
    .map_err(|e| format!("control {host}:{port}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    Ok(s)
}

fn authenticate(s: &mut TcpStream) -> Result<(), String> {
    let info = control_cmd(s, "PROTOCOLINFO")?;
    if let Some(path) = cookie_path_from_protocolinfo(&info) {
        if let Ok(raw) = std::fs::read(&path) {
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let resp = control_cmd(s, &format!("AUTHENTICATE {hex}"))?;
            if resp.iter().any(|l| l.starts_with("250")) {
                return Ok(());
            }
        }
    }
    let resp = control_cmd(s, "AUTHENTICATE")?;
    if resp.iter().any(|l| l.starts_with("250")) {
        return Ok(());
    }
    Err(format!("control auth failed: {resp:?}"))
}

fn cookie_path_from_protocolinfo(lines: &[String]) -> Option<String> {
    for line in lines {
        if let Some(idx) = line.find("COOKIEFILE=") {
            let rest = &line[idx + 11..];
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

fn add_onion(s: &mut TcpStream, local_port: u16) -> Result<String, String> {
    let cmd = format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:{local_port}");
    let resp = control_cmd(s, &cmd)?;
    for line in &resp {
        if let Some(id) = line.strip_prefix("250-ServiceID=") {
            return Ok(format!("{id}.onion"));
        }
    }
    Err(format!("ADD_ONION failed: {resp:?}"))
}

fn control_cmd(s: &mut TcpStream, cmd: &str) -> Result<Vec<String>, String> {
    s.write_all(cmd.as_bytes()).map_err(|e| e.to_string())?;
    s.write_all(b"\r\n").map_err(|e| e.to_string())?;
    s.flush().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let t = line.trim_end_matches(['\r', '\n']).to_string();
        let done = t.starts_with("250 ") || t.starts_with("5");
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

    #[test]
    fn parses_cookiefile() {
        let lines = vec![
            "250-PROTOCOLINFO 1".into(),
            "250-AUTH METHODS=COOKIE COOKIEFILE=\"/run/tor/control.authcookie\"".into(),
            "250 OK".into(),
        ];
        assert_eq!(
            cookie_path_from_protocolinfo(&lines).as_deref(),
            Some("/run/tor/control.authcookie")
        );
    }
}
