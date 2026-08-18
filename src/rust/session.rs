//! Burner profiles, contact QR/links, X3DH bootstrap, persist, wipe.

use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::{decrypt_with_key, encrypt_with_key, DoubleRatchet};
use crate::wire::{frame_v2, unframe};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub struct Contact {
    pub name: String,
    pub onion: String,
    pub x25519: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ChatMsg {
    pub from_me: bool,
    pub text: String,
    pub step: u32,
}

pub struct Session {
    pub profile: String,
    pub contacts: Vec<Contact>,
    pub current: usize,
    pub messages: HashMap<String, Vec<ChatMsg>>,
    pub ratchets: HashMap<String, DoubleRatchet>,
    pub longterm: LongTermIdentity,
    pub extreme: bool,
    pub logs: Vec<String>,
    pub onion: Option<String>,
    pub onion_key: Option<String>,
    pub pending: Vec<(String, Vec<u8>)>,
}

impl Session {
    pub fn burner() -> Self {
        let mut s = Session {
            profile: format!("burner-{}", &hex_short(&rand_bytes())[..8]),
            contacts: Vec::new(),
            current: 0,
            messages: HashMap::new(),
            ratchets: HashMap::new(),
            longterm: LongTermIdentity::generate(),
            extreme: false,
            logs: Vec::new(),
            onion: None,
            onion_key: None,
            pending: Vec::new(),
        };
        s.log("burner profile created — add a peer with :add-contact <link>");
        s
    }

    pub fn open() -> Self {
        match Self::load_disk() {
            Some(s) => s,
            None => Self::burner(),
        }
    }

    pub fn log(&mut self, line: impl Into<String>) {
        let line = line.into();
        if self.logs.len() > 80 {
            self.logs.remove(0);
        }
        self.logs.push(line);
    }

    pub fn current_contact(&self) -> Option<&Contact> {
        self.contacts.get(self.current)
    }

    pub fn next_contact(&mut self) {
        if !self.contacts.is_empty() {
            self.current = (self.current + 1) % self.contacts.len();
        }
    }

    pub fn prev_contact(&mut self) {
        if !self.contacts.is_empty() {
            self.current = if self.current == 0 {
                self.contacts.len() - 1
            } else {
                self.current - 1
            };
        }
    }

    pub fn my_x25519(&self) -> [u8; 32] {
        *self.longterm.x25519_public().as_bytes()
    }

    pub fn my_contact_link(&self) -> String {
        let onion = self.onion.as_deref().unwrap_or("offline.onion");
        format_contact_link(onion, &self.my_x25519())
    }

    /// Parse a peer link, store the contact, init a symmetric ratchet from X25519 DH.
    pub fn add_contact_link(&mut self, raw: &str) -> Result<String, &'static str> {
        if self.extreme {
            return Err("extreme: contact add refused");
        }
        let (onion, x25519) = parse_contact_link(raw)?;
        if onion == "offline.onion" || onion == "local.onion" {
            return Err("peer has no onion yet — they must :listen first");
        }
        if Some(&onion) == self.onion.as_ref() {
            return Err("that is your own link");
        }
        let name = format!("peer-{}", &hex_encode(&x25519)[..8]);
        if self.contacts.iter().any(|c| c.onion == onion || c.x25519 == x25519) {
            return Err("contact already added");
        }
        let peer = X25519Public::from(x25519);
        let shared = self.longterm.x25519_dh(&peer);
        let mut r = DoubleRatchet::new();
        r.init_symmetric(&shared);
        self.ratchets.insert(name.clone(), r);
        self.contacts.push(Contact {
            name: name.clone(),
            onion,
            x25519,
        });
        self.current = self.contacts.len() - 1;
        self.log(format!("added {name}"));
        Ok(name)
    }

    pub fn send_text(&mut self, text: &str) -> Result<Vec<u8>, &'static str> {
        if self.extreme {
            return Err("extreme: send refused");
        }
        let name = self
            .current_contact()
            .map(|c| c.name.clone())
            .ok_or("no contact — :add-contact <link>")?;
        let r = self
            .ratchets
            .entry(name.clone())
            .or_insert_with(DoubleRatchet::new);
        let (mut key, step) = r.ratchet_send();
        let dh = *r.public_key().as_bytes();
        let ct = encrypt_with_key(&key, text.as_bytes())?;
        key.zeroize();
        let frame = frame_v2(&self.my_x25519(), step, &dh, &ct);
        self.messages.entry(name).or_default().push(ChatMsg {
            from_me: true,
            text: text.to_string(),
            step,
        });
        Ok(frame)
    }

    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<String, &'static str> {
        let parsed = unframe(frame).ok_or("bad frame")?;
        if parsed.hint.len() != 32 {
            return Err("bad hint");
        }
        let mut hx = [0u8; 32];
        hx.copy_from_slice(&parsed.hint);
        let name = self
            .contacts
            .iter()
            .find(|c| c.x25519 == hx)
            .map(|c| c.name.clone())
            .ok_or("unknown sender — add their :my-contact link first")?;
        let r = self.ratchets.get_mut(&name).ok_or("no ratchet")?;
        let remote = match parsed.sender_dh {
            Some(dh) => x25519_dalek::PublicKey::from(dh),
            None => r.public_key(),
        };
        let (mut key, step) = r.ratchet_recv(&remote);
        let ct = parsed.ciphertext;
        let pt = decrypt_with_key(&key, &ct)?;
        key.zeroize();
        let text = String::from_utf8(pt).map_err(|_| "utf8")?;
        self.messages.entry(name.clone()).or_default().push(ChatMsg {
            from_me: false,
            text: text.clone(),
            step,
        });
        if let Some(i) = self.contacts.iter().position(|c| c.name == name) {
            self.current = i;
        }
        Ok(text)
    }

    pub fn selftest(&mut self) -> Result<String, &'static str> {
        let a = LongTermIdentity::generate();
        let b = LongTermIdentity::generate();
        let sa = a.x25519_dh(&b.x25519_public());
        let sb = b.x25519_dh(&a.x25519_public());
        if sa != sb {
            return Err("dh not commutative");
        }
        let mut ra = DoubleRatchet::new();
        let mut rb = DoubleRatchet::new();
        ra.init_symmetric(&sa);
        rb.init_symmetric(&sb);
        let (mut k, step) = ra.ratchet_send();
        let dh = *ra.public_key().as_bytes();
        let ct = encrypt_with_key(&k, b"hashchat-rust-e2ee")?;
        k.zeroize();
        let frame = frame_v2(a.x25519_public().as_bytes(), step, &dh, &ct);
        let parsed = unframe(&frame).ok_or("frame")?;
        assert_eq!(parsed.hint, a.x25519_public().as_bytes());
        let remote = x25519_dalek::PublicKey::from(parsed.sender_dh.unwrap());
        let (mut k2, _) = rb.ratchet_recv(&remote);
        let pt = decrypt_with_key(&k2, &parsed.ciphertext)?;
        k2.zeroize();
        if pt != b"hashchat-rust-e2ee" {
            return Err("selftest mismatch");
        }
        Ok("E2EE selftest ok (X25519 DH + symmetric ratchet + frame)".into())
    }

    pub fn nuclear_wipe(&mut self) {
        for r in self.ratchets.values_mut() {
            r.zeroize();
        }
        self.ratchets.clear();
        self.messages.clear();
        self.longterm.wipe();
        self.onion = None;
        self.onion_key = None;
        self.pending.clear();
        let _ = remove_tree("hashchat_data");
        let _ = remove_tree("tor/hidden_service");
        crate::rust_wipe_files();
        self.profile = "wiped".into();
        self.contacts.clear();
        self.log("nuclear wipe: ratchets zeroized, hashchat_data removed");
    }

    pub fn queue_outgoing(&mut self, onion: String, frame: Vec<u8>) {
        if self.pending.len() < 64 {
            self.pending.push((onion, frame));
        }
        self.log(format!("queued ({} waiting)", self.pending.len()));
    }

    pub fn take_pending(&mut self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut self.pending)
    }

    pub fn save_disk(&self) -> Result<(), &'static str> {
        fs::create_dir_all("hashchat_data").map_err(|_| "mkdir")?;
        let key = machine_key()?;
        let mut plain = Vec::new();
        plain.push(1u8);
        plain.extend_from_slice(&self.longterm.to_bytes());
        let onion = self.onion.clone().unwrap_or_default();
        let ok = self.onion_key.clone().unwrap_or_default();
        write_len_str(&mut plain, &onion);
        write_len_str(&mut plain, &ok);
        let env = wrap_blob(&plain, &key)?;
        fs::write("hashchat_data/state.enc", env).map_err(|_| "write")?;
        let _ = set_private("hashchat_data/state.enc");
        Ok(())
    }

    pub fn load_disk() -> Option<Self> {
        let key = machine_key().ok()?;
        let env = fs::read("hashchat_data/state.enc").ok()?;
        let plain = unwrap_blob(&env, &key).ok()?;
        if plain.is_empty() || plain[0] != 1 {
            return None;
        }
        if plain.len() < 33 {
            return None;
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&plain[1..33]);
        let mut pos = 33;
        let onion = read_len_str(&plain, &mut pos)?;
        let okey = read_len_str(&plain, &mut pos)?;
        let mut s = Session::burner();
        s.longterm = LongTermIdentity::from_seed(seed);
        s.onion = if onion.is_empty() { None } else { Some(onion) };
        s.onion_key = if okey.is_empty() { None } else { Some(okey) };
        s.profile = "restored".into();
        s.log("restored identity + onion from disk");
        Some(s)
    }
}

/// hashchat://contact/v1/<onion>/<64-hex-x25519>
pub fn format_contact_link(onion: &str, x25519: &[u8; 32]) -> String {
    format!("hashchat://contact/v1/{}/{}", onion.trim(), hex_encode(x25519))
}

pub fn parse_contact_link(raw: &str) -> Result<(String, [u8; 32]), &'static str> {
    let s = raw.trim();
    let rest = s
        .strip_prefix("hashchat://contact/v1/")
        .ok_or("need hashchat://contact/v1/<onion>/<x25519-hex>")?;
    let (onion, hex) = rest.split_once('/').ok_or("missing key in link")?;
    let onion = onion.trim().to_lowercase();
    if !onion.ends_with(".onion") || onion.len() < 62 {
        return Err("onion looks invalid (need v3 …56chars.onion)");
    }
    let key = hex_decode32(hex.trim())?;
    Ok((onion, key))
}

pub fn maybe_qr_text(link: &str) -> Option<String> {
    let out = std::process::Command::new("qrencode")
        .args(["-t", "UTF8", "-m", "1", link])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn write_len_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn read_len_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 4 > buf.len() {
        return None;
    }
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if *pos + n > buf.len() {
        return None;
    }
    let s = String::from_utf8(buf[*pos..*pos + n].to_vec()).ok()?;
    *pos += n;
    Some(s)
}

fn machine_key() -> Result<[u8; 32], &'static str> {
    let path = Path::new("hashchat_data/machine.key");
    if let Ok(b) = fs::read(path) {
        if b.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            return Ok(k);
        }
    }
    fs::create_dir_all("hashchat_data").map_err(|_| "mkdir")?;
    let k = rand_bytes();
    fs::write(path, k).map_err(|_| "write key")?;
    let _ = set_private("hashchat_data/machine.key");
    Ok(k)
}

fn set_private(path: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn wrap_blob(plain: &[u8], pass: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&pass[..32.min(pass.len())]);
    crate::ratchet::encrypt_with_key(&key, plain)
}

fn unwrap_blob(blob: &[u8], pass: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&pass[..32.min(pass.len())]);
    crate::ratchet::decrypt_with_key(&key, blob)
}

fn remove_tree(p: &str) -> std::io::Result<()> {
    if Path::new(p).exists() {
        fs::remove_dir_all(p)
    } else {
        Ok(())
    }
}

fn rand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    let _ = getrandom::getrandom(&mut b);
    b
}

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_short(b: &[u8; 32]) -> String {
    hex_encode(&b[..8])
}

fn hex_decode32(s: &str) -> Result<[u8; 32], &'static str> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("x25519 must be 64 hex chars");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "hex")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_e2ee() {
        let mut s = Session::burner();
        let msg = s.selftest().expect("selftest");
        assert!(msg.contains("ok"));
    }

    #[test]
    fn contact_link_roundtrip() {
        let onion = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion";
        let key = [0x11u8; 32];
        let link = format_contact_link(onion, &key);
        let (o, k) = parse_contact_link(&link).unwrap();
        assert_eq!(o, onion);
        assert_eq!(k, key);
    }

    #[test]
    fn two_sessions_x3dh_send_recv() {
        let mut a = Session::burner();
        let mut b = Session::burner();
        a.onion = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion".into());
        b.onion = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion".into());
        a.add_contact_link(&b.my_contact_link()).unwrap();
        b.add_contact_link(&a.my_contact_link()).unwrap();
        let frame = a.send_text("hello over tor path").unwrap();
        let text = b.receive_frame(&frame).unwrap();
        assert_eq!(text, "hello over tor path");
        let frame2 = b.send_text("ack").unwrap();
        let text2 = a.receive_frame(&frame2).unwrap();
        assert_eq!(text2, "ack");
        // More messages exercise DH rotation after both sides have a remote pub.
        for i in 0..5 {
            let f = a.send_text(&format!("round-{i}")).unwrap();
            assert_eq!(b.receive_frame(&f).unwrap(), format!("round-{i}"));
        }
    }

    #[test]
    fn wipe_clears_state() {
        let mut s = Session::burner();
        s.onion = Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion".into());
        // no contacts — send should fail
        assert!(s.send_text("secret").is_err());
        s.nuclear_wipe();
        assert!(s.ratchets.is_empty());
        assert!(s.messages.is_empty());
    }
}
