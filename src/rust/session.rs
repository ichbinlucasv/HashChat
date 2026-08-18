//! Burner profiles, contact QR/links, X3DH bootstrap, persist, wipe.

use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::{decrypt_with_key, encrypt_with_key, DoubleRatchet};
use crate::wire::{frame_for_wire, unframe_from_wire};
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
        };
        s.log("burner profile created — add a peer with :add-contact <link>");
        s
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
        let ct = encrypt_with_key(&key, text.as_bytes())?;
        key.zeroize();
        let frame = frame_for_wire(&self.my_x25519(), step, &ct);
        self.messages.entry(name).or_default().push(ChatMsg {
            from_me: true,
            text: text.to_string(),
            step,
        });
        Ok(frame)
    }

    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<String, &'static str> {
        let (hint, _step, ct) = unframe_from_wire(frame).ok_or("bad frame")?;
        if hint.len() != 32 {
            return Err("bad hint");
        }
        let mut hx = [0u8; 32];
        hx.copy_from_slice(&hint);
        let name = self
            .contacts
            .iter()
            .find(|c| c.x25519 == hx)
            .map(|c| c.name.clone())
            .ok_or("unknown sender — add their :my-contact link first")?;
        let r = self.ratchets.get_mut(&name).ok_or("no ratchet")?;
        let pk = r.public_key();
        let (mut key, step) = r.ratchet_recv(&pk);
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
        let ct = encrypt_with_key(&k, b"hashchat-rust-e2ee")?;
        k.zeroize();
        let frame = frame_for_wire(a.x25519_public().as_bytes(), step, &ct);
        let (hint, _, ct2) = unframe_from_wire(&frame).ok_or("frame")?;
        assert_eq!(hint, a.x25519_public().as_bytes());
        let (mut k2, _) = rb.ratchet_recv(&rb.public_key());
        let pt = decrypt_with_key(&k2, &ct2)?;
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
        let _ = remove_tree("hashchat_data");
        let _ = remove_tree("tor/hidden_service");
        crate::rust_wipe_files();
        self.profile = "wiped".into();
        self.contacts.clear();
        self.log("nuclear wipe: ratchets zeroized, hashchat_data removed");
    }

    pub fn persist(&self, passphrase: &[u8]) -> Result<(), &'static str> {
        if passphrase.is_empty() {
            return Err("empty pass");
        }
        let dir = format!("hashchat_data/profiles/{}", sanitize(&self.profile));
        fs::create_dir_all(&dir).map_err(|_| "mkdir")?;
        let blob = crate::longterm_identity::export_encrypted(&self.longterm, passphrase)?;
        fs::write(format!("{dir}/longterm.enc"), blob).map_err(|_| "write")?;
        Ok(())
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

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
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
