//! In-process session: burner profiles, per-contact ratchets, persist, wipe.

use crate::longterm_identity::LongTermIdentity;
use crate::ratchet::{decrypt_with_key, encrypt_with_key, DoubleRatchet};
use crate::wire::{frame_for_wire, unframe_from_wire};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub struct Contact {
    pub name: String,
    pub onion: String,
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
}

impl Session {
    pub fn burner() -> Self {
        let mut s = Session {
            profile: format!("burner-{}", &hex_short(&rand_bytes())[..8]),
            contacts: vec![
                Contact {
                    name: "Alice".into(),
                    onion: "alice.onion".into(),
                },
                Contact {
                    name: "Bob".into(),
                    onion: "bob.onion".into(),
                },
            ],
            current: 0,
            messages: HashMap::new(),
            ratchets: HashMap::new(),
            longterm: LongTermIdentity::generate(),
            extreme: false,
            logs: Vec::new(),
        };
        s.log("burner profile created — identity is local-only");
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

    pub fn my_contact_link(&self) -> String {
        let ed = self.longterm.ed25519_public().to_bytes();
        format!(
            "hashchat://contact/v1/local.onion/{}",
            hex_encode(&ed)
        )
    }

    pub fn send_text(&mut self, text: &str) -> Result<Vec<u8>, &'static str> {
        if self.extreme {
            return Err("extreme: send refused");
        }
        let name = self
            .current_contact()
            .map(|c| c.name.clone())
            .ok_or("no contact")?;
        let r = self
            .ratchets
            .entry(name.clone())
            .or_insert_with(DoubleRatchet::new);
        let (mut key, step) = r.ratchet_send();
        let ct = encrypt_with_key(&key, text.as_bytes())?;
        key.zeroize();
        let hint = self.longterm.ed25519_public().to_bytes();
        let frame = frame_for_wire(&hint, step, &ct);
        self.messages.entry(name).or_default().push(ChatMsg {
            from_me: true,
            text: text.to_string(),
            step,
        });
        Ok(frame)
    }

    /// Decrypt a framed blob into the current contact (needs a paired ratchet).
    pub fn receive_frame(&mut self, contact: &str, frame: &[u8]) -> Result<String, &'static str> {
        let (_hint, _step, ct) = unframe_from_wire(frame).ok_or("bad frame")?;
        let r = self.ratchets.get_mut(contact).ok_or("no ratchet")?;
        let pk = r.public_key();
        let (mut key, step) = r.ratchet_recv(&pk);
        let pt = decrypt_with_key(&key, &ct)?;
        key.zeroize();
        let text = String::from_utf8(pt).map_err(|_| "utf8")?;
        self.messages.entry(contact.to_string()).or_default().push(ChatMsg {
            from_me: false,
            text: text.clone(),
            step,
        });
        Ok(text)
    }

    /// Two local ratchets, shared secret, encrypt/decrypt. Proves the Rust E2EE path.
    pub fn selftest(&mut self) -> Result<String, &'static str> {
        let mut a = DoubleRatchet::new();
        let mut b = DoubleRatchet::new();
        let shared = rand_bytes();
        let a_pub = a.public_key();
        let b_pub = b.public_key();
        a.init_from_shared(b_pub, &shared);
        b.init_from_shared(a_pub, &shared);
        let (mut k, step) = a.ratchet_send();
        let ct = encrypt_with_key(&k, b"hashchat-rust-e2ee")?;
        k.zeroize();
        let (mut k2, _) = b.ratchet_recv(&a.public_key());
        let pt = decrypt_with_key(&k2, &ct)?;
        k2.zeroize();
        if pt != b"hashchat-rust-e2ee" {
            return Err("selftest mismatch");
        }
        let frame = frame_for_wire(b"self", step, &ct);
        let _ = unframe_from_wire(&frame).ok_or("frame")?;
        Ok("E2EE selftest ok (two ratchets + unique nonce GCM + wire frame)".into())
    }

    pub fn nuclear_wipe(&mut self) {
        for r in self.ratchets.values_mut() {
            r.zeroize();
        }
        self.ratchets.clear();
        self.messages.clear();
        self.longterm.wipe();
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
        let blob = self.longterm_export(passphrase)?;
        fs::write(format!("{dir}/longterm.enc"), blob).map_err(|_| "write")?;
        Ok(())
    }

    fn longterm_export(&self, pass: &[u8]) -> Result<Vec<u8>, &'static str> {
        crate::longterm_identity::export_encrypted(&self.longterm, pass)
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
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

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_short(b: &[u8; 32]) -> String {
    hex_encode(&b[..8])
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
    fn send_produces_framed_ciphertext() {
        let mut s = Session::burner();
        let frame = s.send_text("hello rust").expect("send");
        let (hint, _step, ct) = unframe_from_wire(&frame).unwrap();
        assert_eq!(hint.len(), 32);
        assert_ne!(ct, b"hello rust");
        assert!(!s.messages["Alice"].is_empty());
    }

    #[test]
    fn wipe_clears_state() {
        let mut s = Session::burner();
        let _ = s.send_text("secret");
        s.nuclear_wipe();
        assert!(s.ratchets.is_empty());
        assert!(s.messages.is_empty());
    }
}
