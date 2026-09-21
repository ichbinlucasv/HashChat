//! HashChat native Rust TUI (transitional desktop path toward max-Rust).
//!
//! Build: `cargo build --bin hashchat-tui --features tui`
//!
//! Uses crate APIs: session_persist, contact_link, LongTermIdentity, wipe,
//! Tor ControlPort cookie auth + ADD_ONION listen, SOCKS send (fail-closed).
//! Transport policy: Tor default (explicit modes via :mode / env); no silent fallback.

use std::io::{self, stdout};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hashchat_rust::{
    bootstrap_ratchet_from_signed_link, build_wire_aad, commit_outgoing, encrypt_with_key,
    format_signed_contact_link, frame_v2, is_onion_destination, load_session,
    parse_signed_contact_link, sas_fingerprint, save_session, socks5_send,
    start_hidden_service_with_key, state_exists, tor_probe, unframe_v2, wipe_local_sensitive,
    DnsPreference, DoubleRatchet, HiddenService, IdentityOnionState, LongTermIdentity,
    NetConfig, NetworkMode, PersistMode, PersistedContact, PostureProfile, SessionState,
    WIRE_VERSION_V2,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use zeroize::Zeroize;

const DATA_DIR: &str = "hashchat_data";
const GOLD: Color = Color::Rgb(255, 215, 0); // #FFD700
const BG: Color = Color::Rgb(10, 10, 10); // #0A0A0A
const PANEL: Color = Color::Rgb(26, 26, 26); // #1A1A1A
const TEXT: Color = Color::Rgb(245, 245, 245);
const DIM: Color = Color::Rgb(160, 160, 160);
const DANGER: Color = Color::Rgb(255, 77, 77);
const OK: Color = Color::Rgb(61, 220, 151);

const SOCKS_HOST: &str = "127.0.0.1";
const SOCKS_PORTS: [u16; 2] = [9050, 9150];
const CONTROL_PORT: u16 = 9051;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Unlock,
    Main,
    ConfirmWipe,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Contacts,
    Input,
}

struct App {
    screen: Screen,
    focus: Focus,
    passphrase: String,
    passphrase_confirm: String,
    unlock_mode_create: bool,
    unlock_step: UnlockStep,
    status_msg: String,
    input: String,
    session: Option<SessionState>,
    my_sas: String,
    my_contact_link: String,
    contacts_state: ListState,
    selected_contact: Option<usize>,
    messages: Vec<String>,
    tor_status: TorStatus,
    last_tor_check: Instant,
    socks_port: u16,
    hs: Option<HiddenService>,
    /// In-memory network mode (env + :mode). Not yet in session blob.
    net: NetConfig,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnlockStep {
    EnterPass,
    ConfirmPass,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TorStatus {
    Checking,
    Available,
    Unavailable,
}

impl TorStatus {
    fn label(self, listening: bool) -> String {
        let base = match self {
            TorStatus::Checking => "Tor: checking…".to_string(),
            TorStatus::Available => "Tor: SOCKS ready".to_string(),
            TorStatus::Unavailable => "Tor: SOCKS unavailable".to_string(),
        };
        if listening {
            format!("{base} · listening")
        } else {
            base
        }
    }

    fn style(self) -> Style {
        match self {
            TorStatus::Checking => Style::default().fg(DIM),
            TorStatus::Available => Style::default().fg(OK),
            TorStatus::Unavailable => Style::default().fg(DANGER),
        }
    }
}

impl App {
    fn new() -> Self {
        let exists = state_exists(Path::new(DATA_DIR));
        Self {
            screen: Screen::Unlock,
            focus: Focus::Contacts,
            passphrase: String::new(),
            passphrase_confirm: String::new(),
            unlock_mode_create: !exists,
            unlock_step: UnlockStep::EnterPass,
            status_msg: if exists {
                "Enter passphrase to unlock.".into()
            } else {
                "No local session. Create a passphrase to initialize.".into()
            },
            input: String::new(),
            session: None,
            my_sas: String::new(),
            my_contact_link: String::new(),
            contacts_state: ListState::default(),
            selected_contact: None,
            messages: Vec::new(),
            tor_status: TorStatus::Checking,
            last_tor_check: Instant::now() - Duration::from_secs(60),
            socks_port: 9050,
            hs: None,
            net: NetConfig::from_env(),
        }
    }

    fn refresh_identity_display(&mut self) {
        let Some(session) = self.session.as_ref() else {
            self.my_sas.clear();
            self.my_contact_link.clear();
            return;
        };
        let id = session.identity.identity();
        let onion = session.identity.onion.clone();
        if onion.is_empty() {
            self.my_sas = sas_fingerprint(
                &id.ed25519_public_bytes(),
                &id.x25519_public_bytes(),
                "onion-pending.onion",
            );
            self.my_contact_link =
                "(contact link available after :listen publishes a v3 onion)".into();
            return;
        }
        self.my_sas = sas_fingerprint(
            &id.ed25519_public_bytes(),
            &id.x25519_public_bytes(),
            &onion,
        );
        match format_signed_contact_link(&id, &onion) {
            Ok(link) => self.my_contact_link = link,
            Err(_) => {
                self.my_contact_link =
                    "(contact link unavailable — check onion address)".into();
            }
        }
    }

    fn persist_session(&mut self) -> Result<(), &'static str> {
        let Some(session) = self.session.as_ref() else {
            return Err("no session");
        };
        if self.passphrase.is_empty() {
            return Err("passphrase required");
        }
        save_session(
            Path::new(DATA_DIR),
            PersistMode::Passphrase,
            self.passphrase.as_bytes(),
            session,
        )
    }

    fn try_unlock(&mut self) {
        let pass = self.passphrase.as_bytes();
        if pass.is_empty() {
            self.status_msg = "Passphrase required.".into();
            return;
        }
        if self.unlock_mode_create {
            if self.unlock_step == UnlockStep::EnterPass {
                self.unlock_step = UnlockStep::ConfirmPass;
                self.status_msg = "Confirm passphrase.".into();
                return;
            }
            if self.passphrase != self.passphrase_confirm {
                self.status_msg = "Passphrases do not match. Try again.".into();
                self.passphrase.zeroize();
                self.passphrase_confirm.zeroize();
                self.passphrase.clear();
                self.passphrase_confirm.clear();
                self.unlock_step = UnlockStep::EnterPass;
                return;
            }
            match LongTermIdentity::generate() {
                Ok(id) => {
                    let identity = IdentityOnionState {
                        seed: id.seed_bytes(),
                        onion: String::new(),
                        onion_key: Vec::new(),
                    };
                    let state = SessionState::from_identity(identity);
                    match save_session(
                        Path::new(DATA_DIR),
                        PersistMode::Passphrase,
                        pass,
                        &state,
                    ) {
                        Ok(()) => {
                            self.session = Some(state);
                            self.refresh_identity_display();
                            self.screen = Screen::Main;
                            self.status_msg =
                                "Session created. Use :listen when Tor ControlPort is ready.".into();
                            self.messages.push(
                                "Session initialized. :listen then :my-contact to share a signed link."
                                    .into(),
                            );
                        }
                        Err(_) => {
                            self.status_msg = "Failed to save session.".into();
                        }
                    }
                }
                Err(_) => self.status_msg = "Identity generation failed.".into(),
            }
        } else {
            match load_session(Path::new(DATA_DIR), PersistMode::Passphrase, pass) {
                Ok(state) => {
                    self.session = Some(state);
                    self.refresh_identity_display();
                    self.screen = Screen::Main;
                    self.status_msg = "Session unlocked.".into();
                    if let Some(s) = self.session.as_ref() {
                        self.messages.push(format!(
                            "Loaded {} contact(s), {} pending. Transport: Tor only.",
                            s.contacts.len(),
                            s.pending.len()
                        ));
                    }
                }
                Err(_) => {
                    self.status_msg = "Unlock failed (wrong passphrase or corrupt store).".into();
                    self.passphrase.zeroize();
                    self.passphrase.clear();
                }
            }
        }
        self.passphrase_confirm.zeroize();
        self.passphrase_confirm.clear();
    }

    fn contact_names(&self) -> Vec<String> {
        self.session
            .as_ref()
            .map(|s| {
                s.contacts
                    .iter()
                    .map(|c| {
                        if c.display_name.is_empty() {
                            c.id.clone()
                        } else {
                            c.display_name.clone()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_contact_record(&self) -> Option<&PersistedContact> {
        let session = self.session.as_ref()?;
        let idx = self.selected_contact?;
        session.contacts.get(idx)
    }

    fn listen(&mut self) {
        if let Err(e) = self.net.require_messenger_transport() {
            self.status_msg = format!(":listen refused: {e}");
            self.messages.push(self.status_msg.clone());
            return;
        }
        if self.hs.is_some() {
            let onion = self
                .session
                .as_ref()
                .map(|s| s.identity.onion.as_str())
                .unwrap_or("?");
            self.status_msg = format!("Already listening as {onion}");
            return;
        }
        if self.session.is_none() {
            self.status_msg = "Unlock a session first.".into();
            return;
        }
        let existing = self
            .session
            .as_ref()
            .map(|s| s.identity.onion_key.clone())
            .unwrap_or_default();
        let existing_ref = if existing.is_empty() {
            None
        } else {
            Some(existing.as_slice())
        };
        match start_hidden_service_with_key(SOCKS_HOST, CONTROL_PORT, existing_ref) {
            Ok((hs, privkey)) => {
                if let Some(session) = self.session.as_mut() {
                    session.identity.onion = hs.onion.clone();
                    if !privkey.is_empty() {
                        session.identity.onion_key.zeroize();
                        session.identity.onion_key = privkey;
                    }
                }
                match self.persist_session() {
                    Ok(()) => {
                        self.status_msg = format!(
                            "Listening on {} (local :{})",
                            hs.onion, hs.local_port
                        );
                        self.messages.push(
                            "Hidden service published; accept loop running (framed wire v2)."
                                .into(),
                        );
                        self.messages.push(
                            "Share :my-contact; peer must :add-contact your link (and you theirs)."
                                .into(),
                        );
                        self.hs = Some(hs);
                        self.refresh_identity_display();
                        self.retry_pending();
                    }
                    Err(_) => {
                        // Drop HS if we cannot persist onion material (fail closed on H2).
                        drop(hs);
                        self.status_msg =
                            "Listen aborted: could not persist onion material.".into();
                    }
                }
            }
            Err(e) => {
                // OPSEC: surface short reason only (no cookie bytes / paths with secrets).
                self.status_msg = format!(":listen failed: {e}");
                self.messages.push(self.status_msg.clone());
            }
        }
    }

    fn retry_pending(&mut self) {
        if let Err(e) = self.net.require_messenger_transport() {
            self.status_msg = format!(":retry refused: {e}");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if session.pending.is_empty() {
            return;
        }
        let waiting: Vec<(String, Vec<u8>)> = session.pending.drain(..).collect();
        let mut fail = 0usize;
        let mut ok = 0usize;
        let mut remain = Vec::new();
        for (onion, frame) in waiting {
            match socks5_send(SOCKS_HOST, self.socks_port, &onion, 80, &frame) {
                Ok(()) => ok += 1,
                Err(_) => {
                    remain.push((onion, frame));
                    fail += 1;
                }
            }
        }
        for (o, f) in remain {
            session.queue_pending(o, f);
        }
        let _ = self.persist_session();
        self.status_msg = if fail == 0 {
            format!("Delivered {ok} queued frame(s)")
        } else {
            format!("{ok} delivered, {fail} still queued")
        };
    }

    fn drain_incoming(&mut self) {
        let frames: Vec<Vec<u8>> = {
            let Some(hs) = self.hs.as_ref() else {
                return;
            };
            let mut out = Vec::new();
            while let Some(f) = hs.try_recv() {
                out.push(f);
            }
            out
        };
        for frame in frames {
            let n = frame.len();
            match self.try_decrypt_incoming(&frame) {
                Ok((peer, text)) => {
                    // UI inbox may show plaintext; status/logs must not.
                    self.messages.push(format!("[{peer}] {text}"));
                    self.status_msg = format!("Received {n} B · {peer}");
                }
                Err(_e) => {
                    // OPSEC: no frame bytes / decrypt detail in status.
                    self.messages
                        .push("Incoming frame dropped (decrypt/verify failed)".into());
                    self.status_msg = format!("Dropped inbound frame ({n} B)");
                }
            }
        }
    }

    fn try_decrypt_incoming(&mut self, transport_frame: &[u8]) -> Result<(String, String), String> {
        let (hint, step, sender_dh, ct) =
            unframe_v2(transport_frame).map_err(|_| "malformed wire frame".to_string())?;
        let pass = self.passphrase.as_bytes().to_vec();
        let session = self.session.as_mut().ok_or_else(|| "no session".to_string())?;
        let contacts = session.contacts.clone();
        // Wire hint is the sender's static x25519 — try matching contacts first.
        let mut order: Vec<usize> = (0..contacts.len()).collect();
        if hint.len() == 32 {
            order.sort_by_key(|&i| if contacts[i].x25519.as_slice() == hint.as_slice() { 0 } else { 1 });
        }
        for idx in order {
            let c = &contacts[idx];
            let ratchet_bytes = session
                .ratchets
                .iter()
                .find(|(id, _)| id == &c.id)
                .map(|(_, b)| b.clone());
            let Some(rb) = ratchet_bytes else {
                continue;
            };
            let mut r = DoubleRatchet::from_bytes(&rb).map_err(|_| "ratchet restore".to_string())?;
            let aad = build_wire_aad(WIRE_VERSION_V2, &hint, step, &sender_dh);
            let remote = x25519_dalek::PublicKey::from(sender_dh);
            match r.try_recv_decrypt(&remote, &ct, &aad) {
                Ok((mut pt, _)) => {
                    let text = String::from_utf8_lossy(&pt).to_string();
                    pt.zeroize();
                    session.set_ratchet_bytes(&c.id, r.to_bytes());
                    let label = if c.display_name.is_empty() {
                        c.id.clone()
                    } else {
                        c.display_name.clone()
                    };
                    let _ = save_session(
                        Path::new(DATA_DIR),
                        PersistMode::Passphrase,
                        &pass,
                        session,
                    );
                    return Ok((label, text));
                }
                Err(_) => continue,
            }
        }
        Err("no matching ratchet".into())
    }

    fn add_contact_link(&mut self, link: &str) {
        if self.session.is_none() {
            self.status_msg = "Unlock first.".into();
            return;
        }
        let local = self.session.as_ref().unwrap().identity.identity();
        let boot = bootstrap_ratchet_from_signed_link(&local, link);
        let parsed = parse_signed_contact_link(link);
        match (boot, parsed) {
            (Ok((ratchet, sas)), Ok(peer)) => {
                if !is_onion_destination(&peer.onion) {
                    self.status_msg = "Contact refused (onion not v3)".into();
                    return;
                }
                let onion_tail: String = peer
                    .onion
                    .chars()
                    .rev()
                    .take(12)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                let (select_idx, was_update) = {
                    let session = self.session.as_mut().unwrap();
                    let existing = session
                        .contacts
                        .iter()
                        .position(|c| c.onion == peer.onion || c.ed25519 == peer.ed25519);
                    let id = if let Some(i) = existing {
                        let id = session.contacts[i].id.clone();
                        session.contacts[i].display_name = sas.clone();
                        session.contacts[i].onion = peer.onion.clone();
                        session.contacts[i].x25519 = peer.x25519;
                        session.contacts[i].ed25519 = peer.ed25519;
                        id
                    } else {
                        let id = format!("c{}", session.contacts.len() + 1);
                        session.contacts.push(PersistedContact {
                            id: id.clone(),
                            display_name: sas.clone(),
                            onion: peer.onion.clone(),
                            x25519: peer.x25519,
                            ed25519: peer.ed25519,
                        });
                        id
                    };
                    session.set_ratchet_bytes(&id, ratchet.to_bytes());
                    let idx = session.contacts.iter().position(|c| c.id == id);
                    (idx, existing.is_some())
                };
                match self.persist_session() {
                    Ok(()) => {
                        let verb = if was_update { "Updated" } else { "Added" };
                        self.status_msg = format!("{verb} contact (SAS {sas})");
                        self.messages.push(format!(
                            "{verb} {sas} — onion …{onion_tail} (peer must :add-contact you too)"
                        ));
                        if let Some(i) = select_idx {
                            self.selected_contact = Some(i);
                            self.contacts_state.select(Some(i));
                        }
                    }
                    Err(_) => self.status_msg = "Failed to persist contact.".into(),
                }
            }
            (Err(_), _) => {
                self.status_msg = "Contact refused (bad signature or format).".into();
            }
            (_, Err(_)) => {
                self.status_msg = "Contact parse failed after verify.".into();
            }
        }
    }

    fn send_text(&mut self, text: &str) {
        if let Err(e) = self.net.require_messenger_transport() {
            self.messages.push(format!("Send refused: {e}"));
            return;
        }
        if self.tor_status != TorStatus::Available {
            self.messages.push(
                "Send refused: Tor SOCKS not available (Tor-only policy).".into(),
            );
            return;
        }
        let contact = match self.selected_contact_record() {
            Some(c) => c.clone(),
            None => {
                self.messages
                    .push("Select a contact before sending.".into());
                return;
            }
        };
        if !is_onion_destination(&contact.onion) {
            self.messages
                .push("Send refused: contact has no valid v3 .onion.".into());
            return;
        }

        let peer_label = if contact.display_name.is_empty() {
            contact.id.clone()
        } else {
            contact.display_name.clone()
        };

        let (frame, rbytes) = {
            let session = match self.session.as_mut() {
                Some(s) => s,
                None => return,
            };
            let local = session.identity.identity();
            let mut ratchet = if let Some((_, bytes)) =
                session.ratchets.iter().find(|(id, _)| id == &contact.id)
            {
                match DoubleRatchet::from_bytes(bytes) {
                    Ok(r) => r,
                    Err(_) => {
                        self.messages.push("Ratchet restore failed.".into());
                        return;
                    }
                }
            } else if contact.x25519 != [0u8; 32] {
                let shared = local.x25519_dh(&x25519_dalek::PublicKey::from(contact.x25519));
                let mut r = DoubleRatchet::new();
                r.init_symmetric(&shared);
                r
            } else {
                self.messages.push(
                    "No ratchet for contact — add via :add-contact <signed link>.".into(),
                );
                return;
            };

            let hint = local.x25519_public_bytes();
            let (mut msg_key, step) = ratchet.ratchet_send();
            let sender_dh = ratchet.public_key().to_bytes();
            let aad = build_wire_aad(WIRE_VERSION_V2, &hint, step, &sender_dh);
            let ct = match encrypt_with_key(&msg_key, text.as_bytes(), &aad) {
                Ok(c) => c,
                Err(_) => {
                    msg_key.zeroize();
                    self.messages.push("Encrypt failed.".into());
                    return;
                }
            };
            msg_key.zeroize();
            let frame = frame_v2(&hint, step, &sender_dh, &ct);
            let rbytes = ratchet.to_bytes();
            (frame, rbytes)
        };

        // H3: durable queue commit before Tor send.
        if commit_outgoing(
            Path::new(DATA_DIR),
            PersistMode::Passphrase,
            self.passphrase.as_bytes(),
            &contact.id,
            rbytes.clone(),
            &contact.onion,
            frame.clone(),
        )
        .is_err()
        {
            self.messages
                .push("Send aborted: durable commit failed.".into());
            return;
        }

        // Mirror commit into in-memory session.
        if let Some(session) = self.session.as_mut() {
            session.set_ratchet_bytes(&contact.id, rbytes);
            session.queue_pending(&contact.onion, frame.clone());
        }

        let sent_ok = socks5_send(SOCKS_HOST, self.socks_port, &contact.onion, 80, &frame).is_ok();
        if sent_ok {
            if let Some(session) = self.session.as_mut() {
                session.ack_pending_frame(&contact.onion, &frame);
            }
            let _ = self.persist_session();
            let frame_len = frame.len();
            self.messages
                .push(format!("[{peer_label}] you: {text}  ({frame_len} B via Tor)"));
            self.status_msg = format!("Sent {frame_len} B via SOCKS");
        } else {
            // OPSEC: short reason only — frame stays queued for :retry.
            self.messages
                .push(format!("[{peer_label}] queued offline (SOCKS send failed)"));
            self.status_msg = "Queued: SOCKS send failed (frame committed)".into();
        }
    }

    /// `:mode` — inspect / set network mode (in-memory; env also applies at start).
    fn handle_mode(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() || args == "status" || args == "show" {
            self.messages.push(self.net.status_line());
            self.status_msg = self.net.status_line();
            return;
        }
        let mut parts = args.split_whitespace();
        let Some(head) = parts.next() else {
            return;
        };
        let head_l = head.to_ascii_lowercase();
        match head_l.as_str() {
            "tor" | "i2p" | "clearnet" | "clear" | "onion" | "garlic" | "direct" => {
                match NetworkMode::parse_token(&head_l) {
                    Ok(mode) => match self.net.set_mode(mode) {
                        Ok(()) => {
                            self.status_msg = format!("Network mode set to {}", self.net.mode);
                            self.messages.push(self.net.status_line());
                        }
                        Err(e) => {
                            self.status_msg = e.to_string();
                            self.messages.push(e.to_string());
                        }
                    },
                    Err(e) => {
                        self.status_msg = e.to_string();
                        self.messages.push(e.to_string());
                    }
                }
            }
            "dns" => {
                let Some(tok) = parts.next() else {
                    self.status_msg = "Usage: :mode dns system|quad9|custom <addr>".into();
                    return;
                };
                match DnsPreference::parse_token(tok) {
                    Ok(DnsPreference::Custom) => {
                        let addr = parts.next().map(|s| s.to_string());
                        match self.net.set_dns(DnsPreference::Custom, addr) {
                            Ok(()) => {
                                self.status_msg = self.net.status_line();
                                self.messages.push(self.status_msg.clone());
                            }
                            Err(e) => {
                                self.status_msg = e.to_string();
                                self.messages.push(e.to_string());
                            }
                        }
                    }
                    Ok(dns) => match self.net.set_dns(dns, None) {
                        Ok(()) => {
                            self.status_msg = self.net.status_line();
                            self.messages.push(self.status_msg.clone());
                        }
                        Err(e) => {
                            self.status_msg = e.to_string();
                            self.messages.push(e.to_string());
                        }
                    },
                    Err(e) => {
                        self.status_msg = e.to_string();
                        self.messages.push(e.to_string());
                    }
                }
            }
            "extreme" | "paranoid" => {
                self.net.set_posture(PostureProfile::Extreme);
                self.status_msg = format!("Posture extreme (Tor-only). {}", self.net.status_line());
                self.messages.push(self.status_msg.clone());
            }
            "standard" | "normal" => {
                self.net.set_posture(PostureProfile::Standard);
                self.status_msg = format!("Posture standard. {}", self.net.status_line());
                self.messages.push(self.status_msg.clone());
            }
            "help" => {
                self.messages.push(
                    "Usage: :mode [status|tor|i2p|clearnet|dns system|dns quad9|dns custom <addr>|extreme|standard]"
                        .into(),
                );
                self.messages.push(
                    "Default Tor. I2P/clearnet refuse messenger sockets until implemented. Extreme locks Tor-only."
                        .into(),
                );
            }
            other => {
                self.status_msg = format!("Unknown :mode argument: {other} (:mode help)");
                self.messages.push(self.status_msg.clone());
            }
        }
    }

    fn handle_command(&mut self, cmd: &str) {
        let c = cmd.trim();
        match c {
            ":q" | ":quit" | ":exit" => {
                self.status_msg = "__QUIT__".into();
            }
            ":wipe" => {
                // Loud confirm: blank chat/status residue so the modal is not overlaid on plaintext.
                self.messages.clear();
                self.input.clear();
                self.screen = Screen::ConfirmWipe;
                self.status_msg =
                    "NUCLEAR WIPE: type :wipe-confirm to erase local secrets, or Esc to cancel."
                        .into();
            }
            ":wipe-confirm" => {
                self.hs = None;
                wipe_local_sensitive();
                if let Some(mut s) = self.session.take() {
                    s.wipe_memory_secure();
                }
                self.passphrase.zeroize();
                self.passphrase.clear();
                self.passphrase_confirm.zeroize();
                self.passphrase_confirm.clear();
                self.input.clear();
                self.my_sas.clear();
                self.my_contact_link.clear();
                self.messages.clear();
                self.contacts_state = ListState::default();
                self.selected_contact = None;
                self.unlock_mode_create = true;
                self.unlock_step = UnlockStep::EnterPass;
                self.screen = Screen::Unlock;
                // OPSEC: status must not echo prior chat/passphrase material.
                self.status_msg =
                    "Local sensitive data erased. Unlock with a new passphrase to continue.".into();
            }
            ":my-contact" => {
                if self.my_contact_link.is_empty() {
                    self.messages
                        .push("No contact link yet (unlock + :listen first).".into());
                } else {
                    self.messages.push(format!("SAS: {}", self.my_sas));
                    self.messages
                        .push(format!("Contact: {}", self.my_contact_link));
                }
            }
            ":listen" => self.listen(),
            ":retry" => self.retry_pending(),
            ":status" | ":tor" => {
                self.check_tor(true);
                let probe = tor_probe(SOCKS_HOST, self.socks_port, CONTROL_PORT);
                let onion = self
                    .session
                    .as_ref()
                    .map(|s| {
                        if s.identity.onion.is_empty() {
                            "-".into()
                        } else {
                            s.identity.onion.clone()
                        }
                    })
                    .unwrap_or_else(|| "-".into());
                let listening = self.hs.is_some();
                self.messages.push(format!(
                    "{} · onion={} · listening={} · pending={}",
                    probe.note,
                    onion,
                    listening,
                    self.session
                        .as_ref()
                        .map(|s| s.pending.len())
                        .unwrap_or(0)
                ));
                self.messages.push(self.net.status_line());
                self.status_msg = self.tor_status.label(listening);
            }
            ":help" => {
                self.messages.push(
                    "Commands: :listen  :my-contact  :add-contact <link>  :tor  :mode  :retry  :wipe  :quit"
                        .into(),
                );
                self.messages.push(
                    "Two devices: both :listen, exchange :my-contact links via :add-contact, then chat."
                        .into(),
                );
                self.messages.push(
                    "Transport: Tor default; :mode selects explicit network (no silent fallback)."
                        .into(),
                );
            }
            "" => {}
            other if other.starts_with(":add-contact ") => {
                let link = other.strip_prefix(":add-contact ").unwrap_or("").trim();
                self.add_contact_link(link);
            }
            other if other == ":mode" || other.starts_with(":mode ") => {
                let args = other.strip_prefix(":mode").unwrap_or("").trim();
                self.handle_mode(args);
            }
            other if other.starts_with(':') => {
                self.messages
                    .push(format!("Unknown command: {other}  (:help)"));
            }
            other => self.send_text(other),
        }
    }

    fn check_tor(&mut self, force: bool) {
        if !force && self.last_tor_check.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.last_tor_check = Instant::now();
        let mut ok = false;
        for p in SOCKS_PORTS {
            let probe = tor_probe(SOCKS_HOST, p, CONTROL_PORT);
            if probe.socks_ok {
                self.socks_port = p;
                ok = true;
                break;
            }
        }
        self.tor_status = if ok {
            TorStatus::Available
        } else {
            TorStatus::Unavailable
        };
    }
}

fn gold_style() -> Style {
    Style::default().fg(GOLD).add_modifier(Modifier::BOLD)
}

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let area = f.area();
    f.render_widget(
        Block::default().style(Style::default().bg(BG).fg(TEXT)),
        area,
    );

    match app.screen {
        Screen::Unlock => draw_unlock(f, app, area),
        Screen::Main => draw_main(f, app, area),
        // Full-screen confirm: never render chat/contacts under the wipe prompt.
        Screen::ConfirmWipe => draw_wipe_modal(f, app, area),
    }
}

fn draw_unlock(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled("  #  ", gold_style()),
        Span::styled("HashChat", gold_style()),
        Span::styled("  ·  Rust desktop", Style::default().fg(DIM)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GOLD))
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(title, chunks[0]);

    let prompt = if app.unlock_mode_create {
        match app.unlock_step {
            UnlockStep::EnterPass => "New passphrase:",
            UnlockStep::ConfirmPass => "Confirm passphrase:",
        }
    } else {
        "Passphrase:"
    };
    let masked = if app.unlock_step == UnlockStep::ConfirmPass {
        "*".repeat(app.passphrase_confirm.chars().count())
    } else {
        "*".repeat(app.passphrase.chars().count())
    };
    let body = Paragraph::new(vec![
        Line::from(Span::styled(
            if app.unlock_mode_create {
                "Initialize local session (Argon2id-wrapped at rest)"
            } else {
                "Unlock local session"
            },
            Style::default().fg(TEXT),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(prompt, Style::default().fg(GOLD)),
            Span::raw(" "),
            Span::styled(masked, Style::default().fg(TEXT)),
            Span::styled("▌", Style::default().fg(GOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(&app.status_msg, Style::default().fg(DIM))),
        Line::from(""),
        Line::from(Span::styled(
            "Enter unlock · Esc clear · Tor required for network use",
            Style::default().fg(DIM),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" unlock ", gold_style()))
            .border_style(Style::default().fg(GOLD))
            .style(Style::default().bg(PANEL)),
    )
    .wrap(Wrap { trim: false });
    f.render_widget(body, chunks[1]);

    let foot = Paragraph::new(Line::from(Span::styled(
        "Transport default: Tor · :mode for explicit nets · No silent fallback",
        Style::default().fg(DIM),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DIM))
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(foot, chunks[2]);
}

fn draw_main(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area);

    let listening = app.hs.is_some();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" # HashChat ", gold_style()),
        Span::styled("│ ", Style::default().fg(DIM)),
        Span::styled(format!("SAS {}", app.my_sas), Style::default().fg(GOLD)),
        Span::styled(" │ ", Style::default().fg(DIM)),
        Span::styled(
            app.tor_status.label(listening),
            app.tor_status.style(),
        ),
        Span::styled(" · ", Style::default().fg(DIM)),
        Span::styled(
            format!("mode={}", app.net.mode),
            Style::default().fg(DIM),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GOLD))
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(header, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(root[1]);

    let names = app.contact_names();
    let items: Vec<ListItem> = if names.is_empty() {
        vec![ListItem::new(Span::styled(
            "(no contacts)",
            Style::default().fg(DIM),
        ))]
    } else {
        names
            .iter()
            .map(|n| ListItem::new(Span::styled(n.clone(), Style::default().fg(TEXT))))
            .collect()
    };
    let contacts_border = if app.focus == Focus::Contacts {
        Style::default().fg(GOLD)
    } else {
        Style::default().fg(DIM)
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" contacts ", gold_style()))
                .border_style(contacts_border)
                .style(Style::default().bg(PANEL)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 40, 20))
                .fg(GOLD)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");
    f.render_stateful_widget(list, body[0], &mut app.contacts_state);

    let msg_lines: Vec<Line> = if app.messages.is_empty() {
        vec![Line::from(Span::styled(
            "No messages. :help for commands. :listen to publish onion.",
            Style::default().fg(DIM),
        ))]
    } else {
        app.messages
            .iter()
            .rev()
            .take(body[1].height.saturating_sub(2) as usize)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|m| Line::from(Span::styled(m.as_str(), Style::default().fg(TEXT))))
            .collect()
    };
    let chat = Paragraph::new(msg_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" chat ", gold_style()))
                .border_style(Style::default().fg(GOLD))
                .style(Style::default().bg(PANEL)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(chat, body[1]);

    let input_border = if app.focus == Focus::Input {
        Style::default().fg(GOLD)
    } else {
        Style::default().fg(DIM)
    };
    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", gold_style()),
        Span::styled(&app.input, Style::default().fg(TEXT)),
        Span::styled("▌", Style::default().fg(GOLD)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" input ", gold_style()))
            .border_style(input_border)
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(input, root[2]);

    let status = Paragraph::new(Line::from(Span::styled(
        &app.status_msg,
        Style::default().fg(DIM),
    )))
    .style(Style::default().bg(BG));
    f.render_widget(status, root[3]);
}

fn draw_wipe_modal(f: &mut ratatui::Frame, app: &App, area: Rect) {
    // Full-area danger backdrop — no chat plaintext visible behind the confirm.
    f.render_widget(Clear, area);
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let w = area.width.min(72).max(48);
    let h = 12u16.min(area.height.saturating_sub(2)).max(10);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);
    f.render_widget(Clear, rect);
    let body = Paragraph::new(vec![
        Line::from(Span::styled(
            "NUCLEAR WIPE",
            Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Erases on-disk session (state.enc), Tor HS dir, and in-RAM",
            Style::default().fg(TEXT),
        )),
        Line::from(Span::styled(
            "passphrase, onion_key, ratchets, and pending frames.",
            Style::default().fg(TEXT),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Type :wipe-confirm then Enter.  Esc cancels.",
            Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Limits: not a kernel-implant / prior-exfil mitigator (THREATMODEL).",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(&app.status_msg, Style::default().fg(DIM))),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " DANGER · wipe ",
                Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(DANGER))
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(body, rect);
}

fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    app.check_tor(true);

    let tick = Duration::from_millis(100);
    loop {
        app.check_tor(false);
        app.drain_incoming();
        terminal.draw(|f| ui(f, &mut app))?;

        if !event::poll(tick)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            break;
        }

        match app.screen {
            Screen::Unlock => match key.code {
                KeyCode::Esc => {
                    app.passphrase.zeroize();
                    app.passphrase.clear();
                    app.passphrase_confirm.zeroize();
                    app.passphrase_confirm.clear();
                    app.unlock_step = UnlockStep::EnterPass;
                }
                KeyCode::Enter => app.try_unlock(),
                KeyCode::Backspace => {
                    if app.unlock_step == UnlockStep::ConfirmPass {
                        app.passphrase_confirm.pop();
                    } else {
                        app.passphrase.pop();
                    }
                }
                KeyCode::Char(ch) => {
                    if app.unlock_step == UnlockStep::ConfirmPass {
                        app.passphrase_confirm.push(ch);
                    } else {
                        app.passphrase.push(ch);
                    }
                }
                _ => {}
            },
            Screen::ConfirmWipe => match key.code {
                KeyCode::Esc => {
                    app.screen = Screen::Main;
                    app.input.clear();
                    app.status_msg = "Wipe cancelled.".into();
                    app.focus = Focus::Input;
                }
                KeyCode::Char(ch) => {
                    // Collect confirm command without restoring the chat pane yet.
                    app.focus = Focus::Input;
                    app.input.push(ch);
                    app.status_msg = format!("Confirm input: {}", app.input);
                }
                KeyCode::Backspace => {
                    app.input.pop();
                    app.status_msg = if app.input.is_empty() {
                        "NUCLEAR WIPE: type :wipe-confirm to erase local secrets, or Esc to cancel."
                            .into()
                    } else {
                        format!("Confirm input: {}", app.input)
                    };
                }
                KeyCode::Enter => {
                    let cmd = app.input.trim().to_string();
                    app.input.clear();
                    if cmd == ":wipe-confirm" {
                        app.handle_command(&cmd);
                    } else {
                        app.screen = Screen::Main;
                        app.status_msg =
                            "Wipe cancelled (expected :wipe-confirm).".into();
                        app.focus = Focus::Input;
                    }
                }
                _ => {}
            },
            Screen::Main => match key.code {
                KeyCode::Tab => {
                    app.focus = match app.focus {
                        Focus::Contacts => Focus::Input,
                        Focus::Input => Focus::Contacts,
                    };
                }
                KeyCode::Up if app.focus == Focus::Contacts => {
                    let len = app.contact_names().len();
                    if len > 0 {
                        let i = app.selected_contact.unwrap_or(0);
                        let ni = if i == 0 { len - 1 } else { i - 1 };
                        app.selected_contact = Some(ni);
                        app.contacts_state.select(Some(ni));
                    }
                }
                KeyCode::Down if app.focus == Focus::Contacts => {
                    let len = app.contact_names().len();
                    if len > 0 {
                        let i = app.selected_contact.unwrap_or(len - 1);
                        let ni = (i + 1) % len;
                        app.selected_contact = Some(ni);
                        app.contacts_state.select(Some(ni));
                    }
                }
                KeyCode::Enter if app.focus == Focus::Input || !app.input.is_empty() => {
                    let cmd = std::mem::take(&mut app.input);
                    app.handle_command(&cmd);
                    if app.status_msg == "__QUIT__" {
                        break;
                    }
                }
                KeyCode::Backspace if app.focus == Focus::Input => {
                    app.input.pop();
                }
                KeyCode::Char(ch) => {
                    app.focus = Focus::Input;
                    app.input.push(ch);
                }
                KeyCode::Esc => {
                    app.input.clear();
                    app.status_msg = "Input cleared.".into();
                }
                _ => {}
            },
        }
    }

    app.hs = None;
    app.passphrase.zeroize();
    app.passphrase_confirm.zeroize();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn main() {
    if std::env::var_os("HASHCHAT_INSECURE_DEV_PERSIST").is_some() {
        eprintln!(
            "hashchat-tui: HASHCHAT_INSECURE_DEV_PERSIST is set; refusing to run (passphrase-only)."
        );
        std::process::exit(2);
    }
    if let Err(e) = run() {
        eprintln!("hashchat-tui error: {e}");
        std::process::exit(1);
    }
}
