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
    extreme_default_ttl, format_signed_contact_link, format_ttl, frame_v2, is_onion_destination,
    load_session, parse_signed_contact_link, parse_ttl_token, sas_fingerprint, sas_for_signed,
    save_session, socks5_send, start_hidden_service_with_key, state_exists, tor_probe, unframe_v2,
    wipe_local_sensitive, DnsPreference, DoubleRatchet, HiddenService, IdentityOnionState,
    InboundDenyPolicy, LongTermIdentity, NetConfig, NetworkMode, PersistMode, PersistedContact,
    PostureProfile, SessionState, WIRE_VERSION_V2,
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

/// In-memory transcript line. Chat bodies may carry a local TTL; system notes do not.
struct ChatLine {
    text: String,
    expires_at: Option<Instant>,
    /// Contact id + ratchet message number for [`DoubleRatchet::wipe_skipped_key`] on expiry.
    wipe_key: Option<(String, u32)>,
}

impl ChatLine {
    fn sys(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            expires_at: None,
            wipe_key: None,
        }
    }

    fn chat(text: impl Into<String>, ttl_secs: u32, wipe_key: Option<(String, u32)>) -> Self {
        let expires_at = if ttl_secs == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(u64::from(ttl_secs)))
        };
        Self {
            text: text.into(),
            expires_at,
            wipe_key,
        }
    }
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
    messages: Vec<ChatLine>,
    tor_status: TorStatus,
    last_tor_check: Instant,
    socks_port: u16,
    hs: Option<HiddenService>,
    /// Network prefs: env at cold start / new identity; after unlock, loaded blob wins.
    net: NetConfig,
    /// Local disappearing TTL seconds (0 = off). Synced into session blob v4+.
    disappear_ttl_secs: u32,
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
            disappear_ttl_secs: 0,
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
        let Some(session) = self.session.as_mut() else {
            return Err("no session");
        };
        if self.passphrase.is_empty() {
            return Err("passphrase required");
        }
        // Keep blob prefs aligned with live NetConfig + disappearing TTL.
        session.net = self.net.clone();
        session.disappear_ttl_secs = self.disappear_ttl_secs;
        save_session(
            Path::new(DATA_DIR),
            PersistMode::Passphrase,
            self.passphrase.as_bytes(),
            session,
        )
    }

    /// Persist current session after a successful `:mode` change.
    /// Returns false if a session is unlocked but durable save failed.
    fn persist_net_after_mode_change(&mut self) -> bool {
        if self.session.is_none() {
            // Pre-unlock :mode is process-local only (env / cold start).
            return true;
        }
        match self.persist_session() {
            Ok(()) => true,
            Err(_) => {
                self.push_msg(
                    "Mode updated in memory; durable save failed (unlock/passphrase?).",
                );
                false
            }
        }
    }


    fn push_msg(&mut self, text: impl Into<String>) {
        self.messages.push(ChatLine::sys(text));
    }

    fn push_chat(&mut self, text: impl Into<String>, contact_id: &str, msg_number: u32) {
        let wipe = if contact_id.is_empty() {
            None
        } else {
            Some((contact_id.to_string(), msg_number))
        };
        self.messages
            .push(ChatLine::chat(text, self.disappear_ttl_secs, wipe));
    }

    /// Drop expired chat lines (zeroize plaintext) and wipe matching skipped ratchet keys.
    fn expire_messages(&mut self) {
        let now = Instant::now();
        let mut to_wipe: Vec<(String, u32)> = Vec::new();
        let mut kept: Vec<ChatLine> = Vec::with_capacity(self.messages.len());
        for mut line in self.messages.drain(..) {
            let expired = line
                .expires_at
                .map(|t| now >= t)
                .unwrap_or(false);
            if expired {
                if let Some(w) = line.wipe_key.take() {
                    to_wipe.push(w);
                }
                line.text.zeroize();
            } else {
                kept.push(line);
            }
        }
        self.messages = kept;
        for (cid, num) in to_wipe {
            self.wipe_contact_skipped_key(&cid, num);
        }
    }

    fn wipe_contact_skipped_key(&mut self, contact_id: &str, msg_number: u32) {
        let pass = self.passphrase.as_bytes().to_vec();
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(bytes) = session
            .ratchets
            .iter()
            .find(|(id, _)| id == contact_id)
            .map(|(_, b)| b.clone())
        else {
            return;
        };
        let Ok(mut r) = DoubleRatchet::from_bytes(&bytes) else {
            return;
        };
        r.wipe_skipped_key(msg_number);
        session.set_ratchet_bytes(contact_id, r.to_bytes());
        if !pass.is_empty() {
            let _ = save_session(
                Path::new(DATA_DIR),
                PersistMode::Passphrase,
                &pass,
                session,
            );
        }
    }

    /// Zeroize and drop in-memory chat transcript (Extreme switch / wipe hygiene).
    fn clear_transcript_secure(&mut self) {
        for line in self.messages.iter_mut() {
            line.text.zeroize();
        }
        self.messages.clear();
    }

    fn apply_extreme_ttl_default(&mut self) {
        let next = extreme_default_ttl(self.net.is_extreme(), self.disappear_ttl_secs);
        if next != self.disappear_ttl_secs {
            self.disappear_ttl_secs = next;
            self.push_msg(format!(
                "Disappearing messages defaulted to {} under Extreme (local TTL; peer not enforced).",
                format_ttl(next)
            ));
        }
    }

    fn handle_disappear(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() || args == "status" || args == "show" {
            let line = format!(
                "disappear={} (local TTL; not on wire — peer is not forced to erase)",
                format_ttl(self.disappear_ttl_secs)
            );
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        match parse_ttl_token(args) {
            Ok(secs) => {
                self.disappear_ttl_secs = secs;
                let saved = if self.session.is_some() {
                    match self.persist_session() {
                        Ok(()) => true,
                        Err(_) => {
                            self.push_msg(
                                "TTL updated in memory; durable save failed (unlock/passphrase?).",
                            );
                            false
                        }
                    }
                } else {
                    true
                };
                let line = if saved {
                    format!(
                        "Disappearing TTL set to {} (saved; local only)",
                        format_ttl(secs)
                    )
                } else {
                    format!(
                        "Disappearing TTL set to {} (memory only)",
                        format_ttl(secs)
                    )
                };
                self.status_msg = line.clone();
                self.push_msg(line);
                self.push_msg(
                    "Honesty: TTL is not carried on the wire; the peer must set their own policy.",
                );
            }
            Err(e) => {
                self.status_msg = e.into();
                self.push_msg(format!(
                    "Usage: :disappear [off|30s|5m|1h|1d|status] — {e}"
                ));
            }
        }
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
                    let state =
                        SessionState::from_identity_with_net(identity, self.net.clone());
                    match save_session(
                        Path::new(DATA_DIR),
                        PersistMode::Passphrase,
                        pass,
                        &state,
                    ) {
                        Ok(()) => {
                            self.session = Some(state);
                            self.disappear_ttl_secs = 0;
                            self.apply_extreme_ttl_default();
                            let _ = self.persist_session();
                            self.refresh_identity_display();
                            self.screen = Screen::Main;
                            self.status_msg =
                                "Session created. Use :listen when Tor ControlPort is ready.".into();
                            self.push_msg(
                                "Session initialized. :listen then :my-contact to share a signed link.",
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
                    let n_contacts = state.contacts.len();
                    let n_pending = state.pending.len();
                    // Loaded blob wins over cold-start env for net prefs + TTL.
                    self.net = state.net.clone();
                    self.disappear_ttl_secs = state.disappear_ttl_secs;
                    self.session = Some(state);
                    self.apply_extreme_ttl_default();
                    let _ = self.persist_session();
                    self.refresh_identity_display();
                    self.screen = Screen::Main;
                    self.push_msg(format!(
                        "Loaded {n_contacts} contact(s), {n_pending} pending. {} · disappear={}",
                        self.net.status_line(),
                        format_ttl(self.disappear_ttl_secs)
                    ));
                    if n_contacts > 0 {
                        self.select_contact(0);
                        // Keep unlock summary; select_contact already set SAS status.
                        self.status_msg = format!(
                            "Unlocked · {n_contacts} contact(s), {n_pending} pending · {}",
                            self.status_msg
                        );
                    } else {
                        self.status_msg =
                            "Session unlocked. :listen then :add-contact to begin.".into();
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

    fn contact_sas_short(c: &PersistedContact) -> &str {
        if c.display_name.is_empty() {
            c.id.as_str()
        } else {
            c.display_name.as_str()
        }
    }

    fn onion_tail(onion: &str) -> String {
        onion
            .chars()
            .rev()
            .take(12)
            .collect::<String>()
            .chars()
            .rev()
            .collect()
    }

    /// Contact list labels: short SAS only (OPSEC — no plaintext bodies).
    fn contact_names(&self) -> Vec<String> {
        self.session
            .as_ref()
            .map(|s| {
                s.contacts
                    .iter()
                    .map(|c| {
                        let mut label = format!("SAS {}", Self::contact_sas_short(c));
                        if s.is_blocked_id(&c.id) {
                            label.push_str(" [blocked]");
                        } else if s.is_muted_id(&c.id) {
                            label.push_str(" [muted]");
                        }
                        label
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

    /// Select contact and set OPSEC-safe status (SAS + onion tail; never message bodies).
    fn select_contact(&mut self, idx: usize) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(c) = session.contacts.get(idx) else {
            return;
        };
        let sas = Self::contact_sas_short(c).to_string();
        let tail = Self::onion_tail(&c.onion);
        self.selected_contact = Some(idx);
        self.contacts_state.select(Some(idx));
        self.status_msg = format!("Selected SAS {sas} · …{tail}");
    }

    fn show_sas_command(&mut self, args: &str) {
        let args = args.trim();
        let extreme = self.net.is_extreme();
        if args.is_empty() {
            if let Some((sas, tail)) = self.selected_contact_record().map(|c| {
                (
                    Self::contact_sas_short(c).to_string(),
                    Self::onion_tail(&c.onion),
                )
            }) {
                // Extreme: short SAS only — avoid onion material in scrollback.
                if extreme {
                    self.push_msg(format!("Peer SAS {sas} (compare out-of-band)"));
                } else {
                    self.push_msg(format!("Peer SAS {sas} (compare out-of-band) · …{tail}"));
                }
                self.status_msg = format!("SAS {sas}");
            } else if !self.my_sas.is_empty() {
                let mine = self.my_sas.clone();
                self.push_msg(format!("Your SAS {mine} (no contact selected)"));
                self.status_msg = format!("SAS {mine}");
            } else {
                self.status_msg = "No SAS yet — unlock first.".into();
            }
            return;
        }
        match parse_signed_contact_link(args) {
            Ok(peer) => {
                let sas = sas_for_signed(&peer);
                // Never echo the signed URI; Extreme also skips onion tails.
                if extreme {
                    self.push_msg(format!(
                        "Link SAS {sas} (not added — Extreme: use :add-contact privately)"
                    ));
                } else {
                    let tail = Self::onion_tail(&peer.onion);
                    self.push_msg(format!(
                        "Link SAS {sas} · …{tail} (not added — use :add-contact)"
                    ));
                }
                self.status_msg = format!("SAS {sas}");
            }
            Err(_) => {
                self.status_msg = "SAS refused (bad signature or format).".into();
                self.push_msg(self.status_msg.clone());
            }
        }
    }

    fn listen(&mut self) {
        if let Err(e) = self.net.require_messenger_transport() {
            self.status_msg = format!(":listen refused: {e}");
            self.push_msg(self.status_msg.clone());
            return;
        }
        if self.hs.is_some() {
            let onion = self
                .session
                .as_ref()
                .map(|s| s.identity.onion.as_str())
                .unwrap_or("?");
            if self.net.is_extreme() {
                let tail = Self::onion_tail(onion);
                self.status_msg = format!("Already listening (Extreme · …{tail})");
            } else {
                self.status_msg = format!("Already listening as {onion}");
            }
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
                        if self.net.is_extreme() {
                            let tail = Self::onion_tail(&hs.onion);
                            self.status_msg = format!(
                                "Listening (Extreme · …{tail} · local :{})",
                                hs.local_port
                            );
                            self.push_msg(
                                "Hidden service published (Extreme: Tor-only; contact-link export locked).",
                            );
                            self.push_msg(
                                "Peer exchange: use :add-contact with an out-of-band link; :my-contact is refused under Extreme.",
                            );
                        } else {
                            self.status_msg = format!(
                                "Listening on {} (local :{})",
                                hs.onion, hs.local_port
                            );
                            self.push_msg(
                                "Hidden service published; accept loop running (framed wire v2).",
                            );
                            self.push_msg(
                                "Share :my-contact; peer must :add-contact your link (and you theirs).",
                            );
                        }
                        self.hs = Some(hs);
                        self.refresh_identity_display();
                        self.retry_pending(false);
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
                self.push_msg(self.status_msg.clone());
            }
        }
    }

    /// Flush pending outbound frames. `report_empty` is true for explicit `:retry`
    /// (listen auto-flush must not clobber the listening status when the queue is empty).
    fn retry_pending(&mut self, report_empty: bool) {
        if let Err(e) = self.net.require_messenger_transport() {
            self.status_msg = format!(":retry refused: {e}");
            self.push_msg(self.status_msg.clone());
            return;
        }
        if self.tor_status != TorStatus::Available {
            self.status_msg = ":retry refused: Tor SOCKS unavailable".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        let Some(session) = self.session.as_mut() else {
            self.status_msg = "Unlock first.".into();
            return;
        };
        if session.pending.is_empty() {
            if report_empty {
                self.status_msg = "No pending frames".into();
            }
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
        self.push_msg(self.status_msg.clone());
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
                Ok((peer, text, contact_id, msg_number, display)) => {
                    if display {
                        // UI inbox may show plaintext; status/logs must not.
                        self.push_chat(format!("[{peer}] {text}"), &contact_id, msg_number);
                        self.status_msg = format!("Received {n} B · {peer}");
                    } else {
                        // Mute: decrypt advanced ratchet; suppress UI plaintext.
                        let _ = text;
                        self.status_msg = format!("Muted inbound suppressed ({n} B)");
                    }
                }
                Err(e) if e == "blocked" => {
                    // OPSEC: no frame bytes / plaintext in status.
                    self.push_msg("Incoming frame dropped (blocked contact)");
                    self.status_msg = format!("Dropped inbound (blocked, {n} B)");
                }
                Err(_e) => {
                    // OPSEC: no frame bytes / decrypt detail in status.
                    self.push_msg("Incoming frame dropped (decrypt/verify failed)");
                    self.status_msg = format!("Dropped inbound frame ({n} B)");
                }
            }
        }
    }

    /// Returns `(peer_label, plaintext, contact_id, msg_number, display_in_ui)`.
    /// `display_in_ui` is false for muted contacts (ratchet still advanced).
    fn try_decrypt_incoming(
        &mut self,
        transport_frame: &[u8],
    ) -> Result<(String, String, String, u32, bool), String> {
        let (hint, step, sender_dh, ct) =
            unframe_v2(transport_frame).map_err(|_| "malformed wire frame".to_string())?;
        let pass = self.passphrase.as_bytes().to_vec();
        let net = self.net.clone();
        let session = self.session.as_mut().ok_or_else(|| "no session".to_string())?;
        session.net = net;
        let contacts = session.contacts.clone();
        // Wire hint is the sender's static x25519 — try matching contacts first.
        let mut order: Vec<usize> = (0..contacts.len()).collect();
        if hint.len() == 32 {
            order.sort_by_key(|&i| if contacts[i].x25519.as_slice() == hint.as_slice() { 0 } else { 1 });
        }
        for idx in order {
            let c = &contacts[idx];
            // Fail-closed block: do not decrypt or display for blocked contacts.
            match session.inbound_deny_policy(&c.id) {
                InboundDenyPolicy::DropNoDecrypt => {
                    if hint.len() == 32 && c.x25519.as_slice() == hint.as_slice() {
                        return Err("blocked".into());
                    }
                    continue;
                }
                InboundDenyPolicy::DecryptNoDisplay | InboundDenyPolicy::Accept => {}
            }
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
                Ok((mut pt, step)) => {
                    let text = String::from_utf8_lossy(&pt).to_string();
                    pt.zeroize();
                    let contact_id = c.id.clone();
                    session.set_ratchet_bytes(&contact_id, r.to_bytes());
                    let label = if c.display_name.is_empty() {
                        contact_id.clone()
                    } else {
                        c.display_name.clone()
                    };
                    let display = !session.is_muted_id(&contact_id);
                    let _ = save_session(
                        Path::new(DATA_DIR),
                        PersistMode::Passphrase,
                        &pass,
                        session,
                    );
                    return Ok((label, text, contact_id, step, display));
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
                let onion_tail = Self::onion_tail(&peer.onion);
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
                        self.push_msg(format!(
                            "{verb} {sas} — onion …{onion_tail} (peer must :add-contact you too)"
                        ));
                        if let Some(i) = select_idx {
                            self.select_contact(i);
                            // Prefer add/update verb in status over generic Selected line.
                            self.status_msg = format!("{verb} contact (SAS {sas})");
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
            self.status_msg = format!("Send refused: {e}");
            self.push_msg(self.status_msg.clone());
            return;
        }
        if self.tor_status != TorStatus::Available {
            self.status_msg = "Send refused: Tor SOCKS not available (Tor-only policy).".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        let contact = match self.selected_contact_record() {
            Some(c) => c.clone(),
            None => {
                self.status_msg = "Select a contact before sending.".into();
                self.push_msg(self.status_msg.clone());
                return;
            }
        };
        if let Some(session) = self.session.as_ref() {
            if let Err(_) = session.refuse_send_if_blocked(&contact.id) {
                self.status_msg = "Send refused: contact is blocked.".into();
                self.push_msg(self.status_msg.clone());
                return;
            }
        }
        if !is_onion_destination(&contact.onion) {
            self.push_msg("Send refused: contact has no valid v3 .onion.");
            return;
        }

        let peer_label = if contact.display_name.is_empty() {
            contact.id.clone()
        } else {
            contact.display_name.clone()
        };

        let (frame, rbytes, msg_number) = {
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
                        self.push_msg("Ratchet restore failed.");
                        return;
                    }
                }
            } else if contact.x25519 != [0u8; 32] {
                let shared = local.x25519_dh(&x25519_dalek::PublicKey::from(contact.x25519));
                let mut r = DoubleRatchet::new();
                r.init_symmetric(&shared);
                r
            } else {
                self.push_msg(
                    "No ratchet for contact — add via :add-contact <signed link>.",
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
                    self.push_msg("Encrypt failed.");
                    return;
                }
            };
            msg_key.zeroize();
            let frame = frame_v2(&hint, step, &sender_dh, &ct);
            let rbytes = ratchet.to_bytes();
            (frame, rbytes, step)
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
            self.push_msg("Send aborted: durable commit failed.");
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
            self.push_chat(
                format!("[{peer_label}] you: {text}  ({frame_len} B via Tor)"),
                &contact.id,
                msg_number,
            );
            self.status_msg = format!("Sent {frame_len} B via SOCKS");
        } else {
            // OPSEC: short reason only — frame stays queued for :retry.
            self.push_msg(format!("[{peer_label}] queued offline (SOCKS send failed)"));
            self.status_msg = "Queued: SOCKS send failed (frame committed)".into();
        }
    }

    /// `:mode` — inspect / set network mode (durable in session blob after unlock).
    fn handle_mode(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() || args == "status" || args == "show" {
            self.push_msg(self.net.status_line());
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
                            let saved = self.persist_net_after_mode_change();
                            self.status_msg = if saved {
                                format!("Network mode set to {} (saved)", self.net.mode)
                            } else {
                                format!("Network mode set to {} (not saved)", self.net.mode)
                            };
                            self.push_msg(self.net.status_line());
                        }
                        Err(e) => {
                            self.status_msg = e.to_string();
                            self.push_msg(e.to_string());
                        }
                    },
                    Err(e) => {
                        self.status_msg = e.to_string();
                        self.push_msg(e.to_string());
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
                                self.persist_net_after_mode_change();
                                self.status_msg = self.net.status_line();
                                self.push_msg(self.status_msg.clone());
                            }
                            Err(e) => {
                                self.status_msg = e.to_string();
                                self.push_msg(e.to_string());
                            }
                        }
                    }
                    Ok(dns) => match self.net.set_dns(dns, None) {
                        Ok(()) => {
                            self.persist_net_after_mode_change();
                            self.status_msg = self.net.status_line();
                            self.push_msg(self.status_msg.clone());
                        }
                        Err(e) => {
                            self.status_msg = e.to_string();
                            self.push_msg(e.to_string());
                        }
                    },
                    Err(e) => {
                        self.status_msg = e.to_string();
                        self.push_msg(e.to_string());
                    }
                }
            }
            "extreme" | "paranoid" => {
                let switching_to = !self.net.is_extreme();
                self.net.set_posture(PostureProfile::Extreme);
                if switching_to {
                    // Shrink RAM residue when entering Extreme; contacts stay for this session.
                    self.clear_transcript_secure();
                    self.push_msg(
                        "Extreme: chat transcript cleared. Contacts/queue are not durable across restart — re-add contacts after unlock.",
                    );
                }
                self.apply_extreme_ttl_default();
                let saved = self.persist_net_after_mode_change();
                let tag = if saved { "saved" } else { "not saved" };
                self.status_msg = format!(
                    "Posture extreme ({tag}). {}",
                    self.net.status_line()
                );
                self.push_msg(self.status_msg.clone());
                if let Some(note) = self.net.extreme_lock_summary() {
                    self.push_msg(note);
                }
            }
            "standard" | "normal" => {
                self.net.set_posture(PostureProfile::Standard);
                let saved = self.persist_net_after_mode_change();
                let tag = if saved { "saved" } else { "not saved" };
                self.status_msg = format!(
                    "Posture standard ({tag}). {}",
                    self.net.status_line()
                );
                self.push_msg(self.status_msg.clone());
            }
            "help" => {
                self.push_msg(
                    "Usage: :mode [status|tor|i2p|clearnet|dns system|dns quad9|dns custom <addr>|extreme|standard]",
                );
                self.push_msg(
                    "Default Tor. I2P/clearnet refuse messenger sockets until implemented.",
                );
                self.push_msg(
                    "Extreme: Tor-only; refuses :my-contact/groups/voice; contacts/queue/deny-lists not durable; SAS ok (short). Not Android Extreme parity.",
                );
                if let Some(note) = self.net.extreme_lock_summary() {
                    self.push_msg(note);
                }
            }
            other => {
                self.status_msg = format!("Unknown :mode argument: {other} (:mode help)");
                self.push_msg(self.status_msg.clone());
            }
        }
    }


    fn deny_token_or_selected(&self, args: &str) -> Result<String, &'static str> {
        let args = args.trim();
        let session = self.session.as_ref().ok_or("Unlock first.")?;
        if !args.is_empty() {
            return session
                .resolve_deny_token(args)
                .ok_or("unknown or ambiguous contact (id / SAS prefix)");
        }
        let c = self
            .selected_contact_record()
            .ok_or("Select a contact or pass id/SAS prefix")?;
        Ok(c.id.clone())
    }

    fn handle_block_command(&mut self, args: &str) {
        let id = match self.deny_token_or_selected(args) {
            Ok(id) => id,
            Err(e) => {
                self.status_msg = format!(":block refused: {e}");
                self.push_msg(self.status_msg.clone());
                return;
            }
        };
        let label = self
            .session
            .as_ref()
            .and_then(|s| s.contacts.iter().find(|c| c.id == id))
            .map(|c| Self::contact_sas_short(c).to_string())
            .unwrap_or_else(|| id.clone());
        let newly = self
            .session
            .as_mut()
            .map(|s| s.block_contact_id(id))
            .unwrap_or(false);
        match self.persist_session() {
            Ok(()) => {
                let verb = if newly { "Blocked" } else { "Already blocked" };
                self.status_msg = format!("{verb} SAS {label} (send+inbound refused)");
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => self.status_msg = "Failed to persist block list.".into(),
        }
    }

    fn handle_unblock_command(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() {
            // Prefer selected contact id when present.
            let token = match self.selected_contact_record() {
                Some(c) => c.id.clone(),
                None => {
                    self.status_msg = "Usage: :unblock <contact|sas-prefix|id>".into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
            };
            return self.handle_unblock_command(&token);
        }
        let Some(session) = self.session.as_mut() else {
            self.status_msg = "Unlock first.".into();
            return;
        };
        let removed = session.unblock_contact_id(args);
        if !removed {
            self.status_msg = ":unblock: not on block list (or ambiguous)".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        match self.persist_session() {
            Ok(()) => {
                self.status_msg = "Unblocked contact.".into();
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => self.status_msg = "Failed to persist unblock.".into(),
        }
    }

    fn handle_blocked_list(&mut self) {
        let Some(session) = self.session.as_ref() else {
            self.status_msg = "Unlock first.".into();
            return;
        };
        let n_blocked = session.blocked_ids.len();
        let n_muted = session.muted_ids.len();
        if n_blocked == 0 && n_muted == 0 {
            self.push_msg("No blocked or muted contacts.");
            self.status_msg = "Deny list empty.".into();
            return;
        }
        let mut lines: Vec<String> = Vec::new();
        if n_blocked > 0 {
            lines.push("Blocked:".into());
            for id in &session.blocked_ids {
                let sas = session
                    .contacts
                    .iter()
                    .find(|c| &c.id == id)
                    .map(|c| Self::contact_sas_short(c).to_string())
                    .unwrap_or_else(|| id.clone());
                lines.push(format!("  {id} · SAS {sas}"));
            }
        }
        if n_muted > 0 {
            lines.push("Muted:".into());
            for id in &session.muted_ids {
                let sas = session
                    .contacts
                    .iter()
                    .find(|c| &c.id == id)
                    .map(|c| Self::contact_sas_short(c).to_string())
                    .unwrap_or_else(|| id.clone());
                lines.push(format!("  {id} · SAS {sas}"));
            }
        }
        for line in lines {
            self.push_msg(line);
        }
        self.status_msg = format!("{n_blocked} blocked · {n_muted} muted");
    }

    fn handle_mute_command(&mut self, args: &str) {
        let id = match self.deny_token_or_selected(args) {
            Ok(id) => id,
            Err(e) => {
                self.status_msg = format!(":mute refused: {e}");
                self.push_msg(self.status_msg.clone());
                return;
            }
        };
        let label = self
            .session
            .as_ref()
            .and_then(|s| s.contacts.iter().find(|c| c.id == id))
            .map(|c| Self::contact_sas_short(c).to_string())
            .unwrap_or_else(|| id.clone());
        let result = self
            .session
            .as_mut()
            .map(|s| s.mute_contact_id(id))
            .unwrap_or(Err("no session"));
        match result {
            Ok(newly) => match self.persist_session() {
                Ok(()) => {
                    let verb = if newly { "Muted" } else { "Already muted" };
                    self.status_msg =
                        format!("{verb} SAS {label} (inbound UI suppressed; decrypt ok)");
                    self.push_msg(self.status_msg.clone());
                }
                Err(_) => self.status_msg = "Failed to persist mute list.".into(),
            },
            Err(e) => {
                self.status_msg = format!(":mute refused: {e}");
                self.push_msg(self.status_msg.clone());
            }
        }
    }

    fn handle_unmute_command(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() {
            let token = match self.selected_contact_record() {
                Some(c) => c.id.clone(),
                None => {
                    self.status_msg = "Usage: :unmute <contact|sas-prefix|id>".into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
            };
            return self.handle_unmute_command(&token);
        }
        let Some(session) = self.session.as_mut() else {
            self.status_msg = "Unlock first.".into();
            return;
        };
        let removed = session.unmute_contact_id(args);
        if !removed {
            self.status_msg = ":unmute: not on mute list (or ambiguous)".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        match self.persist_session() {
            Ok(()) => {
                self.status_msg = "Unmuted contact.".into();
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => self.status_msg = "Failed to persist unmute.".into(),
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
                self.clear_transcript_secure();
                self.disappear_ttl_secs = 0;
                self.net = NetConfig::from_env();
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
                if self.net.extreme_blocks_contact_export() {
                    self.status_msg =
                        "extreme posture refuses contact-link export (minimize link sharing)"
                            .into();
                    self.push_msg(self.status_msg.clone());
                } else if let Err(e) = self.net.require_messenger_transport() {
                    self.status_msg = format!(":my-contact refused: {e}");
                    self.push_msg(self.status_msg.clone());
                } else if self.my_contact_link.is_empty() {
                    self.push_msg("No contact link yet (unlock + :listen first).");
                } else {
                    self.push_msg(format!("SAS: {}", self.my_sas));
                    self.push_msg(format!("Contact: {}", self.my_contact_link));
                    self.status_msg = format!("SAS {}", self.my_sas);
                }
            }
            ":listen" => self.listen(),
            ":retry" => self.retry_pending(true),
            ":status" | ":tor" => {
                self.check_tor(true);
                let probe = tor_probe(SOCKS_HOST, self.socks_port, CONTROL_PORT);
                let onion_disp = self
                    .session
                    .as_ref()
                    .map(|s| {
                        if s.identity.onion.is_empty() {
                            "-".into()
                        } else if self.net.is_extreme() {
                            format!("…{}", Self::onion_tail(&s.identity.onion))
                        } else {
                            s.identity.onion.clone()
                        }
                    })
                    .unwrap_or_else(|| "-".into());
                let listening = self.hs.is_some();
                self.push_msg(format!(
                    "{} · onion={} · listening={} · pending={}",
                    probe.note,
                    onion_disp,
                    listening,
                    self.session
                        .as_ref()
                        .map(|s| s.pending.len())
                        .unwrap_or(0)
                ));
                self.push_msg(self.net.status_line());
                self.push_msg(format!(
                    "disappear={} (local TTL; peer not enforced)",
                    format_ttl(self.disappear_ttl_secs)
                ));
                if let Some(s) = self.session.as_ref() {
                    self.push_msg(format!(
                        "deny: {} blocked · {} muted{}",
                        s.blocked_ids.len(),
                        s.muted_ids.len(),
                        if self.net.is_extreme() {
                            " (Extreme: deny lists not durable)"
                        } else {
                            ""
                        }
                    ));
                }
                if let Some(note) = self.net.extreme_lock_summary() {
                    self.push_msg(note);
                }
                self.status_msg = self.tor_status.label(listening);
            }
            ":help" => {
                self.push_msg("HashChat commands:");
                self.push_msg("  :listen                 publish Tor v3 onion (ControlPort)");
                self.push_msg(
                    "  :add-contact <link>     verify signed link + bootstrap ratchet",
                );
                self.push_msg("  :my-contact             your signed link + short SAS");
                self.push_msg("  :sas [link]             short SAS (selected contact or link)");
                self.push_msg(
                    "  :mode [tor|status|…]    network mode (Tor default; fail-closed)",
                );
                self.push_msg(
                    "  :retry                  flush pending queue (Tor / net_mode gate)",
                );
                self.push_msg(
                    "  :disappear [off|30s|…]  local TTL erase + ratchet skipped-key wipe",
                );
                self.push_msg(
                    "  :block / :unblock [id]  refuse send + drop inbound (fail-closed)",
                );
                self.push_msg(
                    "  :mute / :unmute [id]    suppress inbound UI (decrypt for sync)",
                );
                self.push_msg("  :blocked                list blocked + muted ids");
                self.push_msg("  :wipe                   nuclear local wipe (confirm)");
                self.push_msg("  :quit                   exit");
                self.push_msg(
                    "Keys: Tab focus · ↑↓ select contact · Enter select/send. Status never shows plaintext bodies.",
                );
                if let Some(note) = self.net.extreme_lock_summary() {
                    self.push_msg(note);
                } else {
                    self.push_msg(
                        "Posture: standard (use :mode extreme for Tor-only + metadata locks).",
                    );
                }
                self.status_msg = "Help listed in chat.".into();
            }
            "" => {}
            cmd if matches!(cmd, ":group" | ":groups" | ":voice" | ":record") => {
                // No group/voice commands in this TUI; Extreme still refuses explicitly.
                if matches!(cmd, ":voice" | ":record") {
                    if self.net.extreme_blocks_voice() {
                        self.status_msg = "extreme posture refuses voice".into();
                    } else {
                        self.status_msg =
                            "Voice not available in this TUI (desktop text/Tor path only).".into();
                    }
                } else if self.net.extreme_blocks_groups() {
                    self.status_msg = "extreme posture refuses groups".into();
                } else {
                    self.status_msg =
                        "Groups not available in this TUI (desktop text/Tor path only).".into();
                }
                self.push_msg(self.status_msg.clone());
            }
            other if other.starts_with(":add-contact ") => {
                let link = other.strip_prefix(":add-contact ").unwrap_or("").trim();
                self.add_contact_link(link);
            }
            other if other == ":sas" || other.starts_with(":sas ") => {
                let args = other.strip_prefix(":sas").unwrap_or("").trim();
                self.show_sas_command(args);
            }
            other if other == ":mode" || other.starts_with(":mode ") => {
                let args = other.strip_prefix(":mode").unwrap_or("").trim();
                self.handle_mode(args);
            }
            other if other == ":block" || other.starts_with(":block ") => {
                let args = other.strip_prefix(":block").unwrap_or("").trim();
                self.handle_block_command(args);
            }
            other if other == ":unblock" || other.starts_with(":unblock ") => {
                let args = other.strip_prefix(":unblock").unwrap_or("").trim();
                self.handle_unblock_command(args);
            }
            ":blocked" => self.handle_blocked_list(),
            other if other == ":mute" || other.starts_with(":mute ") => {
                let args = other.strip_prefix(":mute").unwrap_or("").trim();
                self.handle_mute_command(args);
            }
            other if other == ":unmute" || other.starts_with(":unmute ") => {
                let args = other.strip_prefix(":unmute").unwrap_or("").trim();
                self.handle_unmute_command(args);
            }
            other if other == ":disappear"
                || other.starts_with(":disappear ")
                || other == ":ttl"
                || other.starts_with(":ttl ") =>
            {
                let args = if other.starts_with(":ttl") {
                    other.strip_prefix(":ttl").unwrap_or("").trim()
                } else {
                    other.strip_prefix(":disappear").unwrap_or("").trim()
                };
                self.handle_disappear(args);
            }
            other if other.starts_with(':') => {
                self.push_msg(format!("Unknown command: {other}  (:help)"));
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
        Span::styled(" · ", Style::default().fg(DIM)),
        Span::styled(
            format!("ttl={}", format_ttl(app.disappear_ttl_secs)),
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
            .map(|m| Line::from(Span::styled(m.text.as_str(), Style::default().fg(TEXT))))
            .collect()
    };
    let chat_title = match app.selected_contact_record() {
        Some(c) => format!(" chat · SAS {} ", App::contact_sas_short(c)),
        None => " chat ".to_string(),
    };
    let chat = Paragraph::new(msg_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(chat_title, gold_style()))
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
        app.expire_messages();
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
                        app.select_contact(ni);
                    }
                }
                KeyCode::Down if app.focus == Focus::Contacts => {
                    let len = app.contact_names().len();
                    if len > 0 {
                        let i = app.selected_contact.unwrap_or(len - 1);
                        let ni = (i + 1) % len;
                        app.select_contact(ni);
                    }
                }
                KeyCode::Enter if app.focus == Focus::Contacts && app.input.is_empty() => {
                    if let Some(i) = app.selected_contact {
                        app.select_contact(i);
                    } else if !app.contact_names().is_empty() {
                        app.select_contact(0);
                    } else {
                        app.status_msg = "No contacts — :add-contact <signed link>".into();
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
