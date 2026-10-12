//! HashChat native Rust TUI (transitional desktop path toward max-Rust).
//!
//! Build: `cargo build --bin hashchat-tui --features tui`
//!
//! Uses crate APIs: session_persist, contact_link, LongTermIdentity, wipe,
//! Tor ControlPort cookie auth + ADD_ONION listen, SOCKS send (fail-closed).
//! Transport policy: Tor default (explicit modes via :mode / env); no silent fallback.
//!
//! Panic / SIGINT / SIGTERM: best-effort in-RAM secret scrub (not a substitute for `:wipe`).

use std::io::{self, stdout};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hashchat_rust::{
    attempt_failed, attempt_succeeded, begin_attempt, binary_status,
    bootstrap_ratchet_from_signed_link, build_wire_aad_v3, check_new_passphrase,
    check_plaintext_send_size, check_save_mark, check_state_storage, clear_deadman, clear_duress,
    clear_failwipe, clear_scrub_callback, clock_rollback_secs, commit_outgoing_with_key,
    deadman_config, digest_hex, disable_core_dumps_best_effort, duress_configured,
    encrypt_with_key, extreme_default_lock_timeout, extreme_default_ttl, failwipe_config,
    format_bound_contact_link, format_jitter, format_lock_timeout, format_rollback, format_ttl,
    frame_v3, install_panic_scrub_hook, install_terminate_signal_flag, is_onion_destination,
    is_terminal_safe, mlockall_current, pad_message, parse_bridge_line, parse_jitter_token,
    parse_lock_timeout_token, parse_signed_contact_link, parse_ttl_token, push_char_no_realloc,
    query_bridge_status, register_scrub_callback, running_binary_digest, sample_send_delay,
    sanitize_for_terminal, sas_fingerprint, sas_for_signed, save_session_with_key, set_deadman,
    set_duress_passphrase_with, set_failwipe, socks5_send, socks_isolation_for_contact,
    socks_isolation_for_onion, start_hidden_service_with_key, state_exists, take_terminate_signal,
    take_zeroizing_vec, tor_probe, torrc_snippet, touch_deadman, unframe_v3, unix_now,
    unlock_backoff_delay_secs, unlock_session, unpad_message, wipe_if_deadman_due,
    wipe_local_sensitive, wipe_on_duress, Attempt, BinaryStatus, BridgeVerdict, DnsPreference,
    DoubleRatchet, DumpHardening, DuressAction, FrameV3, HiddenService, IdentityOnionState,
    InboundDenyPolicy, LongTermIdentity, NetConfig, NetworkMode, PersistedContact, PostureProfile,
    SaveMarkStatus, SessionState, SocksIsolationCreds, StoreKey, UnlockBackoffPolicy, WipeSettings,
    DEFAULT_LOCK_TIMEOUT_SECS, ERR_QUEUE_FULL, MAX_DEADMAN_DAYS, MAX_FAIL_LIMIT,
    MAX_PLAINTEXT_SEND_BYTES, MIN_NEW_PASSPHRASE_CHARS, MIN_NEW_PASSPHRASE_CHARS_EXTREME,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::Terminal;
use zeroize::{Zeroize, Zeroizing};

const DATA_DIR: &str = "hashchat_data";
/// Turning a wipe protection off needs the passphrase, so someone at the
/// locked screen cannot disarm it before forcing an unlock.
const UNLOCK_TO_DISABLE: &str = "Unlock first: turning a wipe protection off needs the passphrase.";
// Design tokens: docs/DESIGN.md (dark-first, black and gold).
const GOLD: Color = Color::Rgb(255, 210, 74); // #FFD24A
const GOLD_DEEP: Color = Color::Rgb(232, 180, 0); // #E8B400
const BG: Color = Color::Rgb(0, 0, 0); // #000000 window
const PANEL: Color = Color::Rgb(11, 11, 13); // #0B0B0D panels
const SURFACE: Color = Color::Rgb(18, 18, 20); // #121214 inputs, incoming bubbles
const HAIRLINE: Color = Color::Rgb(58, 54, 40); // borders (hairline, lifted for terminals)
const TEXT: Color = Color::Rgb(237, 237, 237); // #EDEDED
const DIM: Color = Color::Rgb(138, 135, 120); // #8A8778 muted
const DANGER: Color = Color::Rgb(255, 138, 138); // #FF8A8A
const SELECT_BG: Color = Color::Rgb(36, 31, 14); // selected contact row
const TOR: Color = Color::Rgb(196, 168, 255); // #C4A8FF
const I2P: Color = Color::Rgb(126, 224, 198); // #7EE0C6

fn tui_restore_terminal_best_effort() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
}

/// Panic-hook callback: restore the terminal without touching `App`.
///
/// The earlier raw-pointer callback was unsound if panic began while `App` was
/// already mutably borrowed. Rust unwinding drops `App` and its safe `Drop`
/// implementation performs the actual best-effort secret scrub.
fn tui_registered_scrub() {
    tui_restore_terminal_best_effort();
}

fn bind_app_scrub() {
    register_scrub_callback(tui_registered_scrub);
}

fn unbind_app_scrub() {
    clear_scrub_callback();
}

const SOCKS_HOST: &str = "127.0.0.1";
const SOCKS_PORTS: [u16; 2] = [9050, 9150];
const CONTROL_PORT: u16 = 9051;
/// How long a passing bridge check lets sends through before Tor is asked again.
const BRIDGE_CHECK_OK_SECS: u64 = 30;
/// How long a failing bridge check is reused before Tor is asked again.
const BRIDGE_CHECK_FAIL_SECS: u64 = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Unlock,
    Main,
    ConfirmWipe,
    /// Two-step `:delete-contact` confirm (OPSEC; not a remote wipe).
    ConfirmDeleteContact,
    /// Masked two-step entry for the duress passphrase (`:duress set`).
    SetDuress,
    /// Read-only SAS comparison grid (`:sas-grid`). Esc/Enter returns.
    SasGrid,
    /// Read-only own contact-link card (`:contact-card`). Esc/Enter returns.
    ContactCard,
    /// Read-only plans + pay-what-you-want (`:support`). No network.
    Support,
}

/// Delivery state of an outgoing bubble (display only; policy lives in send paths).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Delivery {
    Sent,
    Held,
    Queued,
}

impl Delivery {
    fn label(self) -> &'static str {
        match self {
            Delivery::Sent => "sent",
            Delivery::Held => "held · random delay",
            Delivery::Queued => "queued",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Contacts,
    Input,
}

/// A committed frame waiting out its send jitter. The plaintext is not kept;
/// the frame is also in the durable queue, so dropping this only delays it.
struct HeldSend {
    due: Instant,
    contact_id: String,
    onion: String,
    frame: Vec<u8>,
    peer_label: String,
    msg_number: u32,
}

impl Drop for HeldSend {
    fn drop(&mut self) {
        self.frame.zeroize();
    }
}

/// In-memory transcript line. Chat bodies may carry a local TTL; system notes do not.
struct ChatLine {
    text: String,
    expires_at: Option<Instant>,
    /// Contact id + ratchet message number for [`DoubleRatchet::wipe_skipped_key`] on expiry.
    wipe_key: Option<(String, u32)>,
    /// Presentation only: render as outgoing (gold) bubble.
    outgoing: bool,
    /// Outgoing only: last known delivery state (display only).
    delivery: Option<Delivery>,
}

/// Passphrase buffers are pre-allocated to this many bytes and never grow, so
/// typing does not leave freed copies of passphrase prefixes on the heap.
const PASSPHRASE_BUF_CAP: usize = 1024;

fn push_secret_char(buf: &mut String, ch: char) -> bool {
    push_char_no_realloc(buf, ch, PASSPHRASE_BUF_CAP)
}

/// Transcript text is sanitised when stored so no later render path can forget.
/// The unsanitised original is zeroized (it may be peer plaintext).
fn terminal_safe_owned(mut s: String) -> String {
    if is_terminal_safe(&s) {
        return s;
    }
    let out = sanitize_for_terminal(&s).into_owned();
    s.zeroize();
    out
}

impl ChatLine {
    fn sys(text: impl Into<String>) -> Self {
        Self {
            text: terminal_safe_owned(text.into()),
            expires_at: None,
            wipe_key: None,
            outgoing: false,
            delivery: None,
        }
    }

    fn chat(
        text: impl Into<String>,
        ttl_secs: u32,
        wipe_key: Option<(String, u32)>,
        outgoing: bool,
    ) -> Self {
        let expires_at = if ttl_secs == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(u64::from(ttl_secs)))
        };
        Self {
            text: terminal_safe_owned(text.into()),
            expires_at,
            wipe_key,
            outgoing,
            delivery: None,
        }
    }
}

impl Drop for ChatLine {
    fn drop(&mut self) {
        self.text.zeroize();
        if let Some((ref mut cid, _)) = self.wipe_key {
            cid.zeroize();
        }
    }
}

struct App {
    screen: Screen,
    focus: Focus,
    passphrase: String,
    /// Argon2id-derived store key kept after unlock instead of the passphrase
    /// (boxed so its address is stable for mlock). Dropped (zeroized) on lock.
    store_key: Option<Box<StoreKey>>,
    /// Core-dump / ptrace hardening applied at startup (posture token for :evidence).
    dump_hardening: Option<DumpHardening>,
    passphrase_confirm: String,
    unlock_mode_create: bool,
    unlock_step: UnlockStep,
    /// Status note "mlock unavailable (best-effort)" shown at most once per process.
    mlock_note_shown: bool,
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
    /// Last observed HS inbound drop counter (backpressure; no contents).
    hs_drops_seen: u64,
    /// Network prefs: env at cold start / new identity; after unlock, loaded blob wins.
    net: NetConfig,
    /// Local disappearing TTL seconds (0 = off). Synced into session blob v4+.
    disappear_ttl_secs: u32,
    /// Idle auto-lock timeout seconds (0 = off). Synced into session blob v7+.
    lock_timeout_secs: u32,
    /// Maximum random send delay in seconds (0 = off). Synced into session blob v8+.
    send_jitter_secs: u32,
    /// Frames committed but not yet handed to Tor because of send jitter.
    held_sends: Vec<HeldSend>,
    /// Last bridge check for `:bridges require on`: when, and why sends were
    /// held (`Ok` = bridges active). Re-asked after a short cache window.
    bridge_check: Option<(Instant, Result<(), String>)>,
    /// Set at unlock when the clock reads well before the mark in state.enc.
    clock_behind_secs: Option<u64>,
    /// Set at unlock when the running binary is not the one recorded in state.enc.
    binary_changed: bool,
    /// Wipe settings that differ from the record in state.enc, set at unlock.
    wipe_settings_changed: Vec<&'static str>,
    /// How `state.enc` compared with `state.mark` at the last unlock.
    save_mark: SaveMarkStatus,
    /// Action chosen by `:duress set` / `:duress set decoy` while the entry screen is open.
    duress_setup_action: DuressAction,
    /// Last user input Instant (Main / confirm screens). Used for idle auto-lock.
    last_input_at: Instant,
    /// Pending contact id for `:delete-contact-confirm` (cleared on Esc / success).
    pending_delete_contact: Option<String>,
    /// Consecutive wrong-passphrase unlock failures (reset on success).
    unlock_fail_count: u32,
    /// When set, refuse unlock attempts until this Instant (local UI backoff).
    unlock_cooldown_until: Option<Instant>,
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

/// A change between reachable and unreachable SOCKS. The first probe after
/// start (from `Checking`) is not a change; the header already shows it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TorChange {
    WentDown,
    CameBack,
}

fn tor_change(prev: TorStatus, next: TorStatus) -> Option<TorChange> {
    match (prev, next) {
        (TorStatus::Available, TorStatus::Unavailable) => Some(TorChange::WentDown),
        (TorStatus::Unavailable, TorStatus::Available) => Some(TorChange::CameBack),
        _ => None,
    }
}

/// Header note for frames committed but not yet handed to Tor.
fn queued_label(n: usize) -> Option<String> {
    (n > 0).then(|| format!("{n} queued"))
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
}

impl App {
    fn new() -> Self {
        let exists = state_exists(Path::new(DATA_DIR));
        Self {
            screen: Screen::Unlock,
            focus: Focus::Contacts,
            passphrase: String::with_capacity(PASSPHRASE_BUF_CAP),
            store_key: None,
            dump_hardening: None,
            passphrase_confirm: String::with_capacity(PASSPHRASE_BUF_CAP),
            unlock_mode_create: !exists,
            unlock_step: UnlockStep::EnterPass,
            mlock_note_shown: false,
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
            hs_drops_seen: 0,
            net: NetConfig::from_env(),
            disappear_ttl_secs: 0,
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            send_jitter_secs: 0,
            held_sends: Vec::new(),
            bridge_check: None,
            clock_behind_secs: None,
            binary_changed: false,
            wipe_settings_changed: Vec::new(),
            save_mark: SaveMarkStatus::Unrecorded,
            duress_setup_action: DuressAction::Wipe,
            last_input_at: Instant::now(),
            pending_delete_contact: None,
            unlock_fail_count: 0,
            unlock_cooldown_until: None,
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
        let onion_key = Zeroizing::new(session.identity.onion_key.clone());
        match format_bound_contact_link(&id, &onion, &onion_key) {
            Ok(link) => self.my_contact_link = link,
            Err(_) => {
                self.my_contact_link =
                    "(contact link unavailable — onion key missing or does not match the onion)"
                        .into();
            }
        }
    }

    fn persist_session(&mut self) -> Result<(), &'static str> {
        let Some(session) = self.session.as_mut() else {
            return Err("no session");
        };
        let Some(key) = self.store_key.as_deref() else {
            return Err("locked");
        };
        // Keep blob prefs aligned with live NetConfig + TTL + idle lock.
        session.net = self.net.clone();
        session.disappear_ttl_secs = self.disappear_ttl_secs;
        session.lock_timeout_secs = self.lock_timeout_secs;
        session.send_jitter_secs = self.send_jitter_secs;
        save_session_with_key(Path::new(DATA_DIR), key, session)
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
                self.push_msg("Mode updated in memory; durable save failed (unlock/passphrase?).");
                false
            }
        }
    }

    fn push_msg(&mut self, text: impl Into<String>) {
        self.messages.push(ChatLine::sys(text));
    }

    fn push_chat(&mut self, text: impl Into<String>, contact_id: &str, msg_number: u32) {
        self.push_chat_dir(text, contact_id, msg_number, false);
    }

    fn push_chat_out(&mut self, text: impl Into<String>, contact_id: &str, msg_number: u32) {
        self.push_chat_out_state(text, contact_id, msg_number, Delivery::Sent);
    }

    fn push_chat_out_state(
        &mut self,
        text: impl Into<String>,
        contact_id: &str,
        msg_number: u32,
        delivery: Delivery,
    ) {
        self.push_chat_dir(text, contact_id, msg_number, true);
        if let Some(m) = self.messages.last_mut() {
            m.delivery = Some(delivery);
        }
    }

    /// Update the bubble footer of an outgoing line (display only).
    fn set_delivery(&mut self, contact_id: &str, msg_number: u32, d: Delivery) {
        for m in self.messages.iter_mut().filter(|m| m.outgoing) {
            if let Some((cid, n)) = &m.wipe_key {
                if cid == contact_id && *n == msg_number {
                    m.delivery = Some(d);
                }
            }
        }
    }

    fn push_chat_dir(
        &mut self,
        text: impl Into<String>,
        contact_id: &str,
        msg_number: u32,
        outgoing: bool,
    ) {
        let wipe = if contact_id.is_empty() {
            None
        } else {
            Some((contact_id.to_string(), msg_number))
        };
        self.messages.push(ChatLine::chat(
            text,
            self.disappear_ttl_secs,
            wipe,
            outgoing,
        ));
    }

    /// Drop expired chat lines (zeroize plaintext) and wipe matching skipped ratchet keys.
    fn expire_messages(&mut self) {
        let now = Instant::now();
        let mut to_wipe: Vec<(String, u32)> = Vec::new();
        let mut kept: Vec<ChatLine> = Vec::with_capacity(self.messages.len());
        for mut line in self.messages.drain(..) {
            let expired = line.expires_at.map(|t| now >= t).unwrap_or(false);
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
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(bytes) = session
            .ratchets
            .iter()
            .find(|(id, _)| id == contact_id)
            .map(|(_, b)| Zeroizing::new(b.clone()))
        else {
            return;
        };
        let Ok(mut r) = DoubleRatchet::from_bytes(&bytes) else {
            return;
        };
        drop(bytes);
        r.wipe_skipped_key(msg_number);
        session.set_ratchet_bytes(contact_id, take_zeroizing_vec(r.to_bytes()));
        if let Some(key) = self.store_key.as_deref() {
            let _ = save_session_with_key(Path::new(DATA_DIR), key, session);
        }
    }

    /// Zeroize and drop in-memory chat transcript (Extreme switch / wipe hygiene).
    fn clear_transcript_secure(&mut self) {
        for line in self.messages.iter_mut() {
            line.text.zeroize();
        }
        self.messages.clear();
    }

    /// Clear the draft/input buffer after scrubbing (L-2: `clear` alone leaves residues).
    fn clear_input_secure(&mut self) {
        self.input.zeroize();
        self.input.clear();
    }

    /// Zeroize plaintext chat lines tagged with `contact_id` (via wipe_key).
    fn clear_contact_chat_lines(&mut self, contact_id: &str) {
        let mut kept: Vec<ChatLine> = Vec::with_capacity(self.messages.len());
        for mut line in self.messages.drain(..) {
            let match_cid = line
                .wipe_key
                .as_ref()
                .map(|(cid, _)| cid == contact_id)
                .unwrap_or(false);
            if match_cid {
                line.text.zeroize();
                if let Some((mut cid, _)) = line.wipe_key.take() {
                    cid.zeroize();
                }
            } else {
                kept.push(line);
            }
        }
        self.messages = kept;
    }

    /// Adjust selection after removing contact at `removed_idx`.
    fn fix_selection_after_contact_removal(&mut self, removed_idx: usize) {
        let len = self.session.as_ref().map(|s| s.contacts.len()).unwrap_or(0);
        match self.selected_contact {
            Some(sel) if sel == removed_idx => {
                self.selected_contact = None;
                self.contacts_state.select(None);
            }
            Some(sel) if sel > removed_idx => {
                let ni = sel - 1;
                if ni < len {
                    self.selected_contact = Some(ni);
                    self.contacts_state.select(Some(ni));
                } else {
                    self.selected_contact = None;
                    self.contacts_state.select(None);
                }
            }
            _ => {}
        }
    }

    fn handle_delete_contact_command(&mut self, args: &str) {
        let id = match self.deny_token_or_selected(args) {
            Ok(id) => id,
            Err(e) => {
                self.status_msg = format!(":delete-contact refused: {e}");
                self.push_msg(self.status_msg.clone());
                return;
            }
        };
        self.pending_delete_contact = Some(id);
        self.clear_input_secure();
        self.screen = Screen::ConfirmDeleteContact;
        self.status_msg =
            "DELETE CONTACT: type :delete-contact-confirm to wipe ratchet, or Esc to cancel."
                .into();
    }

    fn handle_duress(&mut self, args: &str) {
        let data_dir = Path::new(DATA_DIR);
        match args.trim() {
            "" | "status" => {
                self.status_msg = if duress_configured(data_dir) {
                    "duress passphrase: set".into()
                } else {
                    "duress passphrase: not set".into()
                };
                self.push_msg(self.status_msg.clone());
            }
            "set" | "set decoy" => {
                if self.session.is_none() {
                    self.status_msg = "Unlock first.".into();
                    return;
                }
                self.duress_setup_action = if args.trim() == "set decoy" {
                    DuressAction::Decoy
                } else {
                    DuressAction::Wipe
                };
                self.clear_input_secure();
                self.passphrase.zeroize();
                self.passphrase.clear();
                self.passphrase_confirm.zeroize();
                self.passphrase_confirm.clear();
                self.unlock_step = UnlockStep::EnterPass;
                self.screen = Screen::SetDuress;
                self.status_msg = "Enter the duress passphrase.".into();
            }
            "clear" => {
                if self.session.is_none() {
                    self.status_msg = UNLOCK_TO_DISABLE.into();
                    return;
                }
                clear_duress(data_dir);
                self.record_wipe_settings();
                self.status_msg = "duress passphrase removed".into();
                self.push_msg(self.status_msg.clone());
            }
            _ => {
                self.status_msg = "Usage: :duress [status|set|set decoy|clear]".into();
            }
        }
    }

    fn handle_wipe_after(&mut self, args: &str) {
        let data_dir = Path::new(DATA_DIR);
        let mut words = args.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (None, _, _) | (Some("status"), None, _) => {
                self.status_msg = match failwipe_config(data_dir) {
                    Some(cfg) => format!(
                        "wipe after {} failed unlocks ({} used)",
                        cfg.limit, cfg.count
                    ),
                    None => "wipe after failed unlocks: off".into(),
                };
            }
            (Some("off"), None, _) => {
                if self.session.is_none() {
                    self.status_msg = UNLOCK_TO_DISABLE.into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
                clear_failwipe(data_dir);
                self.record_wipe_settings();
                self.status_msg = "wipe after failed unlocks: off".into();
            }
            (Some("set"), Some(n), None) => {
                if self.session.is_none() {
                    self.status_msg = "Unlock first.".into();
                    return;
                }
                self.status_msg = match n.parse::<u32>() {
                    Ok(limit) => match set_failwipe(data_dir, limit) {
                        Ok(()) => {
                            self.record_wipe_settings();
                            format!(
                                "wipe after {limit} failed unlocks. The count survives restarts."
                            )
                        }
                        Err(reason) => format!("Refused: {reason}."),
                    },
                    Err(_) => format!("Usage: :wipe-after set <3-{MAX_FAIL_LIMIT}>"),
                };
            }
            _ => {
                self.status_msg =
                    format!("Usage: :wipe-after [status|off|set <3-{MAX_FAIL_LIMIT}>]");
            }
        }
        self.push_msg(self.status_msg.clone());
    }

    fn handle_deadman(&mut self, args: &str) {
        let data_dir = Path::new(DATA_DIR);
        let mut words = args.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (None, _, _) | (Some("status"), None, _) => {
                self.status_msg = match deadman_config(data_dir) {
                    Some(cfg) => {
                        let left = cfg.remaining_secs(unix_now()) / 3600;
                        format!(
                            "dead-man switch: wipe after {} day(s) without unlock ({left} h left)",
                            cfg.days
                        )
                    }
                    None => "dead-man switch: off".into(),
                };
            }
            (Some("off"), None, _) => {
                if self.session.is_none() {
                    self.status_msg = UNLOCK_TO_DISABLE.into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
                clear_deadman(data_dir);
                self.record_wipe_settings();
                self.status_msg = "dead-man switch off".into();
            }
            (Some("set"), Some(n), None) => {
                if self.session.is_none() {
                    self.status_msg = "Unlock first.".into();
                    return;
                }
                self.status_msg = match n.parse::<u32>() {
                    Ok(days) => match set_deadman(data_dir, days, unix_now()) {
                        Ok(()) => {
                            self.record_wipe_settings();
                            format!(
                                "dead-man switch: wipe after {days} day(s) without unlock. \
                                 It only checks when HashChat starts."
                            )
                        }
                        Err(reason) => format!("Dead-man switch refused: {reason}."),
                    },
                    Err(_) => format!("Usage: :deadman set <1-{MAX_DEADMAN_DAYS}>"),
                };
            }
            _ => {
                self.status_msg =
                    format!("Usage: :deadman [status|off|set <1-{MAX_DEADMAN_DAYS}>]");
            }
        }
        self.push_msg(self.status_msg.clone());
    }

    fn cancel_duress_entry(&mut self) {
        self.duress_setup_action = DuressAction::Wipe;
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.passphrase_confirm.zeroize();
        self.passphrase_confirm.clear();
        self.unlock_step = UnlockStep::EnterPass;
        self.screen = Screen::Main;
        self.focus = Focus::Input;
    }

    fn submit_duress_entry(&mut self) {
        if self.passphrase.is_empty() {
            self.status_msg = "Passphrase required.".into();
            return;
        }
        if self.unlock_step == UnlockStep::EnterPass {
            self.unlock_step = UnlockStep::ConfirmPass;
            self.status_msg = "Confirm the duress passphrase.".into();
            return;
        }
        let result = if self.passphrase == self.passphrase_confirm {
            set_duress_passphrase_with(
                Path::new(DATA_DIR),
                self.passphrase.as_bytes(),
                self.duress_setup_action,
            )
        } else {
            Err("passphrases do not match")
        };
        let action = self.duress_setup_action;
        self.cancel_duress_entry();
        if result.is_ok() {
            self.record_wipe_settings();
        }
        self.status_msg = match (result, action) {
            (Ok(()), DuressAction::Wipe) => "duress passphrase set (wipe)".into(),
            (Ok(()), DuressAction::Decoy) => {
                "duress passphrase set (wipe, then open an empty decoy profile)".into()
            }
            (Err(reason), _) => format!("Duress passphrase refused: {reason}."),
        };
        self.push_msg(self.status_msg.clone());
    }

    fn handle_delete_contact_confirm(&mut self) {
        let Some(id) = self.pending_delete_contact.take() else {
            self.screen = Screen::Main;
            self.status_msg = "No pending contact delete (use :delete-contact first).".into();
            self.push_msg(self.status_msg.clone());
            return;
        };
        let removed_idx = self
            .session
            .as_ref()
            .and_then(|s| s.contacts.iter().position(|c| c.id == id));
        let ok = self
            .session
            .as_mut()
            .map(|s| s.delete_contact_secure(&id))
            .unwrap_or(false);
        if !ok {
            self.screen = Screen::Main;
            self.status_msg = "Contact delete failed (unknown id).".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        self.clear_contact_chat_lines(&id);
        if let Some(idx) = removed_idx {
            self.fix_selection_after_contact_removal(idx);
        }
        match self.persist_session() {
            Ok(()) => {
                self.screen = Screen::Main;
                // OPSEC: no onion / plaintext dumps.
                self.status_msg = "Contact removed and ratchet wiped".into();
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => {
                self.screen = Screen::Main;
                self.status_msg =
                    "Contact wiped in memory; durable save failed (unlock/passphrase?).".into();
                self.push_msg(self.status_msg.clone());
            }
        }
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

    fn apply_extreme_lock_default(&mut self) {
        let next = extreme_default_lock_timeout(self.net.is_extreme(), self.lock_timeout_secs);
        if next != self.lock_timeout_secs {
            self.lock_timeout_secs = next;
            self.push_msg(format!(
                "Idle auto-lock defaulted to {} under Extreme (local UI lock; not remote wipe).",
                format_lock_timeout(next)
            ));
        }
    }

    /// Touch idle timer (any key while unlocked).
    fn touch_input(&mut self) {
        self.last_input_at = Instant::now();
    }

    /// True when unlocked and idle past configured timeout (0 = never).
    fn idle_should_lock(&self) -> bool {
        if self.lock_timeout_secs == 0 {
            return false;
        }
        if !matches!(
            self.screen,
            Screen::Main
                | Screen::ConfirmWipe
                | Screen::ConfirmDeleteContact
                | Screen::SetDuress
                | Screen::SasGrid
                | Screen::ContactCard
                | Screen::Support
        ) {
            return false;
        }
        if self.session.is_none() {
            return false;
        }
        self.last_input_at.elapsed() >= Duration::from_secs(u64::from(self.lock_timeout_secs))
    }

    /// Idle / manual lock: zeroize secrets in RAM, stop HS accept, return to unlock.
    /// Disk `state.enc` is left intact (prefer durable save first). Re-unlock via load_session.
    fn lock_ui(&mut self) {
        // Best-effort save while the store key is still available (prefs / pending).
        if self.session.is_some() && self.store_key.is_some() {
            let _ = self.persist_session();
        }
        touch_deadman(Path::new(DATA_DIR), unix_now());
        // Held frames stay in state.enc and go out with :retry after unlock.
        self.held_sends.clear();
        self.clock_behind_secs = None;
        self.binary_changed = false;
        self.wipe_settings_changed.clear();
        self.save_mark = SaveMarkStatus::Unrecorded;
        self.store_key = None;
        // Drop HS: stops accept thread + closes ControlPort (onion key stays in state.enc).
        self.hs = None;
        self.hs_drops_seen = 0;
        if let Some(mut s) = self.session.take() {
            s.wipe_memory_secure();
        }
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.passphrase_confirm.zeroize();
        self.passphrase_confirm.clear();
        self.clear_input_secure();
        self.my_sas.clear();
        self.my_contact_link.clear();
        self.clear_transcript_secure();
        self.pending_delete_contact = None;
        self.contacts_state = ListState::default();
        self.selected_contact = None;
        // Prefs kept in App for status until re-unlock overwrites from blob.
        self.unlock_mode_create = !state_exists(Path::new(DATA_DIR));
        self.unlock_step = UnlockStep::EnterPass;
        self.screen = Screen::Unlock;
        // OPSEC: no plaintext / onion / passphrase material in lock status.
        self.status_msg = "Session locked. Enter passphrase to unlock.".into();
    }

    /// Best-effort in-RAM secret wipe for panic / signal / quit / Drop.
    ///
    /// Zeroizes passphrase buffers, `SessionState` (via `wipe_memory_secure`),
    /// chat lines, SAS / contact-link display strings, and the draft input.
    /// Does **not** touch disk — not a substitute for `:wipe`.
    fn emergency_scrub_fields(&mut self) {
        self.held_sends.clear();
        self.hs = None;
        self.hs_drops_seen = 0;
        if let Some(mut s) = self.session.take() {
            s.wipe_memory_secure();
        }
        self.store_key = None;
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.passphrase_confirm.zeroize();
        self.passphrase_confirm.clear();
        self.clear_input_secure();
        self.my_sas.zeroize();
        self.my_sas.clear();
        self.my_contact_link.zeroize();
        self.my_contact_link.clear();
        self.clear_transcript_secure();
        self.pending_delete_contact = None;
        self.contacts_state = ListState::default();
        self.selected_contact = None;
    }

    /// `:bridges` asks Tor (read-only) whether bridges are configured and in
    /// use; `:bridges torrc LINE` checks a bridge line and prints torrc lines.
    fn handle_bridges(&mut self, args: &str) {
        if args.is_empty() || args == "check" {
            let line = match query_bridge_status(SOCKS_HOST, CONTROL_PORT) {
                Ok(st) => st.summary_line(),
                Err(e) => format!("bridges=unknown ({e})"),
            };
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        if let Some(arg) = args.strip_prefix("require") {
            self.handle_bridges_require(arg.trim());
            return;
        }
        for line in bridges_text(args) {
            self.push_msg(line);
        }
        self.status_msg = "See transcript for bridge help.".into();
    }

    /// `:bridges require [on|off]`: hold every outgoing frame in the encrypted
    /// queue unless Tor reports bridges active. Turning it off needs an
    /// unlocked session, like the other protections.
    fn handle_bridges_require(&mut self, arg: &str) {
        let line = match arg {
            "" | "status" => format!(
                "bridges require={}",
                if self.net.require_bridges {
                    "on (sends held unless bridges are active)"
                } else {
                    "off"
                }
            ),
            "on" | "off" if self.session.is_none() => {
                "Unlock first: the setting lives in state.enc.".to_string()
            }
            "on" | "off" => {
                self.net.require_bridges = arg == "on";
                self.bridge_check = None;
                let saved = self.persist_net_after_mode_change();
                format!(
                    "bridges require={arg} ({})",
                    if saved { "saved" } else { "not saved" }
                )
            }
            _ => "usage: :bridges require [on|off]".to_string(),
        };
        self.status_msg = line.clone();
        self.push_msg(line);
    }

    /// With `:bridges require on`, the reason outgoing frames must stay
    /// queued, or `None` when they may go to Tor. Uses a short cache so a
    /// burst of sends does not open a ControlPort connection each time.
    fn bridges_hold_reason(&mut self) -> Option<String> {
        if !self.net.require_bridges {
            return None;
        }
        if let Some((at, res)) = &self.bridge_check {
            let ttl = if res.is_ok() {
                BRIDGE_CHECK_OK_SECS
            } else {
                BRIDGE_CHECK_FAIL_SECS
            };
            if at.elapsed() < Duration::from_secs(ttl) {
                return res.clone().err();
            }
        }
        let res = match query_bridge_status(SOCKS_HOST, CONTROL_PORT) {
            Ok(st) if st.verdict() == BridgeVerdict::Active => Ok(()),
            Ok(st) => Err(st.summary_line()),
            Err(e) => Err(format!("bridges=unknown ({e})")),
        };
        self.bridge_check = Some((Instant::now(), res.clone()));
        res.err()
    }

    /// `:clock` shows whether the clock was set back; `:clock-reset` accepts
    /// the current time as correct and lowers the stored mark to it.
    fn handle_clock(&mut self, reset: bool) {
        if self.session.is_none() {
            self.status_msg = "Unlock first: the clock mark lives in state.enc.".into();
            return;
        }
        if reset {
            if let Some(s) = self.session.as_mut() {
                s.clock_mark_unix = 0;
            }
            let saved = self.persist_session().is_ok();
            if let Some(s) = self.session.as_mut() {
                s.clock_mark_unix = unix_now();
            }
            self.clock_behind_secs = None;
            let line = format!(
                "Clock mark reset to the current time ({})",
                if saved { "saved" } else { "memory only" }
            );
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        let line = match self.clock_behind_secs {
            Some(behind) => clock_warning_line(behind),
            None => "clock=ok (not behind the last saved time)".into(),
        };
        self.status_msg = line.clone();
        self.push_msg(line);
    }

    /// Record the wipe settings now on disk as the trusted ones. Called after
    /// the user changes one from an unlocked session; does nothing when locked,
    /// so a file changed behind HashChat's back is reported at the next unlock.
    fn record_wipe_settings(&mut self) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        s.wipe_settings = Some(WipeSettings::from_disk(Path::new(DATA_DIR)));
        self.wipe_settings_changed.clear();
        let _ = self.persist_session();
    }

    /// `:wipe-settings` compares the wipe setting files with the record in
    /// the profile; `:wipe-settings-accept` records the current files.
    fn handle_wipe_settings(&mut self, accept: bool) {
        let Some(recorded) = self.session.as_ref().map(|s| s.wipe_settings) else {
            self.status_msg = "Unlock first: the record lives in state.enc.".into();
            return;
        };
        if accept {
            self.record_wipe_settings();
            let line = "Current wipe settings recorded as trusted.".to_string();
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        let on_disk = WipeSettings::from_disk(Path::new(DATA_DIR));
        let line = match recorded {
            None => "wipe_settings=unrecorded".to_string(),
            Some(rec) => {
                let changed = on_disk.changes_since(&rec);
                if changed.is_empty() {
                    "wipe_settings=ok".to_string()
                } else {
                    format!("wipe_settings=changed ({})", changed.join(", "))
                }
            }
        };
        self.status_msg = line.clone();
        self.push_msg(line);
    }

    /// `:binary` shows whether this binary is the one recorded in the profile;
    /// `:binary-accept` records the running binary as trusted.
    fn handle_binary(&mut self, accept: bool) {
        let Some(stored) = self.session.as_ref().map(|s| s.binary_digest) else {
            self.status_msg = "Unlock first: the binary record lives in state.enc.".into();
            return;
        };
        let running = running_binary_digest();
        if accept {
            let Some(cur) = running else {
                self.status_msg = "Cannot read the running binary; nothing recorded.".into();
                return;
            };
            if let Some(s) = self.session.as_mut() {
                s.binary_digest = cur;
            }
            self.binary_changed = false;
            let saved = self.persist_session().is_ok();
            let line = format!(
                "Running binary recorded as trusted ({})",
                if saved { "saved" } else { "memory only" }
            );
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        let status = binary_status(&stored, running.as_ref());
        let line = match running {
            Some(cur) => format!("binary={} sha256={}", status.as_token(), digest_hex(&cur)),
            None => format!("binary={}", status.as_token()),
        };
        self.status_msg = line.clone();
        self.push_msg(line);
    }

    fn handle_jitter(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() || args == "status" || args == "show" {
            let line = format!(
                "jitter={} (random delay before each send; blurs timing, not cover traffic)",
                format_jitter(self.send_jitter_secs)
            );
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        let secs = match parse_jitter_token(args) {
            Ok(s) => s,
            Err(e) => {
                self.status_msg = e.into();
                self.push_msg(e);
                return;
            }
        };
        self.send_jitter_secs = secs;
        let saved = self.session.is_none() || self.persist_session().is_ok();
        let line = format!(
            "Send jitter set to {} ({})",
            format_jitter(secs),
            if saved { "saved" } else { "memory only" }
        );
        self.status_msg = line.clone();
        self.push_msg(line);
    }

    fn handle_lock_timeout(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() || args == "status" || args == "show" {
            let line = format!(
                "lock-timeout={} (idle auto-lock; local UI defense — not remote wipe)",
                format_lock_timeout(self.lock_timeout_secs)
            );
            self.status_msg = line.clone();
            self.push_msg(line);
            return;
        }
        match parse_lock_timeout_token(args) {
            Ok(secs) => {
                self.lock_timeout_secs = secs;
                self.touch_input();
                let saved = if self.session.is_some() {
                    match self.persist_session() {
                        Ok(()) => true,
                        Err(_) => {
                            self.push_msg(
                                "Lock timeout updated in memory; durable save failed (unlock/passphrase?).",
                            );
                            false
                        }
                    }
                } else {
                    true
                };
                let line = if saved {
                    format!(
                        "Idle auto-lock set to {} (saved; local UI only)",
                        format_lock_timeout(secs)
                    )
                } else {
                    format!(
                        "Idle auto-lock set to {} (memory only)",
                        format_lock_timeout(secs)
                    )
                };
                self.status_msg = line.clone();
                self.push_msg(line);
                self.push_msg(
                    "Honesty: idle lock clears RAM secrets and returns to unlock; disk state.enc is untouched; not a remote wipe.",
                );
            }
            Err(e) => {
                self.status_msg = e.into();
                self.push_msg(format!(
                    "Usage: :lock-timeout [off|1m|5m|15m|30m|status] — {e}"
                ));
            }
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
                    format!("Disappearing TTL set to {} (memory only)", format_ttl(secs))
                };
                self.status_msg = line.clone();
                self.push_msg(line);
                self.push_msg(
                    "Honesty: TTL is not carried on the wire; the peer must set their own policy.",
                );
            }
            Err(e) => {
                self.status_msg = e.into();
                self.push_msg(format!("Usage: :disappear [off|30s|5m|1h|1d|status] — {e}"));
            }
        }
    }

    /// Best-effort anti-swap after passphrase accepted.
    ///
    /// Calls `mlockall(MCL_CURRENT|MCL_FUTURE)` then `mlock` on the boxed store key. Failure never aborts the session (unprivileged users often
    /// lack `RLIMIT_MEMLOCK`). Status notes once: "mlock unavailable (best-effort)".
    ///
    /// **Imperfection:** `String` may reallocate on later growth; that drops the per-buffer
    /// lock on old pages. `mlockall(...|MCL_FUTURE)` covers new pages when it succeeds.
    /// Wipe path only zeroizes (no `munlock`) — keep wipe strong.
    fn apply_mlock_best_effort(&mut self) {
        let all_ok = mlockall_current();
        // Lock the boxed store key (stable heap address while unlocked).
        let pass_ok = self
            .store_key
            .as_deref()
            .map(|k| k.mlock_best_effort())
            .unwrap_or(true);
        if !(all_ok && pass_ok) && !self.mlock_note_shown {
            self.mlock_note_shown = true;
            let note = "mlock unavailable (best-effort)";
            if self.status_msg.is_empty() {
                self.status_msg = note.into();
            } else if !self.status_msg.contains(note) {
                self.status_msg = format!("{} · {}", self.status_msg, note);
            }
        }
    }

    /// Install a freshly created session (create path and duress decoy).
    fn adopt_new_session(&mut self, state: SessionState, key: StoreKey) {
        self.store_key = Some(Box::new(key));
        self.unlock_fail_count = 0;
        self.unlock_cooldown_until = None;
        self.session = Some(state);
        self.disappear_ttl_secs = 0;
        self.lock_timeout_secs = DEFAULT_LOCK_TIMEOUT_SECS;
        self.send_jitter_secs = 0;
        self.clock_behind_secs = None;
        self.binary_changed = false;
        self.wipe_settings_changed.clear();
        self.save_mark = SaveMarkStatus::Unrecorded;
        self.apply_extreme_ttl_default();
        self.apply_extreme_lock_default();
        let _ = self.persist_session();
        self.refresh_identity_display();
        self.screen = Screen::Main;
        self.touch_input();
    }

    /// Open the empty profile made after a duress wipe. The messages match an
    /// ordinary unlock of a store with no contacts.
    fn open_decoy_session(&mut self, state: SessionState, key: StoreKey) {
        let data_dir = Path::new(DATA_DIR);
        attempt_succeeded(data_dir);
        touch_deadman(data_dir, unix_now());
        self.adopt_new_session(state, key);
        self.push_msg(format!(
            "Loaded 0 contact(s), 0 pending. {} · disappear={} · lock={}",
            self.net.status_line(),
            format_ttl(self.disappear_ttl_secs),
            format_lock_timeout(self.lock_timeout_secs)
        ));
        self.status_msg = "Session unlocked. :listen then :add-contact to begin.".into();
        self.apply_mlock_best_effort();
    }

    fn try_unlock(&mut self) {
        let pass = self.passphrase.as_bytes();
        if pass.is_empty() {
            self.status_msg = "Passphrase required.".into();
            return;
        }

        // Existing-session unlock only: local UI backoff (not remote auth).
        if !self.unlock_mode_create {
            if let Some(until) = self.unlock_cooldown_until {
                let now = Instant::now();
                if now < until {
                    let rem = (until - now).as_secs().max(1);
                    // Opaque: do not reveal whether the prior attempt was "close".
                    self.status_msg = format!("Unlock cooldown: wait {rem}s.");
                    self.passphrase.zeroize();
                    self.passphrase.clear();
                    return;
                }
            }
        }

        if self.unlock_mode_create {
            if self.unlock_step == UnlockStep::EnterPass {
                // Creation-time strength floor (stricter under Extreme).
                if let Err(reason) = check_new_passphrase(&self.passphrase, self.net.is_extreme()) {
                    self.status_msg = format!("Refused: {reason}.");
                    self.passphrase.zeroize();
                    self.passphrase.clear();
                    return;
                }
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
            match create_session_on_disk(pass, &self.net) {
                Ok((state, key)) => {
                    self.adopt_new_session(state, key);
                    self.status_msg =
                        "Session created. Use :listen when Tor ControlPort is ready.".into();
                    self.apply_mlock_best_effort();
                    self.push_msg(
                        "Session initialized. :listen then :my-contact to share a signed link.",
                    );
                }
                // Reasons are fixed, path-free strings (no secrets).
                Err(reason) => self.status_msg = format!("Failed to save session: {reason}."),
            }
        } else {
            // Storage policy (symlink / owner / mode / type) is checked before any KDF
            // work and is not counted as a failed passphrase attempt.
            if let Err(reason) = check_state_storage(Path::new(DATA_DIR)) {
                self.status_msg = format!("State storage refused: {reason}.");
                self.passphrase.zeroize();
                self.passphrase.clear();
                return;
            }
            let data_dir = Path::new(DATA_DIR);
            let attempt = begin_attempt(data_dir);
            let unlocked = if attempt == Attempt::WipeNow {
                // The failure limit was already used up: wipe without trying.
                wipe_local_sensitive();
                Err("failure limit reached")
            } else {
                unlock_session(data_dir, pass)
            };
            match unlocked {
                Ok((mut state, key)) => {
                    attempt_succeeded(data_dir);
                    self.store_key = Some(Box::new(key));
                    touch_deadman(Path::new(DATA_DIR), unix_now());
                    self.unlock_fail_count = 0;
                    self.unlock_cooldown_until = None;
                    let n_contacts = state.contacts.len();
                    let n_pending = state.pending.len();
                    // Loaded blob wins over cold-start env for net prefs + TTL + lock.
                    self.net = state.net.clone();
                    self.disappear_ttl_secs = state.disappear_ttl_secs;
                    self.lock_timeout_secs = state.lock_timeout_secs;
                    self.send_jitter_secs = state.send_jitter_secs;
                    self.clock_behind_secs = clock_rollback_secs(state.clock_mark_unix, unix_now());
                    let running = running_binary_digest();
                    self.binary_changed =
                        match binary_status(&state.binary_digest, running.as_ref()) {
                            BinaryStatus::Changed => true,
                            BinaryStatus::Unrecorded => {
                                // First unlock with a build that records it.
                                if let Some(cur) = running {
                                    state.binary_digest = cur;
                                }
                                false
                            }
                            BinaryStatus::Same | BinaryStatus::Unavailable => false,
                        };
                    let on_disk = WipeSettings::from_disk(data_dir);
                    self.wipe_settings_changed = match &state.wipe_settings {
                        Some(recorded) => on_disk.changes_since(recorded),
                        None => {
                            // First unlock with a build that records them.
                            state.wipe_settings = Some(on_disk);
                            Vec::new()
                        }
                    };
                    // Before persist_session below replaces the mark.
                    self.save_mark = check_save_mark(data_dir, state.save_id.as_ref());
                    self.session = Some(state);
                    self.apply_extreme_ttl_default();
                    self.apply_extreme_lock_default();
                    let _ = self.persist_session();
                    self.refresh_identity_display();
                    self.screen = Screen::Main;
                    self.touch_input();
                    self.push_msg(format!(
                        "Loaded {n_contacts} contact(s), {n_pending} pending. {} · disappear={} · lock={}",
                        self.net.status_line(),
                        format_ttl(self.disappear_ttl_secs),
                        format_lock_timeout(self.lock_timeout_secs)
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
                    self.apply_mlock_best_effort();
                    if let Some(behind) = self.clock_behind_secs {
                        let line = clock_warning_line(behind);
                        self.push_msg(line.clone());
                        self.status_msg = line;
                    }
                    if self.binary_changed {
                        self.push_msg(BINARY_WARNING.to_string());
                        self.status_msg = BINARY_WARNING.into();
                    }
                    if !self.wipe_settings_changed.is_empty() {
                        let line = wipe_settings_warning(&self.wipe_settings_changed);
                        self.push_msg(line.clone());
                        self.status_msg = line;
                    }
                    if self.save_mark.is_warning() {
                        self.push_msg(SAVE_MARK_WARNING.to_string());
                        self.status_msg = SAVE_MARK_WARNING.into();
                    }
                }
                Err(_) => {
                    // A duress passphrase wipes, then either looks like any other
                    // failure or opens a fresh decoy profile under the same passphrase.
                    let duress = wipe_on_duress(data_dir, pass, wipe_local_sensitive);
                    if duress == Some(DuressAction::Decoy) {
                        if let Ok((state, key)) = create_session_on_disk(pass, &self.net) {
                            self.open_decoy_session(state, key);
                            self.passphrase.zeroize();
                            self.passphrase.clear();
                            return;
                        }
                        // Could not write the decoy: the store is already wiped, so
                        // fall through to the ordinary failure message.
                    }
                    if duress.is_none() && attempt == Attempt::Allowed && attempt_failed(data_dir) {
                        wipe_local_sensitive();
                    }
                    self.unlock_fail_count = self.unlock_fail_count.saturating_add(1);
                    let policy = UnlockBackoffPolicy::for_extreme(self.net.is_extreme());
                    let delay = unlock_backoff_delay_secs(self.unlock_fail_count, &policy);
                    if delay > 0 {
                        self.unlock_cooldown_until =
                            Some(Instant::now() + Duration::from_secs(delay));
                        // Keep wrong-pass opacity; cooldown is local-UI friction only.
                        self.status_msg = format!(
                            "Unlock failed (wrong passphrase or corrupt store). Cooldown {delay}s."
                        );
                    } else {
                        self.status_msg =
                            "Unlock failed (wrong passphrase or corrupt store).".into();
                    }
                    self.passphrase.zeroize();
                    self.passphrase.clear();
                }
            }
        }
        self.passphrase_confirm.zeroize();
        self.passphrase_confirm.clear();
        // The passphrase is not kept after unlock / create; the store key is.
        self.passphrase.zeroize();
        self.passphrase.clear();
    }

    /// Short SAS fingerprint from contact public keys (not display_name).
    /// Custom `:rename` labels must never replace out-of-band SAS compare material.
    fn contact_sas_short(c: &PersistedContact) -> String {
        if c.ed25519 != [0u8; 32] && !c.onion.is_empty() {
            sas_fingerprint(&c.ed25519, &c.x25519, &c.onion)
        } else if !c.display_name.is_empty() {
            c.display_name.clone()
        } else {
            c.id.clone()
        }
    }

    /// Contact-list / UI label: display_name when set, else short SAS / id.
    fn contact_list_label(c: &PersistedContact) -> String {
        if !c.display_name.is_empty() {
            c.display_name.clone()
        } else {
            Self::contact_sas_short(c)
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

    /// Contact list labels: display name (or SAS fallback). Never message bodies.
    fn contact_names(&self) -> Vec<String> {
        self.session
            .as_ref()
            .map(|s| {
                s.contacts
                    .iter()
                    .map(|c| {
                        let mut label = Self::contact_list_label(c);
                        if s.is_blocked_id(&c.id) {
                            label.push_str(" [blocked]");
                        } else if s.is_muted_id(&c.id) {
                            label.push_str(" [muted]");
                        }
                        if !s.is_verified_id(&c.id) {
                            label.push_str(" [unverified]");
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
        if let Some(why) = self.bridges_hold_reason() {
            self.status_msg = format!(":listen held: bridges required, {why}");
            self.push_msg(self.status_msg.clone());
            return;
        }
        // L-2: wrap onion private-key clone so it zeroizes when dropped.
        let existing = Zeroizing::new(
            self.session
                .as_ref()
                .map(|s| s.identity.onion_key.clone())
                .unwrap_or_default(),
        );
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
                            self.status_msg =
                                format!("Listening (Extreme · …{tail} · local :{})", hs.local_port);
                            self.push_msg(
                                "Hidden service published (Extreme: Tor-only; contact-link export locked).",
                            );
                            self.push_msg(
                                "Peer exchange: use :add-contact with an out-of-band link; :my-contact is refused under Extreme.",
                            );
                        } else {
                            self.status_msg =
                                format!("Listening on {} (local :{})", hs.onion, hs.local_port);
                            self.push_msg(
                                "Hidden service published; accept loop running (framed wire v2).",
                            );
                            self.push_msg(
                                "Share :my-contact; peer must :add-contact your link (and you theirs).",
                            );
                        }
                        self.hs = Some(hs);
                        self.hs_drops_seen = 0;
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

    /// Build SOCKS isolation credentials when prefs enable isolation.
    /// Prefer contact-id + local seed; fall back to onion tags for pending retries.
    fn socks_isolation_creds_for(
        &self,
        contact_id: Option<&str>,
        onion: &str,
    ) -> Option<SocksIsolationCreds> {
        if !self.net.socks_isolation_enabled() {
            return None;
        }
        let session = self.session.as_ref()?;
        if let Some(id) = contact_id {
            return Some(socks_isolation_for_contact(id, &session.identity.seed));
        }
        if let Some(c) = session.contacts.iter().find(|c| c.onion == onion) {
            return Some(socks_isolation_for_contact(&c.id, &session.identity.seed));
        }
        socks_isolation_for_onion(onion).ok()
    }

    fn is_held_until_later(&self, onion: &str, frame: &[u8], now: Instant) -> bool {
        self.held_sends
            .iter()
            .any(|h| h.due > now && h.onion == onion && h.frame.as_slice() == frame)
    }

    /// Hand frames whose jitter has run out to Tor. A frame no longer in the
    /// durable queue was already delivered (`:retry`) or its contact was
    /// deleted, so it is dropped. If Tor is down the frame stays queued.
    fn flush_held_sends(&mut self) {
        if self.held_sends.is_empty() {
            return;
        }
        let now = Instant::now();
        let (due, later): (Vec<HeldSend>, Vec<HeldSend>) =
            self.held_sends.drain(..).partition(|h| h.due <= now);
        self.held_sends = later;
        if due.is_empty() {
            return;
        }
        let transport_ok = self.net.require_messenger_transport().is_ok()
            && self.tor_status == TorStatus::Available;
        let bridge_hold = if transport_ok {
            self.bridges_hold_reason()
        } else {
            None
        };
        let mut changed = false;
        for held in due {
            let queued = self
                .session
                .as_ref()
                .map(|s| {
                    s.pending
                        .iter()
                        .any(|(o, f)| *o == held.onion && *f == held.frame)
                })
                .unwrap_or(false);
            if !queued {
                continue;
            }
            if !transport_ok {
                self.set_delivery(&held.contact_id, held.msg_number, Delivery::Queued);
                self.push_msg(format!(
                    "[{}] queued offline (Tor unavailable)",
                    held.peer_label
                ));
                self.status_msg = "Queued: Tor unavailable (frame committed)".into();
                continue;
            }
            if let Some(why) = &bridge_hold {
                self.set_delivery(&held.contact_id, held.msg_number, Delivery::Queued);
                self.push_msg(format!(
                    "[{}] queued: bridges required, {why}",
                    held.peer_label
                ));
                self.status_msg = "Queued: bridges not active (frame committed)".into();
                continue;
            }
            let isol = self.socks_isolation_creds_for(Some(&held.contact_id), &held.onion);
            let sent = socks5_send(
                SOCKS_HOST,
                self.socks_port,
                &held.onion,
                80,
                &held.frame,
                isol.as_ref(),
            )
            .is_ok();
            if sent {
                if let Some(session) = self.session.as_mut() {
                    session.ack_pending_frame(&held.onion, &held.frame);
                }
                changed = true;
                self.set_delivery(&held.contact_id, held.msg_number, Delivery::Sent);
                self.status_msg = format!("Sent {} B via SOCKS after jitter", held.frame.len());
            } else {
                self.set_delivery(&held.contact_id, held.msg_number, Delivery::Queued);
                self.push_msg(format!(
                    "[{}] queued offline (SOCKS send failed)",
                    held.peer_label
                ));
                self.status_msg = "Queued: SOCKS send failed (frame committed)".into();
            }
        }
        if changed {
            let _ = self.persist_session();
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
        if let Some(why) = self.bridges_hold_reason() {
            self.status_msg = format!(":retry held: bridges required, {why}");
            self.push_msg(self.status_msg.clone());
            return;
        }
        let waiting: Vec<(String, Vec<u8>)> = {
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
            std::mem::take(&mut session.pending)
        };
        let now = Instant::now();
        let (held, waiting): (Vec<_>, Vec<_>) = waiting
            .into_iter()
            .partition(|(o, f)| self.is_held_until_later(o, f, now));
        let n_held = held.len();
        if let Some(session) = self.session.as_mut() {
            for (o, f) in held {
                let _ = session.queue_pending(o, f);
            }
        }
        if waiting.is_empty() {
            if report_empty {
                self.status_msg = format!("{n_held} frame(s) still waiting out send jitter");
            }
            return;
        }
        let mut fail = 0usize;
        let mut ok = 0usize;
        let mut remain = Vec::new();
        for (onion, frame) in waiting {
            // Session borrow ended above so isolation helper can read contacts/seed.
            let isol = self.socks_isolation_creds_for(None, &onion);
            match socks5_send(
                SOCKS_HOST,
                self.socks_port,
                &onion,
                80,
                &frame,
                isol.as_ref(),
            ) {
                Ok(()) => ok += 1,
                Err(_) => {
                    remain.push((onion, frame));
                    fail += 1;
                }
            }
        }
        if let Some(session) = self.session.as_mut() {
            for (o, f) in remain {
                let _ = session.queue_pending(o, f);
            }
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
        let (frames, drop_count): (Vec<Vec<u8>>, u64) = {
            let Some(hs) = self.hs.as_ref() else {
                return;
            };
            let mut out = Vec::new();
            while let Some(f) = hs.try_recv() {
                out.push(f);
            }
            // Count only — never log frame contents.
            (out, hs.dropped_frame_count())
        };
        if drop_count > self.hs_drops_seen {
            let delta = drop_count - self.hs_drops_seen;
            self.hs_drops_seen = drop_count;
            // OPSEC: numeric backpressure signal only (no frame bytes).
            self.status_msg = format!("HS inbound backpressure: dropped {delta} frame(s)");
            self.push_msg(self.status_msg.clone());
        }
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
        let FrameV3 {
            hint,
            step,
            epoch_start,
            sender_dh,
            ciphertext: ct,
        } = unframe_v3(transport_frame).map_err(|_| "malformed wire frame".to_string())?;
        let net = self.net.clone();
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "no session".to_string())?;
        session.net = net;
        let contacts = session.contacts.clone();
        // Wire hint is the sender's static x25519 — try matching contacts first.
        let mut order: Vec<usize> = (0..contacts.len()).collect();
        if hint.len() == 32 {
            order.sort_by_key(|&i| {
                if contacts[i].x25519.as_slice() == hint.as_slice() {
                    0
                } else {
                    1
                }
            });
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
                .map(|(_, b)| Zeroizing::new(b.clone()));
            let Some(rb) = ratchet_bytes else {
                continue;
            };
            let mut r =
                DoubleRatchet::from_bytes(&rb).map_err(|_| "ratchet restore".to_string())?;
            drop(rb);
            let aad = build_wire_aad_v3(&hint, step, epoch_start, &sender_dh);
            let remote = x25519_dalek::PublicKey::from(sender_dh);
            match r.try_recv_decrypt_epoch(&remote, step, epoch_start, &ct, &aad) {
                Ok((mut padded, step)) => {
                    // Opened, so the sender used this contact's chain; a bad
                    // padding layout is a protocol error, not a wrong contact.
                    let unpadded = unpad_message(&padded);
                    padded.zeroize();
                    let Ok(mut pt) = unpadded else {
                        return Err("bad padding".into());
                    };
                    // Neutralise terminal control / bidi characters before the text
                    // can reach any widget; zeroize intermediate copies.
                    let text = {
                        let lossy = String::from_utf8_lossy(&pt);
                        let safe = sanitize_for_terminal(&lossy).into_owned();
                        if let std::borrow::Cow::Owned(mut o) = lossy {
                            o.zeroize();
                        }
                        safe
                    };
                    pt.zeroize();
                    let contact_id = c.id.clone();
                    session.set_ratchet_bytes(&contact_id, take_zeroizing_vec(r.to_bytes()));
                    let label = if c.display_name.is_empty() {
                        contact_id.clone()
                    } else {
                        c.display_name.clone()
                    };
                    let display = !session.is_muted_id(&contact_id);
                    if let Some(key) = self.store_key.as_deref() {
                        let _ = save_session_with_key(Path::new(DATA_DIR), key, session);
                    }
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
                if !peer.onion_bound {
                    self.status_msg =
                        "Contact refused: link does not prove control of its onion. Ask for a new link."
                            .into();
                    return;
                }
                let onion_tail = Self::onion_tail(&peer.onion);
                let (select_idx, up) = {
                    let session = self.session.as_mut().unwrap();
                    let up = session.upsert_contact_from_link(
                        &peer.onion,
                        peer.x25519,
                        peer.ed25519,
                        &sas,
                    );
                    session.set_ratchet_bytes(&up.id, take_zeroizing_vec(ratchet.to_bytes()));
                    let idx = session.contacts.iter().position(|c| c.id == up.id);
                    (idx, up)
                };
                let was_update = up.was_update;
                let verified = up.verified;
                if up.identity_changed {
                    // Loud notice: the SAS the user compared no longer applies.
                    let (old_label, old_sas) = up
                        .previous
                        .as_ref()
                        .map(|p| (Self::contact_list_label(p), Self::contact_sas_short(p)))
                        .unwrap_or_default();
                    self.push_msg(format!(
                        "!! SAFETY NUMBER CHANGED for {old_label}: SAS {old_sas} -> {sas}. \
                         Contact is now UNVERIFIED; sending is refused until you compare \
                         the new SAS out of band and run :verify."
                    ));
                }
                match self.persist_session() {
                    Ok(()) => {
                        let verb = if was_update { "Updated" } else { "Added" };
                        let trust = if verified {
                            "verified"
                        } else {
                            "unverified — :verify after SAS compare"
                        };
                        self.status_msg = if up.identity_changed {
                            format!("SAS CHANGED · {verb} contact (SAS {sas}, {trust})")
                        } else {
                            format!("{verb} contact (SAS {sas}, {trust})")
                        };
                        if was_update {
                            self.push_msg(format!("{verb} {sas} — onion …{onion_tail} ({trust})"));
                        } else {
                            self.push_msg(format!(
                                "{verb} {sas} [unverified] — onion …{onion_tail}; compare SAS then :verify (peer must :add-contact you too)"
                            ));
                        }
                        if let Some(i) = select_idx {
                            self.select_contact(i);
                            // Prefer add/update verb in status over generic Selected line.
                            self.status_msg = format!("{verb} contact (SAS {sas}, {trust})");
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

    fn send_text(&mut self, text: &str, allow_unverified: bool) {
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
            if session.refuse_send_if_blocked(&contact.id).is_err() {
                self.status_msg = "Send refused: contact is blocked.".into();
                self.push_msg(self.status_msg.clone());
                return;
            }
            if !allow_unverified {
                if session.refuse_send_if_unverified(&contact.id).is_err() {
                    self.status_msg =
                        "Send refused: contact unverified — compare SAS then :verify (or :send-unverified under Standard)."
                            .into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
            } else if self.net.is_extreme() {
                // Defense in depth: Extreme never bypasses the verify gate.
                self.status_msg =
                    "Send refused: Extreme forbids :send-unverified — :verify required.".into();
                self.push_msg(self.status_msg.clone());
                return;
            } else if session.refuse_send_if_unverified(&contact.id).is_err() {
                // Allowed bypass under Standard — note in status, still no onion dump.
                self.push_msg(
                    "Sending to unverified contact (Standard bypass via :send-unverified).",
                );
            }
        }
        if !is_onion_destination(&contact.onion) {
            self.push_msg("Send refused: contact has no valid v3 .onion.");
            return;
        }
        // Local UX gate: refuse huge pastes before ratchet encrypt (no body echo).
        if check_plaintext_send_size(text.as_bytes()).is_err() {
            let kib = MAX_PLAINTEXT_SEND_BYTES / 1024;
            self.status_msg = format!("Send refused: message exceeds {kib} KiB plaintext limit.");
            self.push_msg(self.status_msg.clone());
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
                let mut shared =
                    match local.x25519_dh_checked(&x25519_dalek::PublicKey::from(contact.x25519)) {
                        Some(s) => s,
                        None => {
                            self.push_msg("Contact key rejected (invalid).");
                            return;
                        }
                    };
                let mut r = DoubleRatchet::new();
                r.init_directional(&shared, &local.x25519_public_bytes(), &contact.x25519);
                shared.zeroize();
                r
            } else {
                self.push_msg("No ratchet for contact — add via :add-contact <signed link>.");
                return;
            };

            let hint = local.x25519_public_bytes();
            let (mut msg_key, step) = ratchet.ratchet_send();
            let sender_dh = ratchet.public_key().to_bytes();
            let epoch_start = ratchet.epoch_start();
            let aad = build_wire_aad_v3(&hint, step, epoch_start, &sender_dh);
            let mut padded = match pad_message(text.as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    msg_key.zeroize();
                    self.push_msg("Send refused: message too long.");
                    return;
                }
            };
            let sealed = encrypt_with_key(&msg_key, &padded, &aad);
            padded.zeroize();
            msg_key.zeroize();
            let ct = match sealed {
                Ok(c) => c,
                Err(_) => {
                    self.push_msg("Encrypt failed.");
                    return;
                }
            };
            let frame = frame_v3(&hint, step, epoch_start, &sender_dh, &ct);
            let rbytes = ratchet.to_bytes();
            (frame, rbytes, step)
        };

        // H3: durable queue commit before Tor send.
        let Some(key) = self.store_key.as_deref() else {
            self.push_msg("Send aborted: session locked.");
            return;
        };
        match commit_outgoing_with_key(
            Path::new(DATA_DIR),
            key,
            &contact.id,
            rbytes.to_vec(),
            &contact.onion,
            frame.clone(),
        ) {
            Ok(()) => {}
            Err(e) if e == ERR_QUEUE_FULL => {
                self.push_msg("Send aborted: outgoing queue full. Run :retry once Tor is up.");
                return;
            }
            Err(_) => {
                self.push_msg("Send aborted: durable commit failed.");
                return;
            }
        }

        // Mirror commit into in-memory session.
        if let Some(session) = self.session.as_mut() {
            session.set_ratchet_bytes(&contact.id, take_zeroizing_vec(rbytes));
            let _ = session.queue_pending(&contact.onion, frame.clone());
        }

        if self.send_jitter_secs > 0 {
            let due = Instant::now() + sample_send_delay(self.send_jitter_secs);
            self.push_chat_out_state(
                format!("[{peer_label}] you: {text}  (held, random delay before send)"),
                &contact.id,
                msg_number,
                Delivery::Held,
            );
            self.held_sends.push(HeldSend {
                due,
                contact_id: contact.id.clone(),
                onion: contact.onion.clone(),
                frame,
                peer_label,
                msg_number,
            });
            self.status_msg = format!(
                "Held for jitter ({}); committed to queue",
                format_jitter(self.send_jitter_secs)
            );
            return;
        }

        if let Some(why) = self.bridges_hold_reason() {
            self.push_chat_out_state(
                format!("[{peer_label}] you: {text}  (queued: bridges required, {why})"),
                &contact.id,
                msg_number,
                Delivery::Queued,
            );
            self.status_msg = "Queued: bridges not active (frame committed)".into();
            return;
        }

        let isol = self.socks_isolation_creds_for(Some(&contact.id), &contact.onion);
        let sent_ok = socks5_send(
            SOCKS_HOST,
            self.socks_port,
            &contact.onion,
            80,
            &frame,
            isol.as_ref(),
        )
        .is_ok();
        if sent_ok {
            if let Some(session) = self.session.as_mut() {
                session.ack_pending_frame(&contact.onion, &frame);
            }
            let _ = self.persist_session();
            let frame_len = frame.len();
            self.push_chat_out(
                format!("[{peer_label}] you: {text}  ({frame_len} B via Tor)"),
                &contact.id,
                msg_number,
            );
            self.status_msg = if isol.is_some() {
                format!("Sent {frame_len} B via SOCKS (isol)")
            } else {
                format!("Sent {frame_len} B via SOCKS")
            };
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
                self.apply_extreme_lock_default();
                let saved = self.persist_net_after_mode_change();
                let tag = if saved { "saved" } else { "not saved" };
                self.status_msg = format!("Posture extreme ({tag}). {}", self.net.status_line());
                self.push_msg(self.status_msg.clone());
                if let Some(note) = self.net.extreme_lock_summary() {
                    self.push_msg(note);
                }
            }
            "standard" | "normal" => {
                self.net.set_posture(PostureProfile::Standard);
                let saved = self.persist_net_after_mode_change();
                let tag = if saved { "saved" } else { "not saved" };
                self.status_msg = format!("Posture standard ({tag}). {}", self.net.status_line());
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
                    "Extreme: Tor-only; refuses :my-contact/groups/voice/:send-unverified; contacts/queue/deny/verify lists not durable; SAS ok (short). Not Android Extreme parity.",
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

    /// `:isolate` — Tor SOCKS stream isolation on/off/status (durable prefs).
    fn handle_isolate(&mut self, args: &str) {
        let args = args.trim().to_ascii_lowercase();
        if args.is_empty() || args == "status" || args == "show" {
            let on = self.net.socks_isolation_enabled();
            let line = format!(
                "socks_isol={}{}",
                if on { "on" } else { "off" },
                if self.net.is_extreme() {
                    " (Extreme forces on)"
                } else {
                    ""
                }
            );
            // Never print isolation username/password tags.
            self.push_msg(line.clone());
            self.status_msg = line;
            return;
        }
        match args.as_str() {
            "on" | "1" | "true" | "yes" => match self.net.set_socks_isolation(true) {
                Ok(()) => {
                    let saved = self.persist_net_after_mode_change();
                    let tag = if saved { "saved" } else { "not saved" };
                    self.status_msg = format!("SOCKS isolation on ({tag})");
                    self.push_msg(self.status_msg.clone());
                }
                Err(e) => {
                    self.status_msg = e.to_string();
                    self.push_msg(e.to_string());
                }
            },
            "off" | "0" | "false" | "no" => match self.net.set_socks_isolation(false) {
                Ok(()) => {
                    let saved = self.persist_net_after_mode_change();
                    let tag = if saved { "saved" } else { "not saved" };
                    self.status_msg = format!("SOCKS isolation off ({tag})");
                    self.push_msg(self.status_msg.clone());
                }
                Err(e) => {
                    self.status_msg = e.to_string();
                    self.push_msg(e.to_string());
                }
            },
            "help" => {
                self.push_msg("Usage: :isolate [on|off|status]");
                self.push_msg(
                    "Default on. Uses Tor IsolateSOCKSAuth tags per contact (never logged).",
                );
                self.push_msg("Extreme posture forces isolation on (refuse off).");
            }
            other => {
                self.status_msg = format!("Unknown :isolate argument: {other} (:isolate help)");
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

    fn handle_verify_command(&mut self, args: &str) {
        let id = match self.deny_token_or_selected(args) {
            Ok(id) => id,
            Err(e) => {
                self.status_msg = format!(":verify refused: {e}");
                self.push_msg(self.status_msg.clone());
                return;
            }
        };
        let (label, extreme) = {
            let extreme = self.net.is_extreme();
            let label = self
                .session
                .as_ref()
                .and_then(|s| s.contacts.iter().find(|c| c.id == id))
                .map(|c| Self::contact_sas_short(c).to_string())
                .unwrap_or_else(|| id.clone());
            (label, extreme)
        };
        // Show short SAS again for out-of-band confirm (no full onion URI in Extreme).
        if extreme {
            self.push_msg(format!("Confirm SAS {label} (compare out-of-band)"));
        } else {
            let tail = self
                .session
                .as_ref()
                .and_then(|s| s.contacts.iter().find(|c| c.id == id))
                .map(|c| Self::onion_tail(&c.onion))
                .unwrap_or_else(|| "?".into());
            self.push_msg(format!(
                "Confirm SAS {label} · …{tail} (compare out-of-band)"
            ));
        }
        let newly = self
            .session
            .as_mut()
            .map(|s| s.verify_contact_id(id))
            .unwrap_or(false);
        match self.persist_session() {
            Ok(()) => {
                let verb = if newly {
                    "Verified"
                } else {
                    "Already verified"
                };
                self.status_msg = format!("{verb} SAS {label} (send allowed)");
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => self.status_msg = "Failed to persist verified set.".into(),
        }
    }

    fn handle_unverify_command(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() {
            let token = match self.selected_contact_record() {
                Some(c) => c.id.clone(),
                None => {
                    self.status_msg = "Usage: :unverify <contact|sas-prefix|id>".into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
            };
            return self.handle_unverify_command(&token);
        }
        let Some(session) = self.session.as_mut() else {
            self.status_msg = "Unlock first.".into();
            return;
        };
        let removed = session.unverify_contact_id(args);
        if !removed {
            self.status_msg = ":unverify: not verified (or ambiguous)".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        match self.persist_session() {
            Ok(()) => {
                self.status_msg = "Contact marked unverified (send refused until :verify).".into();
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => self.status_msg = "Failed to persist unverify.".into(),
        }
    }

    fn handle_send_unverified(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            self.status_msg = "Usage: :send-unverified <message>".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        if self.net.is_extreme() {
            self.status_msg = "Extreme refuses :send-unverified — compare SAS then :verify.".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        self.send_text(text, true);
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

    /// `:rename <name>` (selected) or `:rename <id|sas-prefix> <name>`.
    /// Updates display_name only; status omits onions/SAS.
    fn handle_rename_command(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() {
            self.status_msg = "Usage: :rename <name> | :rename <id|sas-prefix> <name>".into();
            self.push_msg(self.status_msg.clone());
            return;
        }
        let Some(session) = self.session.as_ref() else {
            self.status_msg = "Unlock first.".into();
            return;
        };

        let (contact_id, name_raw) = {
            let mut split = args.splitn(2, char::is_whitespace);
            let first = split.next().unwrap_or("").trim();
            let rest = split.next().map(str::trim).unwrap_or("");
            if !rest.is_empty() {
                if let Some(id) = session.resolve_deny_token(first) {
                    (id, rest.to_string())
                } else if let Some(c) = self.selected_contact_record() {
                    // First token is not a contact — whole string is the new name.
                    (c.id.clone(), args.to_string())
                } else {
                    self.status_msg =
                        ":rename refused: unknown or ambiguous contact (id / SAS prefix)".into();
                    self.push_msg(self.status_msg.clone());
                    return;
                }
            } else {
                match self.selected_contact_record() {
                    Some(c) => (c.id.clone(), args.to_string()),
                    None => {
                        self.status_msg =
                            "Usage: :rename <name> | :rename <id|sas-prefix> <name>".into();
                        self.push_msg(self.status_msg.clone());
                        return;
                    }
                }
            }
        };

        let renamed = match self
            .session
            .as_mut()
            .unwrap()
            .rename_contact_display_name(&contact_id, &name_raw)
        {
            Ok(()) => self
                .session
                .as_ref()
                .and_then(|s| s.contacts.iter().find(|c| c.id == contact_id))
                .map(|c| c.display_name.clone())
                .unwrap_or_default(),
            Err(e) => {
                self.status_msg = format!(":rename refused: {e}");
                self.push_msg(self.status_msg.clone());
                return;
            }
        };

        match self.persist_session() {
            Ok(()) => {
                // Short success — echo the user-chosen label only (no onion / SAS dump).
                self.status_msg = format!("Renamed contact to {renamed}");
                self.push_msg(self.status_msg.clone());
            }
            Err(_) => self.status_msg = "Failed to persist rename.".into(),
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

    /// OPSEC-safe posture dump for two-peer validation evidence.
    /// Prints counts and tokens only — never onions, links, SAS, passphrases, or bodies.
    /// Not a cryptographic proof of E2EE; see docs/TWO_PEER_VALIDATION.md.
    fn handle_evidence(&mut self) {
        self.check_tor(true);
        let probe = tor_probe(SOCKS_HOST, self.socks_port, CONTROL_PORT);
        let unlocked = self.session.is_some();
        let unlock_state = if unlocked { "unlocked" } else { "locked" };

        let version = env!("CARGO_PKG_VERSION");
        let crate_name = env!("CARGO_PKG_NAME");
        self.push_msg(format!(
            "evidence: hashchat-tui · crate={crate_name} · version={version}"
        ));
        self.push_msg(format!("unlock={unlock_state}"));
        // Tokens only — never echo custom DNS address (may be identifying).
        self.push_msg(format!(
            "net: mode={} · dns={} · posture={}",
            self.net.mode.as_str(),
            self.net.dns.as_str(),
            self.net.posture.as_str()
        ));
        self.push_msg(format!(
            "disappear={} · lock-timeout={} · jitter={}",
            format_ttl(self.disappear_ttl_secs),
            format_lock_timeout(self.lock_timeout_secs),
            format_jitter(self.send_jitter_secs)
        ));

        let (contacts, blocked, muted, unverified) = match self.session.as_ref() {
            Some(s) => {
                let unverified = s
                    .contacts
                    .iter()
                    .filter(|c| !s.is_verified_id(&c.id))
                    .count();
                (
                    s.contacts.len(),
                    s.blocked_ids.len(),
                    s.muted_ids.len(),
                    unverified,
                )
            }
            None => (0, 0, 0, 0),
        };
        self.push_msg(format!(
            "contacts={contacts} · blocked={blocked} · muted={muted} · unverified={unverified}"
        ));
        if unlocked {
            let clock = if self.clock_behind_secs.is_some() {
                "behind"
            } else {
                "ok"
            };
            self.push_msg(format!("clock={clock}"));
            let binary = if self.binary_changed { "changed" } else { "ok" };
            self.push_msg(format!("binary={binary}"));
            let wipe = if self.wipe_settings_changed.is_empty() {
                "ok"
            } else {
                "changed"
            };
            self.push_msg(format!("wipe_settings={wipe}"));
            self.push_msg(format!("state_copy={}", self.save_mark.token()));
        }

        let (core0, nodump) = match self.dump_hardening {
            Some(h) => (h.core_limit_zero, h.non_dumpable),
            None => (false, false),
        };
        self.push_msg(format!(
            "process: core_limit={} · dumpable={}",
            if core0 { "0" } else { "unchanged" },
            if nodump { "off" } else { "on" }
        ));

        let socks = if probe.socks_ok { "ok" } else { "fail" };
        let control = if probe.control_ok { "ok" } else { "fail" };
        self.push_msg(format!("tor: socks={socks} · control={control}"));
        // Token only — never echo isolation username/password tags.
        self.push_msg(format!(
            "socks_isol={}{}",
            if self.net.socks_isolation_enabled() {
                "on"
            } else {
                "off"
            },
            if self.net.is_extreme() {
                " (Extreme forces on)"
            } else {
                ""
            }
        ));

        let listening = self.hs.is_some();
        let drops = self
            .hs
            .as_ref()
            .map(|h| h.dropped_frame_count())
            .unwrap_or(self.hs_drops_seen);
        self.push_msg(format!(
            "hs: listening={} · drops={drops} · refused_conns={}",
            if listening { "yes" } else { "no" },
            self.hs
                .as_ref()
                .map(|h| h.refused_connection_count())
                .unwrap_or(0)
        ));
        self.push_msg(
            "evidence: metadata only — not a proof of E2EE (see docs/TWO_PEER_VALIDATION.md)",
        );
        self.status_msg = format!(
            "evidence · unlock={unlock_state} · socks={socks} · control={control} · hs={}",
            if listening { "yes" } else { "no" }
        );
    }

    fn handle_command(&mut self, cmd: &str) {
        let c = cmd.trim();
        match c {
            ":q" | ":quit" | ":exit" => {
                self.emergency_scrub_fields();
                self.status_msg = "__QUIT__".into();
            }
            ":clear" | ":cls" => {
                // In-memory transcript only — not session wipe, not disk erase.
                self.clear_transcript_secure();
                debug_assert!(self.messages.is_empty());
                self.status_msg = "Chat transcript cleared (session intact).".into();
            }
            ":evidence" | ":audit-status" => self.handle_evidence(),
            ":wipe" => {
                // Loud confirm: blank chat/status residue so the modal is not overlaid on plaintext.
                self.clear_transcript_secure();
                self.clear_input_secure();
                self.screen = Screen::ConfirmWipe;
                self.status_msg =
                    "NUCLEAR WIPE: type :wipe-confirm to erase local secrets, or Esc to cancel."
                        .into();
            }
            ":wipe-confirm" => {
                self.held_sends.clear();
                self.hs = None;
                self.hs_drops_seen = 0;
                wipe_local_sensitive();
                if let Some(mut s) = self.session.take() {
                    s.wipe_memory_secure();
                }
                self.store_key = None;
                self.passphrase.zeroize();
                self.passphrase.clear();
                self.passphrase_confirm.zeroize();
                self.passphrase_confirm.clear();
                self.clear_input_secure();
                self.my_sas.clear();
                self.my_contact_link.clear();
                self.clear_transcript_secure();
                self.pending_delete_contact = None;
                self.disappear_ttl_secs = 0;
                self.lock_timeout_secs = DEFAULT_LOCK_TIMEOUT_SECS;
                self.send_jitter_secs = 0;
                self.net = NetConfig::from_env();
                self.contacts_state = ListState::default();
                self.selected_contact = None;
                self.unlock_mode_create = true;
                self.unlock_step = UnlockStep::EnterPass;
                self.unlock_fail_count = 0;
                self.unlock_cooldown_until = None;
                self.screen = Screen::Unlock;
                // OPSEC: status must not echo prior chat/passphrase material.
                self.status_msg =
                    "Local sensitive data erased. Unlock with a new passphrase to continue.".into();
            }
            ":delete-contact-confirm" => {
                self.handle_delete_contact_confirm();
            }
            ":sas-grid" => {
                if self.session.is_none() {
                    self.status_msg = "Unlock first.".into();
                } else if self.selected_contact_record().is_none() {
                    self.status_msg = ":sas-grid needs a selected contact.".into();
                } else {
                    self.screen = Screen::SasGrid;
                    self.status_msg = "Compare out of band · Esc back".into();
                }
            }
            ":support" | ":pay" => {
                // Static text only: no network, no wallet, no telemetry.
                self.screen = Screen::Support;
                self.status_msg = "Privacy is always free · Esc back".into();
            }
            ":contact-card" => {
                // Same refusals as :my-contact; the card only displays.
                if self.net.extreme_blocks_contact_export() {
                    self.status_msg =
                        "extreme posture refuses contact-link export (minimize link sharing)"
                            .into();
                    self.push_msg(self.status_msg.clone());
                } else if let Err(e) = self.net.require_messenger_transport() {
                    self.status_msg = format!(":contact-card refused: {e}");
                    self.push_msg(self.status_msg.clone());
                } else if self.my_contact_link.is_empty() {
                    self.push_msg("No contact link yet (unlock + :listen first).");
                } else {
                    self.screen = Screen::ContactCard;
                    self.status_msg = "Share privately · Esc back".into();
                }
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
                    self.session.as_ref().map(|s| s.pending.len()).unwrap_or(0)
                ));
                self.push_msg(self.net.status_line());
                self.push_msg(format!(
                    "disappear={} (local TTL; peer not enforced)",
                    format_ttl(self.disappear_ttl_secs)
                ));
                self.push_msg(format!(
                    "lock-timeout={} (idle auto-lock; local UI — not remote wipe)",
                    format_lock_timeout(self.lock_timeout_secs)
                ));
                if let Some(s) = self.session.as_ref() {
                    let unverified = s
                        .contacts
                        .iter()
                        .filter(|c| !s.is_verified_id(&c.id))
                        .count();
                    self.push_msg(format!(
                        "deny: {} blocked · {} muted · {} unverified{}",
                        s.blocked_ids.len(),
                        s.muted_ids.len(),
                        unverified,
                        if self.net.is_extreme() {
                            " (Extreme: deny/verify lists not durable)"
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
                self.push_msg("  :add-contact <link>     verify signed link + bootstrap ratchet");
                self.push_msg(
                    "  :sas-grid               SAS comparison grid for the selected contact",
                );
                self.push_msg("  :contact-card           your signed contact-link card");
                self.push_msg("  :support                plans and pay-what-you-want (offline)");
                self.push_msg("  :my-contact             your signed link + short SAS");
                self.push_msg("  :sas [link]             short SAS (selected contact or link)");
                self.push_msg("  :mode [tor|status|…]    network mode (Tor default; fail-closed)");
                self.push_msg("  :isolate [on|off|status] Tor SOCKS stream isolation (default on)");
                self.push_msg(
                    "  :retry                  flush pending queue (Tor / net_mode gate)",
                );
                self.push_msg(
                    "  :disappear [off|30s|…]  local TTL erase + ratchet skipped-key wipe",
                );
                self.push_msg("  :lock                   lock UI now (clear RAM; disk untouched)");
                self.push_msg("  :lock-timeout [off|…]   idle auto-lock (default 5m; Extreme→1m)");
                self.push_msg(
                    "  :jitter [off|30s|2m]    random delay before each send (default off)",
                );
                self.push_msg("  :block / :unblock [id]  refuse send + drop inbound (fail-closed)");
                self.push_msg("  :mute / :unmute [id]    suppress inbound UI (decrypt for sync)");
                self.push_msg("  :blocked                list blocked + muted ids");
                self.push_msg(
                    "  :rename / :rename-contact  set display name (label only; not id/keys)",
                );
                self.push_msg(
                    "  :verify / :unverify [id] SAS trust gate (new contacts unverified)",
                );
                self.push_msg("  :send-unverified <msg>  Standard only — Extreme: no bypass");
                self.push_msg(format!(
                    "  plaintext send cap        max {} KiB UTF-8 before encrypt (local UX)",
                    MAX_PLAINTEXT_SEND_BYTES / 1024
                ));
                self.push_msg("  :delete-contact [id]    remove contact + wipe ratchet (confirm)");
                self.push_msg("  :clear / :cls           zeroize in-memory chat transcript only");
                self.push_msg(
                    "  :evidence / :audit-status  OPSEC posture dump (counts/tokens only)",
                );
                self.push_msg(
                    "  :duress [set|clear]     passphrase that wipes instead of unlocking",
                );
                self.push_msg(
                    "  :duress set decoy       same, then opens an empty profile instead",
                );
                self.push_msg("  :deadman [set N|off]    wipe at start if not unlocked for N days");
                self.push_msg("  :wipe-after [set N|off] wipe after N failed unlocks");
                self.push_msg(
                    "  :clock / :clock-reset   check for a clock set back; accept current time",
                );
                self.push_msg(
                    "  :bridges [check]        ask Tor whether bridges are on and in use",
                );
                self.push_msg(
                    "  :bridges torrc LINE     check a bridge line and print the torrc lines",
                );
                self.push_msg(
                    "  :bridges require on|off hold sends unless Tor reports bridges active",
                );
                self.push_msg(
                    "  :binary / :binary-accept check this binary against the profile; trust it",
                );
                self.push_msg(
                    "  :wipe-settings[-accept]  check wipe setting files against the profile",
                );
                self.push_msg("  :wipe                   nuclear local wipe (confirm)");
                self.push_msg("  Ctrl+\\                 panic: wipe and quit now, no prompt");
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
            other if other == ":isolate" || other.starts_with(":isolate ") => {
                let args = other.strip_prefix(":isolate").unwrap_or("").trim();
                self.handle_isolate(args);
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
            other
                if other == ":rename"
                    || other.starts_with(":rename ")
                    || other == ":rename-contact"
                    || other.starts_with(":rename-contact ") =>
            {
                let args = if other.starts_with(":rename-contact") {
                    other.strip_prefix(":rename-contact").unwrap_or("").trim()
                } else {
                    other.strip_prefix(":rename").unwrap_or("").trim()
                };
                self.handle_rename_command(args);
            }
            other if other == ":verify" || other.starts_with(":verify ") => {
                let args = other.strip_prefix(":verify").unwrap_or("").trim();
                self.handle_verify_command(args);
            }
            other if other == ":unverify" || other.starts_with(":unverify ") => {
                let args = other.strip_prefix(":unverify").unwrap_or("").trim();
                self.handle_unverify_command(args);
            }
            other if other == ":send-unverified" || other.starts_with(":send-unverified ") => {
                let args = other.strip_prefix(":send-unverified").unwrap_or("").trim();
                self.handle_send_unverified(args);
            }
            other if other == ":mute" || other.starts_with(":mute ") => {
                let args = other.strip_prefix(":mute").unwrap_or("").trim();
                self.handle_mute_command(args);
            }
            other if other == ":unmute" || other.starts_with(":unmute ") => {
                let args = other.strip_prefix(":unmute").unwrap_or("").trim();
                self.handle_unmute_command(args);
            }
            other
                if other == ":delete-contact"
                    || other.starts_with(":delete-contact ")
                    || other == ":rm-contact"
                    || other.starts_with(":rm-contact ") =>
            {
                let args = if other.starts_with(":rm-contact") {
                    other.strip_prefix(":rm-contact").unwrap_or("").trim()
                } else {
                    other.strip_prefix(":delete-contact").unwrap_or("").trim()
                };
                self.handle_delete_contact_command(args);
            }
            other if other == ":wipe-after" || other.starts_with(":wipe-after ") => {
                let args = other.strip_prefix(":wipe-after").unwrap_or("").trim();
                self.handle_wipe_after(args);
            }
            other if other == ":deadman" || other.starts_with(":deadman ") => {
                let args = other.strip_prefix(":deadman").unwrap_or("").trim();
                self.handle_deadman(args);
            }
            other if other == ":duress" || other.starts_with(":duress ") => {
                let args = other.strip_prefix(":duress").unwrap_or("").trim();
                self.handle_duress(args);
            }
            other if other == ":bridges" || other.starts_with(":bridges ") => {
                let args = other.strip_prefix(":bridges").unwrap_or("").trim();
                self.handle_bridges(args);
            }
            ":clock" => self.handle_clock(false),
            ":clock-reset" => self.handle_clock(true),
            ":binary" => self.handle_binary(false),
            ":binary-accept" => self.handle_binary(true),
            ":wipe-settings" => self.handle_wipe_settings(false),
            ":wipe-settings-accept" => self.handle_wipe_settings(true),
            ":lock" => {
                if self.session.is_none() {
                    self.status_msg = "Already locked (or no session).".into();
                } else {
                    self.lock_ui();
                }
            }
            other if other == ":jitter" || other.starts_with(":jitter ") => {
                let args = other.strip_prefix(":jitter").unwrap_or("").trim();
                self.handle_jitter(args);
            }
            other if other == ":lock-timeout" || other.starts_with(":lock-timeout ") => {
                let args = other.strip_prefix(":lock-timeout").unwrap_or("").trim();
                self.handle_lock_timeout(args);
            }
            other
                if other == ":disappear"
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
            other => self.send_text(other, false),
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
        let next = if ok {
            TorStatus::Available
        } else {
            TorStatus::Unavailable
        };
        let change = tor_change(self.tor_status, next);
        self.tor_status = next;
        if let Some(change) = change {
            self.on_tor_change(change);
        }
    }

    /// Say so in the transcript when Tor drops or returns. Nothing is sent
    /// while it is down; committed frames wait in the encrypted queue and go
    /// out over Tor once SOCKS answers again. Locked sessions stay quiet.
    fn on_tor_change(&mut self, change: TorChange) {
        let Some(pending) = self.session.as_ref().map(|s| s.pending.len()) else {
            return;
        };
        match change {
            TorChange::WentDown => {
                self.status_msg = "Tor went down: sends are held in the encrypted queue".into();
                self.push_msg(self.status_msg.clone());
            }
            TorChange::CameBack => {
                self.push_msg("Tor is reachable again");
                if pending > 0 && self.net.require_messenger_transport().is_ok() {
                    self.retry_pending(false);
                } else {
                    self.status_msg = "Tor is reachable again".into();
                }
            }
        }
    }

    fn pending_count(&self) -> usize {
        self.session.as_ref().map_or(0, |s| s.pending.len())
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
        Screen::ConfirmDeleteContact => draw_delete_contact_modal(f, app, area),
        Screen::SetDuress => draw_duress_entry(f, app, area),
        Screen::SasGrid => draw_sas_grid(f, app, area),
        Screen::ContactCard => draw_contact_card(f, app, area),
        Screen::Support => draw_support(f, area),
    }
}

fn draw_unlock(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let rect = centered_rect(area, area.width.clamp(52, 72), 18);
    let prompt = if app.unlock_mode_create {
        match app.unlock_step {
            UnlockStep::EnterPass => {
                let min = if app.net.is_extreme() {
                    MIN_NEW_PASSPHRASE_CHARS_EXTREME
                } else {
                    MIN_NEW_PASSPHRASE_CHARS
                };
                format!("New passphrase ({min}+ chars):")
            }
            UnlockStep::ConfirmPass => "Confirm passphrase:".to_string(),
        }
    } else {
        "Passphrase:".to_string()
    };
    let masked = if app.unlock_step == UnlockStep::ConfirmPass {
        "•".repeat(app.passphrase_confirm.chars().count())
    } else {
        "•".repeat(app.passphrase.chars().count())
    };
    let mut pills: Vec<Span> = Vec::new();
    pills.extend(pill("● Locked", GOLD));
    pills.extend(pill("Argon2id at rest", DIM));
    pills.extend(pill("Tor required", TOR));
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " # ",
                Style::default()
                    .fg(BG)
                    .bg(GOLD)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  HashChat", gold_style()),
        ])
        .centered(),
        Line::from(Span::styled(
            "Private messaging over Tor. Nothing leaves this device unencrypted.",
            Style::default().fg(DIM),
        ))
        .centered(),
        Line::from(""),
        Line::from(pills).centered(),
        Line::from(""),
        Line::from(Span::styled(
            if app.unlock_mode_create {
                "Initialize local session (Argon2id-wrapped at rest)"
            } else {
                "Unlock local session"
            },
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        confirm_field(&prompt, masked, false),
        Line::from(""),
        Line::from(Span::styled(
            sanitize_for_terminal(&app.status_msg).into_owned(),
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Enter unlock · Esc clear · Tor required for network use",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "Transport default: Tor · :mode for explicit nets · No silent fallback",
            Style::default().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(card_block("unlock", false))
            .wrap(Wrap { trim: false }),
        rect,
    );
}

/// Rounded "pill" span (design: status bar pills, always on).
fn pill(text: impl Into<String>, fg: Color) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {} ", text.into()),
            Style::default().fg(BG).bg(fg).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
    ]
}

/// Tor transport pill text + colour. Presentation only; the policy lives in send paths.
fn tor_pill(status: TorStatus, listening: bool) -> (String, Color) {
    match status {
        TorStatus::Checking => ("◌ Tor · checking…".into(), DIM),
        TorStatus::Available if listening => ("● Tor · onion listening".into(), TOR),
        TorStatus::Available => ("● Tor · SOCKS ready".into(), TOR),
        TorStatus::Unavailable => ("✕ Tor · SOCKS unavailable".into(), DANGER),
    }
}

/// Fail-closed indicator: red when Tor is down (sends are refused, never a clearnet fallback).
fn fail_closed_pill(status: TorStatus) -> (String, Color) {
    match status {
        TorStatus::Unavailable => ("Fail-closed · sending refused".into(), DANGER),
        _ => ("Fail-closed · no clearnet".into(), GOLD),
    }
}

/// Contact row view model (labels only; never message bodies).
struct ContactRow {
    label: String,
    verified: bool,
    blocked: bool,
    muted: bool,
}

impl App {
    fn contact_rows(&self) -> Vec<ContactRow> {
        self.session
            .as_ref()
            .map(|s| {
                s.contacts
                    .iter()
                    .map(|c| ContactRow {
                        label: Self::contact_list_label(c),
                        verified: s.is_verified_id(&c.id),
                        blocked: s.is_blocked_id(&c.id),
                        muted: s.is_muted_id(&c.id),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_is_verified(&self) -> Option<bool> {
        let s = self.session.as_ref()?;
        let c = self.selected_contact_record()?;
        Some(s.is_verified_id(&c.id))
    }
}

fn avatar_initial(label: &str) -> String {
    label
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "#".into())
}

fn panel_block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused { GOLD } else { HAIRLINE };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(format!(" {title} "), gold_style()))
        .border_style(Style::default().fg(border))
        .style(Style::default().bg(PANEL))
}

fn draw_main(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    // ── Header: wordmark + always-on security pills ──────────────────────────
    let listening = app.hs.is_some();
    let (tor_txt, tor_col) = tor_pill(app.tor_status, listening);
    let (fc_txt, fc_col) = fail_closed_pill(app.tor_status);
    let mut pills: Vec<Span> = vec![Span::raw(" ")];
    pills.extend(pill(tor_txt, tor_col));
    pills.extend(pill(fc_txt, fc_col));
    let i2p_col = if app.net.mode.as_str() == "i2p" {
        I2P
    } else {
        DIM
    };
    pills.extend(pill("I2P · refused", i2p_col));
    if let Some(q) = queued_label(app.pending_count()) {
        pills.extend(pill(q, GOLD_DEEP));
    }
    let title_line = Line::from(vec![
        Span::styled(
            " # ",
            Style::default()
                .fg(BG)
                .bg(GOLD)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" HashChat", gold_style()),
        Span::styled("   SAS ", Style::default().fg(DIM)),
        Span::styled(app.my_sas.clone(), Style::default().fg(GOLD)),
        Span::styled(
            format!(
                "   mode {} · posture {} · ttl {} · lock {}",
                app.net.mode,
                app.net.posture.as_str(),
                format_ttl(app.disappear_ttl_secs),
                format_lock_timeout(app.lock_timeout_secs)
            ),
            Style::default().fg(DIM),
        ),
    ]);
    let header = Paragraph::new(vec![title_line, Line::from(pills)]).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(HAIRLINE))
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(header, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(root[1]);

    // ── Contact list: avatar initial, name, one status line ─────────────────
    let rows = app.contact_rows();
    let items: Vec<ListItem> = if rows.is_empty() {
        vec![ListItem::new(vec![
            Line::from(Span::styled("No contacts yet", Style::default().fg(DIM))),
            Line::from(Span::styled(
                ":add-contact <link>",
                Style::default().fg(GOLD_DEEP),
            )),
        ])]
    } else {
        let sel = app.contacts_state.selected();
        rows.iter()
            .enumerate()
            .map(|(idx, r)| {
                let row_bg = if sel == Some(idx) { SELECT_BG } else { PANEL };
                let name = sanitize_for_terminal(&r.label).into_owned();
                let (status, col) = if r.blocked {
                    ("⊘ blocked", DANGER)
                } else if !r.verified {
                    ("⚠ unverified", DANGER)
                } else if r.muted {
                    ("✓ verified · muted", DIM)
                } else {
                    ("✓ verified (SAS)", GOLD)
                };
                let av_bg = if r.verified { GOLD } else { SURFACE };
                let av_fg = if r.verified { BG } else { GOLD };
                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(
                            format!(" {} ", avatar_initial(&name)),
                            Style::default()
                                .fg(av_fg)
                                .bg(av_bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(" ", Style::default().bg(row_bg)),
                        Span::styled(
                            name,
                            Style::default()
                                .fg(TEXT)
                                .bg(row_bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ])
                    .style(Style::default().bg(row_bg)),
                    Line::from(vec![
                        Span::raw("    "),
                        Span::styled(status, Style::default().fg(col)),
                    ])
                    .style(Style::default().bg(row_bg)),
                    Line::from(""),
                ])
            })
            .collect()
    };
    let list = List::new(items)
        .block(panel_block("Chats", app.focus == Focus::Contacts))
        .highlight_style(Style::default())
        .highlight_symbol("▌");
    f.render_stateful_widget(list, body[0], &mut app.contacts_state);

    // ── Conversation: verification banner + bubbles ─────────────────────────
    let chat_area = body[1];
    let verified = app.selected_is_verified();
    let banner_h = if verified.is_some() { 1 } else { 0 };
    let chat_title = match app.selected_contact_record() {
        Some(c) => format!(
            "{} · SAS {}",
            App::contact_list_label(c),
            App::contact_sas_short(c)
        ),
        None => "Conversation".to_string(),
    };
    let chat_block = panel_block(&sanitize_for_terminal(&chat_title), true);
    let inner = chat_block.inner(chat_area);
    f.render_widget(chat_block, chat_area);
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(banner_h), Constraint::Min(1)])
        .split(inner);
    match verified {
        Some(true) => f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " ✓ Verified (SAS) ",
                    Style::default()
                        .fg(BG)
                        .bg(GOLD)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  via Tor v3 · Double Ratchet", Style::default().fg(DIM)),
            ])),
            parts[0],
        ),
        Some(false) => f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " ⚠ Unverified ",
                    Style::default()
                        .fg(BG)
                        .bg(DANGER)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "  compare SAS out of band, then :verify · sending refused",
                    Style::default().fg(DANGER),
                ),
            ]))
            .style(Style::default().bg(Color::Rgb(40, 16, 16))),
            parts[0],
        ),
        None => {}
    }

    let width = parts[1].width as usize;
    let max_bubble = (width * 3 / 4).max(10);
    let mut msg_lines: Vec<Line> = Vec::new();
    if app.messages.is_empty() {
        msg_lines.push(Line::from(""));
        msg_lines.push(
            Line::from(Span::styled(
                "No messages yet",
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ))
            .centered(),
        );
        msg_lines.push(
            Line::from(Span::styled(
                ":help for commands · :listen to publish your onion",
                Style::default().fg(DIM),
            ))
            .centered(),
        );
    } else {
        for m in &app.messages {
            let mut text = sanitize_for_terminal(&m.text).into_owned();
            if m.outgoing {
                // Display only: the bubble side already says "you".
                if let Some(i) = text.find("] you: ") {
                    text = text[i + 7..].to_string();
                }
                // The delivery note moves to the footer.
                if m.delivery.is_some() {
                    if let Some(i) = text.rfind("  (") {
                        if text.ends_with(')') {
                            text.truncate(i);
                        }
                    }
                }
            }
            if m.wipe_key.is_none() && !m.outgoing && m.expires_at.is_none() {
                // System note: muted, centred, no bubble.
                msg_lines.push(
                    Line::from(Span::styled(
                        format!("· {text} ·"),
                        Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
                    ))
                    .centered(),
                );
                continue;
            }
            let style = if m.outgoing {
                Style::default().fg(BG).bg(GOLD)
            } else {
                Style::default().fg(TEXT).bg(SURFACE)
            };
            for chunk in wrap_chars(&text, max_bubble.saturating_sub(2)) {
                let l = Line::from(Span::styled(format!(" {chunk} "), style));
                msg_lines.push(if m.outgoing { l.right_aligned() } else { l });
            }
            let ml = Line::from(bubble_meta(m));
            msg_lines.push(if m.outgoing { ml.right_aligned() } else { ml });
            msg_lines.push(Line::from(""));
        }
    }
    let h = parts[1].height as usize;
    let skip = msg_lines.len().saturating_sub(h);
    let msg_lines: Vec<Line> = msg_lines.into_iter().skip(skip).collect();
    f.render_widget(Paragraph::new(msg_lines), parts[1]);

    // ── Composer ────────────────────────────────────────────────────────────
    let input = Paragraph::new(Line::from(vec![
        Span::styled("› ", gold_style()),
        Span::styled(sanitize_for_terminal(&app.input), Style::default().fg(TEXT)),
        Span::styled("▌", Style::default().fg(GOLD)),
    ]))
    .block(panel_block("Message", app.focus == Focus::Input).style(Style::default().bg(SURFACE)));
    f.render_widget(input, root[2]);

    let status = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            sanitize_for_terminal(&app.status_msg),
            Style::default().fg(DIM),
        ),
    ]))
    .style(Style::default().bg(BG));
    f.render_widget(status, root[3]);
}

/// Bubble footer: real transport + delivery state (display only).
fn bubble_meta(m: &ChatLine) -> Vec<Span<'static>> {
    let mut v = vec![Span::styled(
        "via Tor v3 · Double Ratchet",
        Style::default().fg(DIM),
    )];
    if let Some(d) = m.delivery {
        let col = match d {
            Delivery::Sent => GOLD_DEEP,
            Delivery::Held => TOR,
            Delivery::Queued => DANGER,
        };
        v.push(Span::styled(" · ", Style::default().fg(DIM)));
        v.push(Span::styled(d.label(), Style::default().fg(col)));
    }
    if m.expires_at.is_some() {
        v.push(Span::styled(" · ⏱ disappearing", Style::default().fg(DIM)));
    }
    v
}

/// Hard-wrap by characters for bubble rendering (display only).
fn wrap_chars(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut n = 0;
    for ch in s.chars() {
        if n == width {
            out.push(std::mem::take(&mut cur));
            n = 0;
        }
        cur.push(ch);
        n += 1;
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// Centered rect clamped to the area (presentation only).
fn centered_rect(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

/// Rounded card block; red for destructive actions (DESIGN.md).
fn card_block(title: &str, danger: bool) -> Block<'static> {
    let col = if danger { DANGER } else { GOLD };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(col).add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(col))
        .padding(ratatui::widgets::Padding::horizontal(2))
        .style(Style::default().bg(PANEL))
}

/// Full-screen backdrop: never render chat/contacts under a modal.
fn blank_backdrop(f: &mut ratatui::Frame, area: Rect) {
    f.render_widget(Clear, area);
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);
}

fn danger_pill(text: &str) -> Span<'static> {
    Span::styled(
        format!(" ⚠ {text} "),
        Style::default()
            .fg(BG)
            .bg(DANGER)
            .add_modifier(Modifier::BOLD),
    )
}

fn confirm_field(label: &str, value: String, danger: bool) -> Line<'static> {
    let col = if danger { DANGER } else { GOLD };
    Line::from(vec![
        Span::styled(format!("{label} "), Style::default().fg(DIM)),
        Span::styled("› ", Style::default().fg(col).add_modifier(Modifier::BOLD)),
        Span::styled(value, Style::default().fg(TEXT).bg(SURFACE)),
        Span::styled("▌", Style::default().fg(col)),
    ])
}

#[allow(clippy::too_many_arguments)] // presentation-only text slots
fn draw_destructive(
    f: &mut ratatui::Frame,
    app: &App,
    area: Rect,
    title: &str,
    heading: &str,
    body: [&str; 2],
    confirm_cmd: &str,
    limits: &str,
) {
    blank_backdrop(f, area);
    let rect = centered_rect(area, area.width.clamp(48, 76), 15);
    let txt = |t: &str| Line::from(Span::styled(t.to_string(), Style::default().fg(TEXT)));
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            danger_pill(heading),
            Span::styled("  irreversible", Style::default().fg(DANGER)),
        ]),
        Line::from(""),
        txt(body[0]),
        txt(body[1]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Type ", Style::default().fg(TEXT)),
            Span::styled(
                confirm_cmd.to_string(),
                Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" then Enter.  Esc cancels.", Style::default().fg(TEXT)),
        ]),
        Line::from(""),
        confirm_field(
            "confirm",
            sanitize_for_terminal(&app.input).into_owned(),
            true,
        ),
        Line::from(""),
        Line::from(Span::styled(limits.to_string(), Style::default().fg(DIM))),
        Line::from(Span::styled(
            sanitize_for_terminal(&app.status_msg).into_owned(),
            Style::default().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(card_block(title, true))
            .wrap(Wrap { trim: false }),
        rect,
    );
}

fn draw_wipe_modal(f: &mut ratatui::Frame, app: &App, area: Rect) {
    draw_destructive(
        f,
        app,
        area,
        "DANGER · wipe",
        "NUCLEAR WIPE",
        [
            "Erases on-disk session (state.enc), Tor HS dir, and in-RAM",
            "passphrase, onion_key, ratchets, and pending frames.",
        ],
        ":wipe-confirm",
        "Limits: not a kernel-implant / prior-exfil mitigator (THREATMODEL).",
    );
}

fn draw_delete_contact_modal(f: &mut ratatui::Frame, app: &App, area: Rect) {
    draw_destructive(
        f,
        app,
        area,
        "DANGER · delete-contact",
        "DELETE CONTACT",
        [
            "Removes the contact and zeroizes local ratchet bytes,",
            "pending frames for that dest, and mute/block entries.",
        ],
        ":delete-contact-confirm",
        "Local only — not a remote wipe (THREATMODEL).",
    );
}

fn draw_duress_entry(f: &mut ratatui::Frame, app: &App, area: Rect) {
    blank_backdrop(f, area);
    let rect = centered_rect(area, area.width.clamp(48, 76), 14);
    let (prompt, len) = if app.unlock_step == UnlockStep::ConfirmPass {
        ("Confirm:", app.passphrase_confirm.chars().count())
    } else {
        ("Duress passphrase:", app.passphrase.chars().count())
    };
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            danger_pill("DURESS"),
            Span::styled(
                "  wipes local data when entered",
                Style::default().fg(DANGER),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Entering this at the unlock prompt wipes local data.",
            Style::default().fg(TEXT),
        )),
        Line::from(Span::styled(
            "It must differ from the normal passphrase.",
            Style::default().fg(TEXT),
        )),
        Line::from(""),
        confirm_field(prompt, "•".repeat(len), true),
        Line::from(""),
        Line::from(Span::styled(
            sanitize_for_terminal(&app.status_msg).into_owned(),
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "Enter accept · Esc cancel",
            Style::default().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(card_block("duress passphrase", true))
            .wrap(Wrap { trim: false }),
        rect,
    );
}

/// `:sas-grid` — SAS of the selected contact as 8 mono blocks (compare out of band).
fn draw_sas_grid(f: &mut ratatui::Frame, app: &App, area: Rect) {
    blank_backdrop(f, area);
    let rect = centered_rect(area, area.width.clamp(52, 80), 19);
    let Some(c) = app.selected_contact_record() else {
        return;
    };
    let name = sanitize_for_terminal(&App::contact_list_label(c)).into_owned();
    let sas: Vec<char> = App::contact_sas_short(c)
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    let verified = app.selected_is_verified().unwrap_or(false);
    let block_style = Style::default()
        .fg(BG)
        .bg(GOLD)
        .add_modifier(Modifier::BOLD);
    let mut top = vec![Span::raw("  ")];
    let mut mid = vec![Span::raw("  ")];
    let mut idx = vec![Span::raw("  ")];
    for (i, ch) in sas.iter().enumerate() {
        if i == 4 {
            for v in [&mut top, &mut mid, &mut idx] {
                v.push(Span::raw("   "));
            }
        }
        top.push(Span::styled("     ", block_style));
        mid.push(Span::styled(format!("  {ch}  "), block_style));
        idx.push(Span::styled(
            format!("  {}  ", i + 1),
            Style::default().fg(DIM),
        ));
        for v in [&mut top, &mut mid, &mut idx] {
            v.push(Span::raw(" "));
        }
    }
    let status = if verified {
        Line::from(Span::styled(
            " ✓ Verified (SAS) ",
            Style::default()
                .fg(BG)
                .bg(GOLD)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(danger_pill("Unverified · sending refused"))
    };
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(name, Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
            Span::styled("  ·  safety code (SAS)", Style::default().fg(DIM)),
        ]),
        Line::from(""),
        status,
        Line::from(""),
        Line::from(top.clone()),
        Line::from(mid),
        Line::from(top),
        Line::from(idx),
        Line::from(""),
        Line::from(Span::styled(
            "Read the 8 characters to each other in person or on a call.",
            Style::default().fg(TEXT),
        )),
        Line::from(Span::styled(
            "Never compare over HashChat itself.",
            Style::default().fg(TEXT),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " :verify ",
                Style::default()
                    .fg(BG)
                    .bg(GOLD)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" if they match   ", Style::default().fg(DIM)),
            Span::styled(
                " :block ",
                Style::default()
                    .fg(BG)
                    .bg(DANGER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" if they differ   Esc back", Style::default().fg(DIM)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines).block(card_block("verify contact", false)),
        rect,
    );
}

/// `:contact-card` — own signed Contact Link v1 with the checks a peer will run.
fn draw_contact_card(f: &mut ratatui::Frame, app: &App, area: Rect) {
    blank_backdrop(f, area);
    let rect = centered_rect(area, area.width.clamp(56, 86), 21);
    let inner_w = rect.width.saturating_sub(6) as usize;
    let mono = Style::default().fg(GOLD).bg(SURFACE);
    let check = |t: &str| {
        Line::from(vec![
            Span::styled(
                "  ✓ ",
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            ),
            Span::styled(t.to_string(), Style::default().fg(TEXT)),
        ])
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " # ",
                Style::default()
                    .fg(BG)
                    .bg(GOLD)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Your contact link", gold_style()),
            Span::styled("  ·  Contact Link v1 · signed", Style::default().fg(DIM)),
        ]),
        Line::from(""),
    ];
    let link = sanitize_for_terminal(&app.my_contact_link).into_owned();
    for chunk in wrap_chars(&link, inner_w).into_iter().take(5) {
        lines.push(Line::from(Span::styled(chunk, mono)));
    }
    lines.extend([
        Line::from(""),
        Line::from(vec![
            Span::styled("SAS ", Style::default().fg(DIM)),
            Span::styled(
                app.my_sas.clone(),
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Your contact's app checks:",
            Style::default().fg(DIM),
        )),
        check("Ed25519 signature over the link"),
        check("onion address bound to the signed identity"),
        check("Tor-only transport · no clearnet fallback"),
        Line::from(""),
        Line::from(Span::styled(
            "Share privately. Compare the SAS out of band before :verify.  Esc back",
            Style::default().fg(DIM),
        )),
    ]);
    f.render_widget(
        Paragraph::new(lines).block(card_block("contact link", false)),
        rect,
    );
}

/// `:support` — plans and pay-what-you-want. Static, offline.
fn draw_support(f: &mut ratatui::Frame, area: Rect) {
    use hashchat_rust::entitlement::{LIGHTNING, PAY_WHAT_YOU_WANT, PLANS, PRINCIPLE, XMR_ADDRESS};
    blank_backdrop(f, area);
    let rect = centered_rect(area, area.width.clamp(56, 92), 26);
    let inner_w = rect.width.saturating_sub(6) as usize;
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled("  Support HashChat", gold_style())),
        Line::from(Span::styled(
            format!("  {PRINCIPLE}"),
            Style::default().fg(TEXT),
        )),
        Line::from(""),
    ];
    for (plan, price) in PLANS {
        lines.push(Line::from(vec![
            Span::styled(format!("  {plan:<28}"), Style::default().fg(GOLD)),
            Span::styled((*price).to_string(), Style::default().fg(TEXT)),
        ]));
    }
    lines.push(Line::from(""));
    for chunk in wrap_chars(PAY_WHAT_YOU_WANT, inner_w) {
        lines.push(Line::from(Span::styled(chunk, Style::default().fg(DIM))));
    }
    lines.push(Line::from(Span::styled("  XMR", Style::default().fg(DIM))));
    for chunk in wrap_chars(XMR_ADDRESS, inner_w.saturating_sub(2).max(8)) {
        lines.push(Line::from(Span::styled(
            format!("  {chunk}"),
            Style::default().fg(GOLD).bg(SURFACE),
        )));
    }
    lines.push(Line::from(vec![
        Span::styled("  LN  ", Style::default().fg(DIM)),
        Span::styled(LIGHTNING, Style::default().fg(GOLD).bg(SURFACE)),
    ]));
    lines.push(Line::from(Span::styled(
        "  BTC on-chain: BTCPay invoice (fresh address per payment)",
        Style::default().fg(DIM),
    )));
    lines.push(Line::from(Span::styled(
        "  Esc back",
        Style::default().fg(DIM),
    )));
    f.render_widget(
        Paragraph::new(lines).block(card_block("support", false)),
        rect,
    );
}

impl Drop for App {
    fn drop(&mut self) {
        // Also runs during panic unwinding, after active borrows have ended.
        self.emergency_scrub_fields();
    }
}

fn run(dumps: DumpHardening) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Before the unlock prompt, so an overdue store is gone before anyone can type.
    wipe_if_deadman_due(Path::new(DATA_DIR), unix_now(), wipe_local_sensitive);
    let mut app = App::new();
    app.dump_hardening = Some(dumps);
    if !dumps.all() {
        app.status_msg = "core-dump hardening incomplete (best-effort)".into();
    }
    bind_app_scrub();
    app.check_tor(true);

    let tick = Duration::from_millis(100);
    loop {
        if take_terminate_signal() {
            app.emergency_scrub_fields();
            break;
        }
        app.check_tor(false);
        app.drain_incoming();
        app.flush_held_sends();
        app.expire_messages();
        if app.idle_should_lock() {
            app.lock_ui();
        }
        terminal.draw(|f| ui(f, &mut app))?;

        let ready = match event::poll(tick) {
            Ok(v) => v,
            Err(_) => {
                app.emergency_scrub_fields();
                break;
            }
        };
        if !ready {
            continue;
        }
        let Event::Key(key) = (match event::read() {
            Ok(ev) => ev,
            Err(_) => {
                app.emergency_scrub_fields();
                break;
            }
        }) else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            app.emergency_scrub_fields();
            break;
        }

        // Panic key: wipe local data and quit, from any screen, no prompt.
        if key.code == KeyCode::Char('\\') && key.modifiers.contains(KeyModifiers::CONTROL) {
            app.emergency_scrub_fields();
            wipe_local_sensitive();
            break;
        }

        // Any key while unlocked resets the idle auto-lock timer.
        if matches!(
            app.screen,
            Screen::Main
                | Screen::ConfirmWipe
                | Screen::ConfirmDeleteContact
                | Screen::SetDuress
                | Screen::SasGrid
                | Screen::ContactCard
                | Screen::Support
        ) {
            app.touch_input();
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
                    let buf = if app.unlock_step == UnlockStep::ConfirmPass {
                        &mut app.passphrase_confirm
                    } else {
                        &mut app.passphrase
                    };
                    if !push_secret_char(buf, ch) {
                        app.status_msg = "Passphrase too long.".into();
                    }
                }
                _ => {}
            },
            Screen::SetDuress => match key.code {
                KeyCode::Esc => {
                    app.cancel_duress_entry();
                    app.status_msg = "Duress setup cancelled.".into();
                }
                KeyCode::Enter => app.submit_duress_entry(),
                KeyCode::Backspace => {
                    if app.unlock_step == UnlockStep::ConfirmPass {
                        app.passphrase_confirm.pop();
                    } else {
                        app.passphrase.pop();
                    }
                }
                KeyCode::Char(ch) => {
                    let buf = if app.unlock_step == UnlockStep::ConfirmPass {
                        &mut app.passphrase_confirm
                    } else {
                        &mut app.passphrase
                    };
                    if !push_secret_char(buf, ch) {
                        app.status_msg = "Passphrase too long.".into();
                    }
                }
                _ => {}
            },
            Screen::ConfirmWipe => match key.code {
                KeyCode::Esc => {
                    app.screen = Screen::Main;
                    app.clear_input_secure();
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
                    let mut cmd = app.input.trim().to_string();
                    app.clear_input_secure();
                    if cmd == ":wipe-confirm" {
                        app.handle_command(&cmd);
                    } else {
                        app.screen = Screen::Main;
                        app.status_msg = "Wipe cancelled (expected :wipe-confirm).".into();
                        app.focus = Focus::Input;
                    }
                    cmd.zeroize();
                }
                _ => {}
            },
            Screen::ConfirmDeleteContact => match key.code {
                KeyCode::Esc => {
                    app.pending_delete_contact = None;
                    app.screen = Screen::Main;
                    app.clear_input_secure();
                    app.status_msg = "Contact delete cancelled.".into();
                    app.focus = Focus::Input;
                }
                KeyCode::Char(ch) => {
                    app.focus = Focus::Input;
                    app.input.push(ch);
                    app.status_msg = format!("Confirm input: {}", app.input);
                }
                KeyCode::Backspace => {
                    app.input.pop();
                    app.status_msg = if app.input.is_empty() {
                        "DELETE CONTACT: type :delete-contact-confirm to wipe ratchet, or Esc to cancel."
                            .into()
                    } else {
                        format!("Confirm input: {}", app.input)
                    };
                }
                KeyCode::Enter => {
                    let mut cmd = app.input.trim().to_string();
                    app.clear_input_secure();
                    if cmd == ":delete-contact-confirm" {
                        app.handle_command(&cmd);
                    } else {
                        app.pending_delete_contact = None;
                        app.screen = Screen::Main;
                        app.status_msg =
                            "Contact delete cancelled (expected :delete-contact-confirm).".into();
                        app.focus = Focus::Input;
                    }
                    cmd.zeroize();
                }
                _ => {}
            },
            Screen::SasGrid | Screen::ContactCard | Screen::Support => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                    app.screen = Screen::Main;
                    app.focus = Focus::Input;
                    app.status_msg = "Back to chats.".into();
                }
            }
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
                    let mut cmd = std::mem::take(&mut app.input);
                    app.handle_command(&cmd);
                    cmd.zeroize();
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
                    app.clear_input_secure();
                    app.status_msg = "Input cleared.".into();
                }
                _ => {}
            },
        }
    }

    if app.session.is_some() {
        touch_deadman(Path::new(DATA_DIR), unix_now());
    }
    unbind_app_scrub();
    app.hs = None;
    app.store_key = None;
    app.passphrase.zeroize();
    app.passphrase_confirm.zeroize();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

/// Warning shown when the running binary differs from the recorded one.
const BINARY_WARNING: &str = "Warning: this hashchat-tui binary is not the one that last saved \
    this profile. If you did not update it, stop and check it against the published checksum \
    (:binary). :binary-accept if the update was yours.";

/// Warning shown when `state.enc` is not the copy this directory last saved.
const SAVE_MARK_WARNING: &str = "Warning: this state.enc is not the copy last saved here. \
    It may have been restored from an older backup or image, which brings back deleted \
    contacts and old keys. If you did not restore it, someone had access to this data \
    directory. The warning clears with the next save.";

/// Warning shown when wipe setting files changed while the profile was locked.
fn wipe_settings_warning(changed: &[&str]) -> String {
    format!(
        "Warning: changed while locked: {}. If you did not do this, someone had access \
         to this data directory. Check with :deadman, :wipe-after and :duress; \
         :wipe-settings-accept once they are right.",
        changed.join(", ")
    )
}

/// Warning shown when the clock reads earlier than the last save. Says why it
/// matters without echoing any timestamps.
fn clock_warning_line(behind_secs: u64) -> String {
    format!(
        "Warning: system clock is {} behind the last saved time. Expiry and the dead-man \
         switch rely on it. Fix the clock, or :clock-reset if it is right.",
        format_rollback(behind_secs)
    )
}

/// Generate a new identity, seal it under `pass` in the data directory and
/// return it with the derived store key. Argon2id runs once.
fn create_session_on_disk(
    pass: &[u8],
    net: &NetConfig,
) -> Result<(SessionState, StoreKey), &'static str> {
    let id = LongTermIdentity::generate().map_err(|_| "identity generation failed")?;
    let identity = IdentityOnionState {
        seed: id.seed_bytes(),
        onion: String::new(),
        onion_key: Vec::new(),
    };
    let mut state = SessionState::from_identity_with_net(identity, net.clone());
    if let Some(cur) = running_binary_digest() {
        state.binary_digest = cur;
    }
    state.wipe_settings = Some(WipeSettings::from_disk(Path::new(DATA_DIR)));
    let key = StoreKey::derive_new(pass)?;
    save_session_with_key(Path::new(DATA_DIR), &key, &state)?;
    Ok((state, key))
}

fn main() {
    if std::env::var_os("HASHCHAT_INSECURE_DEV_PERSIST").is_some() {
        eprintln!(
            "hashchat-tui: HASHCHAT_INSECURE_DEV_PERSIST is set; refusing to run (passphrase-only)."
        );
        std::process::exit(2);
    }
    // `--wipe`: erase local data and exit without starting the UI, for use from a
    // script or another terminal. Run it from the directory that holds hashchat_data.
    if std::env::args().skip(1).any(|a| a == "--wipe") {
        wipe_local_sensitive();
        println!("local data wiped");
        return;
    }
    // First, before any secret exists: no core files, no same-uid ptrace.
    let dumps = disable_core_dumps_best_effort();
    // Hash the executable now, while it is the file that was started.
    let _ = running_binary_digest();
    // Before App exists: hook is a no-op until bind_app_scrub.
    install_panic_scrub_hook();
    install_terminate_signal_flag();
    if let Err(e) = run(dumps) {
        eprintln!("hashchat-tui error: {e}");
        std::process::exit(1);
    }
}

/// Text for `:bridges help` and `:bridges torrc LINE`. Never echoes an
/// invalid line back, since it may be a private bridge.
fn bridges_text(args: &str) -> Vec<String> {
    if let Some(line) = args.strip_prefix("torrc") {
        return match parse_bridge_line(line) {
            Ok(b) => {
                let mut out =
                    vec!["Add these lines to torrc, then reload Tor and run :bridges:".to_string()];
                out.extend(torrc_snippet(&[b]).into_iter().map(|l| format!("  {l}")));
                out.push("HashChat does not store bridge lines; torrc keeps them.".into());
                out
            }
            Err(e) => vec![format!("Bridge line refused: {e}")],
        };
    }
    vec![
        "Bridges hide that you use Tor from your network. Get lines from".into(),
        "bridges.torproject.org or the Tor Project's Telegram/email bots.".into(),
        "  :bridges torrc LINE   check one line and print what to add to torrc".into(),
        "  :bridges              ask Tor whether bridges are on and every circuit starts at one"
            .into(),
        "  :bridges require on   keep messages queued unless that check passes".into(),
        "HashChat only reads Tor's settings; it never changes them.".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_app() -> App {
        let app = App::new();
        assert!(app.session.is_none());
        app
    }

    #[test]
    fn bridges_torrc_prints_snippet_for_valid_line() {
        let fp = "0123456789ABCDEF0123456789ABCDEF01234567";
        let out = bridges_text(&format!(
            "torrc obfs4 192.0.2.10:443 {fp} cert=abc iat-mode=0"
        ));
        assert!(out.iter().any(|l| l.trim() == "UseBridges 1"));
        assert!(out
            .iter()
            .any(|l| l.trim().starts_with("ClientTransportPlugin obfs4")));
        assert!(out
            .iter()
            .any(|l| l.trim().starts_with("Bridge obfs4 192.0.2.10:443")));
    }

    #[test]
    fn bridges_torrc_refusal_does_not_echo_line() {
        let out = bridges_text("torrc obfs4 192.0.2.99:443 cert=SECRET iat-mode=0");
        assert_eq!(out.len(), 1);
        assert!(out[0].starts_with("Bridge line refused"));
        assert!(!out[0].contains("SECRET") && !out[0].contains("192.0.2.99"));
    }

    #[test]
    fn bridge_hold_off_by_default_and_uses_cache() {
        let mut app = locked_app();
        assert!(!app.net.require_bridges);
        assert_eq!(app.bridges_hold_reason(), None);
        app.net.require_bridges = true;
        app.bridge_check = Some((Instant::now(), Err("bridges=off".into())));
        assert_eq!(app.bridges_hold_reason().as_deref(), Some("bridges=off"));
        app.bridge_check = Some((Instant::now(), Ok(())));
        assert_eq!(app.bridges_hold_reason(), None);
    }

    #[test]
    fn bridges_require_needs_unlock_to_change() {
        let mut app = locked_app();
        app.handle_bridges_require("on");
        assert!(!app.net.require_bridges);
        assert!(app.status_msg.starts_with("Unlock first"));
        app.handle_bridges_require("");
        assert_eq!(app.status_msg, "bridges require=off");
    }

    #[test]
    fn listen_held_while_bridges_required_and_inactive() {
        let mut app = locked_app();
        let id = LongTermIdentity::generate().unwrap();
        let identity = IdentityOnionState {
            seed: id.seed_bytes(),
            onion: String::new(),
            onion_key: Vec::new(),
        };
        app.session = Some(SessionState::from_identity_with_net(
            identity,
            NetConfig::default(),
        ));
        app.net.require_bridges = true;
        app.bridge_check = Some((Instant::now(), Err("bridges=off".into())));
        app.listen();
        assert!(app.hs.is_none());
        assert!(app.status_msg.starts_with(":listen held: bridges required"));
    }

    #[test]
    fn bridges_help_for_unknown_args() {
        let out = bridges_text("help");
        assert!(out.iter().any(|l| l.contains(":bridges torrc LINE")));
    }

    #[test]
    fn tor_change_only_between_known_states() {
        use TorStatus::*;
        assert_eq!(
            tor_change(Available, Unavailable),
            Some(TorChange::WentDown)
        );
        assert_eq!(
            tor_change(Unavailable, Available),
            Some(TorChange::CameBack)
        );
        assert_eq!(tor_change(Checking, Unavailable), None);
        assert_eq!(tor_change(Checking, Available), None);
        assert_eq!(tor_change(Available, Available), None);
        assert_eq!(tor_change(Unavailable, Unavailable), None);
    }

    #[test]
    fn queued_label_hidden_when_empty() {
        assert_eq!(queued_label(0), None);
        assert_eq!(queued_label(3).as_deref(), Some("3 queued"));
    }

    #[test]
    fn tor_change_silent_while_locked() {
        let mut app = locked_app();
        let before = app.messages.len();
        app.on_tor_change(TorChange::WentDown);
        app.on_tor_change(TorChange::CameBack);
        assert_eq!(app.messages.len(), before);
        assert_eq!(app.pending_count(), 0);
    }

    #[test]
    fn deadman_off_refused_while_locked() {
        let mut app = locked_app();
        app.handle_deadman("off");
        assert_eq!(app.status_msg, UNLOCK_TO_DISABLE);
    }

    #[test]
    fn wipe_after_off_refused_while_locked() {
        let mut app = locked_app();
        app.handle_wipe_after("off");
        assert_eq!(app.status_msg, UNLOCK_TO_DISABLE);
    }

    #[test]
    fn duress_clear_refused_while_locked() {
        let mut app = locked_app();
        app.handle_duress("clear");
        assert_eq!(app.status_msg, UNLOCK_TO_DISABLE);
    }

    #[test]
    fn status_still_works_while_locked() {
        let mut app = locked_app();
        app.handle_deadman("status");
        assert_ne!(app.status_msg, UNLOCK_TO_DISABLE);
        app.handle_wipe_after("");
        assert_ne!(app.status_msg, UNLOCK_TO_DISABLE);
    }

    // ── Design-system render tests (presentation only) ──────────────────────
    fn demo_app(verified_first: bool, tor: TorStatus) -> App {
        let mut app = locked_app();
        let mut s = SessionState::from_identity(IdentityOnionState {
            seed: [1u8; 32],
            onion: "demo".into(),
            onion_key: Vec::new(),
        });
        for (i, name) in ["Alice", "Bruno", "Carla"].iter().enumerate() {
            let b = (i as u8) + 3;
            s.contacts.push(PersistedContact {
                id: format!("demo-{i}"),
                display_name: (*name).into(),
                onion: format!("{}demo.onion", "x".repeat(50)),
                x25519: [b; 32],
                ed25519: [b + 9; 32],
            });
        }
        if verified_first {
            s.verify_contact_id("demo-0");
        }
        s.verify_contact_id("demo-2");
        let _ = s.mute_contact_id("demo-2");
        app.session = Some(s);
        app.screen = Screen::Main;
        app.my_sas = "1234 5678 9012".into();
        app.tor_status = tor;
        app.selected_contact = Some(0);
        app.contacts_state.select(Some(0));
        app.push_msg("Session unlocked · contacts loaded");
        app.push_chat("[Alice] Olá! Chegou bem pelo Tor?", "demo-0", 1);
        app.push_chat_out(
            "[Alice] you: Chegou sim, tudo cifrado ponta a ponta.",
            "demo-0",
            2,
        );
        app.push_chat(
            "[Alice] Perfeito. Comparei o SAS fora da rede ✓",
            "demo-0",
            3,
        );
        app.status_msg = "Sent 1024 B via SOCKS (isol)".into();
        app
    }

    fn render(app: &mut App, w: u16, h: u16) -> ratatui::buffer::Buffer {
        let mut term = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        term.draw(|f| ui(f, app)).unwrap();
        term.backend().buffer().clone()
    }

    fn buf_text(b: &ratatui::buffer::Buffer) -> String {
        b.content().iter().map(|c| c.symbol()).collect()
    }

    /// Optional: dump coloured cells for docs/screenshots/real (scripts/tui_snapshot.py).
    fn dump(b: &ratatui::buffer::Buffer, name: &str) {
        let Ok(dir) = std::env::var("HASHCHAT_SNAPSHOT_DIR") else {
            return;
        };
        let col = |c: Color| match c {
            Color::Rgb(r, g, b) => format!("{r:02x}{g:02x}{b:02x}"),
            _ => "-".into(),
        };
        let mut out = format!("{} {}\n", b.area.width, b.area.height);
        for c in b.content() {
            let bold = c.modifier.contains(Modifier::BOLD) as u8;
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                col(c.fg),
                col(c.bg),
                bold,
                c.symbol()
            ));
        }
        std::fs::write(format!("{dir}/{name}.cells"), out).unwrap();
    }

    #[test]
    fn design_header_shows_tor_and_fail_closed_pills() {
        let mut app = demo_app(true, TorStatus::Available);
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-chat");
        let t = buf_text(&b);
        assert!(t.contains("Tor · SOCKS ready"));
        assert!(t.contains("Fail-closed · no clearnet"));
        assert!(t.contains("I2P · refused"));
        assert!(t.contains("✓ Verified (SAS)"));
        assert!(t.contains("⚠ unverified"));
    }

    #[test]
    fn design_fail_closed_turns_red_when_tor_down() {
        let mut app = demo_app(false, TorStatus::Unavailable);
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-unverified-tor-down");
        let t = buf_text(&b);
        assert!(t.contains("Fail-closed · sending refused"));
        assert!(t.contains("⚠ Unverified"));
        let cell = b
            .content()
            .iter()
            .position(|c| c.symbol() == "✕")
            .map(|i| &b.content()[i])
            .unwrap();
        assert_eq!(cell.bg, DANGER);
    }

    #[test]
    fn design_outgoing_flag_only_from_send_path() {
        let app = demo_app(true, TorStatus::Available);
        let out: Vec<bool> = app.messages.iter().map(|m| m.outgoing).collect();
        assert_eq!(out, vec![false, false, true, false]);
    }

    #[test]
    fn design_unlock_card() {
        let mut app = locked_app();
        app.passphrase.push_str("secret");
        app.status_msg = "Enter your passphrase.".into();
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-unlock");
        let t = buf_text(&b);
        assert!(t.contains("Unlock local session") || t.contains("Initialize local session"));
        assert!(!t.contains("secret"));
    }

    #[test]
    fn design_destructive_modals_are_red_and_need_confirm() {
        let mut app = demo_app(true, TorStatus::Available);
        app.screen = Screen::ConfirmWipe;
        app.input = ":wipe-con".into();
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-wipe");
        let t = buf_text(&b);
        assert!(t.contains("NUCLEAR WIPE") && t.contains(":wipe-confirm"));
        assert!(!t.contains("Olá"), "no chat under the modal");
        app.input.clear();
        app.screen = Screen::ConfirmDeleteContact;
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-delete-contact");
        assert!(buf_text(&b).contains(":delete-contact-confirm"));
        app.screen = Screen::SetDuress;
        app.passphrase.push_str("hunter2");
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-duress");
        let t = buf_text(&b);
        assert!(t.contains("Duress passphrase:") && !t.contains("hunter2"));
    }

    #[test]
    fn design_sas_grid_shows_eight_blocks() {
        let mut app = demo_app(false, TorStatus::Available);
        app.handle_command(":sas-grid");
        assert!(app.screen == Screen::SasGrid);
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-sas-grid");
        let t = buf_text(&b);
        let sas = App::contact_sas_short(app.selected_contact_record().unwrap());
        for ch in sas.chars().filter(|c| c.is_ascii_alphanumeric()) {
            assert!(t.contains(&format!("  {ch}  ")));
        }
        assert!(t.contains(":verify") && t.contains(":block"));
    }

    #[test]
    fn support_screen_is_offline_and_shows_plans() {
        let mut app = demo_app(false, TorStatus::Unavailable);
        app.handle_command(":support");
        assert!(app.screen == Screen::Support);
        // Tall enough for the wrapped XMR primary address.
        let b = render(&mut app, 120, 40);
        let t = buf_text(&b);
        assert!(t.contains("€149") && t.contains("Pay what you want"));
        // Address wraps across rows; assert contiguous head and final wrap chunk.
        assert!(t.contains("42i5CYsjGALfD8GgCiL3Wv1WPKtWbeUKEYe4"));
        assert!(t.contains("Wz9L1F3bwJn"));
        assert!(t.contains("treulicht@cake.cash"));
        assert!(t.contains("BTCPay"));
    }

    #[test]
    fn design_contact_card_respects_refusals() {
        let mut app = demo_app(true, TorStatus::Available);
        app.handle_command(":contact-card");
        assert!(app.screen == Screen::Main, "no link yet → no card");
        app.my_contact_link = "hashchat://v1/EXAMPLE-NOT-A-REAL-LINK-0000000000000000000000000000000000000000000000000000000000000000/sig".into();
        app.handle_command(":contact-card");
        assert!(app.screen == Screen::ContactCard);
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-contact-card");
        let t = buf_text(&b);
        assert!(t.contains("Ed25519 signature") && t.contains("Tor-only"));
    }

    #[test]
    fn design_bubble_footer_shows_delivery_and_selected_avatar_stays_gold() {
        let mut app = demo_app(true, TorStatus::Available);
        app.push_chat_out_state(
            "[Alice] you: later  (held, random delay before send)",
            "demo-0",
            4,
            Delivery::Held,
        );
        app.push_chat_out_state(
            "[Alice] you: offline  (queued: bridges required, x)",
            "demo-0",
            5,
            Delivery::Queued,
        );
        let b = render(&mut app, 120, 34);
        dump(&b, "hashchat-tui-chat-delivery");
        let t = buf_text(&b);
        assert!(t.contains("via Tor v3 · Double Ratchet · sent"));
        assert!(t.contains("held · random delay") && t.contains("· queued"));
        app.set_delivery("demo-0", 4, Delivery::Sent);
        assert_eq!(app.messages[4].delivery, Some(Delivery::Sent));
        let av = b
            .content()
            .iter()
            .find(|c| c.symbol() == "A" && c.bg == GOLD && c.fg == BG);
        assert!(av.is_some(), "selected row keeps gold avatar");
    }

    #[test]
    fn design_wrap_chars_bounds() {
        assert_eq!(wrap_chars("abcdef", 4), vec!["abcd", "ef"]);
        assert_eq!(wrap_chars("", 4), vec![""]);
        assert_eq!(avatar_initial("  bruno"), "B");
    }
}
