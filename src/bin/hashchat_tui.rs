//! HashChat native Rust TUI (transitional desktop path toward max-Rust).
//!
//! Build: `cargo build --bin hashchat-tui --features tui`
//!
//! Uses existing crate APIs: session_persist, contact_link, LongTermIdentity, wipe.
//! Transport policy: Tor SOCKS only — no clearnet fallback.

use std::io::{self, stdout};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hashchat_rust::{
    format_signed_contact_link, sas_fingerprint, wipe_local_sensitive, IdentityOnionState,
    LongTermIdentity, PersistMode, PersistedContact, SessionState, load_session, save_session,
    state_exists,
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
    fn label(self) -> &'static str {
        match self {
            TorStatus::Checking => "Tor: checking…",
            TorStatus::Available => "Tor: SOCKS ready",
            TorStatus::Unavailable => "Tor: SOCKS unavailable",
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
            // SAS without onion still useful for identity material; link needs Tor HS.
            self.my_sas = sas_fingerprint(
                &id.ed25519_public_bytes(),
                &id.x25519_public_bytes(),
                "onion-pending.onion",
            );
            self.my_contact_link =
                "(contact link available after Tor hidden service is configured)".into();
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
                                "Session created. Tor required for messaging.".into();
                            self.messages.push(
                                "Session initialized. Use :my-contact for your signed link."
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
                            "Loaded {} contact(s). Transport: Tor only.",
                            s.contacts.len()
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
        // Keep passphrase in memory only while session is active for re-saves;
        // wipe confirm buffer.
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

    fn handle_command(&mut self, cmd: &str) {
        let c = cmd.trim();
        match c {
            ":q" | ":quit" | ":exit" => {
                // Caller checks a quit flag via status — we use a sentinel.
                self.status_msg = "__QUIT__".into();
            }
            ":wipe" => {
                self.screen = Screen::ConfirmWipe;
                self.status_msg = "Type :wipe-confirm to erase local sensitive data.".into();
            }
            ":wipe-confirm" => {
                wipe_local_sensitive();
                if let Some(mut s) = self.session.take() {
                    s.clear_pending_secure();
                    s.clear_ratchets_secure();
                    s.seed_zeroize_hint();
                }
                self.passphrase.zeroize();
                self.passphrase.clear();
                self.my_sas.clear();
                self.my_contact_link.clear();
                self.messages.clear();
                self.contacts_state = ListState::default();
                self.selected_contact = None;
                self.unlock_mode_create = true;
                self.unlock_step = UnlockStep::EnterPass;
                self.screen = Screen::Unlock;
                self.status_msg = "Local sensitive data erased.".into();
            }
            ":my-contact" => {
                if self.my_contact_link.is_empty() {
                    self.messages
                        .push("No contact link yet (unlock first).".into());
                } else {
                    self.messages
                        .push(format!("SAS: {}", self.my_sas));
                    self.messages
                        .push(format!("Contact: {}", self.my_contact_link));
                }
            }
            ":status" | ":tor" => {
                self.check_tor(true);
                self.messages
                    .push(format!("{} (no clearnet fallback)", self.tor_status.label()));
            }
            ":help" => {
                self.messages.push(
                    "Commands: :my-contact  :tor  :wipe  :quit  | Tab focus | Enter send (local stub)"
                        .into(),
                );
            }
            "" => {}
            other if other.starts_with(':') => {
                self.messages
                    .push(format!("Unknown command: {other}  (:help)"));
            }
            other => {
                // Local-only chat stub — full Tor send path still lives in Haskell for now.
                let peer = self
                    .selected_contact_record()
                    .map(|c| {
                        if c.display_name.is_empty() {
                            c.id.as_str()
                        } else {
                            c.display_name.as_str()
                        }
                    })
                    .unwrap_or("(no contact)");
                if self.tor_status != TorStatus::Available {
                    self.messages.push(
                        "Send refused: Tor SOCKS not available (Tor-only policy).".into(),
                    );
                } else {
                    self.messages.push(format!("[{peer}] {other}"));
                    self.messages.push(
                        "(outbound Tor frame not yet wired in Rust TUI — use Haskell client for live send)"
                            .into(),
                    );
                }
            }
        }
    }

    fn check_tor(&mut self, force: bool) {
        if !force && self.last_tor_check.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.last_tor_check = Instant::now();
        // Tor Browser / system Tor SOCKS — never fall back to clearnet.
        let ports = [9050u16, 9150];
        let ok = ports.iter().any(|p| {
            TcpStream::connect_timeout(
                &format!("127.0.0.1:{p}").parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_ok()
        });
        self.tor_status = if ok {
            TorStatus::Available
        } else {
            TorStatus::Unavailable
        };
    }
}

/// Helper so we can zeroize seed after wipe without exposing internals further.
trait SeedZeroize {
    fn seed_zeroize_hint(&mut self);
}

impl SeedZeroize for SessionState {
    fn seed_zeroize_hint(&mut self) {
        self.identity.seed.zeroize();
        self.identity.onion_key.zeroize();
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
        Screen::ConfirmWipe => {
            draw_main(f, app, area);
            draw_wipe_modal(f, app, area);
        }
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
        "Transport default: Tor · No clearnet fallback",
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

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" # HashChat ", gold_style()),
        Span::styled("│ ", Style::default().fg(DIM)),
        Span::styled(format!("SAS {}", app.my_sas), Style::default().fg(GOLD)),
        Span::styled(" │ ", Style::default().fg(DIM)),
        Span::styled(app.tor_status.label(), app.tor_status.style()),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GOLD))
            .style(Style::default().bg(PANEL)),
    );
    f.render_widget(header, root[0]);

    // Body: contacts | chat
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
            "No messages. :help for commands.",
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

    // Input
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

    // Status footer
    let status = Paragraph::new(Line::from(Span::styled(
        &app.status_msg,
        Style::default().fg(DIM),
    )))
    .style(Style::default().bg(BG));
    f.render_widget(status, root[3]);
}

fn draw_wipe_modal(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let w = area.width.min(64).max(40);
    let h = 7u16;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);
    f.render_widget(Clear, rect);
    let body = Paragraph::new(vec![
        Line::from(Span::styled(
            "Erase local sensitive data?",
            Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Type :wipe-confirm in input, or Esc to cancel.",
            Style::default().fg(TEXT),
        )),
        Line::from(Span::styled(&app.status_msg, Style::default().fg(DIM))),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" wipe ", Style::default().fg(DANGER)))
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

        // Global quit
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
                    app.status_msg = "Wipe cancelled.".into();
                    app.focus = Focus::Input;
                }
                KeyCode::Char(ch) => {
                    app.focus = Focus::Input;
                    app.screen = Screen::Main;
                    app.input.push(ch);
                }
                KeyCode::Enter => {
                    app.screen = Screen::Main;
                    app.focus = Focus::Input;
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

    // Best-effort wipe passphrase from process memory on exit.
    app.passphrase.zeroize();
    app.passphrase_confirm.zeroize();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn main() {
    // Refuse insecure-dev persist as default for this binary.
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
