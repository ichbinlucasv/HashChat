//! HashChat desktop TUI — two-device Tor path.
//!
//! 1. :listen     publish a v3 onion (keeps the control connection open)
//! 2. :my-contact share hashchat://… (qrencode if installed)
//! 3. :add-contact hashchat://contact/v1/<onion>/<x25519>
//! 4. type a message + Enter  (framed ciphertext over SOCKS to onion:80)

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hashchat_rust::hidden_service::{start_hidden_service_with_key, HiddenService};
use hashchat_rust::session::{maybe_qr_text, Session};
use hashchat_rust::tor_socks::{probe, socks5_send};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, stdout};
use std::time::Duration;

const GOLD: Color = Color::Rgb(255, 215, 0);

struct App {
    session: Session,
    hs: Option<HiddenService>,
    input: String,
    help: bool,
    status: String,
    socks_host: String,
    socks_port: u16,
    control_port: u16,
}

impl App {
    fn new() -> Self {
        let mut session = Session::open();
        let tor = probe("127.0.0.1", 9050, 9051);
        session.log(tor.note.clone());
        App {
            session,
            hs: None,
            input: String::new(),
            help: false,
            status: format!("{} — :listen to publish your onion", tor.note),
            socks_host: "127.0.0.1".into(),
            socks_port: 9050,
            control_port: 9051,
        }
    }

    fn drain_incoming(&mut self) {
        let Some(hs) = self.hs.as_ref() else {
            return;
        };
        let mut frames = Vec::new();
        while let Some(f) = hs.try_recv() {
            frames.push(f);
        }
        for frame in frames {
            match self.session.receive_frame(&frame) {
                Ok(text) => {
                    self.status = format!("recv: {text}");
                    self.session.log(format!("recv {text}"));
                }
                Err(e) => {
                    self.status = format!("recv failed: {e}");
                    self.session.log(self.status.clone());
                }
            }
        }
    }

    fn listen(&mut self) {
        if self.hs.is_some() {
            self.status = format!(
                "already listening as {}",
                self.session.onion.as_deref().unwrap_or("?")
            );
            return;
        }
        let existing = self.session.onion_key.clone();
        match start_hidden_service_with_key(
            &self.socks_host,
            self.control_port,
            existing.as_deref(),
        ) {
            Ok((hs, privkey)) => {
                self.session.onion = Some(hs.onion.clone());
                if !privkey.is_empty() {
                    self.session.onion_key = Some(privkey);
                }
                let _ = self.session.save_disk();
                self.status = format!("onion {}  (local :{})", hs.onion, hs.local_port);
                self.session.log(self.status.clone());
                self.hs = Some(hs);
                self.retry_pending();
            }
            Err(e) => {
                self.status = format!(":listen failed: {e}");
                self.session.log(self.status.clone());
            }
        }
    }

    fn retry_pending(&mut self) {
        let waiting = self.session.take_pending();
        if waiting.is_empty() {
            return;
        }
        let mut fail = 0;
        for (onion, frame) in waiting {
            if socks5_send(&self.socks_host, self.socks_port, &onion, 80, &frame).is_err() {
                self.session.queue_outgoing(onion, frame);
                fail += 1;
            }
        }
        self.status = if fail == 0 {
            "queued messages delivered".into()
        } else {
            format!("{fail} still queued")
        };
    }
}

fn main() -> io::Result<()> {
    let _ = hashchat_rust::rust_mlockall_current();
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let result = run(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    loop {
        app.drain_incoming();
        terminal.draw(|f| draw(f, app))?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Char('q') if app.input.is_empty() => return Ok(()),
            KeyCode::Esc => return Ok(()),
            KeyCode::Char('?') if app.input.is_empty() => app.help = !app.help,
            KeyCode::Char('n') if app.input.is_empty() => {
                app.hs = None;
                app.session = Session::burner();
                app.status = format!("new burner {}", app.session.profile);
            }
            KeyCode::Char('w') if app.input.is_empty() => {
                app.hs = None;
                app.session.nuclear_wipe();
                app.status = "wiped".into();
            }
            KeyCode::Char('l') if app.input.is_empty() => app.listen(),
            KeyCode::Char('t') if app.input.is_empty() => {
                let st = probe(&app.socks_host, app.socks_port, app.control_port);
                app.status = st.note.clone();
                app.session.log(st.note);
            }
            KeyCode::Char('s') if app.input.is_empty() => match app.session.selftest() {
                Ok(m) => {
                    app.status = m.clone();
                    app.session.log(m);
                }
                Err(e) => app.status = format!("selftest failed: {e}"),
            },
            KeyCode::Tab if app.input.is_empty() => app.session.next_contact(),
            KeyCode::BackTab => app.session.prev_contact(),
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Enter => {
                if !handle_enter(app) {
                    return Ok(());
                }
            }
            KeyCode::Char(c) => app.input.push(c),
            _ => {}
        }
    }
}

fn handle_enter(app: &mut App) -> bool {
    let line = app.input.trim().to_string();
    app.input.clear();
    if line.is_empty() {
        return true;
    }
    if line == ":q" || line == ":quit" {
        return false;
    }
    if line == ":listen" {
        app.listen();
        return true;
    }
    if line == ":retry" {
        app.retry_pending();
        return true;
    }
    if line == ":status" {
        let tor = probe(&app.socks_host, app.socks_port, app.control_port);
        app.status = format!(
            "profile={} onion={} extreme={} {}",
            app.session.profile,
            app.session.onion.as_deref().unwrap_or("-"),
            app.session.extreme,
            tor.note
        );
        return true;
    }
    if line == ":my-contact" {
        let link = app.session.my_contact_link();
        if let Some(qr) = maybe_qr_text(&link) {
            app.session.log(qr);
        }
        app.status = link.clone();
        app.session.log(link);
        return true;
    }
    if let Some(rest) = line.strip_prefix(":add-contact ") {
        match app.session.add_contact_link(rest) {
            Ok(name) => app.status = format!("added {name}"),
            Err(e) => app.status = e.into(),
        }
        return true;
    }
    if line == ":extreme on" {
        app.session.extreme = true;
        hashchat_rust::rust_set_extreme_mode(true);
        app.status = "EXTREME on — send/add refused".into();
        return true;
    }
    if line == ":extreme off" {
        app.session.extreme = false;
        hashchat_rust::rust_set_extreme_mode(false);
        app.status = "EXTREME off".into();
        return true;
    }
    if let Some(rest) = line.strip_prefix(":set-proxy ") {
        let mut parts = rest.split_whitespace();
        if let (Some(h), Some(p)) = (parts.next(), parts.next()) {
            if let Ok(port) = p.parse() {
                app.socks_host = h.to_string();
                app.socks_port = port;
                app.status = format!("proxy {h}:{port}");
            }
        }
        return true;
    }
    match app.session.send_text(&line) {
        Ok(frame) => {
            let dest = app
                .session
                .current_contact()
                .map(|c| c.onion.clone())
                .unwrap_or_default();
            match socks5_send(&app.socks_host, app.socks_port, &dest, 80, &frame) {
                Ok(()) => {
                    app.status = format!("sent {} bytes → {dest}", frame.len());
                    app.retry_pending();
                }
                Err(e) => {
                    app.session.queue_outgoing(dest, frame);
                    app.status = format!("queued (offline): {e}");
                }
            }
        }
        Err(e) => app.status = e.into(),
    }
    true
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let gold = Style::default().fg(GOLD);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(f.area());

    let title = format!(
        " HashChat  {}  [{}] {} ",
        app.session.profile,
        if app.session.extreme { "EXTREME" } else { "RUST" },
        app.session.onion.as_deref().unwrap_or("no onion")
    );
    f.render_widget(
        Paragraph::new(app.status.as_str()).style(gold).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(gold),
        ),
        chunks[0],
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(chunks[1]);

    let items: Vec<ListItem> = if app.session.contacts.is_empty() {
        vec![ListItem::new(" (none — :add-contact)")]
    } else {
        app.session
            .contacts
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mark = if i == app.session.current { ">" } else { " " };
                ListItem::new(format!("{mark} {}", c.name))
            })
            .collect()
    };
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" contacts ")
                .border_style(gold),
        ),
        body[0],
    );

    if app.help {
        f.render_widget(
            Paragraph::new(help_text())
                .style(gold)
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" help ")
                        .border_style(gold),
                ),
            body[1],
        );
    } else {
        let name = app
            .session
            .current_contact()
            .map(|c| c.name.as_str())
            .unwrap_or("?");
        let msgs = app.session.messages.get(name).cloned().unwrap_or_default();
        let mut lines: Vec<Line> = msgs
            .iter()
            .map(|m| {
                let who = if m.from_me { "you" } else { name };
                Line::from(vec![
                    Span::styled(format!("{who}: "), gold.add_modifier(Modifier::BOLD)),
                    Span::raw(m.text.clone()),
                ])
            })
            .collect();
        for log in app.session.logs.iter().rev().take(8).rev() {
            lines.push(Line::from(Span::styled(
                format!("· {log}"),
                Style::default().fg(Color::DarkGray),
            )));
        }
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" chat · {name} "))
                    .border_style(gold),
            ),
            body[1],
        );
    }

    f.render_widget(
        Paragraph::new(app.input.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" :listen  :my-contact  :add-contact <link> ")
                .border_style(gold),
        ),
        chunks[2],
    );
    f.render_widget(
        Paragraph::new("q quit  ? help  l listen  n burner  w wipe  t tor  s selftest  Tab contact")
            .style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
}

fn help_text() -> String {
    [
        "Two devices (both need a local Tor with ControlPort 9051 + SOCKS 9050):",
        "",
        "  l / :listen              publish a v3 onion (reused if saved)",
        "  :my-contact              your hashchat:// link (qrencode if installed)",
        "  :add-contact <link>      paste the other person's link",
        "  :retry                   flush queued ciphertext if a peer was offline",
        "  type a message + Enter   encrypt + send over Tor SOCKS to their onion",
        "",
        "s  X25519 + ratchet selftest (no network)",
        "w  wipe keys + data",
        "",
        "Exchange links out of band. Private keys never leave this machine.",
        "First-message crypto is X25519 DH of long-term keys, then a symmetric ratchet.",
    ]
    .join("\n")
}
