//! HashChat desktop TUI — Rust (ratatui). Replaces the Haskell Brick UI.
//!
//! Keys: Enter send · Tab contact · n burner · w wipe · t Tor · s selftest
//!       :status :my-contact :extreme · q quit · ? help

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hashchat_rust::session::Session;
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
    input: String,
    help: bool,
    status: String,
    socks_host: String,
    socks_port: u16,
}

impl App {
    fn new() -> Self {
        let mut session = Session::burner();
        let tor = probe("127.0.0.1", 9050, 9051);
        session.log(tor.note.clone());
        App {
            session,
            input: String::new(),
            help: false,
            status: tor.note,
            socks_host: "127.0.0.1".into(),
            socks_port: 9050,
        }
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
                app.session = Session::burner();
                app.status = format!("new burner {}", app.session.profile);
            }
            KeyCode::Char('w') if app.input.is_empty() => {
                app.session.nuclear_wipe();
                app.status = "wiped".into();
            }
            KeyCode::Char('t') if app.input.is_empty() => {
                let st = probe(&app.socks_host, app.socks_port, 9051);
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
    if line == ":status" {
        let tor = probe(&app.socks_host, app.socks_port, 9051);
        app.status = format!(
            "profile={} extreme={} tor={}",
            app.session.profile, app.session.extreme, tor.note
        );
        return true;
    }
    if line == ":my-contact" {
        app.status = app.session.my_contact_link();
        app.session.log(app.status.clone());
        return true;
    }
    if line == ":extreme on" {
        app.session.extreme = true;
        hashchat_rust::rust_set_extreme_mode(true);
        app.status = "EXTREME on — send refused".into();
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
            if dest.ends_with(".onion") && dest != "alice.onion" && dest != "bob.onion" {
                match socks5_send(&app.socks_host, app.socks_port, &dest, 80, &frame) {
                    Ok(()) => app.status = format!("sent {} bytes over Tor SOCKS", frame.len()),
                    Err(e) => app.status = format!("encrypted locally; Tor send failed: {e}"),
                }
            } else {
                app.status = format!("encrypted {} bytes (set a real .onion to send via Tor)", frame.len());
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
        " HashChat  {}  [{}] ",
        app.session.profile,
        if app.session.extreme { "EXTREME" } else { "RUST" }
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

    let items: Vec<ListItem> = app
        .session
        .contacts
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mark = if i == app.session.current { ">" } else { " " };
            ListItem::new(format!("{mark} {}", c.name))
        })
        .collect();
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
        for log in app.session.logs.iter().rev().take(6).rev() {
            lines.push(Line::from(Span::styled(format!("· {log}"), Style::default().fg(Color::DarkGray))));
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
                .title(" message  (:status :my-contact :extreme on/off) ")
                .border_style(gold),
        ),
        chunks[2],
    );
    f.render_widget(
        Paragraph::new("q quit  ? help  n burner  w wipe  t tor  s e2ee-selftest  Tab contact")
            .style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
}

fn help_text() -> String {
    [
        "HashChat Rust TUI — the whole desktop stack is this crate.",
        "",
        "n          new burner profile (new long-term keys)",
        "w          nuclear wipe (zeroize ratchets, delete hashchat_data)",
        "s          two-ratchet E2EE selftest (proves GCM+frame+DH)",
        "t          probe Tor SOCKS 9050 + control 9051",
        "Enter      encrypt to current contact; send via Tor if onion is real",
        ":my-contact   show shareable public link (no private material)",
        ":extreme on   refuse sends",
        "",
        "Android UI stays Kotlin (platform shell). Crypto is this same crate.",
    ]
    .join("\n")
}
