//! Make untrusted text safe to hand to a terminal UI widget.
//!
//! ratatui's `Paragraph` path writes grapheme symbols into the buffer verbatim,
//! and the crossterm backend prints them as-is. Any control character in a
//! rendered string therefore reaches the terminal, where ESC / CSI / OSC / DCS
//! sequences are interpreted. Peer message text, and anything else that did not
//! originate in this process, must pass through [`sanitize_for_terminal`] before
//! it is rendered.
//!
//! Policy (by character, no sequence parsing, so nothing can be smuggled past a
//! parser state machine):
//! - `\t`, `\n`, `\r` → a single space (layout stays on one line; lines are split
//!   by the caller, never by peer data).
//! - every other `char::is_control()` code point (C0, DEL, C1 incl. 8-bit CSI
//!   U+009B and OSC U+009D) → U+FFFD.
//! - bidirectional embedding / override / isolate / mark controls, the Arabic
//!   letter mark, and line / paragraph separators → U+FFFD, so peer text cannot
//!   visually reorder or break the surrounding UI line.
//! - interlinear annotation controls (U+FFF9..U+FFFB) → U+FFFD.
//!
//! Everything else, including ZWJ emoji sequences and combining marks, is kept.

use std::borrow::Cow;

const REPLACEMENT: char = '\u{FFFD}';

/// What to do with a single code point.
#[inline]
fn map_char(c: char) -> Option<char> {
    match c {
        '\t' | '\n' | '\r' => Some(' '),
        c if c.is_control() => Some(REPLACEMENT),
        // Bidi marks, embeddings/overrides, isolates, Arabic letter mark.
        '\u{200E}' | '\u{200F}' | '\u{061C}' => Some(REPLACEMENT),
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => Some(REPLACEMENT),
        // Line / paragraph separator.
        '\u{2028}' | '\u{2029}' => Some(REPLACEMENT),
        // Interlinear annotation anchors.
        '\u{FFF9}'..='\u{FFFB}' => Some(REPLACEMENT),
        _ => None,
    }
}

/// True if `s` contains nothing that [`sanitize_for_terminal`] would change.
pub fn is_terminal_safe(s: &str) -> bool {
    s.chars().all(|c| map_char(c).is_none())
}

/// Return `s` with terminal-unsafe code points replaced (see module docs).
/// Borrows when no change is needed.
pub fn sanitize_for_terminal(s: &str) -> Cow<'_, str> {
    if is_terminal_safe(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(map_char(c).unwrap_or(c));
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_unsafe_bytes(s: &str) -> bool {
        s.bytes().any(|b| b < 0x20 || b == 0x7f)
            || s.chars().any(|c| ('\u{80}'..='\u{9f}').contains(&c))
    }

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        for s in ["hello", "grüezi 👋", "👨‍👩‍👧 family", "e\u{301}", "中文", ""] {
            let out = sanitize_for_terminal(s);
            assert!(matches!(out, Cow::Borrowed(_)), "{s:?}");
            assert_eq!(out, s);
        }
    }

    #[test]
    fn c0_del_and_c1_are_replaced() {
        let samples = [
            "A\x1b]0;title\x07B",
            "C\x1b[2JD",
            "I\x07J",
            "K\u{9b}31mL",
            "M\u{9d}0;t\u{9c}N",
            "O\x7fP",
            "Q\x00R",
            "S\x1bPq\x1b\\T",
        ];
        for s in samples {
            let out = sanitize_for_terminal(s);
            assert!(!has_unsafe_bytes(&out), "{s:?} -> {out:?}");
            assert!(out.contains('\u{FFFD}'));
        }
    }

    #[test]
    fn every_control_codepoint_is_neutralised() {
        for cp in (0u32..0x20).chain(0x7f..0xa0) {
            let c = char::from_u32(cp).unwrap();
            let s = format!("x{c}y");
            let out = sanitize_for_terminal(&s);
            assert!(!has_unsafe_bytes(&out), "U+{cp:04X}");
            assert_eq!(out.chars().count(), 3, "U+{cp:04X} must map 1:1");
        }
    }

    #[test]
    fn whitespace_controls_become_space() {
        assert_eq!(sanitize_for_terminal("a\tb\nc\r\nd"), "a b c  d");
    }

    #[test]
    fn bidi_and_separators_replaced() {
        for c in [
            '\u{200E}', '\u{200F}', '\u{061C}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}',
            '\u{FFF9}', '\u{FFFA}', '\u{FFFB}',
        ] {
            let s = format!("[a]{c}[b]");
            assert_eq!(sanitize_for_terminal(&s), "[a]\u{FFFD}[b]", "U+{:04X}", c as u32);
            assert!(!is_terminal_safe(&s));
        }
    }

    #[test]
    fn idempotent() {
        let s = "x\x1b[31my\u{202E}z\u{9b}";
        let once = sanitize_for_terminal(s).into_owned();
        assert_eq!(sanitize_for_terminal(&once), once.as_str());
        assert!(is_terminal_safe(&once));
    }

    /// Render through ratatui's `Paragraph` into a buffer and check that no cell
    /// carries a control character (the widget does not filter them itself).
    #[cfg(feature = "tui")]
    #[test]
    fn paragraph_cells_are_clean_after_sanitize() {
        use ratatui::backend::TestBackend;
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Paragraph, Wrap};
        use ratatui::Terminal;

        let hostile = "hi\x1b]0;x\x07 there\x1b[2J \u{9b}1m end\u{202E}";
        let cells_with_controls = |text: &str| -> bool {
            let mut term = Terminal::new(TestBackend::new(60, 3)).unwrap();
            term.draw(|f| {
                let p = Paragraph::new(Line::from(Span::raw(text.to_string())))
                    .wrap(Wrap { trim: false });
                f.render_widget(p, f.area());
            })
            .unwrap();
            let buf = term.backend().buffer().clone();
            buf.content()
                .iter()
                .any(|cell| cell.symbol().chars().any(|c| c.is_control()))
        };
        // Confirms the widget passes control chars through when unsanitised...
        assert!(cells_with_controls(hostile));
        // ...and that the sanitised form yields clean cells.
        assert!(!cells_with_controls(&sanitize_for_terminal(hostile)));
    }
}
