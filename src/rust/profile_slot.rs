//! Android profile screen: primary or decoy, plus the Extreme build flag.
//!
//! The Kotlin shell used to keep this as two fields (`EXTREME_MODE`,
//! `isDecoyActive`). The decision now lives here so the shell only draws
//! the label and asks before toggling.
//!
//! This is a memory-only screen flag. It does not create an onion, a ratchet
//! or a passphrase, it is not written to disk, and a process restart comes
//! back to the primary screen. It is not the desktop duress decoy, which
//! wipes the profile and opens an empty one under the duress passphrase.
//!
//! While the decoy screen is up, the shell parks the transcript
//! ([`crate::message_book::MessageBook::park`]). Lines typed on that screen
//! are dropped on the way back. They are not a hidden volume.

/// Which screen the shell is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileScreen {
    #[default]
    Primary,
    Decoy,
}

/// Why a switch onto the decoy screen was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyRefusal {
    /// Extreme builds have no decoy screen.
    Extreme,
    /// Posture refused the decoy action. Leaving the screen is not refused
    /// for this reason.
    Strict,
}

impl DecoyRefusal {
    /// JNI status code. `0` and `1` are successful toggle results, not refusals.
    pub fn code(self) -> i32 {
        match self {
            Self::Extreme => -1,
            Self::Strict => -2,
        }
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -1 => Some(Self::Extreme),
            -2 => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Extreme => {
                "EXTREME MODE: Decoy profiles are disabled for minimal attack surface."
            }
            Self::Strict => {
                "STRICT MODE: Decoy profile toggle REFUSED (bad environment - plausible deniability requires clean device)"
            }
        }
    }
}

/// Surfaces an Extreme build turns off. Messaging stays available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatedSurface {
    Voice,
    Groups,
    Export,
    Decoy,
}

impl GatedSurface {
    /// Shell feature name. Unknown names are `None` (not blocked here).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "voice" => Some(Self::Voice),
            "groups" | "group" => Some(Self::Groups),
            "export" => Some(Self::Export),
            "decoy" => Some(Self::Decoy),
            _ => None,
        }
    }
}

/// In-memory profile screen for one Android process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSlot {
    extreme: bool,
    screen: ProfileScreen,
}

impl Default for ProfileSlot {
    fn default() -> Self {
        Self::primary()
    }
}

impl ProfileSlot {
    pub const fn primary() -> Self {
        Self {
            extreme: false,
            screen: ProfileScreen::Primary,
        }
    }

    /// Record the build flag. Turning Extreme on leaves the decoy screen,
    /// because that screen does not exist in an Extreme build.
    ///
    /// Returns true when a decoy screen was showing and is now primary, so
    /// the shell can unpark the transcript. Does not touch the transcript
    /// itself. Call this once at startup, before the transcript is loaded.
    pub fn set_extreme(&mut self, on: bool) -> bool {
        self.extreme = on;
        if on && self.is_decoy() {
            self.screen = ProfileScreen::Primary;
            true
        } else {
            false
        }
    }

    pub fn extreme(&self) -> bool {
        self.extreme
    }

    pub fn is_decoy(&self) -> bool {
        matches!(self.screen, ProfileScreen::Decoy)
    }

    /// Top-bar name. Primary stays "Default", matching the existing shell.
    pub fn label(&self) -> &'static str {
        match self.screen {
            ProfileScreen::Primary => "Default",
            ProfileScreen::Decoy => "Decoy",
        }
    }

    /// Posture line for the decoy screen. Empty on the primary screen, so
    /// the shell keeps the device-posture label.
    pub fn posture_line(&self) -> &'static str {
        match self.screen {
            ProfileScreen::Primary => "",
            ProfileScreen::Decoy => "DECOY - local screen only (not a separate identity)",
        }
    }

    /// Toast after a successful toggle.
    pub fn notice(&self) -> &'static str {
        match self.screen {
            ProfileScreen::Primary => "Primary screen restored. The decoy screen was not saved.",
            ProfileScreen::Decoy => {
                "Decoy screen only: same identity, chat hidden until you switch back. This is not a separate profile."
            }
        }
    }

    /// Extreme turns the named surface off. Unknown names are not blocked.
    pub fn blocks(&self, feature: &str) -> bool {
        self.extreme && GatedSurface::parse(feature).is_some()
    }

    /// Switch screens. `strict_refuses` is the shell's posture answer for
    /// the decoy action: it blocks entry only. Leaving is allowed so a
    /// posture change cannot trap the user on the decoy screen.
    ///
    /// `Ok(true)` means the decoy screen is now showing.
    pub fn toggle_decoy(&mut self, strict_refuses: bool) -> Result<bool, DecoyRefusal> {
        if self.extreme {
            return Err(DecoyRefusal::Extreme);
        }
        match self.screen {
            ProfileScreen::Decoy => {
                self.screen = ProfileScreen::Primary;
                Ok(false)
            }
            ProfileScreen::Primary => {
                if strict_refuses {
                    return Err(DecoyRefusal::Strict);
                }
                self.screen = ProfileScreen::Decoy;
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_toggles_and_comes_back() {
        let mut p = ProfileSlot::primary();
        assert_eq!(p.label(), "Default");
        assert_eq!(p.posture_line(), "");
        assert!(!p.extreme());
        assert_eq!(p.toggle_decoy(false), Ok(true));
        assert!(p.is_decoy());
        assert_eq!(p.label(), "Decoy");
        assert!(p.posture_line().contains("not a separate identity"));
        assert!(p.notice().contains("not a separate profile"));
        assert_eq!(p.toggle_decoy(false), Ok(false));
        assert!(!p.is_decoy());
        assert!(p.notice().contains("not saved"));
    }

    #[test]
    fn extreme_and_strict_refuse_entry_only() {
        let mut p = ProfileSlot::primary();
        assert_eq!(p.toggle_decoy(true), Err(DecoyRefusal::Strict));
        assert!(!p.is_decoy());
        p.toggle_decoy(false).unwrap();
        // A later strict posture still lets the user leave.
        assert_eq!(p.toggle_decoy(true), Ok(false));
        assert!(!p.is_decoy());

        p.set_extreme(true);
        assert!(p.extreme());
        assert_eq!(p.toggle_decoy(false), Err(DecoyRefusal::Extreme));
        assert_eq!(p.label(), "Default");
        assert!(p.blocks("voice"));
        assert!(p.blocks(" groups "));
        assert!(p.blocks("export"));
        assert!(p.blocks("decoy"));
        assert!(!p.blocks("send"));
        assert!(!p.blocks(""));
    }

    #[test]
    fn extreme_drops_a_decoy_screen() {
        let mut p = ProfileSlot::primary();
        p.toggle_decoy(false).unwrap();
        assert!(p.set_extreme(true));
        assert!(!p.is_decoy());
        assert!(!p.set_extreme(true));
        assert!(!ProfileSlot::primary().set_extreme(false));
    }

    #[test]
    fn refusal_codes_round_trip() {
        for r in [DecoyRefusal::Extreme, DecoyRefusal::Strict] {
            assert_eq!(DecoyRefusal::from_code(r.code()), Some(r));
            assert!(!r.label().is_empty());
        }
        assert_eq!(DecoyRefusal::from_code(0), None);
        assert_eq!(DecoyRefusal::from_code(1), None);
    }
}
