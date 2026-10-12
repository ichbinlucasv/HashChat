//! Device posture policy, shared by desktop and Android.
//!
//! First step of the "Android: maximum Rust" migration: the Kotlin shell only
//! collects raw signals (Build fields, debugger flag, airplane mode, file
//! probes) and hands them over; every decision about what they mean lives
//! here, in one tested place. The policy is fail-closed: any bad signal makes
//! the posture `Low`, and risky actions are refused unless the posture is
//! `High`.

/// Raw environment signals collected by the platform shell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceSignals {
    pub debugger_attached: bool,
    pub app_debuggable: bool,
    pub airplane_mode: bool,
    pub build_fingerprint: String,
    pub build_model: String,
    pub build_manufacturer: String,
    pub build_hardware: String,
    pub build_tags: String,
    pub build_type: String,
    pub prop_ro_debuggable: String,
    pub prop_ro_secure: String,
    pub prop_ro_kernel_qemu: String,
    /// Paths of root indicators (su binaries, Superuser apps) that exist.
    pub root_paths_present: Vec<String>,
}

/// Overall posture, ordered from worst to best.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Posture {
    Low,
    Degraded,
    High,
}

/// Why the posture is not `High`, most serious first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureReason {
    Debugger,
    Rooted,
    Emulator,
    DebugBuild,
    InsecureProps,
    AirplaneMode,
}

impl PostureReason {
    pub fn label(self) -> &'static str {
        match self {
            PostureReason::Debugger => "Debugger attached",
            PostureReason::Rooted => "Root indicators present",
            PostureReason::Emulator => "Emulator or test environment",
            PostureReason::DebugBuild => "Debug, userdebug or test-keys build",
            PostureReason::InsecureProps => "Insecure system properties",
            PostureReason::AirplaneMode => "Airplane mode (network isolation)",
        }
    }
}

/// Actions that the shell must gate on posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskyAction {
    Voice,
    Groups,
    Export,
    Decoy,
    Send,
}

impl RiskyAction {
    /// Parse the action name used by the shell. Unknown names are `None`,
    /// and callers must treat `None` as refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "voice" => Some(Self::Voice),
            "groups" | "group" => Some(Self::Groups),
            "export" => Some(Self::Export),
            "decoy" => Some(Self::Decoy),
            "send" => Some(Self::Send),
            _ => None,
        }
    }
}

fn has(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase().contains(needle)
}

/// All reasons found in the signals, most serious first.
pub fn posture_reasons(s: &DeviceSignals) -> Vec<PostureReason> {
    let mut r = Vec::new();
    if s.debugger_attached {
        r.push(PostureReason::Debugger);
    }
    if !s.root_paths_present.is_empty() {
        r.push(PostureReason::Rooted);
    }
    let emulator = has(&s.build_fingerprint, "generic")
        || has(&s.build_model, "emulator")
        || has(&s.build_manufacturer, "genymotion")
        || has(&s.build_hardware, "goldfish")
        || has(&s.build_hardware, "ranchu")
        || s.prop_ro_kernel_qemu.trim() == "1";
    if emulator {
        r.push(PostureReason::Emulator);
    }
    let bt = s.build_type.trim().to_ascii_lowercase();
    if s.app_debuggable || has(&s.build_tags, "test-keys") || bt == "userdebug" || bt == "eng" {
        r.push(PostureReason::DebugBuild);
    }
    if s.prop_ro_debuggable.trim() == "1" || s.prop_ro_secure.trim() == "0" {
        r.push(PostureReason::InsecureProps);
    }
    if s.airplane_mode {
        r.push(PostureReason::AirplaneMode);
    }
    r
}

/// Posture from signals. Airplane mode alone is `Degraded`; anything else is `Low`.
pub fn evaluate_posture(s: &DeviceSignals) -> Posture {
    let reasons = posture_reasons(s);
    if reasons.is_empty() {
        Posture::High
    } else if reasons.iter().all(|r| *r == PostureReason::AirplaneMode) {
        Posture::Degraded
    } else {
        Posture::Low
    }
}

/// One-line label for the top bar, e.g. "LOW - Debugger attached".
pub fn posture_label(s: &DeviceSignals) -> String {
    let reasons = posture_reasons(s);
    match (evaluate_posture(s), reasons.first()) {
        (Posture::High, _) | (_, None) => "HIGH".to_string(),
        (Posture::Degraded, Some(r)) => format!("DEGRADED - {}", r.label()),
        (Posture::Low, Some(r)) => format!("LOW - {}", r.label()),
    }
}

/// Fail-closed gate: an action runs only at `High` posture and only if the
/// shell named a known action.
pub fn action_allowed(posture: Posture, action: &str) -> bool {
    RiskyAction::parse(action).is_some() && posture == Posture::High
}

#[cfg(test)]
mod tests {
    use super::*;

    type Mutation = Box<dyn Fn(&mut DeviceSignals)>;

    fn clean() -> DeviceSignals {
        DeviceSignals {
            build_fingerprint: "google/husky/husky:15/AP4A/123:user/release-keys".into(),
            build_model: "Pixel 8 Pro".into(),
            build_manufacturer: "Google".into(),
            build_hardware: "husky".into(),
            build_tags: "release-keys".into(),
            build_type: "user".into(),
            prop_ro_debuggable: "0".into(),
            prop_ro_secure: "1".into(),
            prop_ro_kernel_qemu: "".into(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_device_is_high_and_allows_known_actions() {
        let s = clean();
        assert_eq!(evaluate_posture(&s), Posture::High);
        assert_eq!(posture_label(&s), "HIGH");
        assert!(action_allowed(Posture::High, "voice"));
        assert!(action_allowed(Posture::High, " Export "));
    }

    #[test]
    fn unknown_action_is_refused_even_at_high() {
        assert!(!action_allowed(Posture::High, "teleport"));
        assert!(!action_allowed(Posture::High, ""));
    }

    #[test]
    fn each_bad_signal_makes_posture_low() {
        let cases: Vec<Mutation> = vec![
            Box::new(|s| s.debugger_attached = true),
            Box::new(|s| s.root_paths_present = vec!["/system/xbin/su".into()]),
            Box::new(|s| s.build_hardware = "ranchu".into()),
            Box::new(|s| s.build_fingerprint = "generic/sdk".into()),
            Box::new(|s| s.prop_ro_kernel_qemu = "1".into()),
            Box::new(|s| s.build_tags = "test-keys".into()),
            Box::new(|s| s.build_type = "userdebug".into()),
            Box::new(|s| s.app_debuggable = true),
            Box::new(|s| s.prop_ro_secure = "0".into()),
            Box::new(|s| s.prop_ro_debuggable = "1".into()),
        ];
        for f in cases {
            let mut s = clean();
            f(&mut s);
            assert_eq!(evaluate_posture(&s), Posture::Low, "{s:?}");
            assert!(posture_label(&s).starts_with("LOW - "));
            assert!(!action_allowed(evaluate_posture(&s), "send"));
        }
    }

    #[test]
    fn airplane_alone_is_degraded_and_still_refuses() {
        let mut s = clean();
        s.airplane_mode = true;
        assert_eq!(evaluate_posture(&s), Posture::Degraded);
        assert_eq!(posture_label(&s), "DEGRADED - Airplane mode (network isolation)");
        assert!(!action_allowed(Posture::Degraded, "voice"));
    }

    #[test]
    fn most_serious_reason_leads_the_label() {
        let mut s = clean();
        s.airplane_mode = true;
        s.build_type = "eng".into();
        s.debugger_attached = true;
        assert_eq!(posture_label(&s), "LOW - Debugger attached");
    }

    #[test]
    fn product_names_containing_eng_are_not_eng_builds() {
        let mut s = clean();
        s.build_type = "user".into();
        s.build_model = "Engage X".into();
        assert_eq!(evaluate_posture(&s), Posture::High);
    }
}
