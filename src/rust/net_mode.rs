//! Explicit network transport modes (fail-closed).
//!
//! **Default:** [`NetworkMode::Tor`]. Messenger send/listen is implemented only
//! for Tor. I2P and Clearnet are selectable as explicit preferences but return
//! a clear refusal — no silent fallback and no clearnet sockets for messenger
//! traffic.
//!
//! DNS preference ([`DnsPreference`]) is orthogonal to transport mode and does
//! not authorize clearnet messenger paths.
//!
//! Prefs persist inside the encrypted session blob (v3+) via
//! [`NetConfig::to_persist_bytes`] / [`NetConfig::from_persist_bytes`]. They are
//! non-secret policy but live in the wrap so a plaintext sibling file cannot
//! silently toggle them. Env (`HASHCHAT_*`) applies at cold start / new
//! identity; after unlock the loaded blob wins.

use std::fmt;

/// Transport network for messenger traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Tor v3 hidden services via local SOCKS / ControlPort (only implemented path).
    #[default]
    Tor,
    /// Reserved: I2P / garlic routing. Not implemented — refuse without sockets.
    I2p,
    /// Reserved: direct clearnet. Refused for messenger traffic (no silent use).
    Clearnet,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::Tor => "tor",
            NetworkMode::I2p => "i2p",
            NetworkMode::Clearnet => "clearnet",
        }
    }

    /// Parse a short token (`tor` / `i2p` / `clearnet`). Unknown → error.
    pub fn parse_token(s: &str) -> Result<Self, NetModeError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tor" | "onion" => Ok(NetworkMode::Tor),
            "i2p" | "garlic" => Ok(NetworkMode::I2p),
            "clearnet" | "clear" | "direct" => Ok(NetworkMode::Clearnet),
            other if other.is_empty() => Err(NetModeError::InvalidMode),
            _ => Err(NetModeError::InvalidMode),
        }
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DNS resolution preference (separate from transport mode).
///
/// Does **not** enable clearnet messenger sockets. Custom addresses are stored
/// for a future resolver path only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DnsPreference {
    #[default]
    System,
    /// Quad9 (9.9.9.9) — preference only until a DNS path is implemented.
    Quad9,
    /// User-supplied resolver address (see [`NetConfig::custom_dns`]).
    Custom,
}

impl DnsPreference {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsPreference::System => "system",
            DnsPreference::Quad9 => "quad9",
            DnsPreference::Custom => "custom",
        }
    }

    pub fn parse_token(s: &str) -> Result<Self, NetModeError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" | "os" | "default" => Ok(DnsPreference::System),
            "quad9" | "9.9.9.9" => Ok(DnsPreference::Quad9),
            "custom" => Ok(DnsPreference::Custom),
            _ => Err(NetModeError::InvalidDns),
        }
    }
}

impl fmt::Display for DnsPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Security posture that can lock transport choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PostureProfile {
    /// User may select unimplemented modes (they still refuse at the gate).
    #[default]
    Standard,
    /// Tor-only lock: mode changes away from Tor are refused.
    Extreme,
}

impl PostureProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            PostureProfile::Standard => "standard",
            PostureProfile::Extreme => "extreme",
        }
    }

    pub fn parse_token(s: &str) -> Result<Self, NetModeError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "standard" | "normal" | "default" => Ok(PostureProfile::Standard),
            "extreme" | "paranoid" => Ok(PostureProfile::Extreme),
            _ => Err(NetModeError::InvalidPosture),
        }
    }

    pub fn locks_tor_only(self) -> bool {
        matches!(self, PostureProfile::Extreme)
    }
}

/// In-memory network preferences for a process / TUI session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetConfig {
    pub mode: NetworkMode,
    pub dns: DnsPreference,
    /// Host or `host:port` for [`DnsPreference::Custom`] only. Never log secrets.
    pub custom_dns: Option<String>,
    pub posture: PostureProfile,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Tor,
            dns: DnsPreference::System,
            custom_dns: None,
            posture: PostureProfile::Standard,
        }
    }
}

impl NetConfig {
    /// Build from environment. Unknown tokens are ignored (stay at defaults).
    ///
    /// - `HASHCHAT_NET_MODE` = `tor` | `i2p` | `clearnet`
    /// - `HASHCHAT_DNS` = `system` | `quad9` | `custom`
    /// - `HASHCHAT_DNS_CUSTOM` = resolver address when DNS is custom
    /// - `HASHCHAT_POSTURE` = `standard` | `extreme` (or `HASHCHAT_EXTREME=1`)
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("HASHCHAT_NET_MODE") {
            if let Ok(m) = NetworkMode::parse_token(&v) {
                cfg.mode = m;
            }
        }
        if let Ok(v) = std::env::var("HASHCHAT_DNS") {
            if let Ok(d) = DnsPreference::parse_token(&v) {
                cfg.dns = d;
            }
        }
        if let Ok(v) = std::env::var("HASHCHAT_DNS_CUSTOM") {
            let t = v.trim();
            if !t.is_empty() {
                cfg.custom_dns = Some(t.to_string());
                if cfg.dns != DnsPreference::Custom {
                    // Explicit custom address implies Custom preference.
                    cfg.dns = DnsPreference::Custom;
                }
            }
        }
        if std::env::var_os("HASHCHAT_EXTREME").is_some() {
            cfg.posture = PostureProfile::Extreme;
        }
        if let Ok(v) = std::env::var("HASHCHAT_POSTURE") {
            if let Ok(p) = PostureProfile::parse_token(&v) {
                cfg.posture = p;
            }
        }
        // Extreme wins: force Tor regardless of env mode.
        if cfg.posture.locks_tor_only() {
            cfg.mode = NetworkMode::Tor;
        }
        cfg
    }

    /// Short status line suitable for TUI (no secrets).
    pub fn status_line(&self) -> String {
        let dns = match (self.dns, self.custom_dns.as_deref()) {
            (DnsPreference::Custom, Some(addr)) => format!("dns=custom({addr})"),
            (d, _) => format!("dns={d}"),
        };
        let base = format!(
            "mode={} · {} · posture={}",
            self.mode,
            dns,
            self.posture.as_str()
        );
        if self.is_extreme() {
            format!("{base} · locks=tor-only,no-contact-export,no-groups,no-voice")
        } else {
            base
        }
    }

    /// Select transport mode. Extreme posture refuses anything but Tor.
    pub fn set_mode(&mut self, mode: NetworkMode) -> Result<(), NetModeError> {
        if self.posture.locks_tor_only() && mode != NetworkMode::Tor {
            return Err(NetModeError::ExtremeTorOnly);
        }
        self.mode = mode;
        Ok(())
    }

    pub fn set_dns(
        &mut self,
        dns: DnsPreference,
        custom: Option<String>,
    ) -> Result<(), NetModeError> {
        if dns == DnsPreference::Custom {
            match custom {
                Some(addr) if !addr.trim().is_empty() => {
                    self.custom_dns = Some(addr.trim().to_string());
                }
                Some(_) | None => {
                    if self.custom_dns.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        return Err(NetModeError::CustomDnsRequired);
                    }
                }
            }
        } else {
            self.custom_dns = None;
        }
        self.dns = dns;
        Ok(())
    }

    pub fn set_posture(&mut self, posture: PostureProfile) {
        self.posture = posture;
        if posture.locks_tor_only() {
            self.mode = NetworkMode::Tor;
        }
    }

    /// Compact UTF-8 token encoding for session blob prefs (no serde).
    ///
    /// Layout: mode\0dns\0custom_dns\0posture as four length-prefixed strings
    /// (u32 BE length + UTF-8). Empty custom_dns means `None`.
    pub fn to_persist_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_persist_str(&mut out, self.mode.as_str());
        write_persist_str(&mut out, self.dns.as_str());
        write_persist_str(&mut out, self.custom_dns.as_deref().unwrap_or(""));
        write_persist_str(&mut out, self.posture.as_str());
        out
    }

    /// Decode prefs written by [`Self::to_persist_bytes`]. Unknown tokens fail.
    /// Extreme posture forces Tor after restore (same lock as live `set_posture`).
    pub fn from_persist_bytes(buf: &[u8]) -> Result<Self, NetModeError> {
        let mut pos = 0usize;
        let mode_s = read_persist_str(buf, &mut pos).map_err(|_| NetModeError::InvalidMode)?;
        let dns_s = read_persist_str(buf, &mut pos).map_err(|_| NetModeError::InvalidDns)?;
        let custom_s = read_persist_str(buf, &mut pos).map_err(|_| NetModeError::InvalidDns)?;
        let posture_s = read_persist_str(buf, &mut pos).map_err(|_| NetModeError::InvalidPosture)?;
        if pos != buf.len() {
            // Trailing junk → refuse (fail closed on corrupt prefs).
            return Err(NetModeError::InvalidMode);
        }
        let mode = NetworkMode::parse_token(&mode_s)?;
        let dns = DnsPreference::parse_token(&dns_s)?;
        let posture = PostureProfile::parse_token(&posture_s)?;
        let custom_dns = if custom_s.is_empty() {
            None
        } else {
            Some(custom_s)
        };
        if dns == DnsPreference::Custom && custom_dns.is_none() {
            return Err(NetModeError::CustomDnsRequired);
        }
        let mut cfg = Self {
            mode,
            dns,
            custom_dns,
            posture,
        };
        if cfg.posture.locks_tor_only() {
            cfg.mode = NetworkMode::Tor;
        }
        Ok(cfg)
    }

    /// Gate for messenger send/listen.
    ///
    /// Only Tor is implemented. Other modes return a clear refusal and must not
    /// open sockets for messenger traffic.
    pub fn require_messenger_transport(&self) -> Result<(), NetModeError> {
        match self.mode {
            NetworkMode::Tor => Ok(()),
            NetworkMode::I2p => Err(NetModeError::I2pNotImplemented),
            NetworkMode::Clearnet => Err(NetModeError::ClearnetRefused),
        }
    }

    /// True when Tor is the active (and only implemented) messenger path.
    pub fn is_tor(&self) -> bool {
        self.mode == NetworkMode::Tor
    }

    /// True when Extreme posture is active.
    pub fn is_extreme(&self) -> bool {
        self.posture == PostureProfile::Extreme
    }

    /// Extreme minimizes link sharing: refuse exporting signed contact URIs to
    /// scrollback / clipboard-style display. Local SAS comparison remains OK.
    pub fn extreme_blocks_contact_export(&self) -> bool {
        self.is_extreme()
    }

    /// Groups are out of Extreme threat budget (TUI has no group commands yet;
    /// helper is shared so future call sites stay consistent).
    pub fn extreme_blocks_groups(&self) -> bool {
        self.is_extreme()
    }

    /// Voice is out of Extreme threat budget (same shared-helper rationale).
    pub fn extreme_blocks_voice(&self) -> bool {
        self.is_extreme()
    }

    /// Short locked-feature note for `:status` / `:help` (no secrets).
    pub fn extreme_lock_summary(&self) -> Option<&'static str> {
        if !self.is_extreme() {
            return None;
        }
        Some(
            "Extreme active — locked: Tor-only; :my-contact export; groups; voice; :send-unverified; contacts/queue/block-mute/verify lists not durable across restart. SAS ok (short). Onion tails preferred. Not Android Extreme parity.",
        )
    }
}

fn write_persist_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn read_persist_str(buf: &[u8], pos: &mut usize) -> Result<String, ()> {
    if *pos + 4 > buf.len() {
        return Err(());
    }
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().map_err(|_| ())?) as usize;
    *pos += 4;
    if *pos + n > buf.len() {
        return Err(());
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + n]).map_err(|_| ())?.to_string();
    *pos += n;
    Ok(s)
}

/// Fail-closed policy errors (professional strings; no secrets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetModeError {
    InvalidMode,
    InvalidDns,
    InvalidPosture,
    ExtremeTorOnly,
    ExtremeContactExport,
    ExtremeGroups,
    ExtremeVoice,
    CustomDnsRequired,
    I2pNotImplemented,
    ClearnetRefused,
}

impl NetModeError {
    pub fn as_str(self) -> &'static str {
        match self {
            NetModeError::InvalidMode => "invalid network mode (use tor|i2p|clearnet)",
            NetModeError::InvalidDns => "invalid DNS preference (use system|quad9|custom)",
            NetModeError::InvalidPosture => "invalid posture (use standard|extreme)",
            NetModeError::ExtremeTorOnly => "extreme posture locks Tor-only",
            NetModeError::ExtremeContactExport => {
                "extreme posture refuses contact-link export (minimize link sharing)"
            }
            NetModeError::ExtremeGroups => "extreme posture refuses groups",
            NetModeError::ExtremeVoice => "extreme posture refuses voice",
            NetModeError::CustomDnsRequired => "custom DNS requires an address",
            NetModeError::I2pNotImplemented => {
                "I2P mode not implemented; messenger traffic refused"
            }
            NetModeError::ClearnetRefused => {
                "clearnet mode refused for messenger traffic (no silent fallback)"
            }
        }
    }
}

impl fmt::Display for NetModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for NetModeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_tor() {
        let cfg = NetConfig::default();
        assert_eq!(cfg.mode, NetworkMode::Tor);
        assert_eq!(cfg.dns, DnsPreference::System);
        assert_eq!(cfg.posture, PostureProfile::Standard);
        assert!(cfg.require_messenger_transport().is_ok());
        assert!(cfg.is_tor());
    }

    #[test]
    fn clearnet_refuses_messenger_without_sockets() {
        let mut cfg = NetConfig::default();
        cfg.set_mode(NetworkMode::Clearnet).unwrap();
        let err = cfg.require_messenger_transport().unwrap_err();
        assert_eq!(err, NetModeError::ClearnetRefused);
        assert!(err.as_str().contains("refused"));
        assert!(!err.as_str().to_ascii_lowercase().contains("fallback from"));
    }

    #[test]
    fn i2p_not_implemented_refuses() {
        let mut cfg = NetConfig::default();
        cfg.set_mode(NetworkMode::I2p).unwrap();
        let err = cfg.require_messenger_transport().unwrap_err();
        assert_eq!(err, NetModeError::I2pNotImplemented);
    }

    #[test]
    fn extreme_locks_tor_only() {
        let mut cfg = NetConfig::default();
        cfg.set_posture(PostureProfile::Extreme);
        assert_eq!(cfg.mode, NetworkMode::Tor);
        assert_eq!(
            cfg.set_mode(NetworkMode::Clearnet).unwrap_err(),
            NetModeError::ExtremeTorOnly
        );
        assert_eq!(
            cfg.set_mode(NetworkMode::I2p).unwrap_err(),
            NetModeError::ExtremeTorOnly
        );
        assert!(cfg.set_mode(NetworkMode::Tor).is_ok());
        assert!(cfg.require_messenger_transport().is_ok());
    }

    #[test]
    fn extreme_forces_tor_when_enabled_after_clearnet() {
        let mut cfg = NetConfig::default();
        cfg.set_mode(NetworkMode::Clearnet).unwrap();
        cfg.set_posture(PostureProfile::Extreme);
        assert_eq!(cfg.mode, NetworkMode::Tor);
        assert!(cfg.require_messenger_transport().is_ok());
    }

    #[test]
    fn parse_mode_tokens() {
        assert_eq!(NetworkMode::parse_token("TOR").unwrap(), NetworkMode::Tor);
        assert_eq!(NetworkMode::parse_token("i2p").unwrap(), NetworkMode::I2p);
        assert_eq!(
            NetworkMode::parse_token("clearnet").unwrap(),
            NetworkMode::Clearnet
        );
        assert!(NetworkMode::parse_token("wifi").is_err());
    }

    #[test]
    fn dns_preference_separate_from_mode() {
        let mut cfg = NetConfig::default();
        cfg.set_dns(DnsPreference::Quad9, None).unwrap();
        assert_eq!(cfg.mode, NetworkMode::Tor);
        assert_eq!(cfg.dns, DnsPreference::Quad9);
        // DNS preference alone must not open clearnet messenger traffic.
        assert!(cfg.require_messenger_transport().is_ok());
        cfg.set_mode(NetworkMode::Clearnet).unwrap();
        assert!(cfg.require_messenger_transport().is_err());
    }

    #[test]
    fn custom_dns_requires_address() {
        let mut cfg = NetConfig::default();
        assert_eq!(
            cfg.set_dns(DnsPreference::Custom, None).unwrap_err(),
            NetModeError::CustomDnsRequired
        );
        cfg.set_dns(DnsPreference::Custom, Some("9.9.9.9".into()))
            .unwrap();
        assert_eq!(cfg.custom_dns.as_deref(), Some("9.9.9.9"));
    }

    #[test]
    fn status_line_has_no_secret_markers() {
        let cfg = NetConfig::default();
        let line = cfg.status_line();
        assert!(line.contains("mode=tor"));
        assert!(!line.contains("cookie"));
        assert!(!line.contains("pass"));
    }

    #[test]
    fn persist_bytes_roundtrip_non_default() {
        let mut cfg = NetConfig::default();
        cfg.set_mode(NetworkMode::I2p).unwrap();
        cfg.set_dns(DnsPreference::Custom, Some("9.9.9.9:53".into()))
            .unwrap();
        cfg.set_posture(PostureProfile::Standard);
        let bytes = cfg.to_persist_bytes();
        let loaded = NetConfig::from_persist_bytes(&bytes).unwrap();
        assert_eq!(loaded, cfg);
        assert_eq!(loaded.mode, NetworkMode::I2p);
        assert_eq!(loaded.dns, DnsPreference::Custom);
        assert_eq!(loaded.custom_dns.as_deref(), Some("9.9.9.9:53"));
    }

    #[test]
    fn persist_extreme_locks_tor_after_restore() {
        let mut cfg = NetConfig::default();
        cfg.set_mode(NetworkMode::Clearnet).unwrap();
        cfg.set_posture(PostureProfile::Extreme);
        assert_eq!(cfg.mode, NetworkMode::Tor);
        let bytes = cfg.to_persist_bytes();
        let mut loaded = NetConfig::from_persist_bytes(&bytes).unwrap();
        assert_eq!(loaded.posture, PostureProfile::Extreme);
        assert_eq!(loaded.mode, NetworkMode::Tor);
        assert_eq!(
            loaded.set_mode(NetworkMode::Clearnet).unwrap_err(),
            NetModeError::ExtremeTorOnly
        );
        assert!(loaded.require_messenger_transport().is_ok());
    }

    #[test]
    fn persist_default_roundtrip() {
        let cfg = NetConfig::default();
        let loaded = NetConfig::from_persist_bytes(&cfg.to_persist_bytes()).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn extreme_blocks_contact_export_and_features() {
        let mut cfg = NetConfig::default();
        assert!(!cfg.extreme_blocks_contact_export());
        assert!(!cfg.extreme_blocks_groups());
        assert!(!cfg.extreme_blocks_voice());
        assert!(cfg.extreme_lock_summary().is_none());

        cfg.set_posture(PostureProfile::Extreme);
        assert!(cfg.is_extreme());
        assert!(cfg.extreme_blocks_contact_export());
        assert!(cfg.extreme_blocks_groups());
        assert!(cfg.extreme_blocks_voice());
        let summary = cfg.extreme_lock_summary().unwrap();
        assert!(summary.to_ascii_lowercase().contains("extreme"));
        assert!(summary.to_ascii_lowercase().contains("contact"));
        assert_eq!(
            NetModeError::ExtremeContactExport.as_str().contains("contact-link"),
            true
        );
        assert!(NetModeError::ExtremeGroups.as_str().contains("groups"));
        assert!(NetModeError::ExtremeVoice.as_str().contains("voice"));
    }

    #[test]
    fn extreme_status_line_lists_locks() {
        let mut cfg = NetConfig::default();
        cfg.set_posture(PostureProfile::Extreme);
        let line = cfg.status_line();
        assert!(line.contains("posture=extreme"));
        assert!(line.contains("no-contact-export"));
        assert!(line.contains("tor-only"));
        assert!(!line.contains("cookie"));
        assert!(!line.contains("pass"));
    }
}
