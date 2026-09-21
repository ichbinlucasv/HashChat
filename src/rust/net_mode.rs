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
//! Runtime state is in-memory (plus env / TUI `:mode`). Session-blob persistence
//! is deferred until a deliberate prefs schema lands; do not imply durability.

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
        format!(
            "mode={} · {} · posture={}",
            self.mode,
            dns,
            self.posture.as_str()
        )
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
}

/// Fail-closed policy errors (professional strings; no secrets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetModeError {
    InvalidMode,
    InvalidDns,
    InvalidPosture,
    ExtremeTorOnly,
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
}
