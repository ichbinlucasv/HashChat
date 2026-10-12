//! Tor bridges: check the bridge lines a user pastes, print the torrc lines
//! to add, and confirm through the ControlPort that Tor really uses them.
//!
//! HashChat talks to the system Tor and does not rewrite its configuration:
//! starting a pluggable-transport binary is Tor's job, and a messenger that
//! can make Tor execute programs is a bigger risk than a few torrc lines.
//! Bridge lines are not stored in the HashChat profile either; torrc stays
//! the one place that holds them.
//!
//! "Took effect" means all of these hold, as reported by Tor itself:
//! `UseBridges` is on, at least one `Bridge` line is set, every transport
//! named by those lines has a `ClientTransportPlugin`, bootstrap reached
//! 100 %, and the first hop of every built circuit is one of the bridges.
//! The last check only works when the bridge lines carry fingerprints; it is
//! reported as unchecked otherwise.

use std::collections::BTreeSet;
use std::fmt;

/// Longest bridge line accepted (snowflake lines with fronts and ICE servers
/// run to a few hundred bytes).
pub const MAX_BRIDGE_LINE: usize = 1024;

/// Pluggable transports HashChat knows how to describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BridgeTransport {
    /// Plain bridge relay, no pluggable transport.
    Vanilla,
    Obfs4,
    Snowflake,
    Webtunnel,
}

impl BridgeTransport {
    fn from_token(t: &str) -> Option<Self> {
        match t {
            "obfs4" => Some(Self::Obfs4),
            "snowflake" => Some(Self::Snowflake),
            "webtunnel" => Some(Self::Webtunnel),
            _ => None,
        }
    }

    /// Name as it appears in torrc, `None` for a plain bridge.
    pub fn torrc_name(self) -> Option<&'static str> {
        match self {
            Self::Vanilla => None,
            Self::Obfs4 => Some("obfs4"),
            Self::Snowflake => Some("snowflake"),
            Self::Webtunnel => Some("webtunnel"),
        }
    }

    /// Usual client binary; the path differs between distributions.
    fn plugin_hint(self) -> Option<&'static str> {
        match self {
            Self::Vanilla => None,
            Self::Obfs4 => Some("ClientTransportPlugin obfs4 exec /usr/bin/lyrebird"),
            Self::Snowflake => {
                Some("ClientTransportPlugin snowflake exec /usr/bin/snowflake-client")
            }
            Self::Webtunnel => Some("ClientTransportPlugin webtunnel exec /usr/bin/lyrebird"),
        }
    }
}

/// Why a pasted bridge line was refused. Messages never echo the line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    Empty,
    TooLong,
    /// Control characters, quotes, backslashes or non-ASCII bytes.
    BadCharacters,
    UnsupportedTransport,
    BadAddress,
    BadFingerprint,
    MissingFingerprint,
    BadArgument,
    MissingArgument(&'static str),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty bridge line"),
            Self::TooLong => write!(f, "bridge line longer than {MAX_BRIDGE_LINE} bytes"),
            Self::BadCharacters => write!(f, "bridge line has characters Tor would not accept"),
            Self::UnsupportedTransport => {
                write!(
                    f,
                    "unsupported transport (use obfs4, snowflake, webtunnel or a plain bridge)"
                )
            }
            Self::BadAddress => write!(f, "bad address (want IPv4:port or [IPv6]:port)"),
            Self::BadFingerprint => write!(f, "bad fingerprint (want 40 hex digits)"),
            Self::MissingFingerprint => write!(f, "obfs4 bridge lines need a fingerprint"),
            Self::BadArgument => write!(f, "bad key=value argument"),
            Self::MissingArgument(k) => write!(f, "missing {k}= argument"),
        }
    }
}

/// One validated bridge line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeLine {
    pub transport: BridgeTransport,
    address: String,
    /// Upper-case hex identity fingerprint.
    fingerprint: Option<String>,
    args: Vec<(String, String)>,
}

impl BridgeLine {
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// The line as torrc wants it, starting with `Bridge `.
    pub fn torrc_line(&self) -> String {
        let mut out = String::from("Bridge");
        if let Some(name) = self.transport.torrc_name() {
            out.push(' ');
            out.push_str(name);
        }
        out.push(' ');
        out.push_str(&self.address);
        if let Some(fp) = &self.fingerprint {
            out.push(' ');
            out.push_str(fp);
        }
        for (k, v) in &self.args {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out
    }
}

fn is_safe_char(b: u8) -> bool {
    ((0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\') || b == b' ' || b == b'\t'
}

fn valid_port(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 5
        && p.bytes().all(|b| b.is_ascii_digit())
        && matches!(p.parse::<u32>(), Ok(1..=65535))
}

fn valid_address(a: &str) -> bool {
    if let Some(rest) = a.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return false;
        };
        return host.parse::<std::net::Ipv6Addr>().is_ok() && valid_port(port);
    }
    let Some((host, port)) = a.rsplit_once(':') else {
        return false;
    };
    host.parse::<std::net::Ipv4Addr>().is_ok() && valid_port(port)
}

fn is_fingerprint_token(t: &str) -> bool {
    t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_arg_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 32
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Parse and check a bridge line as copied from torrc, Tor Browser or the
/// bridge distribution page. A leading `Bridge ` is optional.
pub fn parse_bridge_line(input: &str) -> Result<BridgeLine, BridgeError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(BridgeError::Empty);
    }
    if s.len() > MAX_BRIDGE_LINE {
        return Err(BridgeError::TooLong);
    }
    if !s.bytes().all(is_safe_char) {
        return Err(BridgeError::BadCharacters);
    }
    let mut toks = s.split_ascii_whitespace().peekable();
    if toks
        .peek()
        .is_some_and(|t| t.eq_ignore_ascii_case("bridge"))
    {
        toks.next();
    }
    let first = toks.next().ok_or(BridgeError::Empty)?;
    let (transport, address) = if first.contains(':') {
        (BridgeTransport::Vanilla, first)
    } else {
        let t = BridgeTransport::from_token(first).ok_or(BridgeError::UnsupportedTransport)?;
        (t, toks.next().ok_or(BridgeError::BadAddress)?)
    };
    if !valid_address(address) {
        return Err(BridgeError::BadAddress);
    }
    let mut fingerprint = None;
    let mut args = Vec::new();
    for (i, tok) in toks.enumerate() {
        if i == 0 && !tok.contains('=') {
            if !is_fingerprint_token(tok) {
                return Err(BridgeError::BadFingerprint);
            }
            fingerprint = Some(tok.to_ascii_uppercase());
            continue;
        }
        let (k, v) = tok.split_once('=').ok_or(BridgeError::BadArgument)?;
        if !valid_arg_key(k) || v.is_empty() {
            return Err(BridgeError::BadArgument);
        }
        args.push((k.to_string(), v.to_string()));
    }
    let has = |key: &str| args.iter().any(|(k, _)| k == key);
    match transport {
        BridgeTransport::Obfs4 => {
            if fingerprint.is_none() {
                return Err(BridgeError::MissingFingerprint);
            }
            if !has("cert") {
                return Err(BridgeError::MissingArgument("cert"));
            }
            match args.iter().find(|(k, _)| k == "iat-mode") {
                Some((_, v)) if matches!(v.as_str(), "0" | "1" | "2") => {}
                Some(_) => return Err(BridgeError::BadArgument),
                None => return Err(BridgeError::MissingArgument("iat-mode")),
            }
        }
        BridgeTransport::Webtunnel => match args.iter().find(|(k, _)| k == "url") {
            Some((_, v)) if v.starts_with("https://") && v.len() > 8 => {}
            Some(_) => return Err(BridgeError::BadArgument),
            None => return Err(BridgeError::MissingArgument("url")),
        },
        BridgeTransport::Snowflake | BridgeTransport::Vanilla => {}
    }
    Ok(BridgeLine {
        transport,
        address: address.to_string(),
        fingerprint,
        args,
    })
}

/// torrc lines to add for these bridges: `UseBridges 1`, one
/// `ClientTransportPlugin` hint per transport (paths vary), then the bridges.
pub fn torrc_snippet(lines: &[BridgeLine]) -> Vec<String> {
    let mut out = vec!["UseBridges 1".to_string()];
    let transports: BTreeSet<BridgeTransport> = lines.iter().map(|l| l.transport).collect();
    for t in transports {
        if let Some(hint) = t.plugin_hint() {
            out.push(format!("{hint}   # path depends on your system"));
        }
    }
    out.extend(lines.iter().map(BridgeLine::torrc_line));
    out
}

/// What Tor reports about bridges. Holds counts and transport names only, no
/// bridge addresses or fingerprints, so it is safe to show and to keep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeStatus {
    pub use_bridges: bool,
    pub bridge_count: usize,
    /// Bridge lines in Tor's config that this parser refused.
    pub unparsed_bridges: usize,
    pub transports: Vec<&'static str>,
    pub missing_plugins: Vec<&'static str>,
    pub bootstrap_percent: Option<u8>,
    pub circuits_checked: usize,
    pub circuits_off_bridge: usize,
    /// True when some bridge has no fingerprint, so first hops can't be matched.
    pub first_hop_uncheckable: bool,
}

/// One-line outcome of a [`BridgeStatus`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeVerdict {
    /// `UseBridges` is off: Tor connects to public guards directly.
    Off,
    /// Bridges are asked for but Tor cannot use them as configured.
    Misconfigured(String),
    /// Configured correctly, Tor has not finished bootstrapping yet.
    NotReady(u8),
    /// A built circuit starts at a relay that is not one of the bridges.
    OffBridge(usize),
    /// Everything Tor reports is consistent with bridges in use.
    Active,
}

impl BridgeStatus {
    pub fn verdict(&self) -> BridgeVerdict {
        if !self.use_bridges {
            return BridgeVerdict::Off;
        }
        if self.bridge_count == 0 {
            return BridgeVerdict::Misconfigured(
                "UseBridges is on but no usable Bridge line".into(),
            );
        }
        if !self.missing_plugins.is_empty() {
            return BridgeVerdict::Misconfigured(format!(
                "no ClientTransportPlugin for {}",
                self.missing_plugins.join(", ")
            ));
        }
        match self.bootstrap_percent {
            Some(100) => {}
            Some(p) => return BridgeVerdict::NotReady(p),
            None => return BridgeVerdict::NotReady(0),
        }
        if self.circuits_off_bridge > 0 {
            return BridgeVerdict::OffBridge(self.circuits_off_bridge);
        }
        BridgeVerdict::Active
    }

    /// Human summary for the transcript.
    pub fn summary_line(&self) -> String {
        let circuits = if self.first_hop_uncheckable {
            "first hops unchecked (a bridge line has no fingerprint)".to_string()
        } else if self.circuits_checked == 0 {
            "no built circuits to check yet".to_string()
        } else {
            format!(
                "all {} built circuits start at a bridge",
                self.circuits_checked
            )
        };
        match self.verdict() {
            BridgeVerdict::Off => "bridges=off (Tor uses public guards; see :bridges help)".into(),
            BridgeVerdict::Misconfigured(why) => format!("bridges=broken ({why})"),
            BridgeVerdict::NotReady(p) => format!(
                "bridges=configured, Tor bootstrap at {p}% ({} bridge lines)",
                self.bridge_count
            ),
            BridgeVerdict::OffBridge(n) => {
                format!("bridges=NOT IN EFFECT: {n} built circuits start outside the bridge list")
            }
            BridgeVerdict::Active => format!(
                "bridges=active ({} lines, {}; {circuits})",
                self.bridge_count,
                if self.transports.is_empty() {
                    "plain".to_string()
                } else {
                    self.transports.join("+")
                }
            ),
        }
    }
}

/// Strip the `250-` / `250 ` / `250+` prefix of a control reply line.
fn reply_body(line: &str) -> Option<&str> {
    line.strip_prefix("250-")
        .or_else(|| line.strip_prefix("250 "))
        .or_else(|| line.strip_prefix("250+"))
}

fn parse_bootstrap(lines: &[String]) -> Option<u8> {
    for l in lines {
        let Some(body) = reply_body(l) else { continue };
        let Some(rest) = body.strip_prefix("status/bootstrap-phase=") else {
            continue;
        };
        for tok in rest.split_ascii_whitespace() {
            if let Some(p) = tok.strip_prefix("PROGRESS=") {
                return p.parse::<u8>().ok().filter(|p| *p <= 100);
            }
        }
    }
    None
}

/// First-hop fingerprints of BUILT circuits in a `GETINFO circuit-status` reply.
fn built_first_hops(lines: &[String]) -> Vec<Option<String>> {
    let mut out = Vec::new();
    for l in lines {
        let entry = if let Some(body) = reply_body(l) {
            match body.strip_prefix("circuit-status=") {
                Some(rest) => rest,
                None => continue,
            }
        } else if l == "." {
            continue;
        } else {
            l.as_str()
        };
        let mut parts = entry.split_ascii_whitespace();
        let (Some(_id), Some(state)) = (parts.next(), parts.next()) else {
            continue;
        };
        if state != "BUILT" {
            continue;
        }
        let first = parts
            .next()
            .and_then(|path| path.split(',').next())
            .and_then(|hop| hop.strip_prefix('$'))
            .map(|hop| hop.split(['~', '=']).next().unwrap_or(""))
            .filter(|fp| is_fingerprint_token(fp))
            .map(str::to_ascii_uppercase);
        out.push(first);
    }
    out
}

/// Turn the three ControlPort replies into a [`BridgeStatus`].
///
/// `conf` answers `GETCONF UseBridges Bridge ClientTransportPlugin`,
/// `bootstrap` answers `GETINFO status/bootstrap-phase`, `circuits` answers
/// `GETINFO circuit-status`.
pub fn evaluate_bridge_status(
    conf: &[String],
    bootstrap: &[String],
    circuits: &[String],
) -> BridgeStatus {
    let mut st = BridgeStatus::default();
    let mut fingerprints = BTreeSet::new();
    let mut transports = BTreeSet::new();
    let mut plugins: BTreeSet<String> = BTreeSet::new();
    for l in conf {
        let Some(body) = reply_body(l) else { continue };
        if let Some(v) = body.strip_prefix("UseBridges=") {
            st.use_bridges = v.trim() == "1";
        } else if let Some(v) = body.strip_prefix("Bridge=") {
            match parse_bridge_line(v) {
                Ok(b) => {
                    st.bridge_count += 1;
                    match b.fingerprint() {
                        Some(fp) => {
                            fingerprints.insert(fp.to_string());
                        }
                        None => st.first_hop_uncheckable = true,
                    }
                    if let Some(name) = b.transport.torrc_name() {
                        transports.insert(name);
                    }
                }
                Err(_) => st.unparsed_bridges += 1,
            }
        } else if let Some(v) = body.strip_prefix("ClientTransportPlugin=") {
            // "obfs4,webtunnel exec /path" lists one or more transports.
            if let Some(names) = v.split_ascii_whitespace().next() {
                plugins.extend(names.split(',').map(str::to_string));
            }
        }
    }
    st.transports = transports.iter().copied().collect();
    st.missing_plugins = transports
        .iter()
        .copied()
        .filter(|t| !plugins.contains(*t))
        .collect();
    st.bootstrap_percent = parse_bootstrap(bootstrap);
    if !st.first_hop_uncheckable {
        for hop in built_first_hops(circuits) {
            st.circuits_checked += 1;
            match hop {
                Some(fp) if fingerprints.contains(&fp) => {}
                _ => st.circuits_off_bridge += 1,
            }
        }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
    const FP2: &str = "89ABCDEF0123456789ABCDEF0123456789ABCDEF";

    fn obfs4() -> String {
        format!("obfs4 192.0.2.10:443 {FP} cert=AbCd+/xyz iat-mode=0")
    }

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_obfs4_with_and_without_prefix() {
        let a = parse_bridge_line(&obfs4()).unwrap();
        let b = parse_bridge_line(&format!("Bridge {}", obfs4())).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.transport, BridgeTransport::Obfs4);
        assert_eq!(a.fingerprint(), Some(FP));
        assert_eq!(a.torrc_line(), format!("Bridge {}", obfs4()));
    }

    #[test]
    fn fingerprint_is_uppercased() {
        let l = parse_bridge_line(&obfs4().replace(FP, &FP.to_ascii_lowercase())).unwrap();
        assert_eq!(l.fingerprint(), Some(FP));
    }

    #[test]
    fn obfs4_requires_fingerprint_cert_and_iat_mode() {
        assert_eq!(
            parse_bridge_line("obfs4 192.0.2.10:443 cert=x iat-mode=0"),
            Err(BridgeError::MissingFingerprint)
        );
        assert_eq!(
            parse_bridge_line(&format!("obfs4 192.0.2.10:443 {FP} iat-mode=0")),
            Err(BridgeError::MissingArgument("cert"))
        );
        assert_eq!(
            parse_bridge_line(&format!("obfs4 192.0.2.10:443 {FP} cert=x")),
            Err(BridgeError::MissingArgument("iat-mode"))
        );
        assert_eq!(
            parse_bridge_line(&format!("obfs4 192.0.2.10:443 {FP} cert=x iat-mode=7")),
            Err(BridgeError::BadArgument)
        );
    }

    #[test]
    fn snowflake_webtunnel_and_plain() {
        let s = parse_bridge_line(&format!(
            "snowflake 192.0.2.3:80 {FP} fingerprint={FP} url=https://snowflake-broker.example/ fronts=a.example,b.example ice=stun:stun.example:3478 utls-imitate=hellorandomizedalpn"
        ))
        .unwrap();
        assert_eq!(s.transport, BridgeTransport::Snowflake);
        let w = parse_bridge_line(&format!(
            "webtunnel [2001:db8::1]:443 {FP} url=https://example.org/secretpath ver=0.0.1"
        ))
        .unwrap();
        assert_eq!(w.transport, BridgeTransport::Webtunnel);
        assert_eq!(
            parse_bridge_line(&format!(
                "webtunnel [2001:db8::1]:443 {FP} url=http://x.example/p"
            )),
            Err(BridgeError::BadArgument)
        );
        let p = parse_bridge_line(&format!("198.51.100.7:9001 {FP}")).unwrap();
        assert_eq!(p.transport, BridgeTransport::Vanilla);
        assert_eq!(p.torrc_line(), format!("Bridge 198.51.100.7:9001 {FP}"));
        let nofp = parse_bridge_line("198.51.100.7:9001").unwrap();
        assert_eq!(nofp.fingerprint(), None);
    }

    #[test]
    fn refuses_injection_and_junk() {
        assert_eq!(
            parse_bridge_line(&format!("{}\r\nSETCONF UseBridges=0", obfs4())),
            Err(BridgeError::BadCharacters)
        );
        assert_eq!(
            parse_bridge_line(&format!("{} \"x\"", obfs4())),
            Err(BridgeError::BadCharacters)
        );
        assert_eq!(parse_bridge_line("   "), Err(BridgeError::Empty));
        assert_eq!(parse_bridge_line("Bridge"), Err(BridgeError::Empty));
        assert_eq!(
            parse_bridge_line("meek_lite 192.0.2.1:80"),
            Err(BridgeError::UnsupportedTransport)
        );
        assert_eq!(
            parse_bridge_line("obfs4 example.org:443"),
            Err(BridgeError::BadAddress)
        );
        assert_eq!(
            parse_bridge_line("192.0.2.1:0"),
            Err(BridgeError::BadAddress)
        );
        assert_eq!(
            parse_bridge_line("192.0.2.1:70000"),
            Err(BridgeError::BadAddress)
        );
        assert_eq!(
            parse_bridge_line("192.0.2.1:443 XYZ"),
            Err(BridgeError::BadFingerprint)
        );
        assert_eq!(
            parse_bridge_line(&format!("192.0.2.1:443 {FP} Cert=x")),
            Err(BridgeError::BadArgument)
        );
        assert_eq!(
            parse_bridge_line(&format!("192.0.2.1:443 {FP} cert=")),
            Err(BridgeError::BadArgument)
        );
        let long = format!("{} cert={}", obfs4(), "a".repeat(MAX_BRIDGE_LINE));
        assert_eq!(parse_bridge_line(&long), Err(BridgeError::TooLong));
        assert_eq!(
            parse_bridge_line("obfs4 192.0.2.1:443 é"),
            Err(BridgeError::BadCharacters)
        );
    }

    #[test]
    fn errors_do_not_echo_input() {
        let secret = "obfs4 192.0.2.99:443 cert=SECRET iat-mode=0";
        let e = parse_bridge_line(secret).unwrap_err().to_string();
        assert!(!e.contains("192.0.2.99") && !e.contains("SECRET"));
    }

    #[test]
    fn torrc_snippet_lists_plugins_once() {
        let a = parse_bridge_line(&obfs4()).unwrap();
        let b = parse_bridge_line(&obfs4().replace("192.0.2.10", "192.0.2.11")).unwrap();
        let s = torrc_snippet(&[a, b]);
        assert_eq!(s[0], "UseBridges 1");
        assert_eq!(
            s.iter()
                .filter(|l| l.starts_with("ClientTransportPlugin obfs4"))
                .count(),
            1
        );
        assert_eq!(
            s.iter().filter(|l| l.starts_with("Bridge obfs4")).count(),
            2
        );
    }

    fn conf_on() -> Vec<String> {
        lines(&[
            "250-UseBridges=1",
            &format!("250-Bridge={}", obfs4()),
            "250 ClientTransportPlugin=obfs4,webtunnel exec /usr/bin/lyrebird",
        ])
    }

    fn boot(p: u8) -> Vec<String> {
        vec![
            format!("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={p} TAG=done SUMMARY=\"Done\""),
            "250 OK".into(),
        ]
    }

    fn circuits(first_hops: &[&str]) -> Vec<String> {
        let mut v = vec!["250+circuit-status=".to_string()];
        for (i, fp) in first_hops.iter().enumerate() {
            v.push(format!(
                "{} BUILT ${fp}~bridge,${FP2}~middle,${FP2}~exit BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL",
                i + 1
            ));
        }
        v.push(format!(
            "{} EXTENDED ${FP2}~x PURPOSE=GENERAL",
            first_hops.len() + 1
        ));
        v.push(".".into());
        v.push("250 OK".into());
        v
    }

    #[test]
    fn active_when_everything_matches() {
        let st = evaluate_bridge_status(&conf_on(), &boot(100), &circuits(&[FP, FP]));
        assert_eq!(st.bridge_count, 1);
        assert_eq!(st.transports, vec!["obfs4"]);
        assert!(st.missing_plugins.is_empty());
        assert_eq!(st.circuits_checked, 2);
        assert_eq!(st.verdict(), BridgeVerdict::Active);
        let line = st.summary_line();
        assert!(line.starts_with("bridges=active"));
        assert!(!line.contains("192.0.2.10") && !line.contains(FP));
    }

    #[test]
    fn off_when_use_bridges_is_zero() {
        let conf = lines(&[
            "250-UseBridges=0",
            "250-Bridge",
            "250 ClientTransportPlugin",
        ]);
        let st = evaluate_bridge_status(&conf, &boot(100), &circuits(&[FP2]));
        assert_eq!(st.verdict(), BridgeVerdict::Off);
    }

    #[test]
    fn missing_plugin_or_bridge_is_misconfigured() {
        let conf = lines(&[
            "250-UseBridges=1",
            &format!("250-Bridge={}", obfs4()),
            "250 ClientTransportPlugin",
        ]);
        let st = evaluate_bridge_status(&conf, &boot(100), &[]);
        assert_eq!(st.missing_plugins, vec!["obfs4"]);
        assert!(matches!(st.verdict(), BridgeVerdict::Misconfigured(_)));
        let conf = lines(&[
            "250-UseBridges=1",
            "250-Bridge",
            "250 ClientTransportPlugin",
        ]);
        let st = evaluate_bridge_status(&conf, &boot(100), &[]);
        assert!(matches!(st.verdict(), BridgeVerdict::Misconfigured(_)));
    }

    #[test]
    fn not_ready_until_bootstrap_completes() {
        let st = evaluate_bridge_status(&conf_on(), &boot(45), &circuits(&[]));
        assert_eq!(st.verdict(), BridgeVerdict::NotReady(45));
        let st = evaluate_bridge_status(&conf_on(), &[], &[]);
        assert_eq!(st.verdict(), BridgeVerdict::NotReady(0));
    }

    #[test]
    fn circuit_through_public_guard_is_flagged() {
        let st = evaluate_bridge_status(&conf_on(), &boot(100), &circuits(&[FP, FP2]));
        assert_eq!(st.verdict(), BridgeVerdict::OffBridge(1));
        assert!(st.summary_line().contains("NOT IN EFFECT"));
    }

    #[test]
    fn single_line_circuit_status_and_no_fingerprint_bridge() {
        let circ = lines(&[
            &format!("250-circuit-status=7 BUILT ${FP}=bridge,${FP2}=x"),
            "250 OK",
        ]);
        let st = evaluate_bridge_status(&conf_on(), &boot(100), &circ);
        assert_eq!(st.circuits_checked, 1);
        assert_eq!(st.verdict(), BridgeVerdict::Active);

        let conf = lines(&["250-UseBridges=1", "250 Bridge=198.51.100.7:9001"]);
        let st = evaluate_bridge_status(&conf, &boot(100), &circuits(&[FP2]));
        assert!(st.first_hop_uncheckable);
        assert_eq!(st.verdict(), BridgeVerdict::Active);
        assert!(st.summary_line().contains("unchecked"));
    }

    #[test]
    fn unparsable_bridge_lines_are_counted_not_trusted() {
        let conf = lines(&[
            "250-UseBridges=1",
            "250-Bridge=meek_lite 192.0.2.1:80",
            "250 ClientTransportPlugin",
        ]);
        let st = evaluate_bridge_status(&conf, &boot(100), &[]);
        assert_eq!(st.unparsed_bridges, 1);
        assert_eq!(st.bridge_count, 0);
        assert!(matches!(st.verdict(), BridgeVerdict::Misconfigured(_)));
    }
}
