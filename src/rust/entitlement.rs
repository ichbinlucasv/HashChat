//! Offline supporter license (entitlement).
//!
//! Privacy and anonymity are always free. A license only unlocks *comfort*
//! features listed in [`ComfortFeature`]; no privacy or security feature can
//! be expressed in that enum, so none can be gated. Free mode is the default.
//!
//! The license is a small text file signed with Ed25519 by the maintainer.
//! It is verified locally: no network call, no license server, no telemetry,
//! no account. It carries no buyer identity, only a random order number.
//!
//! Format (UTF-8, `\n` line endings, fields in this exact order):
//!
//! ```text
//! license-v1
//! product=PRODUCT
//! plan=monthly|yearly|lifetime|bundle-monthly|bundle-lifetime|pack-3m|pack-6m|pack-12m
//! expires=YYYY-MM-DD|never
//! order=<16-64 lowercase hex chars>
//! sig=<128 lowercase hex chars: Ed25519 over every line above, each with "\n">
//! ```

use ed25519_dalek::{Signature, VerifyingKey};

/// Maintainer verifying key. `None` until Lucas generates the signing key
/// offline (the private key never enters the repository). While `None`,
/// every license is rejected and the app stays in free mode.
pub const MAINTAINER_PUBKEY: Option<[u8; 32]> = None;

/// Placeholder receiving addresses. Real ones are provided by the maintainer
/// at release time. Never put private keys or seeds here.
pub const XMR_ADDRESS: &str = "<XMR_ADDRESS_TBD>";
pub const BTC_ADDRESS: &str = "<BTC_ADDRESS_TBD>";
pub const LIGHTNING: &str = "<LIGHTNING_TBD>";

/// Paid plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Monthly,
    Yearly,
    Lifetime,
    BundleMonthly,
    BundleLifetime,
    Pack3m,
    Pack6m,
    Pack12m,
}

impl Plan {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "monthly" => Self::Monthly,
            "yearly" => Self::Yearly,
            "lifetime" => Self::Lifetime,
            "bundle-monthly" => Self::BundleMonthly,
            "bundle-lifetime" => Self::BundleLifetime,
            "pack-3m" => Self::Pack3m,
            "pack-6m" => Self::Pack6m,
            "pack-12m" => Self::Pack12m,
            _ => return None,
        })
    }

    pub fn is_lifetime(self) -> bool {
        matches!(self, Self::Lifetime | Self::BundleLifetime)
    }

    pub fn is_bundle(self) -> bool {
        matches!(self, Self::BundleMonthly | Self::BundleLifetime)
    }
}

/// Comfort features a supporter license may unlock. Privacy and security
/// features are deliberately absent and must never be added here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComfortFeature {
    Themes,
    PrioritySupport,
    /// HashChat: groups above the free size.
    LargeGroups,
    /// HashChat: more than one synced device.
    MultiDeviceSync,
    /// HashChat: attachments above the free size.
    BigFiles,
    /// HashChat: encrypted backup export.
    EncryptedBackup,
    /// Frihart: official builds for non-Linux operating systems.
    OtherOsBuilds,
    /// Frihart: advanced profiles and containers.
    AdvancedProfiles,
    /// Frihart: extra curated filter lists.
    ExtraLists,
}

/// Plans table shown on the support screen (no network).
pub const PLANS: &[(&str, &str)] = &[
    ("Free", "€0. Every privacy and security feature, forever."),
    ("Supporter monthly", "€4.99 / month"),
    ("Supporter yearly", "€49 / year (2 months free)"),
    (
        "Supporter lifetime",
        "€149 once (launch: €99 for the first 500 supporters)",
    ),
    (
        "Bundle HashChat + Frihart",
        "€7.99 / month or €229 lifetime",
    ),
    (
        "Prepaid packs",
        "3, 6 or 12 months, with a local expiry reminder",
    ),
    (
        "Pay what you want",
        "Any amount. Thank you; it funds the free version.",
    ),
];

pub const PRINCIPLE: &str =
    "Privacy and anonymity are always free. Paying never unlocks privacy, only comfort.";

pub const PAY_WHAT_YOU_WANT: &str = "Pay what you want: send any amount in Monero (preferred), \
     Bitcoin or Lightning. It is support, not a purchase, and it never changes what the free \
     version can do. See docs/HOW_TO_PAY.md.";

/// A verified license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    pub plan: Plan,
    /// `None` means no expiry.
    pub expires: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseError {
    NoKey,
    Malformed,
    WrongProduct,
    BadSignature,
    Expired,
}

/// What the app may use right now. `Default` is free mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entitlement {
    license: Option<License>,
}

impl Entitlement {
    pub fn free() -> Self {
        Self::default()
    }

    /// Verify `text` with the built-in maintainer key. Any failure yields
    /// free mode; the app keeps working with every privacy feature.
    pub fn load(product: &str, text: &str, today: &str) -> Self {
        match MAINTAINER_PUBKEY {
            Some(k) => verify(&k, product, text, today)
                .map(|l| Self { license: Some(l) })
                .unwrap_or_default(),
            None => Self::free(),
        }
    }

    pub fn from_license(license: License) -> Self {
        Self {
            license: Some(license),
        }
    }

    pub fn is_supporter(&self) -> bool {
        self.license.is_some()
    }

    pub fn license(&self) -> Option<&License> {
        self.license.as_ref()
    }

    pub fn allows(&self, _feature: ComfortFeature) -> bool {
        self.is_supporter()
    }

    /// True when a time-limited license expires within `days_left` days
    /// (caller computes it from the expiry date). Used for the local reminder.
    pub fn needs_reminder(&self, days_left: i64) -> bool {
        matches!(&self.license, Some(l) if l.expires.is_some()) && days_left <= 14
    }
}

fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Verify a license file against `key`. `today` is `YYYY-MM-DD` (local clock).
pub fn verify(
    key: &[u8; 32],
    product: &str,
    text: &str,
    today: &str,
) -> Result<License, LicenseError> {
    if text.len() > 1024 || !valid_date(today) {
        return Err(LicenseError::Malformed);
    }
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    if lines.len() != 6 || lines[0] != "license-v1" {
        return Err(LicenseError::Malformed);
    }
    let field = |i: usize, name: &str| -> Result<&str, LicenseError> {
        lines[i]
            .strip_prefix(name)
            .and_then(|r| r.strip_prefix('='))
            .ok_or(LicenseError::Malformed)
    };
    let prod = field(1, "product")?;
    let plan = Plan::parse(field(2, "plan")?).ok_or(LicenseError::Malformed)?;
    let expires = field(3, "expires")?;
    let order = field(4, "order")?;
    let sig_hex = field(5, "sig")?;
    if !(16..=64).contains(&order.len()) || hex_decode(order).is_none() {
        return Err(LicenseError::Malformed);
    }
    let expires = match expires {
        "never" if plan.is_lifetime() => None,
        d if valid_date(d) && !plan.is_lifetime() => Some(d.to_string()),
        _ => return Err(LicenseError::Malformed),
    };
    let sig = hex_decode(sig_hex)
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .ok_or(LicenseError::Malformed)?;
    let vk = VerifyingKey::from_bytes(key).map_err(|_| LicenseError::NoKey)?;
    let mut signed = String::new();
    for l in &lines[..5] {
        signed.push_str(l);
        signed.push('\n');
    }
    vk.verify_strict(signed.as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| LicenseError::BadSignature)?;
    if prod != product && !(plan.is_bundle() && prod == "bundle") {
        return Err(LicenseError::WrongProduct);
    }
    if let Some(d) = &expires {
        // Fixed-width ISO dates compare correctly as strings.
        if d.as_str() < today {
            return Err(LicenseError::Expired);
        }
    }
    Ok(License { plan, expires })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sk() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn make(product: &str, plan: &str, expires: &str) -> String {
        let body = format!(
            "license-v1\nproduct={product}\nplan={plan}\nexpires={expires}\norder=00112233445566778899aabbccddeeff\n"
        );
        let sig = sk().sign(body.as_bytes()).to_bytes();
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        format!("{body}sig={hex}\n")
    }

    fn pk() -> [u8; 32] {
        sk().verifying_key().to_bytes()
    }

    #[test]
    fn free_is_default_and_gates_comfort_only() {
        let e = Entitlement::default();
        assert!(!e.is_supporter());
        assert!(!e.allows(ComfortFeature::Themes));
    }

    #[test]
    fn no_builtin_key_means_free() {
        let lic = make("p", "lifetime", "never");
        assert_eq!(
            Entitlement::load("p", &lic, "2026-10-12"),
            Entitlement::free()
        );
    }

    #[test]
    fn valid_lifetime() {
        let l = verify(&pk(), "p", &make("p", "lifetime", "never"), "2026-10-12").unwrap();
        assert_eq!(l.plan, Plan::Lifetime);
        let e = Entitlement::from_license(l);
        assert!(e.allows(ComfortFeature::Themes));
        assert!(!e.needs_reminder(1));
    }

    #[test]
    fn expiry_and_reminder() {
        let lic = make("p", "pack-3m", "2026-12-31");
        let l = verify(&pk(), "p", &lic, "2026-12-31").unwrap();
        assert!(Entitlement::from_license(l).needs_reminder(10));
        assert_eq!(
            verify(&pk(), "p", &lic, "2027-01-01"),
            Err(LicenseError::Expired)
        );
    }

    #[test]
    fn tamper_rejected() {
        let lic = make("p", "monthly", "2026-11-12").replace("monthly", "yearly");
        assert_eq!(
            verify(&pk(), "p", &lic, "2026-10-12"),
            Err(LicenseError::BadSignature)
        );
    }

    #[test]
    fn wrong_key_and_product() {
        let lic = make("p", "lifetime", "never");
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify(&other, "p", &lic, "2026-10-12"),
            Err(LicenseError::BadSignature)
        );
        assert_eq!(
            verify(&pk(), "q", &lic, "2026-10-12"),
            Err(LicenseError::WrongProduct)
        );
        let b = make("bundle", "bundle-lifetime", "never");
        assert!(verify(&pk(), "q", &b, "2026-10-12").is_ok());
    }

    #[test]
    fn malformed_rejected() {
        for bad in [
            "",
            "license-v1\n",
            &make("p", "lifetime", "2030-01-01"),
            &make("p", "monthly", "never"),
        ] {
            assert_eq!(
                verify(&pk(), "p", bad, "2026-10-12"),
                Err(LicenseError::Malformed)
            );
        }
    }

    #[test]
    fn placeholders_only() {
        assert!(
            XMR_ADDRESS.contains("TBD") && BTC_ADDRESS.contains("TBD") && LIGHTNING.contains("TBD")
        );
        assert!(MAINTAINER_PUBKEY.is_none());
    }
}
