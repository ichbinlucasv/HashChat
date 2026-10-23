//! Cross-device ratchet export gate (Android maximum-Rust).
//!
//! The shell used to mint a fresh [`crate::ratchet::DoubleRatchet`] and seal it
//! with a passphrase written in the source. That blob was not a contact
//! session, and anyone who had read the source could open it.
//!
//! The decision lives here. The shell collects the strict-posture answer and,
//! only when this module says one established session is loaded, a passphrase.
//! Extreme refuses. A ratchet whose root key is still all zeros was never
//! initialized from a shared secret and is not exported. The Argon2id envelope
//! stays in the Android crate; this module does not seal.

use subtle::ConstantTimeEq;

use crate::envelope::check_new_passphrase;

/// Old shell passphrase. Refused exactly, so a file sealed with it cannot be
/// produced again. The bytes are public (they were in the shell source).
pub const REFUSED_EXPORT_PASSPHRASE: &[u8] = b"device-export-pass-demo";

/// Upper bound on the passphrase the shell may hand over. Longer input is
/// refused before the KDF, so a huge buffer cannot be used to stall export.
pub const MAX_EXPORT_PASSPHRASE_BYTES: usize = 256;

/// Why a cross-device export was refused. `0` is not a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceExportRefusal {
    /// Extreme builds have no cross-device export.
    Extreme,
    /// The shell's strict-posture check refused the action.
    Strict,
    /// No passphrase bytes were passed.
    EmptyPassphrase,
    /// The passphrase is the old hardcoded shell value.
    RefusedPassphrase,
    /// Too short, repetitive, not UTF-8, or longer than the cap.
    WeakPassphrase,
    /// The store has no ratchet initialized from a shared secret.
    MissingRatchet,
    /// The chosen ratchet's root key is still all zeros.
    UnboundRatchet,
    /// More than one established session is loaded, and there is no picker.
    Ambiguous,
    /// The envelope could not be sealed. No blob is returned.
    SealFailed,
}

impl DeviceExportRefusal {
    /// JNI status code. A slot index from prepare is `>= 0`, never one of these.
    pub fn code(self) -> i32 {
        match self {
            Self::Extreme => -1,
            Self::Strict => -2,
            Self::EmptyPassphrase => -3,
            Self::RefusedPassphrase => -4,
            Self::WeakPassphrase => -5,
            Self::MissingRatchet => -6,
            Self::UnboundRatchet => -7,
            Self::Ambiguous => -8,
            Self::SealFailed => -9,
        }
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -1 => Some(Self::Extreme),
            -2 => Some(Self::Strict),
            -3 => Some(Self::EmptyPassphrase),
            -4 => Some(Self::RefusedPassphrase),
            -5 => Some(Self::WeakPassphrase),
            -6 => Some(Self::MissingRatchet),
            -7 => Some(Self::UnboundRatchet),
            -8 => Some(Self::Ambiguous),
            -9 => Some(Self::SealFailed),
            _ => None,
        }
    }

    /// Toast text. Never echoes the passphrase.
    pub fn label(self) -> &'static str {
        match self {
            Self::Extreme => "EXTREME MODE: Cross-device export disabled.",
            Self::Strict => "STRICT MODE: Cross-device export refused (bad environment).",
            Self::EmptyPassphrase => "Cross-device export needs a passphrase.",
            Self::RefusedPassphrase => "That passphrase is refused.",
            Self::WeakPassphrase => "Passphrase refused (at least 12 characters, not repetitive).",
            Self::MissingRatchet => {
                "No contact session to export. A fresh ratchet is not a transfer."
            }
            Self::UnboundRatchet => {
                "That ratchet was never bound to a contact, so it is not exported."
            }
            Self::Ambiguous => {
                "More than one contact session is loaded. Export one contact at a time."
            }
            Self::SealFailed => "Export could not be sealed.",
        }
    }
}

/// Posture gate, before a passphrase is asked for.
pub fn posture_blocks_export(
    extreme: bool,
    strict_refuses: bool,
) -> Result<(), DeviceExportRefusal> {
    if extreme {
        return Err(DeviceExportRefusal::Extreme);
    }
    if strict_refuses {
        return Err(DeviceExportRefusal::Strict);
    }
    Ok(())
}

/// True when `root` is a 32-byte root key that is not all zeros.
///
/// [`crate::ratchet::DoubleRatchet::new`] starts with a zero root.
/// `init_symmetric` / `init_from_shared` replace it from HKDF.
pub fn root_is_established(root: &[u8]) -> bool {
    root.len() == 32 && root.iter().any(|b| *b != 0)
}

/// Index of the only established slot.
///
/// `established[i]` is [`root_is_established`] for that slot. Unbound slots
/// are ignored. None established is [`DeviceExportRefusal::MissingRatchet`].
/// Two or more is [`DeviceExportRefusal::Ambiguous`].
pub fn sole_established_index(established: &[bool]) -> Result<usize, DeviceExportRefusal> {
    let mut found: Option<usize> = None;
    for (i, on) in established.iter().enumerate() {
        if *on {
            if found.is_some() {
                return Err(DeviceExportRefusal::Ambiguous);
            }
            found = Some(i);
        }
    }
    found.ok_or(DeviceExportRefusal::MissingRatchet)
}

/// Passphrase floor for a transfer. Does not echo the input.
pub fn passphrase_allows_export(passphrase: &[u8]) -> Result<(), DeviceExportRefusal> {
    if passphrase.is_empty() {
        return Err(DeviceExportRefusal::EmptyPassphrase);
    }
    if passphrase.len() > MAX_EXPORT_PASSPHRASE_BYTES {
        return Err(DeviceExportRefusal::WeakPassphrase);
    }
    if passphrase.len() == REFUSED_EXPORT_PASSPHRASE.len()
        && bool::from(passphrase.ct_eq(REFUSED_EXPORT_PASSPHRASE))
    {
        return Err(DeviceExportRefusal::RefusedPassphrase);
    }
    let text = std::str::from_utf8(passphrase).map_err(|_| DeviceExportRefusal::WeakPassphrase)?;
    if check_new_passphrase(text, false).is_err() {
        return Err(DeviceExportRefusal::WeakPassphrase);
    }
    Ok(())
}

/// Everything the shell must satisfy before a blob is sealed.
pub struct DeviceExportRequest<'a> {
    pub extreme: bool,
    pub strict_refuses: bool,
    pub passphrase: &'a [u8],
    /// False when the shell has no ratchet slot to export.
    pub ratchet_present: bool,
    /// Root key from [`crate::ratchet::DoubleRatchet::export_state`].
    pub root_key: &'a [u8],
}

pub fn allow_device_export(req: &DeviceExportRequest<'_>) -> Result<(), DeviceExportRefusal> {
    posture_blocks_export(req.extreme, req.strict_refuses)?;
    passphrase_allows_export(req.passphrase)?;
    if !req.ratchet_present {
        return Err(DeviceExportRefusal::MissingRatchet);
    }
    if !root_is_established(req.root_key) {
        return Err(DeviceExportRefusal::UnboundRatchet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::DoubleRatchet;

    fn allowed<'a>(passphrase: &'a [u8], root: &'a [u8]) -> DeviceExportRequest<'a> {
        DeviceExportRequest {
            extreme: false,
            strict_refuses: false,
            passphrase,
            ratchet_present: true,
            root_key: root,
        }
    }

    #[test]
    fn posture_wins_over_passphrase_and_ratchet() {
        let mut req = allowed(b"correct horse battery", &[1u8; 32]);
        req.extreme = true;
        assert_eq!(allow_device_export(&req), Err(DeviceExportRefusal::Extreme));
        req.extreme = false;
        req.strict_refuses = true;
        assert_eq!(allow_device_export(&req), Err(DeviceExportRefusal::Strict));
    }

    #[test]
    fn old_shell_passphrase_is_refused_even_though_it_is_long_enough() {
        assert!(check_new_passphrase(
            std::str::from_utf8(REFUSED_EXPORT_PASSPHRASE).unwrap(),
            false
        )
        .is_ok());
        assert_eq!(
            passphrase_allows_export(REFUSED_EXPORT_PASSPHRASE),
            Err(DeviceExportRefusal::RefusedPassphrase)
        );
        let mut almost = REFUSED_EXPORT_PASSPHRASE.to_vec();
        almost.push(b'x');
        // One extra letter is not the old constant, and it still meets the floor.
        assert!(passphrase_allows_export(&almost).is_ok());
    }

    #[test]
    fn weak_empty_and_huge_passphrases_are_refused() {
        assert_eq!(
            passphrase_allows_export(b""),
            Err(DeviceExportRefusal::EmptyPassphrase)
        );
        assert_eq!(
            passphrase_allows_export(b"short"),
            Err(DeviceExportRefusal::WeakPassphrase)
        );
        assert_eq!(
            passphrase_allows_export(b"aaaaaaaaaaaaaaaa"),
            Err(DeviceExportRefusal::WeakPassphrase)
        );
        assert_eq!(
            passphrase_allows_export(&[0xff, 0xfe]),
            Err(DeviceExportRefusal::WeakPassphrase)
        );
        let huge = vec![b'a'; MAX_EXPORT_PASSPHRASE_BYTES + 1];
        assert_eq!(
            passphrase_allows_export(&huge),
            Err(DeviceExportRefusal::WeakPassphrase)
        );
    }

    #[test]
    fn fresh_ratchet_is_not_a_session_and_a_symmetric_init_is() {
        let fresh = DoubleRatchet::new();
        let (root, send, recv) = fresh.export_state();
        assert_eq!(send, 0);
        assert_eq!(recv, 0);
        assert!(!root_is_established(&root));
        assert_eq!(
            allow_device_export(&allowed(b"correct horse battery", &root)),
            Err(DeviceExportRefusal::UnboundRatchet)
        );

        let mut bound = DoubleRatchet::new();
        bound.init_symmetric(&[9u8; 32]);
        let (root, _, _) = bound.export_state();
        assert!(root_is_established(&root));
        assert_eq!(
            allow_device_export(&allowed(b"correct horse battery", &root)),
            Ok(())
        );
    }

    #[test]
    fn missing_slot_is_not_an_unbound_root() {
        let req = DeviceExportRequest {
            extreme: false,
            strict_refuses: false,
            passphrase: b"correct horse battery",
            ratchet_present: false,
            root_key: &[1u8; 32],
        };
        assert_eq!(
            allow_device_export(&req),
            Err(DeviceExportRefusal::MissingRatchet)
        );
    }

    #[test]
    fn sole_established_slot() {
        assert_eq!(
            sole_established_index(&[]),
            Err(DeviceExportRefusal::MissingRatchet)
        );
        assert_eq!(
            sole_established_index(&[false, false]),
            Err(DeviceExportRefusal::MissingRatchet)
        );
        assert_eq!(sole_established_index(&[false, true, false]), Ok(1));
        assert_eq!(
            sole_established_index(&[true, true]),
            Err(DeviceExportRefusal::Ambiguous)
        );
    }

    #[test]
    fn codes_round_trip_and_labels_do_not_echo_the_passphrase() {
        let refused = std::str::from_utf8(REFUSED_EXPORT_PASSPHRASE).unwrap();
        for r in [
            DeviceExportRefusal::Extreme,
            DeviceExportRefusal::Strict,
            DeviceExportRefusal::EmptyPassphrase,
            DeviceExportRefusal::RefusedPassphrase,
            DeviceExportRefusal::WeakPassphrase,
            DeviceExportRefusal::MissingRatchet,
            DeviceExportRefusal::UnboundRatchet,
            DeviceExportRefusal::Ambiguous,
            DeviceExportRefusal::SealFailed,
        ] {
            assert_eq!(DeviceExportRefusal::from_code(r.code()), Some(r));
            assert!(r.code() < 0);
            assert!(!r.label().is_empty());
            assert!(!r.label().contains(refused));
        }
        assert_eq!(DeviceExportRefusal::from_code(0), None);
        assert_eq!(DeviceExportRefusal::from_code(1), None);
    }
}
