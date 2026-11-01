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
//!
//! Once a blob is sealed, [`pack_carry`] wraps it as a carry file the other
//! device can recognize. [`open_carry`] checks the length and a SHA-256 of
//! the ciphertext and hands the sealed envelope back. It does not run the
//! KDF and it does not decrypt. The digest catches a partial or damaged
//! copy. It is not a MAC: anyone who can rewrite the file can recompute it.
//! The passphrase is never part of the file.
//!
//! When several established sessions are loaded, [`sole_established_index`]
//! returns [`DeviceExportRefusal::Ambiguous`] and the shell lists
//! [`established_indices`]. Export of the chosen slot uses
//! [`chosen_established_index`]. On the other device, [`empty_install_index`]
//! is the first slot that is not established, under [`MAX_RATCHET_SLOTS`].
//! An established session is never replaced. A second copy of a root that
//! is already loaded is refused.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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
            Self::Ambiguous => "More than one contact session is loaded. Choose one to export.",
            Self::SealFailed => "Export could not be sealed.",
        }
    }

    /// Prepare could not pick a single session. The shell lists
    /// [`established_indices`] and the user chooses one.
    pub fn needs_picker(self) -> bool {
        matches!(self, Self::Ambiguous)
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

/// True when `root` is already one of the loaded established roots.
///
/// Every loaded root is compared. A match in the middle does not return
/// early, so the comparison does not stop at the matching slot.
pub fn root_already_loaded(roots: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut found = subtle::Choice::from(0u8);
    for have in roots {
        found |= have.ct_eq(root);
    }
    bool::from(found)
}

/// Index of the only established slot.
///
/// `established[i]` is [`root_is_established`] for that slot. Unbound slots
/// are ignored. None established is [`DeviceExportRefusal::MissingRatchet`].
/// Two or more is [`DeviceExportRefusal::Ambiguous`]: the shell shows a
/// picker and then calls [`chosen_established_index`].
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

/// Slot indices whose flag is set, in order. Empty when nothing is established.
pub fn established_indices(established: &[bool]) -> Vec<usize> {
    established
        .iter()
        .enumerate()
        .filter(|(_, on)| **on)
        .map(|(i, _)| i)
        .collect()
}

/// Picker line for one slot. The index is the only text. No key material.
pub fn session_picker_label(index: usize) -> String {
    format!("Session {index}")
}

/// `choice` may be exported when that slot itself is established.
///
/// Other established slots do not matter: the user already chose. No
/// established session at all is [`DeviceExportRefusal::MissingRatchet`].
/// A loaded slot that is still a fresh ratchet is
/// [`DeviceExportRefusal::UnboundRatchet`]. An index past the store is
/// [`DeviceExportRefusal::MissingRatchet`].
pub fn chosen_established_index(
    established: &[bool],
    choice: usize,
) -> Result<usize, DeviceExportRefusal> {
    if !established.iter().any(|on| *on) {
        return Err(DeviceExportRefusal::MissingRatchet);
    }
    match established.get(choice) {
        Some(true) => Ok(choice),
        Some(false) => Err(DeviceExportRefusal::UnboundRatchet),
        None => Err(DeviceExportRefusal::MissingRatchet),
    }
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

/// Magic at the start of a carry file. ASCII, so a stray envelope is obvious.
pub const CARRY_MAGIC: &[u8; 11] = b"HC-XDEV-v1\n";

/// Prefix of the Android Argon2id envelope. Checked, not parsed.
pub const SEALED_BLOB_MAGIC: &[u8] = b"REAL-EXP-v2";

/// `REAL-EXP-v2` (11) + salt (16) + nonce (12) + length (4) + tag (16).
pub const MIN_SEALED_BLOB_BYTES: usize = 11 + 16 + 12 + 4 + 16;

/// One ratchet state plus skipped keys fits well under this. A larger buffer
/// is refused before it is copied into the carry file.
pub const MAX_SEALED_BLOB_BYTES: usize = 64 * 1024;

const CARRY_DIGEST_LEN: usize = 32;
const CARRY_LEN_OFF: usize = CARRY_MAGIC.len();
const CARRY_DIGEST_OFF: usize = CARRY_MAGIC.len() + 4;

/// Magic + big-endian length + SHA-256.
pub const CARRY_HEADER_LEN: usize = CARRY_MAGIC.len() + 4 + CARRY_DIGEST_LEN;

/// Largest file [`open_carry`] will accept.
pub const MAX_CARRY_FILE_BYTES: usize = CARRY_HEADER_LEN + MAX_SEALED_BLOB_BYTES;

/// Most ratchet slots an import may use. Matches the Android store reservation.
/// Import will not grow the store to this index or past it.
pub const MAX_RATCHET_SLOTS: usize = 64;

/// Why a carry file was not written or not accepted. `0` is not a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryRefusal {
    /// Extreme builds have no cross-device carry.
    Extreme,
    /// No sealed bytes were passed.
    Empty,
    /// The bytes are not a `REAL-EXP-v2` envelope.
    NotSealed,
    /// Larger than [`MAX_SEALED_BLOB_BYTES`] or [`MAX_CARRY_FILE_BYTES`].
    TooLarge,
    /// The file does not start with [`CARRY_MAGIC`].
    NotACarry,
    /// The header or the declared payload is cut off, or extra bytes follow.
    Truncated,
    /// The stored SHA-256 does not match the payload.
    DigestMismatch,
}

impl CarryRefusal {
    /// JNI status code. Does not overlap [`DeviceExportRefusal::code`].
    pub fn code(self) -> i32 {
        match self {
            Self::Extreme => -10,
            Self::Empty => -11,
            Self::NotSealed => -12,
            Self::TooLarge => -13,
            Self::NotACarry => -14,
            Self::Truncated => -15,
            Self::DigestMismatch => -16,
        }
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -10 => Some(Self::Extreme),
            -11 => Some(Self::Empty),
            -12 => Some(Self::NotSealed),
            -13 => Some(Self::TooLarge),
            -14 => Some(Self::NotACarry),
            -15 => Some(Self::Truncated),
            -16 => Some(Self::DigestMismatch),
            _ => None,
        }
    }

    /// Toast text. Never echoes a passphrase.
    pub fn label(self) -> &'static str {
        match self {
            Self::Extreme => "EXTREME MODE: Cross-device carry disabled.",
            Self::Empty => "Nothing to carry.",
            Self::NotSealed => "That is not a sealed export.",
            Self::TooLarge => "Carry file is too large.",
            Self::NotACarry => "That is not a HashChat carry file.",
            Self::Truncated => "Carry file length does not match.",
            Self::DigestMismatch => "Carry file is damaged.",
        }
    }
}

fn sealed_digest(sealed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sealed);
    hasher.finalize().into()
}

/// Wrap an already-sealed envelope. The passphrase is not an argument.
pub fn pack_carry(extreme: bool, sealed: &[u8]) -> Result<Vec<u8>, CarryRefusal> {
    if extreme {
        return Err(CarryRefusal::Extreme);
    }
    if sealed.is_empty() {
        return Err(CarryRefusal::Empty);
    }
    if sealed.len() > MAX_SEALED_BLOB_BYTES {
        return Err(CarryRefusal::TooLarge);
    }
    if sealed.len() < MIN_SEALED_BLOB_BYTES || !sealed.starts_with(SEALED_BLOB_MAGIC) {
        return Err(CarryRefusal::NotSealed);
    }
    let len = u32::try_from(sealed.len()).map_err(|_| CarryRefusal::TooLarge)?;
    let digest = sealed_digest(sealed);
    let mut out = Vec::with_capacity(CARRY_HEADER_LEN + sealed.len());
    out.extend_from_slice(CARRY_MAGIC);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Check a carry file and return the sealed envelope it holds.
///
/// The returned bytes are still ciphertext. Dropping the [`Zeroizing`]
/// buffer clears that copy.
pub fn open_carry(extreme: bool, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, CarryRefusal> {
    if extreme {
        return Err(CarryRefusal::Extreme);
    }
    if file.len() < CARRY_MAGIC.len() || !file.starts_with(CARRY_MAGIC) {
        return Err(CarryRefusal::NotACarry);
    }
    if file.len() < CARRY_HEADER_LEN {
        return Err(CarryRefusal::Truncated);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&file[CARRY_LEN_OFF..CARRY_LEN_OFF + 4]);
    let len = usize::try_from(u32::from_be_bytes(len_bytes)).unwrap_or(usize::MAX);
    if len > MAX_SEALED_BLOB_BYTES {
        return Err(CarryRefusal::TooLarge);
    }
    if len < MIN_SEALED_BLOB_BYTES {
        return Err(CarryRefusal::NotSealed);
    }
    if file.len() != CARRY_HEADER_LEN + len {
        return Err(CarryRefusal::Truncated);
    }
    let mut expected = [0u8; CARRY_DIGEST_LEN];
    expected.copy_from_slice(&file[CARRY_DIGEST_OFF..CARRY_HEADER_LEN]);
    let sealed = &file[CARRY_HEADER_LEN..];
    if !bool::from(sealed_digest(sealed).ct_eq(&expected)) {
        return Err(CarryRefusal::DigestMismatch);
    }
    if !sealed.starts_with(SEALED_BLOB_MAGIC) {
        return Err(CarryRefusal::NotSealed);
    }
    Ok(Zeroizing::new(sealed.to_vec()))
}

/// Why a carry file was not installed. `0` is not a refusal.
///
/// Codes start at `-20` so they do not overlap [`DeviceExportRefusal`] or
/// [`CarryRefusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceImportRefusal {
    /// Extreme builds have no cross-device import.
    Extreme,
    /// The shell's strict-posture check refused the action.
    Strict,
    /// No passphrase bytes were passed.
    EmptyPassphrase,
    /// The passphrase is the old hardcoded shell value.
    RefusedPassphrase,
    /// Too short, repetitive, not UTF-8, or longer than the cap.
    WeakPassphrase,
    /// No carry bytes were passed.
    Empty,
    /// The file does not start with [`CARRY_MAGIC`].
    NotACarry,
    /// The header or the declared payload is cut off, or extra bytes follow.
    Truncated,
    /// The stored SHA-256 does not match the payload.
    DigestMismatch,
    /// Larger than [`MAX_CARRY_FILE_BYTES`].
    TooLarge,
    /// The payload is not a `REAL-EXP-v2` envelope.
    NotSealed,
    /// The passphrase did not open the envelope, or the plaintext is not a ratchet.
    OpenFailed,
    /// The opened ratchet's root key is still all zeros.
    UnboundRatchet,
    /// Every slot under [`MAX_RATCHET_SLOTS`] is already established.
    NoEmptySlot,
    /// That root is already loaded. A second copy is not installed.
    Duplicate,
}

impl DeviceImportRefusal {
    /// JNI status code. A slot index from install is `>= 0`, never one of these.
    pub fn code(self) -> i32 {
        match self {
            Self::Extreme => -20,
            Self::Strict => -21,
            Self::EmptyPassphrase => -22,
            Self::RefusedPassphrase => -23,
            Self::WeakPassphrase => -24,
            Self::Empty => -25,
            Self::NotACarry => -26,
            Self::Truncated => -27,
            Self::DigestMismatch => -28,
            Self::TooLarge => -29,
            Self::NotSealed => -30,
            Self::OpenFailed => -31,
            Self::UnboundRatchet => -32,
            Self::NoEmptySlot => -33,
            Self::Duplicate => -34,
        }
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -20 => Some(Self::Extreme),
            -21 => Some(Self::Strict),
            -22 => Some(Self::EmptyPassphrase),
            -23 => Some(Self::RefusedPassphrase),
            -24 => Some(Self::WeakPassphrase),
            -25 => Some(Self::Empty),
            -26 => Some(Self::NotACarry),
            -27 => Some(Self::Truncated),
            -28 => Some(Self::DigestMismatch),
            -29 => Some(Self::TooLarge),
            -30 => Some(Self::NotSealed),
            -31 => Some(Self::OpenFailed),
            -32 => Some(Self::UnboundRatchet),
            -33 => Some(Self::NoEmptySlot),
            -34 => Some(Self::Duplicate),
            _ => None,
        }
    }

    /// Toast text. Never echoes a passphrase or a root key.
    pub fn label(self) -> &'static str {
        match self {
            Self::Extreme => "EXTREME MODE: Cross-device import disabled.",
            Self::Strict => "STRICT MODE: Cross-device import refused (bad environment).",
            Self::EmptyPassphrase => "Cross-device import needs a passphrase.",
            Self::RefusedPassphrase => "That passphrase is refused.",
            Self::WeakPassphrase => "Passphrase refused (at least 12 characters, not repetitive).",
            Self::Empty => "Nothing to import.",
            Self::NotACarry => "That is not a HashChat carry file.",
            Self::Truncated => "Carry file length does not match.",
            Self::DigestMismatch => "Carry file is damaged.",
            Self::TooLarge => "Carry file is too large.",
            Self::NotSealed => "That is not a sealed export.",
            Self::OpenFailed => "Could not open the carry file.",
            Self::UnboundRatchet => "That file does not hold a contact session.",
            Self::NoEmptySlot => "No empty session slot for this import.",
            Self::Duplicate => "That contact session is already on this device.",
        }
    }
}

/// Posture gate for import, before a file is read and before a passphrase is asked for.
pub fn posture_blocks_import(
    extreme: bool,
    strict_refuses: bool,
) -> Result<(), DeviceImportRefusal> {
    if extreme {
        return Err(DeviceImportRefusal::Extreme);
    }
    if strict_refuses {
        return Err(DeviceImportRefusal::Strict);
    }
    Ok(())
}

/// Same passphrase floor as export, with import status codes.
pub fn passphrase_allows_import(passphrase: &[u8]) -> Result<(), DeviceImportRefusal> {
    match passphrase_allows_export(passphrase) {
        Ok(()) => Ok(()),
        Err(err) => Err(import_passphrase_refusal(err)),
    }
}

fn import_passphrase_refusal(err: DeviceExportRefusal) -> DeviceImportRefusal {
    match err {
        DeviceExportRefusal::EmptyPassphrase => DeviceImportRefusal::EmptyPassphrase,
        DeviceExportRefusal::RefusedPassphrase => DeviceImportRefusal::RefusedPassphrase,
        DeviceExportRefusal::WeakPassphrase => DeviceImportRefusal::WeakPassphrase,
        DeviceExportRefusal::Extreme
        | DeviceExportRefusal::Strict
        | DeviceExportRefusal::MissingRatchet
        | DeviceExportRefusal::UnboundRatchet
        | DeviceExportRefusal::Ambiguous
        | DeviceExportRefusal::SealFailed => DeviceImportRefusal::WeakPassphrase,
    }
}

/// Carry-file shape errors, as import status codes.
pub fn import_from_carry(err: CarryRefusal) -> DeviceImportRefusal {
    match err {
        CarryRefusal::Extreme => DeviceImportRefusal::Extreme,
        CarryRefusal::Empty => DeviceImportRefusal::Empty,
        CarryRefusal::NotSealed => DeviceImportRefusal::NotSealed,
        CarryRefusal::TooLarge => DeviceImportRefusal::TooLarge,
        CarryRefusal::NotACarry => DeviceImportRefusal::NotACarry,
        CarryRefusal::Truncated => DeviceImportRefusal::Truncated,
        CarryRefusal::DigestMismatch => DeviceImportRefusal::DigestMismatch,
    }
}

/// First slot an import may occupy.
///
/// `established[i]` is [`root_is_established`] for that slot. The first
/// index below `cap` that is missing or not established is empty. When
/// every loaded slot in that window is established, the next index is
/// empty only while the store is still shorter than `cap`. A hole at
/// `cap` or past it is not used, and the store is not grown to `cap`.
pub fn empty_install_index(established: &[bool], cap: usize) -> Result<usize, DeviceImportRefusal> {
    let window = established.len().min(cap);
    for (i, on) in established.iter().enumerate().take(window) {
        if !on {
            return Ok(i);
        }
    }
    if established.len() < cap {
        Ok(established.len())
    } else {
        Err(DeviceImportRefusal::NoEmptySlot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::DoubleRatchet;
    use sha2::{Digest, Sha256};

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

    fn sample_sealed() -> Vec<u8> {
        let mut sealed = vec![0x5a; MIN_SEALED_BLOB_BYTES];
        sealed[..SEALED_BLOB_MAGIC.len()].copy_from_slice(SEALED_BLOB_MAGIC);
        sealed
    }

    #[test]
    fn carry_roundtrip_returns_the_sealed_bytes_and_not_the_passphrase() {
        let sealed = sample_sealed();
        let passphrase = b"correct horse battery";
        let file = pack_carry(false, &sealed).unwrap();
        assert!(file.starts_with(CARRY_MAGIC));
        assert!(!file.windows(passphrase.len()).any(|w| w == passphrase));
        let opened = open_carry(false, &file).unwrap();
        assert_eq!(opened.as_slice(), sealed.as_slice());
        assert!(opened.starts_with(SEALED_BLOB_MAGIC));
    }

    #[test]
    fn extreme_refuses_a_valid_carry_file() {
        let file = pack_carry(false, &sample_sealed()).unwrap();
        assert_eq!(
            pack_carry(true, &sample_sealed()),
            Err(CarryRefusal::Extreme)
        );
        assert_eq!(open_carry(true, &file), Err(CarryRefusal::Extreme));
        assert_eq!(open_carry(true, b""), Err(CarryRefusal::Extreme));
    }

    #[test]
    fn a_raw_envelope_is_not_a_carry_file() {
        let sealed = sample_sealed();
        assert_eq!(open_carry(false, &sealed), Err(CarryRefusal::NotACarry));
        assert_eq!(pack_carry(false, b""), Err(CarryRefusal::Empty));
        assert_eq!(pack_carry(false, b"nope"), Err(CarryRefusal::NotSealed));
        assert_eq!(
            pack_carry(false, SEALED_BLOB_MAGIC),
            Err(CarryRefusal::NotSealed)
        );
    }

    #[test]
    fn a_damaged_or_partial_carry_file_is_refused() {
        let sealed = sample_sealed();
        let file = pack_carry(false, &sealed).unwrap();

        let mut flipped = file.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert_eq!(
            open_carry(false, &flipped),
            Err(CarryRefusal::DigestMismatch)
        );

        assert_eq!(
            open_carry(false, &file[..file.len() - 1]),
            Err(CarryRefusal::Truncated)
        );
        let mut extra = file.clone();
        extra.push(0);
        assert_eq!(open_carry(false, &extra), Err(CarryRefusal::Truncated));
        assert_eq!(open_carry(false, CARRY_MAGIC), Err(CarryRefusal::Truncated));
        assert_eq!(open_carry(false, b"HC-XDEV"), Err(CarryRefusal::NotACarry));
    }

    #[test]
    fn an_oversized_envelope_is_refused_before_it_is_wrapped() {
        let mut big = vec![0u8; MAX_SEALED_BLOB_BYTES + 1];
        big[..SEALED_BLOB_MAGIC.len()].copy_from_slice(SEALED_BLOB_MAGIC);
        assert_eq!(pack_carry(false, &big), Err(CarryRefusal::TooLarge));
    }

    #[test]
    fn a_rewritten_digest_is_not_authentication() {
        // The SHA-256 detects accidental damage. Someone who can edit the
        // file can replace the payload and store a new digest. The envelope
        // AEAD, under the passphrase, is what rejects that later.
        let mut file = pack_carry(false, &sample_sealed()).unwrap();
        let at = CARRY_HEADER_LEN + SEALED_BLOB_MAGIC.len();
        file[at] ^= 0x01;
        let digest = Sha256::digest(&file[CARRY_HEADER_LEN..]);
        let digest_at = CARRY_MAGIC.len() + 4;
        file[digest_at..CARRY_HEADER_LEN].copy_from_slice(&digest);
        let opened = open_carry(false, &file).unwrap();
        assert_eq!(opened.as_slice(), &file[CARRY_HEADER_LEN..]);
    }

    #[test]
    fn carry_codes_do_not_overlap_the_export_gate() {
        for r in [
            CarryRefusal::Extreme,
            CarryRefusal::Empty,
            CarryRefusal::NotSealed,
            CarryRefusal::TooLarge,
            CarryRefusal::NotACarry,
            CarryRefusal::Truncated,
            CarryRefusal::DigestMismatch,
        ] {
            assert_eq!(CarryRefusal::from_code(r.code()), Some(r));
            assert!(DeviceExportRefusal::from_code(r.code()).is_none());
            assert!(r.code() < 0);
            assert!(!r.label().is_empty());
            assert!(!r.label().contains("correct horse"));
        }
        assert_eq!(CarryRefusal::from_code(0), None);
        assert_eq!(CarryRefusal::from_code(-1), None);
    }

    #[test]
    fn a_picker_lists_established_slots_and_the_choice_must_be_one_of_them() {
        assert_eq!(established_indices(&[false, true, false, true]), vec![1, 3]);
        assert!(established_indices(&[false, false]).is_empty());
        assert_eq!(session_picker_label(3), "Session 3");
        assert!(!session_picker_label(0).contains("correct horse"));

        assert_eq!(chosen_established_index(&[true, true], 1), Ok(1));
        assert_eq!(chosen_established_index(&[true, true, false], 0), Ok(0));
        assert_eq!(
            chosen_established_index(&[true, false], 1),
            Err(DeviceExportRefusal::UnboundRatchet)
        );
        assert_eq!(
            chosen_established_index(&[true], 4),
            Err(DeviceExportRefusal::MissingRatchet)
        );
        assert_eq!(
            chosen_established_index(&[false, false], 0),
            Err(DeviceExportRefusal::MissingRatchet)
        );
        assert!(DeviceExportRefusal::Ambiguous.needs_picker());
        assert!(!DeviceExportRefusal::MissingRatchet.needs_picker());
        assert!(
            DeviceExportRefusal::from_code(DeviceExportRefusal::Ambiguous.code())
                .unwrap()
                .needs_picker()
        );
    }

    #[test]
    fn an_empty_slot_is_the_first_hole_under_the_cap() {
        assert_eq!(empty_install_index(&[], MAX_RATCHET_SLOTS), Ok(0));
        assert_eq!(
            empty_install_index(&[false, false], MAX_RATCHET_SLOTS),
            Ok(0)
        );
        assert_eq!(
            empty_install_index(&[true, false, true], MAX_RATCHET_SLOTS),
            Ok(1)
        );
        assert_eq!(empty_install_index(&[true, true], MAX_RATCHET_SLOTS), Ok(2));
        let full = vec![true; MAX_RATCHET_SLOTS];
        assert_eq!(
            empty_install_index(&full, MAX_RATCHET_SLOTS),
            Err(DeviceImportRefusal::NoEmptySlot)
        );
        // A hole past the cap is not an install destination, and the store
        // is not grown up to the cap when the window is already full.
        let mut past = vec![true; MAX_RATCHET_SLOTS];
        past.push(false);
        assert_eq!(
            empty_install_index(&past, MAX_RATCHET_SLOTS),
            Err(DeviceImportRefusal::NoEmptySlot)
        );
        assert_eq!(
            empty_install_index(&[false], 0),
            Err(DeviceImportRefusal::NoEmptySlot)
        );
    }

    #[test]
    fn a_loaded_root_is_a_duplicate_whichever_slot_holds_it() {
        let roots = [[1u8; 32], [2u8; 32], [3u8; 32]];
        assert!(root_already_loaded(&roots, &[2u8; 32]));
        assert!(!root_already_loaded(&roots, &[4u8; 32]));
        assert!(!root_already_loaded(&[], &[1u8; 32]));
    }

    #[test]
    fn import_codes_do_not_overlap_export_or_carry_and_labels_stay_quiet() {
        let refused = std::str::from_utf8(REFUSED_EXPORT_PASSPHRASE).unwrap();
        for r in [
            DeviceImportRefusal::Extreme,
            DeviceImportRefusal::Strict,
            DeviceImportRefusal::EmptyPassphrase,
            DeviceImportRefusal::RefusedPassphrase,
            DeviceImportRefusal::WeakPassphrase,
            DeviceImportRefusal::Empty,
            DeviceImportRefusal::NotACarry,
            DeviceImportRefusal::Truncated,
            DeviceImportRefusal::DigestMismatch,
            DeviceImportRefusal::TooLarge,
            DeviceImportRefusal::NotSealed,
            DeviceImportRefusal::OpenFailed,
            DeviceImportRefusal::UnboundRatchet,
            DeviceImportRefusal::NoEmptySlot,
            DeviceImportRefusal::Duplicate,
        ] {
            assert_eq!(DeviceImportRefusal::from_code(r.code()), Some(r));
            assert!(DeviceExportRefusal::from_code(r.code()).is_none());
            assert!(CarryRefusal::from_code(r.code()).is_none());
            assert!(r.code() <= -20);
            assert!(!r.label().is_empty());
            assert!(!r.label().contains(refused));
            assert!(!r.label().contains("correct horse"));
        }
        assert_eq!(DeviceImportRefusal::from_code(0), None);
        assert_eq!(DeviceImportRefusal::from_code(-1), None);
        assert_eq!(DeviceImportRefusal::from_code(-16), None);
        assert_eq!(
            passphrase_allows_import(b""),
            Err(DeviceImportRefusal::EmptyPassphrase)
        );
        assert_eq!(
            passphrase_allows_import(REFUSED_EXPORT_PASSPHRASE),
            Err(DeviceImportRefusal::RefusedPassphrase)
        );
        assert_eq!(
            passphrase_allows_import(b"short"),
            Err(DeviceImportRefusal::WeakPassphrase)
        );
        assert!(passphrase_allows_import(b"correct horse battery").is_ok());
        assert_eq!(
            import_from_carry(CarryRefusal::DigestMismatch),
            DeviceImportRefusal::DigestMismatch
        );
        assert_eq!(
            import_from_carry(CarryRefusal::NotACarry),
            DeviceImportRefusal::NotACarry
        );
        assert_eq!(
            posture_blocks_import(true, false),
            Err(DeviceImportRefusal::Extreme)
        );
        assert_eq!(
            posture_blocks_import(false, true),
            Err(DeviceImportRefusal::Strict)
        );
        assert!(posture_blocks_import(false, false).is_ok());
    }
}
