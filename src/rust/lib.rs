use zeroize::Zeroize;

mod binary_check;
mod bridges;
mod clock_check;
mod contact_link;
mod deadman;
/// Device posture policy shared with the Android shell.
pub mod device_posture;
mod disappearing;
mod duress;
mod emergency_scrub;
/// Offline supporter license; gates comfort features only, never privacy.
pub mod entitlement;
mod envelope;
mod failwipe;
/// Shared group-list encoding for Android and desktop.
pub mod group_store;
mod hidden_service;
/// One-time invitation links carrying the bootstrap salt (M-1).
pub mod invite;
mod longterm_identity;
/// Chat transcript owned by Rust (Android maximum-Rust step 2).
pub mod message_book;
mod net_mode;
mod onion_binding;
mod padding;
mod private_fs;
mod ratchet;
mod save_mark;
mod send_jitter;
mod session_persist;
mod shred;
mod term_sanitize;
mod tor_socks;
mod unlock_backoff;
mod wipe_settings;
mod wire;

pub use binary_check::{
    binary_status, digest_hex, running_binary_digest, BinaryStatus, NO_BINARY_DIGEST,
};
pub use bridges::{
    evaluate_bridge_status, parse_bridge_line, torrc_snippet, BridgeError, BridgeLine,
    BridgeStatus, BridgeTransport, BridgeVerdict, MAX_BRIDGE_LINE,
};
pub use clock_check::{
    advance_clock_mark, clock_rollback_secs, format_rollback, CLOCK_ROLLBACK_TOLERANCE_SECS,
};
pub use contact_link::{
    bootstrap_ratchet_from_signed_link, canonical_payload, format_bound_contact_link,
    format_signed_contact_link, parse_signed_contact_link, parse_unsigned_contact_link_insecure,
    sas_fingerprint, sas_for_signed, ContactLinkError, SignedContact,
};
pub use deadman::{
    clear_deadman, deadman_config, deadman_present, set_deadman, touch_deadman, unix_now,
    wipe_if_deadman_due, DeadmanConfig, MAX_DEADMAN_DAYS,
};
pub use disappearing::{
    extreme_default_lock_timeout, extreme_default_ttl, format_lock_timeout, format_ttl,
    parse_lock_timeout_token, parse_ttl_token, DEFAULT_LOCK_TIMEOUT_SECS,
    EXTREME_DEFAULT_LOCK_TIMEOUT_SECS, EXTREME_DEFAULT_TTL_SECS,
};
pub use duress::{
    clear_duress, duress_action, duress_configured, is_duress_passphrase, set_duress_passphrase,
    set_duress_passphrase_with, wipe_if_duress, wipe_on_duress, DuressAction,
};
pub use emergency_scrub::{
    clear_scrub_callback, emergency_scrub, install_panic_scrub_hook, install_terminate_signal_flag,
    register_scrub_callback, scrub_bytes, take_terminate_signal, terminate_signal_pending,
};
pub use envelope::{
    check_new_passphrase, StoreKey, MIN_NEW_PASSPHRASE_CHARS, MIN_NEW_PASSPHRASE_CHARS_EXTREME,
};
pub use failwipe::{
    attempt_failed, attempt_succeeded, begin_attempt, clear_failwipe, failwipe_config,
    set_failwipe, Attempt, MAX_FAIL_LIMIT,
};
pub use group_store::{decode_groups, encode_groups, GroupBook, GroupBookError, GroupRecord};
pub use hidden_service::{
    cookie_path_from_protocolinfo, query_bridge_status, start_hidden_service_with_key,
    HiddenService, HS_INBOUND_QUEUE_CAP, MAX_HS_INBOUND_FRAME,
};
pub use longterm_identity::LongTermIdentity;
pub use longterm_identity::{
    export_encrypted as longterm_export_encrypted, import_encrypted as longterm_import_encrypted,
};
pub use net_mode::{DnsPreference, NetConfig, NetModeError, NetworkMode, PostureProfile};
pub use padding::{pad as pad_message, unpad as unpad_message, SIZE_CLASSES};
pub use private_fs::MAX_PRIVATE_FILE_BYTES;
pub use ratchet::{
    build_wire_aad, build_wire_aad_v3, decrypt_with_key, encrypt_with_key, take_zeroizing_vec,
    DoubleRatchet, WIRE_VERSION_V2, WIRE_VERSION_V3,
};
pub use save_mark::{check_save_mark, SaveMarkStatus, SAVE_MARK_FILE};
pub use send_jitter::{format_jitter, parse_jitter_token, sample_send_delay, MAX_SEND_JITTER_SECS};
pub use session_persist::{
    check_state_storage, commit_outgoing, commit_outgoing_with_key, load_disk, load_session,
    load_session_with_key, save_disk, save_session, save_session_with_key, state_exists,
    unlock_session, validate_display_name, wipe_disk, ContactUpsert, IdentityOnionState,
    InboundDenyPolicy, PersistMode, PersistedContact, SessionState, ERR_QUEUE_FULL,
    MAX_DISPLAY_NAME_LEN, MAX_PENDING_FRAMES,
};
pub use term_sanitize::{is_terminal_safe, sanitize_for_terminal};
pub use tor_socks::{
    is_loopback_host, is_onion_destination, probe as tor_probe, read_framed_u16,
    read_framed_u16_max, socks5_connect_with_auth, socks5_send, socks_isolation_credentials,
    socks_isolation_for_contact, socks_isolation_for_onion, write_framed_u16, SocksIsolationCreds,
    TorProbe, MAX_SOCKS_FRAME,
};
pub use unlock_backoff::{unlock_backoff_delay_secs, UnlockBackoffPolicy};
pub use wipe_settings::WipeSettings;
pub use wire::{
    check_plaintext_send_size, frame_v2, frame_v3, frame_v3_sealed, is_sealed_hint, unframe_v2,
    unframe_v3, FrameV3, MAX_FRAMED_SEND_BYTES, MAX_FRAMED_V3_BYTES, MAX_PLAINTEXT_SEND_BYTES,
};

// long-13: gated quantum module. Only compiled with `cargo build --features quantum`.
// The module itself documents the strict constant-time / zeroize / side-channel
// requirements that any future real implementation must meet.
#[cfg(feature = "quantum")]
mod quantum;
#[cfg(feature = "quantum")]
pub use quantum::{hybrid_ratchet_new, QuantumHybridRatchet};

/// Wipe local sensitive material on disk (session blob, Tor HS dir, legacy db).
///
/// Safe Rust entry used by the Rust TUI.
/// Callers holding a live [`session_persist::SessionState`] must also call
/// [`session_persist::SessionState::wipe_memory_secure`] (TUI `:wipe-confirm` does this).
///
/// Honest limits: does not defeat kernel implants, prior memory exfiltration,
/// swap/core residues, or forensic copies already taken — see THREATMODEL.md.
pub fn wipe_local_sensitive() {
    shred::shred_dir(std::path::Path::new("tor/hidden_service"));
    shred::shred_file(std::path::Path::new("hashchat.db"));
    // H2/H3: wipe passphrase-wrapped session blob (identity, contacts, ratchets, pending)
    let _ = session_persist::wipe_disk(std::path::Path::new("hashchat_data"));
    shred::shred_dir(std::path::Path::new("hashchat_data"));
}

// === Ultra Paranoid Kernel-Level Security Primitives ===
//
// Safe Rust wrappers for the desktop/TUI path.
// Android keeps its own weaker best-effort stub in `android/src/main/rust`
// (no reliable MCL_CURRENT|MCL_FUTURE for unprivileged apps) — do not weaken
// or replace that path from here.
//
// Honesty: mlock/mlockall are best-effort. Unprivileged users often lack
// RLIMIT_MEMLOCK / CAP_IPC_LOCK; failure must never abort a session.
// Tails/Qubes (RAM-backed / disposable) remain stronger than desktop mlock.
// Per-buffer mlock on a `String`/`Vec` is imperfect if the allocation later
// reallocates — prefer mlockall(MCL_FUTURE) when it succeeds, and always
// zeroize on wipe (munlock is unnecessary).

/// Best-effort `mlockall(MCL_CURRENT | MCL_FUTURE)` (Linux only).
///
/// Returns `true` on success. Never panics. Non-Linux returns `false`.
/// Callers (TUI) must treat `false` as non-fatal.
pub fn mlockall_current() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: mlockall with MCL_CURRENT|MCL_FUTURE is a process-wide hint;
        // errno on failure is ignored — caller gets `false`.
        unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Best-effort `mlock` on a contiguous byte slice (Linux only).
///
/// Returns `true` on success (empty slices succeed). Never panics.
///
/// **Imperfection:** if `buf` is backed by a growable `String`/`Vec` that later
/// reallocates, only the old pages stay locked. Prefer calling after the buffer
/// is finalized for the session, and/or rely on [`mlockall_current`] with
/// `MCL_FUTURE` when available.
pub fn mlock_bytes(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `buf` is a valid Rust slice for `buf.len()` bytes.
        unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Append `ch` to a secret `String` without letting it reallocate beyond `cap`
/// bytes. A reallocation would free the old buffer with the secret prefix still
/// in it. If `buf` has less than `cap` capacity it is moved once into a
/// `cap`-sized allocation and the old buffer is zeroized. Returns `false` (buffer
/// unchanged) if `ch` does not fit.
pub fn push_char_no_realloc(buf: &mut String, ch: char, cap: usize) -> bool {
    if buf.capacity() < cap {
        if buf.len() + ch.len_utf8() > cap {
            return false;
        }
        let mut bigger = String::with_capacity(cap);
        bigger.push_str(buf);
        buf.zeroize();
        *buf = bigger;
    }
    if buf.len() + ch.len_utf8() > buf.capacity() {
        return false;
    }
    buf.push(ch);
    true
}

/// Outcome of [`disable_core_dumps_best_effort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DumpHardening {
    /// `RLIMIT_CORE` set to 0 (soft and hard).
    pub core_limit_zero: bool,
    /// `PR_SET_DUMPABLE` cleared: no core file even via a core pipe handler, and
    /// same-uid ptrace / `/proc/<pid>/mem` access is refused (root excepted).
    pub non_dumpable: bool,
}

impl DumpHardening {
    pub fn all(self) -> bool {
        self.core_limit_zero && self.non_dumpable
    }
}

/// Best-effort: keep secrets out of core files and away from same-uid debuggers.
///
/// Linux only; other targets return both flags `false`. Never panics; callers
/// treat failure as non-fatal and may surface it as a posture note.
pub fn disable_core_dumps_best_effort() -> DumpHardening {
    #[cfg(target_os = "linux")]
    {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: plain syscalls with valid arguments; no memory is shared.
        let core_limit_zero = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0 };
        let non_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 };
        DumpHardening {
            core_limit_zero,
            non_dumpable,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        DumpHardening {
            core_limit_zero: false,
            non_dumpable: false,
        }
    }
}

#[cfg(test)]
mod memlock_tests {
    use super::{mlock_bytes, mlockall_current};

    #[test]
    fn push_char_no_realloc_keeps_one_allocation() {
        let mut s = String::with_capacity(16);
        let ptr = s.as_ptr();
        for _ in 0..16 {
            assert!(super::push_char_no_realloc(&mut s, 'x', 16));
        }
        assert!(!super::push_char_no_realloc(&mut s, 'x', 16), "full");
        assert_eq!(s.len(), 16);
        assert_eq!(s.as_ptr(), ptr, "no reallocation");
        // Multi-byte char that does not fit is refused whole.
        let mut t = String::with_capacity(4);
        assert!(super::push_char_no_realloc(&mut t, 'a', 4));
        assert!(super::push_char_no_realloc(&mut t, 'ä', 4));
        assert!(!super::push_char_no_realloc(&mut t, '€', 4));
        assert_eq!(t, "aä");
        // Undersized buffer is moved once to full capacity.
        let mut u = String::new();
        assert!(super::push_char_no_realloc(&mut u, 'z', 64));
        assert!(u.capacity() >= 64);
        let p = u.as_ptr();
        for _ in 0..63 {
            assert!(super::push_char_no_realloc(&mut u, 'z', 64));
        }
        assert_eq!(u.as_ptr(), p);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disable_core_dumps_sets_limit_and_flag() {
        let h = super::disable_core_dumps_best_effort();
        assert!(h.all(), "{h:?}");
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: valid out-pointer.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) }, 0);
        assert_eq!((lim.rlim_cur, lim.rlim_max), (0, 0));
        // SAFETY: no arguments besides the option.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    /// Smoke: wrappers return a bool and must not panic (no CAP_IPC_LOCK required).
    #[test]
    fn mlock_wrappers_return_bool_without_panic() {
        let _ = mlockall_current();
        let sample = b"hashchat-mlock-smoke";
        let _ = mlock_bytes(sample);
        let _ = mlock_bytes(&[]);
    }
}
