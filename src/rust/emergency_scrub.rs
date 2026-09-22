//! Best-effort in-RAM secret scrub on panic / Unix terminate signals.
//!
//! Intended for the desktop TUI (`hashchat-tui`): register a scrub callback after
//! `App` exists, install a panic hook early, and poll a signal flag each tick.
//!
//! **Honesty (see THREATMODEL.md):**
//! - Best-effort only — race-aware (`try_lock`); may no-op under contention.
//! - Allocator / swap / core dumps may retain copies; not a substitute for `:wipe`.
//! - Tails / Qubes (RAM-backed / disposable VMs) remain stronger.
//! - Signal handlers only set a flag (async-signal-safe); scrub runs on the main path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use zeroize::Zeroize;

type ScrubCallback = fn();

static SCRUB_CB: Mutex<Option<ScrubCallback>> = Mutex::new(None);
static PANIC_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static TERMINATE_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNALS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Register a process-wide scrub callback (typically points at live TUI `App`).
///
/// Replaces any previous callback. Pass a no-op-freeing clear via
/// [`clear_scrub_callback`] before the pointed-at state is dropped.
pub fn register_scrub_callback(cb: ScrubCallback) {
    if let Ok(mut g) = SCRUB_CB.lock() {
        *g = Some(cb);
    }
}

/// Clear the registered scrub callback (call before dropping registered state).
pub fn clear_scrub_callback() {
    if let Ok(mut g) = SCRUB_CB.lock() {
        *g = None;
    }
}

/// Best-effort invoke of the registered scrub callback.
///
/// Uses `try_lock` so panic / nested paths never deadlock waiting on the mutex.
pub fn emergency_scrub() {
    let cb = match SCRUB_CB.try_lock() {
        Ok(g) => *g,
        Err(_) => return,
    };
    if let Some(f) = cb {
        f();
    }
}

/// Zeroize a mutable byte slice in place (unit-testable helper).
pub fn scrub_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

/// Install a panic hook that best-effort scrubs then calls the previous hook.
///
/// Idempotent for the process. Safe to call before any scrub callback is
/// registered (scrub becomes a no-op until registration).
pub fn install_panic_scrub_hook() {
    if PANIC_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        emergency_scrub();
        prev(info);
    }));
}

/// True after SIGINT/SIGTERM (Unix) until consumed by [`take_terminate_signal`].
pub fn terminate_signal_pending() -> bool {
    TERMINATE_REQUESTED.load(Ordering::SeqCst)
}

/// Atomically read-and-clear the terminate flag (main-loop poll).
pub fn take_terminate_signal() -> bool {
    TERMINATE_REQUESTED.swap(false, Ordering::SeqCst)
}

/// Install SIGINT/SIGTERM handlers that only set [`terminate_signal_pending`].
///
/// Idempotent. Non-Unix: no-op. Handlers do **not** scrub directly (not
/// async-signal-safe with mutexes); the TUI main loop must poll and scrub.
#[cfg(unix)]
pub fn install_terminate_signal_flag() {
    if SIGNALS_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: handler only stores to an AtomicBool — async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, terminate_signal_handler as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            terminate_signal_handler as libc::sighandler_t,
        );
    }
}

#[cfg(not(unix))]
pub fn install_terminate_signal_flag() {
    // No Unix signals; Ctrl-C still handled as a crossterm key in the TUI.
}

#[cfg(unix)]
extern "C" fn terminate_signal_handler(_sig: libc::c_int) {
    TERMINATE_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn scrub_bytes_zeroizes_sample_buffer() {
        let mut buf = [0xABu8, 0xCD, 0xEF, 0x01, 0x23];
        scrub_bytes(&mut buf);
        assert_eq!(buf, [0u8; 5]);
    }

    #[test]
    fn scrub_bytes_empty_is_ok() {
        let mut buf: [u8; 0] = [];
        scrub_bytes(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn emergency_scrub_without_callback_is_noop() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_scrub_callback();
        emergency_scrub(); // must not panic
    }

    #[test]
    fn register_and_invoke_callback() {
        let _guard = TEST_LOCK.lock().unwrap();
        use std::sync::atomic::{AtomicUsize, Ordering};
        static HITS: AtomicUsize = AtomicUsize::new(0);
        fn bump() {
            HITS.fetch_add(1, Ordering::SeqCst);
        }
        let before = HITS.load(Ordering::SeqCst);
        register_scrub_callback(bump);
        emergency_scrub();
        clear_scrub_callback();
        assert_eq!(HITS.load(Ordering::SeqCst), before + 1);
        // Cleared: further scrub is no-op.
        emergency_scrub();
        assert_eq!(HITS.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn take_terminate_signal_clears_flag() {
        TERMINATE_REQUESTED.store(true, Ordering::SeqCst);
        assert!(take_terminate_signal());
        assert!(!take_terminate_signal());
        assert!(!terminate_signal_pending());
    }
}
