// Phase3 Tauri GUI stub (minimal, sandboxed).
// TUI (Brick) is the ultra-secure default for paranoid users (Tails/Qubes/etc).
// This is optional mainstream wrapper: strict Tauri caps (no net, no fs direct; only via FFI to our Rust core for ratchet/E2EE/transport/Extreme).
// See ROADMAP: "retain TUI ultra-secure default + optional minimal sandboxed GUI (Tauri strict caps or Electron isolated webview) for mainstream without surface increase + feature parity".
// Monetization: desktop always free.

fn main() {
    println!("HashChat Tauri GUI stub (Phase3, priority table High 'full Tauri app').");
    println!("TUI default secure; this for mainstream with strict caps (no net/fs; only FFI to Rust for all crypto/transport/Extreme/Phase3).");
    // Basic Tauri setup stub (expand with tauri::Builder, window, etc.):
    // tauri::Builder::default()
    //   .invoke_handler(tauri::generate_handler![send_msg, recv, wipe_all, get_posture, hybrid_kex, relay_announce, starlink_detect, channel_post])
    //   .run(tauri::generate_context!())
    //   .expect("error while running tauri application");
    // FFI examples (link rust-lib like TUI/Android):
    // extern "C" { fn rust_init_profile() -> *mut c_void; fn rust_quantum_hybrid_new() -> *mut c_void; fn rust_longterm... }
    println!("No direct sockets/files in JS; crown jewels in Rust FFI (ratchet, relay, quantum, Starlink, channels). Extreme gate.");
    // See tauri.conf.json for allowlist:false + CSP. Build: cargo tauri build (after full setup).
    // For full: add commands that call the Rust FFI from hashchat_rust (same as desktop lib).
}