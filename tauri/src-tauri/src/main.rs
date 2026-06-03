// Phase3 Tauri GUI stub (minimal, sandboxed).
// TUI (Brick) is the ultra-secure default for paranoid users (Tails/Qubes/etc).
// This is optional mainstream wrapper: strict Tauri caps (no net, no fs direct; only via FFI to our Rust core for ratchet/E2EE/transport/Extreme).
// See ROADMAP: "retain TUI ultra-secure default + optional minimal sandboxed GUI (Tauri strict caps or Electron isolated webview) for mainstream without surface increase + feature parity".
// Monetization: desktop always free.

fn main() {
    println!("HashChat Tauri GUI stub (Phase3, priority table High).");
    println!("In real: tauri::Builder::default() ... invoke_handler for FFI calls to hashchat_rust (send, recv, wipe, posture, quantum if feature, relay, starlink detect, public channels).");
    println!("No direct sockets/files in JS; all crown jewels in Rust FFI (same as Android/TUI).");
    println!("Extreme mode: compile or runtime gate to minimal surface.");
    // Example FFI (stub; link to rust-lib/hashchat_rust like TUI):
    // extern "C" { fn rust_init_profile() -> *mut c_void; fn rust_quantum_hybrid_new() -> *mut Quantum...; ... }
    // tauri::Builder::default().invoke_handler(tauri::generate_handler![send_msg, wipe, get_posture, hybrid_kex]).run(...).expect("error");
    // See tauri.conf.json for strict allowlist:false + CSP.
}