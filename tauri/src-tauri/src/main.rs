// Phase3 Tauri GUI stub (minimal, sandboxed).
// TUI (Brick) is the ultra-secure default for paranoid users (Tails/Qubes/etc).
// This is optional mainstream wrapper: strict Tauri caps (no net, no fs direct; only via FFI to our Rust core for ratchet/E2EE/transport/Extreme).
// See ROADMAP: "retain TUI ultra-secure default + optional minimal sandboxed GUI (Tauri strict caps or Electron isolated webview) for mainstream without surface increase + feature parity".
// Monetization: desktop always free.

fn main() {
    println!("HashChat Tauri GUI stub (Phase3).");
    println!("In real: tauri::Builder::default() ... invoke_handler for FFI calls to hashchat_rust (send, recv, wipe, posture, quantum if feature).");
    println!("No direct sockets/files in JS; all crown jewels in Rust FFI (same as Android/TUI).");
    println!("Extreme mode: compile or runtime gate to minimal surface.");
    // TODO: actual Tauri setup + tauri.conf.json with capabilities limited to custom FFI.
}