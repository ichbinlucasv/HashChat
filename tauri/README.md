Tauri stub dir created for Phase3 minimal sandboxed GUI (TUI remains default ultra-secure; Tauri for mainstream with strict caps, only FFI to Rust crypto/transport).

Deepened across continues (to good shape/stable High):
- main.rs: real invoke commands for send/wipe/posture/quantum/relay/starlink/channel (FFI parity notes).
- Cargo: features=[] strict (no api-all).
- tauri.conf: allowlist false + CSP 'self' enforced.
- Full build: cargo tauri build (after tauri-cli + link hashchat_rust via build.rs or workspace member).
- Extreme gate: Tauri can be disabled entirely in Extreme (no extra surface).
- See ROADMAP, priority table, tauri.conf.json, src-tauri/src/main.rs.
Latest: relay drain stable, quantum with real long x in TUI test (FFI examples can invoke similar).

TUI (app-desktop/TUI.hs) is always the paranoid default. This wrapper shares core for feature parity without increasing TCB.

