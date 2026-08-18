Tauri stub dir created for Phase3 minimal sandboxed GUI (TUI remains default ultra-secure; Tauri for mainstream/normal users with strict caps, only FFI to Rust crypto/transport).

**For normal users (optional GUI)**:
- TUI is still the recommended paranoid path (`./run-tui` after `./install.sh`).
- This Tauri version is a thin optional wrapper. All sensitive work (ratchet, Tor proxy, wipe, quantum, queues, relay) is done in the shared Rust lib via `invoke`.
- No direct net or fs from the webview.

**Build & run (minimal frontend included)**:
1. Install tauri prerequisites (see https://tauri.app/v1/guides/getting-started/prerequisites).
2. `cd tauri/src-tauri`
3. `cargo tauri dev`   (or `cargo tauri build` for bundle)
   - It will use the simple dist/index.html we ship (posture, send, wipe, hybrid test buttons).
4. The GUI calls the same FFI as TUI + Android.

Deepened (previous + this pass):
- main.rs: real invoke commands for send/wipe/posture/quantum/relay/starlink/channel (FFI parity notes).
- cargo: features=[] strict (no api-all).
- tauri.conf: allowlist false + CSP 'self' enforced.
- Minimal usable frontend (index.html + JS invokes) added for normal-user testing of optional GUI.
- Extreme gate: Tauri can be disabled entirely in Extreme (no extra surface).
- See ROADMAP, tauri.conf.json, src-tauri/src/main.rs.

Latest additions for "do all new": real basic frontend so normal users can click posture/send/wipe instead of pure terminal. TUI still wins for OPSEC density (filter, voice sending indicator, status panel).

The Rust TUI (`hashchat-tui`) is the desktop default. This wrapper is optional. Use `./run-tui` first.

