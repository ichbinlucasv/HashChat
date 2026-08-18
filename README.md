# HashChat

> **Maximum-anonymity messenger** built with Haskell + Rust.
> See [SECURITY.md](SECURITY.md) before contributing.

**Repository Status (as of 2026)**
- **Primary**: https://codeberg.org/ichbinlucasv/HashChat
- **Mirror**: https://github.com/ichbinlucasv/HashChat (kept for discoverability)

All new development, issues, releases, and CI now happen on **Codeberg**. GitHub is kept only as a read-only mirror.

> **Migration note**: The project has moved its primary home to Codeberg for better alignment with privacy-focused development. All links and processes have been updated.

---

**For Normal Users (Fedora / Ubuntu / Arch / Tails / Qubes)**

You don't need to be a security researcher to use this.

Quick start (Normal User):
1. `git clone https://codeberg.org/ichbinlucasv/HashChat.git`
2. `chmod +x install.sh && ./install.sh`   # unified (detects OS, recommends Nix, runs per-distro)
3. `./run-tui` (it will guide you on audio and Tor)
4. Press `n` for a burner profile
5. Press `v` to test voice recording (real mic on most modern desktops)
6. Use `:filter term` or `/` (clear), `:status`, `:my-contact` (QR link)

The desktop app is a dense black+gold TUI on purpose (small attack surface). It is not a Simplex-style GUI.

**Status (honest):** Rust Double Ratchet + Argon2id envelopes + Tor v3 path exist. Mesh / relay / PQ / Tauri / calls are stubs. No signed v0.2 until two devices exchange a real Tor message and the remaining stubs are either finished or removed. See [ROADMAP.md](ROADMAP.md) and [THREATMODEL.md](THREATMODEL.md).

**No phone numbers. No user IDs. No central servers.**

### Current Working Features (What Actually Works Today)
**Paranoid Core**
- Real Double Ratchet (KDF chains, DH ratcheting, skipped keys) in Rust with mlock + basic seccomp
- Bidirectional Tor v3 hidden services with proper sender-header framing
- Encrypted-at-rest persistence (Argon2id + AES-GCM) for ratchets, messages, and groups
- Nuclear Panic Wipe (7-pass shred + Rust zeroize + kernel drop_caches + mlock)
- Dynamic Security Posture (real environment checks + action refusals in low posture)
- Burner profiles + plausible deniability decoy profiles with auto-wipe on switch
- Disappearing messages with ratchet key erasure

**SimplexChat-Level UX Parity (both TUI and Android)**
- Contact actions: Block, Mute, Delete chat, Report suspicious, View security info, Set disappearing timer
- Group chats with sender-key forward secrecy + member management + QR join
- Voice messages: chunked ratchet streaming + playback with seek bars (Android RecyclerView + TUI ffplay)
- Burner profile switching (p/n keys)
- Panic Wipe as first-class prominent action
- Black + #FFD700 gold theme on both platforms

**Android Specific**
- RecyclerView chat + group member management
- Hardware-backed Keystore + optional BiometricPrompt for ratchet unlock
- QR scanning + group join
- Background Tor receiver thread

**Distribution & Reproducibility**
- Pure-Nix reproducible Flatpak (one command: `nix build .#hashchat-flatpak`)
- Nix cross-compile path for Android Rust libs
- Qubes/Tails disposable VM build scripts that enforce clean-security + anti-forensics

We are now in the "polish to production" phase.

We are very close to a production-grade, auditable, paranoid messenger that can earn real user respect.

### Screenshots / Demo (Text Descriptions)
- **TUI**: Black background, gold titles, contact list on left, active chat in center, input bar at bottom. Press 'g' for group menu, 'v' for voice, 'a' for contact actions (Block/Report/Delete/Disappear), 'w' for nuclear wipe.
- **Android**: Black + gold theme, RecyclerView chat with gold bubbles for your messages, long-press for full Simplex action menu, dedicated group management screen with member list + QR, voice recording + playback with seek bar.
- **Flatpak**: One `nix build` produces a signed, reproducible .flatpak that runs the exact same paranoid TUI in a sandbox.

(Demo videos and real screenshots will be added before v0.2 tag.)

## Quick Start on Fedora (Easiest)

```bash
# Primary repository (recommended)
git clone https://codeberg.org/ichbinlucasv/HashChat.git

# Mirror (GitHub)
# git clone https://github.com/ichbinlucasv/HashChat.git

cd HashChat
chmod +x install-fedora.sh
./install-fedora.sh
```

Then follow the printed instructions to set up Tor (critical).

**Recommended easy install (one-command, reproducible):**
```bash
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

See `flake.nix` and [INSTALL.md](INSTALL.md) for details. This is now the primary distribution path.

## Important: Tor is Required

HashChat is designed as **Tor-only**. You must have a running Tor instance with ControlPort enabled (default 9051) for the anonymous hidden service to work.

See [INSTALL.md](INSTALL.md) for exact steps on Fedora.

### Core Design (Implemented)
- Per-profile random ed25519/x25519 keys + per-contact Double Ratchet (real KDF + DH + skipped keys)
- Tor v3 hidden services only (real bidirectional framed messaging with sender hints)
- Sender-key groups with forward secrecy + encrypted persistence
- Voice streaming: per-chunk ratchet encryption + playback with seek (Android + TUI)
- Android: RecyclerView chat + group management + Keystore + biometric ratchet unlock + QR
- Pure-Nix reproducible Flatpak (no external scripts)
- Nuclear Panic Wipe (7-pass + mlock + kernel anti-forensics + Rust zeroize)
- Dynamic Security Posture (real environment inspection + action refusals)
- Burner + Decoy profiles with auto-wipe
- SimplexChat button/feature parity (block, report, delete, voice, groups, QR, disappearing, etc.) on both platforms (black + #FFD700 gold theme)

### Security Features
- Constant-time crypto in Rust (ring + zeroize)
- Memory zeroization on every sensitive operation
- Extra per-message HMAC verification
- Yubikey-ready MFA hooks (closed for now)
- Dark mode only (Twitter/X palette)
- No light mode ever

### Supported Platforms
- Fedora
- Debian
- Arch Linux
- Windows (via MSYS2)
- Android (native APK via cargo-ndk + Gradle)

### Build Instructions (Current)

**Recommended (reproducible):**
```bash
nix build .#hashchat-flatpak   # Full pure-Nix Flatpak
nix build .#hashchat-tui
```

**Quick:**
```bash
./build.sh tui
./run-tui
```

Android cross:
```bash
nix build .#hashchat-android-rust
```

See [INSTALL.md](INSTALL.md) and `flake.nix`.

### Flatpak (Recommended distribution method)

The only supported and reproducible way to build the Flatpak is:

```bash
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

**Current status**: Manifest minimal install-only (no in-sandbox builds). Improved black+gold lock SVG placeholder committed + exact raster pipeline in ICONS.md. Real professional icons (64/128/256/512 PNGs) still critical blocker before v0.2/Flathub. See flatpak/ for details.

---

## Security & Responsible Development

**This project is security-critical.**

- Read [SECURITY.md](SECURITY.md)
- Never commit anything from `tor/hidden_service/`
- Never commit compiled libraries from `rust-lib/`
- Use `./build.sh` — pure Bash, no Python required

Large media files and old GTK code have been removed from git history for cleanliness.

If you find a vulnerability, please report it privately instead of opening a public issue.
