# HashChat

> Anonymous messenger built with Haskell + Rust.
> See [SECURITY.md](SECURITY.md) before contributing.

**Repository Status (as of 2026)**
- **Primary**: https://codeberg.org/ichbinlucasv/HashChat
- **Mirror**: https://github.com/ichbinlucasv/HashChat (kept for discoverability)

All new development, issues, releases, and CI now happen on **Codeberg**. GitHub is kept only as a read-only mirror.

> **Migration note**: The project has moved its primary home to Codeberg for better alignment with privacy-focused development. All links and processes have been updated.

---

**For Normal Users (Fedora / Ubuntu / Arch / Tails / Qubes)**

You don't need to be a security researcher to use this.

Quick start:
1. `git clone https://codeberg.org/ichbinlucasv/HashChat.git`
2. `./run-tui` (it will guide you on audio and Tor)
3. Press `n` for a burner profile
4. Press `v` to test voice recording (real mic on most modern desktops)
5. Use `:set-proxy` if you're in Qubes or behind a VPN

The TUI is text-based and aimed at normal users on the five recommended OSes without expanding the security model. A full GUI is not planned unless it can be done without increasing attack surface.

See the expanded "Desktop Runtime Notes" section in INSTALL.md for your specific OS.

**Anonymous messenger** — Burner profiles, sender-key groups, contact actions, voice, and QR-style contact links. Rust Double Ratchet core over Tor v3 hidden services. Designed for metadata resistance; see THREATMODEL.md for honest limits.

Note on appearance: The desktop client is a text TUI (black + gold theme, dense status/security cues). It prioritizes a small attack surface and information density over graphical polish. That choice is intentional for the threat model.

**No phone numbers or central user IDs. Tor-only transport. No central servers or server-side message logs.** (Endpoint and network adversaries still exist — see THREATMODEL.md.)

**Current status (as of this build)**: Core crypto, Tor transport, persistence, and most desktop/Android UX features listed below are implemented.

### Current Working Features (What Actually Works Today)
**Core security**
- Real Double Ratchet (KDF chains, DH ratcheting, skipped keys) in Rust with mlock + basic seccomp
- Bidirectional Tor v3 hidden services with proper sender-header framing
- Encrypted-at-rest persistence (Argon2id + AES-GCM) for ratchets, messages, and groups
- Panic wipe (multi-pass shred + Rust zeroize + kernel drop_caches + mlock)
- Dynamic Security Posture (real environment checks + action refusals in low posture)
- Burner profiles + plausible deniability decoy profiles with auto-wipe on switch
- Disappearing messages with ratchet key erasure

**Desktop / Android UX (both platforms)**
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

Work continues on polish, tests, and documentation toward a stable, auditable release.

### Screenshots / Demo (Text Descriptions)
- **TUI**: Black background, gold titles, contact list on left, active chat in center, input bar at bottom. Press 'g' for group menu, 'v' for voice, 'a' for contact actions (Block/Report/Delete/Disappear), 'w' for panic wipe.
- **Android**: Black + gold theme, RecyclerView chat with gold bubbles for your messages, long-press contact actions, dedicated group management screen with member list + QR, voice recording + playback with seek bar.
- **Flatpak**: One `nix build` produces a signed, reproducible .flatpak that runs the same TUI in a sandbox.

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
- Tor v3 hidden services only (bidirectional framed messaging with sender hints)
- Sender-key groups with forward secrecy + encrypted persistence
- Voice streaming: per-chunk ratchet encryption + playback with seek (Android + TUI)
- Android: RecyclerView chat + group management + Keystore + biometric ratchet unlock + QR
- Pure-Nix reproducible Flatpak (no external scripts)
- Panic wipe (multi-pass + mlock + kernel anti-forensics + Rust zeroize)
- Dynamic Security Posture (real environment inspection + action refusals)
- Burner + Decoy profiles with auto-wipe
- Contact/group actions (block, report, delete, voice, groups, QR, disappearing, etc.) on both platforms (black + #FFD700 gold theme)

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
