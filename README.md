# HashChat

> **Maximum-anonymity messenger** built with Haskell + Rust.
> See [SECURITY.md](SECURITY.md) before contributing.

**Presidential-grade anonymous messenger** — SimplexChat-level UI/UX + Session-style metadata resistance, powered by a Rust Double Ratchet core + Tor v3 hidden services.

**No phone numbers. No user IDs. No central servers. No logs. No metadata.**

**Current Status (as of this build)**: Real bidirectional Tor messaging, multi-member groups with sender-key forward secrecy + persistence, end-to-end voice streaming with ratchet-per-chunk + playback + seek bars, Android with RecyclerView + Keystore + biometric + QR/group management, pure-Nix reproducible Flatpak, full Simplex-style button parity (block, report, delete, voice, groups, QR, etc.), dynamic Security Posture with real refusals, nuclear panic wipe, burner + decoy profiles, disappearing messages with key erasure.

We are very close to a production-grade, auditable, paranoid messenger.

## Quick Start on Fedora (Easiest)

```bash
git clone https://github.com/ichbinlucasv/HashChat.git
cd HashChat
chmod +x install-fedora.sh
./install-fedora.sh
```

Then follow the printed instructions to set up Tor (critical).

**Future easy install**: We are building Flatpak support (see `flatpak/` directory). This will be the recommended method for most Fedora + other Linux users.

Full instructions: see [INSTALL.md](INSTALL.md)

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

---

## Security & Responsible Development

**This project is security-critical.**

- Read [SECURITY.md](SECURITY.md)
- Never commit anything from `tor/hidden_service/`
- Never commit compiled libraries from `rust-lib/`
- Use `./build.sh` — pure Bash, no Python required

Large media files and old GTK code have been removed from git history for cleanliness.

If you find a vulnerability, please report it privately instead of opening a public issue.
