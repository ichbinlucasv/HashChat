# HashChat

> **Maximum-anonymity messenger** built with Haskell + Rust.
> See [SECURITY.md](SECURITY.md) before contributing.

![grok-image-c881f444-cc70-4aff-8b35-55e8f616ba02](https://github.com/user-attachments/assets/dbf8185e-a02d-4dc1-b116-3bb35e92b9b9)

**Presidential-grade anonymous messenger** — SimpleX + Session architecture with Rust crypto core.

No phone numbers. No user IDs. No central servers. No logs. No metadata.

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

### Core Design
- Random ed25519/x25519 keypair per profile (never reused)
- Unidirectional SMP queues (SimpleX style)
- Double-ratchet E2EE + extra HMAC-SHA512 layer
- Tor hidden service routing by default
- SQLCipher encrypted local storage (`PRAGMA key='hashchat-secure-passphrase'`)
- Amnesic design — 2-click Panic Wipe (Rust secure erase + 3-pass shred)
- Storage capped to prevent DoS
- Full file transfer (any type, up to 1 GB, chunked + padded)

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

### Build Instructions

**Fedora / Debian / Arch**
```bash
cargo build --release
cabal build
python3 build.py

---

## Security & Responsible Development

**This project is security-critical.**

- Read [SECURITY.md](SECURITY.md)
- Never commit anything from `tor/hidden_service/`
- Never commit compiled libraries from `rust-lib/`
- Use `./build.py` — it handles everything safely

Large media files and old GTK code have been removed from git history for cleanliness.

If you find a vulnerability, please report it privately instead of opening a public issue.
