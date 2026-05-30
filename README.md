# HashChat
![grok-image-c881f444-cc70-4aff-8b35-55e8f616ba02](https://github.com/user-attachments/assets/dbf8185e-a02d-4dc1-b116-3bb35e92b9b9)

**Presidential-grade anonymous messenger** — SimpleX + Session architecture with Rust crypto core.

No phone numbers. No user IDs. No central servers. No logs. No metadata.

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
