# HashChat

Anonymous messenger. **Rust** desktop TUI + shared crypto crate. Android UI is thin Kotlin over that crate.

- **Primary**: https://codeberg.org/ichbinlucasv/HashChat
- **Mirror**: https://github.com/ichbinlucasv/HashChat (push after Codeberg)

No phone numbers. No accounts. Traffic is Tor v3 hidden services when you `:listen`.

## Install (Linux)

```bash
git clone https://codeberg.org/ichbinlucasv/HashChat.git
cd HashChat
chmod +x install.sh && ./install.sh    # Fedora / Ubuntu / Arch
# or:
cargo build --release --locked --features tui --bin hashchat-tui
./run-tui
```

You need a local Tor:

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

Your user must be able to read the control cookie (often `/run/tor/control.authcookie`).

## Two devices

On **both** machines:

1. `./run-tui`
2. `l` or `:listen` — publishes a v3 onion (reused after restart if `hashchat_data/` is kept)
3. `:my-contact` — copy the `hashchat://…` link (or install `qrencode` for a text QR)
4. Exchange links out of band
5. `:add-contact hashchat://contact/v1/<onion>/<x25519-hex>`
6. Type a message and press Enter

If the peer is offline, ciphertext is queued. `:retry` or a later successful send flushes the queue.

Other keys: `n` new burner · `w` wipe · `s` offline E2EE selftest · `t` Tor probe · `q` quit · `?` help

## What is actually implemented

| Works | Does not |
|---|---|
| Double Ratchet in Rust, AES-256-GCM with a random nonce | Mesh, Starlink, email DHT |
| X25519 contact bootstrap + frame v2 (ephemeral DH) | Production Android two-device path |
| Tor `ADD_ONION` listen + SOCKS send | Flathub / signed v0.2 |
| Encrypted local state (`hashchat_data/state.enc`) | Independent audit |
| Nuclear wipe of keys + `hashchat_data/` | SimpleX feature parity |

The desktop binary is `hashchat-tui`. There is no Haskell.

## Build

```bash
cargo test --features tui
cargo build --release --features tui --bin hashchat-tui
# Android JNI .so (same crate):
./build-android.sh    # needs cargo-ndk + NDK
```

See [INSTALL.md](INSTALL.md), [SECURITY.md](SECURITY.md), [THREATMODEL.md](THREATMODEL.md).
