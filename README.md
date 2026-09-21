# HashChat

<p align="center">
  <img src="branding/hashchat-lockup.png" alt="HashChat" width="480"/>
</p>

> Anonymous messenger. **Rust-first** (crypto, Tor, persistence, and the long-term desktop path).
> See [SECURITY.md](SECURITY.md) before contributing.

**Repositories**
- **Primary**: https://codeberg.org/ichbinlucasv/HashChat (`codeberg-primary` is the active tip)
- **Mirror**: https://github.com/ichbinlucasv/HashChat (read-only discoverability)

New work lands on **Codeberg** first; GitHub is mirrored afterward.

---

## Direction

HashChat is moving to **maximum Rust**:

| Layer | Target |
|-------|--------|
| Crypto, Tor, persist, wipe | Rust (done / hardening) |
| Desktop client | Rust TUI (`hashchat-tui --features tui`), then Rust GUI if attack surface stays honest |
| Android | Thin UI over the same Rust crate |
| Legacy Haskell desktop | Transitional only — not the long-term stack |

Inspiration: SimpleX-class UX ideas, with paranoid defaults (Tor-first, no phone/account, nuclear wipe, signed contacts). Brand: black + gold (`#FFD700`), logo 2 (chat bubble / hash mark).

---

## For users (Fedora / Ubuntu / Arch / Tails / Qubes)

1. Clone the primary repo and use branch `codeberg-primary`:
   ```bash
   git clone https://codeberg.org/ichbinlucasv/HashChat.git
   cd HashChat
   git checkout codeberg-primary
   ```
2. Install or build the **Rust** desktop:
   ```bash
   ./install.sh
   # or: cargo build --release --locked --bin hashchat-tui --features tui
   ```
3. `./run-tui` (prefers `./target/release/hashchat-tui`; prints audio + Tor status; Haskell only as fallback)
4. Unlock / create identity with a passphrase (Argon2id-wrapped at rest)
5. `:listen`, exchange signed `hashchat://` contacts, chat over Tor

**Tor is required** for the default path (SOCKS + ControlPort `9051` with cookie authentication). Cookie path comes from Tor `PROTOCOLINFO` (typical file: `/run/tor/control.authcookie`); your user must be able to read it. Do not paste ControlPort cookies or onion keys into issues or chats. No silent clearnet fallback.

See [INSTALL.md](INSTALL.md) for Fedora / Ubuntu / Arch / Tails / Qubes walkthroughs, Flatpak, and packaging notes.

**Transport default:** Tor. Other networks (I2P, clearnet) or DNS choices are planned as **explicit** user modes — no silent fallback from Tor.

---

## What works today (honest)

**Core**
- Rust ratchet + AEAD (speculative receive; AAD-bound frames)
- Signed contact links + SAS fingerprint (`docs/CONTACT_LINK_V1.md`)
- Tor SOCKS / ControlPort path (fail-closed cookie auth; loopback proxy policy)
- Passphrase-wrapped persistence for identity, contacts, ratchets, pending queue
- Panic wipe of local sensitive state

**Clients**
- Desktop: **Rust TUI** (`hashchat-tui`, black + gold) — preferred; two-peer path: `:listen` → exchange `:my-contact` / `:add-contact` → encrypt over Tor SOCKS
- Transitional Haskell Brick TUI over Rust FFI — fallback only (unchanged this pass)
- Android shell over the Rust library (production two-device path still maturing)

**Brand / packaging**
- Logo 2 lockup + Flatpak hicolor icons (`branding/`, `flatpak/icons/hicolor/`)
- Distro scripts: `install.sh`, `install-fedora.sh`, `install-ubuntu.sh`, `install-arch.sh`
- Flatpak app-id `org.hashchat.HashChat` (host Tor still required)

Threat model and limits: [THREATMODEL.md](THREATMODEL.md).

---

## Build

```bash
# Rust library / tests
cargo test --lib
cargo build --release --locked

# Native Rust TUI (preferred desktop)
cargo build --release --locked --bin hashchat-tui --features tui
./target/release/hashchat-tui
# or: ./run-tui

# Transitional Haskell desktop TUI (fallback — not default)
# cabal build -f-tui hashchat-tui

# Flatpak / Nix
nix build .#hashchat-tui
# nix build .#hashchat-flatpak
```

Android Rust libs: `./build-android.sh` (needs NDK / `cargo-ndk`).

---

## Security

This is security-critical software.

- Read [SECURITY.md](SECURITY.md) and [THREATMODEL.md](THREATMODEL.md)
- Do not commit Tor private material or local `hashchat_data/`
- Prefer `./install.sh` / documented Nix paths; never echo secrets in scripts or logs
- Report vulnerabilities privately — do not open a public issue with exploit detail

---

## Licence

See [LICENSE](LICENSE).
