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
| Desktop client | Rust TUI, then Rust GUI if attack surface stays honest |
| Android | Thin UI over the same Rust crate |
| Legacy Haskell desktop | Transitional only — not the long-term stack |

Inspiration: SimpleX-class UX ideas, with paranoid defaults (Tor-first, no phone/account, nuclear wipe, signed contacts). Brand: black + gold (`#FFD700`), shield mark.

---

## For users (Fedora / Ubuntu / Arch / Tails / Qubes)

1. Clone the primary repo (use branch `codeberg-primary` for current work):
   ```bash
   git clone https://codeberg.org/ichbinlucasv/HashChat.git
   cd HashChat
   git checkout codeberg-primary
   ```
2. `./run-tui` (guides audio + Tor)
3. Unlock / create identity with a passphrase (Argon2id-wrapped at rest)
4. `:listen`, exchange signed `hashchat://` contacts, chat over Tor

See [INSTALL.md](INSTALL.md) for OS notes. Tor with ControlPort is required for the default path.

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
- Desktop TUI (black + gold) — transitional Haskell UI over Rust FFI while Rust desktop lands
- Android shell over the Rust library (production two-device path still maturing)

**Brand / packaging**
- Shield lockup + Flatpak hicolor icons under `branding/` and `flatpak/icons/`

Threat model and limits: [THREATMODEL.md](THREATMODEL.md).

---

## Build

```bash
# Rust library / tests
cargo test --lib
cargo build --release

# Desktop TUI (current entry)
./run-tui

# Flatpak / Nix (when using the flake path)
nix build .#hashchat-tui
# nix build .#hashchat-flatpak
```

Android Rust libs: `./build-android.sh` (needs NDK / `cargo-ndk`).

---

## Security

This is security-critical software.

- Read [SECURITY.md](SECURITY.md) and [THREATMODEL.md](THREATMODEL.md)
- Do not commit Tor private material or local `hashchat_data/`
- Prefer `./build.sh` / documented Nix paths
- Report vulnerabilities privately — do not open a public issue with exploit detail

---

## Licence

See [LICENSE](LICENSE).
