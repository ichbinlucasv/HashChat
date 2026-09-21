# HashChat Installation Guide

**Repository Status**
- **Primary**: https://codeberg.org/ichbinlucasv/HashChat
- **Active tip branch**: `codeberg-primary`
- **Mirror**: https://github.com/ichbinlucasv/HashChat (read-only)

All development happens on **Codeberg**. Clone and work on `codeberg-primary` for current Rust-first work. GitHub is a read-only mirror.

---

## Normal User Quick Path (Rust-first)

You do **not** need to be an expert. Desktop focus is the **native Rust TUI**.

1. Clone from Codeberg and check out the tip branch:
   ```bash
   git clone https://codeberg.org/ichbinlucasv/HashChat.git
   cd HashChat
   git checkout codeberg-primary
   ```

2. Install (picks Fedora / Ubuntu / Arch automatically), or build Rust yourself:
   ```bash
   ./install.sh
   # or:
   cargo build --release --locked --bin hashchat-tui --features tui
   ```

3. Run:
   ```bash
   ./run-tui
   # equivalent: ./target/release/hashchat-tui
   ```
   The launcher prefers the Rust binary, prints audio/Tor diagnostics, and only falls back to the transitional Haskell Brick TUI if Rust is missing.

4. Inside the Rust TUI (black + gold): unlock / create identity, `:listen`, exchange signed `hashchat://` contacts, chat over Tor. Panic wipe is available for local sensitive state.

See **Desktop Runtime Notes per OS** below. **Tor with ControlPort is required** for the default anonymity path.

---

## Distro installers (Fedora / Ubuntu / Arch)

| Distro | Script |
|--------|--------|
| Any (detects OS) | `./install.sh` |
| Fedora | `./install-fedora.sh` |
| Ubuntu / Debian | `./install-ubuntu.sh` |
| Arch family | `./install-arch.sh` |

Each script:
- Installs build tools + **Tor** package where applicable
- Runs `cargo build --release --locked` and `cargo build --release --locked --bin hashchat-tui --features tui`
- Does **not** print secrets, passphrases, or Tor cookie material
- Leaves Haskell as an **optional transitional** path (not built by default)

```bash
chmod +x install.sh install-*.sh run-tui
./install.sh
./run-tui
```

---

## Manual Installation (Any Linux)

### 1. System dependencies

**Fedora:**
```bash
sudo dnf install gcc make pkg-config openssl-devel ncurses-devel libffi-devel zlib-devel git curl tor
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev libncurses5-dev libffi-dev zlib1g-dev git curl tor
```

**Arch:**
```bash
sudo pacman -S --needed base-devel pkg-config openssl ncurses libffi zlib git curl tor
```

### 2. Rust toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 3. Build the Rust desktop TUI (recommended)
```bash
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

### 4. Reproducible Flatpak / Nix (optional)
```bash
nix build .#hashchat-flatpak   # Pure Nix .flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat

nix build .#hashchat-tui       # flake TUI wrapper (when available)
```

### 5. Transitional Haskell desktop (fallback only)
Legacy Brick TUI over the Rust FFI — **not** the long-term stack:
```bash
# Install GHC/Cabal (ghcup recommended on Ubuntu/Arch)
cabal update
cabal build -f-tui hashchat-tui
# ./run-tui will use this only if target/release/hashchat-tui is missing
```

---

## Critical: Tor Setup (Required)

HashChat’s default transport is **Tor-only**. You need Tor running with SOCKS and a ControlPort using cookie authentication.

**Do not** paste ControlPort cookies, authenticators, or onion private keys into tickets, chat, or screenshots.

### Fedora / Ubuntu / Arch
Install Tor (install scripts already pull the `tor` package), then edit `/etc/tor/torrc` and add:
```
ControlPort 9051
CookieAuthentication 1
```

Enable and restart:
```bash
sudo systemctl enable --now tor
sudo systemctl restart tor
```

SOCKS is typically `127.0.0.1:9050` (or `9150` for Tor Browser). The Rust client probes loopback SOCKS and fail-closes ControlPort cookie auth.

### Tails
- Tor is usually preconfigured; prefer bridges when needed.
- Prefer a pre-built Flatpak copied onto the session; avoid unnecessary persistence.
- Strongest amnesia properties for casual use.

### Qubes
- Run HashChat in its own qube (disposable or tightly firewalled).
- Build with `scripts/qubes-build.sh` in a disposable, or install a Flatpak built elsewhere.
- Route through **sys-whonix**; point SOCKS at the Tor qube as documented for your template.
- Enable audio in the **template** if you need voice in the app qube.

### Recommended environments
- **Best**: Tails (amnesic, Tor by default)
- **Excellent**: Qubes disposable + Whonix
- **Good**: Fedora/Arch/Ubuntu + hardened Tor + FDE + no swap

See `THREATMODEL.md` and `SECURITY.md`.

---

## Desktop Runtime Notes (Fedora / Ubuntu / Arch / Tails / Qubes)

**Rust TUI**
- Binary name: `hashchat-tui` (Cargo feature `tui`)
- Brand: black `#0A0A0A` + gold `#FFD700` (logo 2 — chat bubble / hash mark); see `branding/`
- Launcher: `./run-tui` (Rust first, Haskell transitional fallback)

**Voice / audio (where supported)**
- Fedora 40+: PipeWire → `pw-record`
- Ubuntu 22.04+: PipeWire or Pulse → `pw-record` / `parecord`
- Arch: PipeWire common
- Tails/Qubes minimal: often `arecord` only
- One-liners:
  - Fedora: `sudo dnf install pipewire-utils alsa-utils && systemctl --user restart pipewire`
  - Ubuntu: `sudo apt install pipewire pipewire-pulse wireplumber alsa-utils && systemctl --user restart pipewire`
  - Arch: `sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils && systemctl --user enable --now pipewire`

**Hardening hints**
- Tails & Qubes disposables: strongest OPSEC (amnesia + compartmentalization)
- Fedora/Arch: FDE + no swap + minimal services
- Ubuntu: prefer minimal install; be aware of default telemetry surface
- After sensitive sessions: `./scripts/clean-security.sh --strict`

---

## Flatpak

Icons (logo 2, black + gold) live under `flatpak/icons/hicolor/` (scalable SVG + 64/128/256/512 PNG). Desktop/metainfo reference `org.hashchat.HashChat`.

```bash
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

**Host Tor is still required** — the Flatpak sandbox does not replace a system Tor daemon with ControlPort. See `flatpak/README.md`.

---

## Packaging notes (Arch / Fedora)

There is no in-tree PKGBUILD or RPM `.spec` yet. When packaging:

| Item | Value |
|------|--------|
| Desktop / binary name | `hashchat-tui` |
| Cargo features | `--features tui` for the desktop binary |
| Library (FFI / transitional Haskell) | `libhashchat_rust.so` |
| Runtime dependency | `tor` (SOCKS + ControlPort cookie auth) |
| Flatpak app-id | `org.hashchat.HashChat` |
| Icon name | `org.hashchat.HashChat` (hicolor) |

Arch PKGBUILD sketch: `cargo build --release --locked --bin hashchat-tui --features tui`, install `target/release/hashchat-tui` to `/usr/bin/hashchat-tui`, depend on `tor`. Fedora: same binary name in `%build` / `%install`; `Requires: tor`.

---

## Android

Early development. Needs NDK, Rust / `cargo-ndk`, secure storage + JNI. See `./build-android.sh`.

---

## Troubleshooting

- **No `hashchat-tui`**: `cargo build --release --locked --bin hashchat-tui --features tui`
- **Missing `libhashchat_rust.so`** (Haskell fallback): `cargo build --release --locked` and copy into `rust-lib/`
- **Tor connection fails**: service running? ControlPort `9051` + `CookieAuthentication 1`? Never log cookie bytes.
- **Cabal dependency hell** (legacy only): `cabal clean` + `rm -rf dist-newstyle` + `cabal update`
- **Wrong branch**: `git checkout codeberg-primary && git pull`

---

## Development

```bash
git checkout codeberg-primary
cargo test --lib
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

Prefer Qubes disposables or Tails for high-risk builds.

---

**Legal / funding**

The Linux/desktop version remains free and open source. An Android build may later be offered as a paid app to fund infrastructure; pricing would decrease with adoption.
