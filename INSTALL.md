# HashChat Installation Guide

## For Fedora (Recommended Easy Method)

```bash
# Primary repository (recommended)
git clone https://codeberg.org/ichbinlucasv/HashChat.git

# Mirror (GitHub)
# git clone https://github.com/ichbinlucasv/HashChat.git

cd HashChat
chmod +x install-fedora.sh
./install-fedora.sh
```

Then follow the on-screen instructions for Tor setup.

## Manual Installation (Any Linux)

### 1. System Dependencies

**Fedora:**
```bash
sudo dnf install gcc make pkg-config openssl-devel ncurses-devel libffi-devel zlib-devel git curl ghc ghc-Cabal cabal-install
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev libncurses5-dev libffi-dev zlib1g-dev git curl ghc cabal-install
```

### 2. Rust Toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 3. Build the Project (Recommended)

**Best (reproducible, no external scripts):**
```bash
nix build .#hashchat-flatpak   # Pure Nix .flatpak
nix build .#hashchat-tui
```

**Quick dev:**
```bash
./build.sh tui
./run-tui
```

This project uses pure Bash (no Python) for the legacy path. Nix is the preferred modern path.

### 4. Run
```bash
./run-tui
```

## Critical: Tor Setup (Required)

HashChat is designed as **Tor-only**. You must have Tor running with ControlPort enabled.

### Fedora
```bash
sudo dnf install tor
sudo systemctl enable --now tor
```

Edit `/etc/tor/torrc` and add:
```
ControlPort 9051
CookieAuthentication 1
```

Then restart:
```bash
sudo systemctl restart tor
```

### Recommended Environments (Strongly Suggested)

- **Best**: Run inside **Tails OS** (amnesic, Tor by default)
- **Excellent**: Run inside a **Qubes OS** disposable VM + Whonix
- **Good**: Fedora + hardened Tor setup + no swap + full disk encryption

See `THREATMODEL.md` for why this matters.

## Android

Currently in early development. Planned as a paid app (initially ~20 CHF, later cheaper).

Will require:
- Android NDK
- Rust + cargo-ndk
- Proper secure storage + JNI integration

## Flatpak (Primary Recommended Distribution Method)

We now have a **pure-Nix reproducible Flatpak** as the main easy install path.

```bash
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

This is currently the best way to get a sandboxed, reproducible build on Fedora and other distros. See `flake.nix` for details.

## Troubleshooting

- **Missing `libhashchat_rust.so`**: Run `cargo build --release` and copy the library to `rust-lib/`.
- **TUI won't start / ncurses errors**: Make sure `ncurses-devel` is installed.
- **Tor connection fails**: Ensure `tor` service is running and ControlPort 9051 is accessible.
- **Cabal dependency hell**: Try `cabal clean` + `rm -rf dist-newstyle` + `cabal update`.

## Development

```bash
./run-tui          # Normal run
cargo build --release && ./run-tui
```

For maximum security during development, consider using Qubes OS.

---

**Legal / Funding Note**

The Linux/desktop version is and will remain free and open source.

The Android version may be offered as a paid app to help fund server infrastructure and continued development. Pricing will decrease over time as adoption grows.
