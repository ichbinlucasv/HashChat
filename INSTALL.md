# HashChat Installation Guide

**Repository Status**
- **Primary**: https://codeberg.org/ichbinlucasv/HashChat
- **Mirror**: https://github.com/ichbinlucasv/HashChat (read-only)

All development happens on **Codeberg**. GitHub is kept only as a read-only mirror.

> The project has migrated its primary home to Codeberg. Use the Codeberg clone for all new work.

---

**Normal User Quick Path (Recommended for most people on these OSes)**

You do **not** need to be an expert.

1. Clone from Codeberg (primary):
   ```bash
   git clone https://codeberg.org/ichbinlucasv/HashChat.git
   cd HashChat
   ```

2. Run the improved launcher:
   ```bash
   ./run-tui
   ```
   It will tell you exactly what audio backends and Tor status you have.

3. Inside the TUI:
   - Press `n` → create a burner profile
   - Press `v` → test real voice recording (works on modern Fedora/Ubuntu/Arch via PipeWire)
   - Use `:set-proxy 127.0.0.1 9050` if needed (very useful in Qubes)

See the big "Desktop Runtime Notes per OS" section below for your specific operating system.

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

### Desktop Runtime Notes (Fedora / Ubuntu / Arch / Tails / Qubes)

**Voice Recording (new in recent waves)**:
- Modern Fedora (40+), Ubuntu (22.04+), and Arch use PipeWire by default.
  - Best: `pw-record` (added support)
  - Fallback: `parecord` (Pulse compatibility layer)
  - Last resort: `arecord` (ALSA) — often the only option in minimal Tails or Qubes Debian templates.
- On Tails/Qubes: Enable audio in the qube/template first. Disposables reset audio settings.
- If no recorder is found, voice falls back to placeholder bytes (keeps attack surface low).

**Per-Profile Proxy (new in recent waves)**:
- Use `:set-proxy <host> <port>` inside the TUI (e.g. `:set-proxy 127.0.0.1 9050` for local Tor).
- On Qubes: Point to a proxy running in sys-vpn or a dedicated proxy qube.
- On Tails: Combine with Tails' bridge or VPN feature.
- The setting is per-burner profile and survives profile switches.

**Tor on different OSes**:
- Fedora / Ubuntu / Arch: `sudo systemctl start tor` + edit `/etc/tor/torrc` for ControlPort 9051 + CookieAuthentication.
- Tails: Tor is pre-configured. Use the built-in bridges when needed.
- Qubes: Usually run through sys-whonix. Use `:set-proxy` inside the HashChat qube to talk to the Tor qube's SOCKS.

**Recommended Hardening per OS**:
- Tails & Qubes disposables: Strongest OPSEC (amnesia + compartmentalization).
- Fedora/Arch with full disk encryption + no swap + hardened kernel: Good balance.
- Ubuntu: Fine for testing, but be aware of more telemetry by default — consider minimal install + hardening.

For maximum security on any of these OSes, combine with the dynamic posture checks and nuclear wipe.

**Quick Audio Enable One-Liners (for Voice on Desktop)**

- **Fedora**: `sudo dnf install pipewire-utils alsa-utils && systemctl --user restart pipewire`
- **Ubuntu 22.04+**: `sudo apt install pipewire pipewire-pulse wireplumber alsa-utils && systemctl --user restart pipewire`
- **Arch**: `sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils && systemctl --user enable --now pipewire`
- **Tails**: Audio is usually available; if not, use the "Configure" screen in Tails to enable it.
- **Qubes**: In the template (preferably Fedora), run `sudo dnf install pipewire-utils alsa-utils`. Then in the HashChat qube: `qvm-service --enable <qube> audio`. Disposables need audio enabled in the template first.

After enabling audio, run `./run-tui` — it will now clearly tell you which recorder is available.

**Detailed per-OS Desktop Notes (Fedora / Ubuntu / Arch / Tails / Qubes)**

**Fedora (40+ recommended)**:
- PipeWire is default → `pw-record` should just work for voice.
- Use `dnf install pipewire-utils alsa-utils` if recorders are missing.
- The `run-tui` script will now clearly show available audio backends at startup.
- For best reproducibility: prefer the Nix/Flatpak path over native cabal.

**Ubuntu (22.04+ or 24.04+)**:
- Newer releases default to PipeWire. Older ones may still be PulseAudio-only (`parecord`).
- Install: `sudo apt install pipewire pipewire-pulse alsa-utils`
- Run inside a hardened VM or with AppArmor profiles for extra paranoia.
- The launcher now detects and reports the audio stack.

**Arch Linux**:
- Rolling release — be careful with ghcup/cabal pins. Prefer Nix for reproducible builds.
- PipeWire is common: `sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils`
- Excellent for desktop experimentation. Use the improved `run-tui` diagnostics.

**Tails**:
- Strongest amnesia properties.
- Audio is often limited in the default environment — enable it explicitly if needed.
- `arecord` is usually the only reliable recorder. `run-tui` will warn accordingly.
- Never persist anything. Use the Flatpak if possible (copy from another machine).
- Combine with Tails' built-in bridges for the `:set-proxy` feature.

**Qubes OS (strongly recommended for compartmentalization)**:
- Run HashChat in its own qube (ideally disposable or with strict firewall).
- Audio: depends on the template. Fedora templates usually have better PipeWire support.
- Use `:set-proxy` to route through a dedicated sys-vpn or sys-whonix qube.
- Build using the `scripts/qubes-build.sh` (it enforces clean + disposable best practices).
- The launcher will help you see exactly what audio/proxy resources are available inside the qube.

If you are on any of these OSes and hit voice or proxy issues, run `./run-tui` first — it now prints the detected audio backends and basic Tor status. This is the fastest way to debug on your specific setup.

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
