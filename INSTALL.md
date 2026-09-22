# HashChat Installation Guide

**Repository Status**
- **Primary**: https://codeberg.org/ichbinlucasv/HashChat
- **Active tip branch**: `codeberg-primary`
- **Mirror**: https://github.com/ichbinlucasv/HashChat (read-only)

All development happens on **Codeberg**. Clone and work on `codeberg-primary` for current Rust-first work. GitHub is a read-only mirror.

---

## Preferred desktop binary

The **only recommended** desktop client is the **native Rust TUI**:

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
# equivalent: ./target/release/hashchat-tui
# or: make tui && ./run-tui
```

- Binary name: `hashchat-tui` (Cargo feature `tui`)
- Launcher `./run-tui` / `install*.sh` **never prefer cabal** when Rust can build
- **Haskell desktop is transitional / not recommended** — opt-in only via `HASHCHAT_ALLOW_HASKELL=1` (tree kept compiling; see [Haskell removal criteria](#haskell-desktop-removal-criteria))
- Brand: black `#0A0A0A` + gold `#FFD700` (logo 2 — chat bubble / hash mark); see `branding/`

**Transport default:** Tor only (SOCKS + ControlPort cookie auth). There is **no silent clearnet fallback**. Other networks (if added later) must be an explicit user choice.

---

## Normal User Quick Path

1. Clone from Codeberg and check out the tip branch:
   ```bash
   git clone https://codeberg.org/ichbinlucasv/HashChat.git
   cd HashChat
   git checkout codeberg-primary
   ```

2. Install (detects Fedora / Ubuntu / Arch), or build Rust yourself:
   ```bash
   ./install.sh
   # or:
   cargo build --release --locked --bin hashchat-tui --features tui
   ```

3. Configure Tor ControlPort + cookie auth (see [Tor setup](#critical-tor-setup-required)), then run:
   ```bash
   ./run-tui
   ```

4. Inside the Rust TUI: unlock / create identity, `:listen`, exchange signed `hashchat://` contacts, chat over Tor. Panic wipe is available for local sensitive state.

---

## Distro installers (Fedora / Ubuntu / Arch)

| Distro | Script |
|--------|--------|
| Any (detects OS) | `./install.sh` |
| Fedora | `./install-fedora.sh` |
| Ubuntu / Debian | `./install-ubuntu.sh` |
| Arch family | `./install-arch.sh` |

Each script:

- Installs build tools + the **Tor** package where applicable
- Runs `cargo build --release --locked` and `cargo build --release --locked --bin hashchat-tui --features tui`
- Does **not** print secrets, passphrases, or Tor cookie material
- Does **not** install or prefer Cabal; Haskell desktop is **transitional / not recommended**

```bash
chmod +x install.sh install-*.sh run-tui
./install.sh
# Then configure Tor (next section), then:
./run-tui
```

Tails and Qubes are **not** auto-installed by `./install.sh`; see their sections below (the unified script prints a short pointer).

---

## Fedora (walkthrough)

### Dependencies

```bash
sudo dnf install gcc make pkg-config openssl-devel ncurses-devel libffi-devel zlib-devel git curl tor
```

Optional voice tooling (PipeWire):

```bash
sudo dnf install pipewire-utils alsa-utils
systemctl --user restart pipewire
```

### Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Or run `./install-fedora.sh` (installs deps + rustup if needed + builds `hashchat-tui`).

### Build and run

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

### Tor on Fedora

1. Edit `/etc/tor/torrc` and ensure (add if missing):
   ```
   SocksPort 9050
   ControlPort 9051
   CookieAuthentication 1
   ```
2. Restart Tor:
   ```bash
   sudo systemctl enable --now tor
   sudo systemctl restart tor
   ```
3. Cookie file (typical): `/run/tor/control.authcookie`  
   HashChat discovers the path via Tor `PROTOCOLINFO` (`COOKIEFILE=…`). Your user must be able to **read** that file (often: add yourself to the `tor` group, then log out/in).  
   **Never** `cat`, `hexdump`, or paste cookie contents into terminals shared with others, tickets, or chat.
4. Verify without secrets:
   ```bash
   systemctl is-active tor
   ss -ltn | grep -E '9050|9051' || true
   ```

---

## Ubuntu / Debian (walkthrough)

### Dependencies

```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev libncurses5-dev libffi-dev zlib1g-dev git curl tor
```

Optional voice:

```bash
sudo apt install pipewire pipewire-pulse wireplumber alsa-utils
systemctl --user restart pipewire
```

### Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Or run `./install-ubuntu.sh`.

### Build and run

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

### Tor on Ubuntu / Debian

1. Edit `/etc/tor/torrc`:
   ```
   SocksPort 9050
   ControlPort 9051
   CookieAuthentication 1
   ```
2. Restart:
   ```bash
   sudo systemctl enable --now tor
   sudo systemctl restart tor
   ```
3. Cookie file (typical): `/run/tor/control.authcookie` (sometimes `/var/run/tor/control.authcookie`).  
   Membership in the **`debian-tor`** group is commonly required to read the cookie; then log out and back in.  
   **Never** print or share cookie bytes.
4. Verify:
   ```bash
   systemctl is-active tor
   ss -ltn | grep -E '9050|9051' || true
   ```

---

## Arch Linux (walkthrough)

### Dependencies

```bash
sudo pacman -S --needed base-devel pkg-config openssl ncurses libffi zlib git curl tor
```

Optional voice:

```bash
sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils
systemctl --user enable --now pipewire
```

### Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Or run `./install-arch.sh`. For bit-for-bit reproducibility prefer Nix/Flatpak (below).

### Build and run

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

### Tor on Arch

1. Edit `/etc/tor/torrc`:
   ```
   SocksPort 9050
   ControlPort 9051
   CookieAuthentication 1
   ```
2. Restart:
   ```bash
   sudo systemctl enable --now tor
   sudo systemctl restart tor
   ```
3. Cookie file (typical): `/run/tor/control.authcookie`.  
   Ensure your user can read it (group/`tor` permissions as configured by the package). **Never** echo cookie contents.
4. Verify with `systemctl is-active tor` and `ss -ltn` as above.

---

## Tails

Tails is amnesic and Tor-first — strong OPSEC for casual sessions, with important caveats for HashChat.

### What works well

- Tor is already the default network path (no “enable Tor” step for browsing).
- Prefer a **pre-built Flatpak** (or a release binary built elsewhere) copied into the session rather than compiling large toolchains on Tails when you can avoid it.
- Avoid Persistent Storage for HashChat identity / chat state unless you deliberately accept the forensics trade-off. Amnesia is the point.

### Tor ControlPort on Tails

HashChat’s `:listen` path needs a **loopback Tor ControlPort** with **cookie authentication** so it can issue `ADD_ONION` (fail-closed; no bare `AUTHENTICATE`).

On Tails, ControlPort access is often **restricted** (filtered / not freely available to arbitrary apps). Do not weaken Tails global Tor policy casually.

Practical guidance:

- Confirm whether a ControlPort is reachable on loopback (e.g. TCP `9051`) **without** dumping cookies.
- Cookie path, when present, is typically under `/run/tor/` (exact name comes from Tor `PROTOCOLINFO` → `COOKIEFILE=`). HashChat reads that path itself — **do not** paste cookie contents into notes or tickets.
- If ControlPort / `ADD_ONION` is unavailable in your Tails version, `:listen` will fail closed. Prefer documenting that limitation over inventing clearnet workarounds. There is **no silent clearnet fallback**.

### Persistence / OPSEC

- Prefer session-only use; wipe when done (`./scripts/clean-security.sh --strict` if you used a writable tree).
- Do not screenshot ControlPort status that might include cookie paths in unusual logging setups; HashChat itself must not log cookie bytes (and install docs must not tell you to print them).
- Bridges: use Tails’ normal Tor configuration UI when your network needs them — that is separate from HashChat.

### Build on Tails (if you must)

```bash
# Only if you accept a large toolchain on an amnesic session
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

Expect slower builds and loss of the binary when the session ends unless you deliberately persist (discouraged for high-risk use).

---

## Qubes OS

Run HashChat in a **dedicated app qube** (disposable for highest paranoia, or a tightly firewalled vault-style qube). Route network through **sys-whonix** (or equivalent Tor NetVM). Never treat the build disposable as a long-lived chat qube.

### Build (disposable)

```bash
# Example pattern — adjust template / dispvm names for your install:
# qvm-run --dispvm=fedora-40-dvm 'bash -s' < scripts/qubes-build.sh
```

`scripts/qubes-build.sh` prefers a Nix Flatpak build inside the disposable, then you `qvm-copy` the `.flatpak` out. Do not reuse the build disposable for sensitive chatting.

### Install / run in the app qube

- Install the Flatpak (or copy a prebuilt `hashchat-tui`) into the app qube only.
- Host Tor still comes from the Tor/Whonix infrastructure — the Flatpak does **not** bundle Tor.
- Preferred local build inside a template/app qube (if you compile there):
  ```bash
  cargo build --release --locked --bin hashchat-tui --features tui
  ./run-tui
  ```

### Tor / SOCKS / ControlPort on Qubes + Whonix

- **SOCKS**: traffic should egress via sys-whonix. Point HashChat at the SOCKS listener your template documents (often loopback `9050` in Whonix-Workstation, or the address your qube networking exposes). Use `:set-proxy` only if your TUI build supports adjusting SOCKS — never point at clearnet.
- **ControlPort + cookie**: Whonix commonly **filters** ControlPort via onion-grater. Unrestricted `ADD_ONION` may be denied until a filtered profile allows it. Treat enabling ControlPort commands as a deliberate OPSEC/admin change on the Whonix side — do not paste cookies between qubes in chat or tickets.
- Cookie files, when used, live on the Tor-providing qube/VM (paths like `/run/tor/control.authcookie`). The HashChat process must be able to read the cookie **in the same place Tor ControlPort is reachable** (usually the workstation/Tor client VM). **Never** `qvm-copy` cookie files or echo them into another qube’s logs.
- Verify connectivity with service status and listening ports only — not by printing cookie material.

### Audio

Enable audio in the **template** if the app qube needs voice; minimal qubes often only have `arecord`.

### OPSEC caveats

- Prefer disposables for one-shot sessions; accept that state dies with the VM.
- Do not mix build artifacts, browsing, and long-term identity in one qube.
- After sensitive work in a persistent qube: `./scripts/clean-security.sh --strict`.

---

## Critical: Tor setup (required)

HashChat’s default transport is **Tor-only**. You need:

| Need | Typical value | Notes |
|------|---------------|--------|
| SOCKS | `127.0.0.1:9050` (or Tor Browser `9150`) | Loopback only |
| ControlPort | TCP `9051` | Desktop client expects **9051** today |
| Auth | `CookieAuthentication 1` | Cookie only; fail-closed if unreadable |

**Do not** paste ControlPort cookies, authenticators, hashed passwords, or onion private keys into tickets, chat, screenshots, or shell history shared with others.

### Minimal `torrc` for the desktop client

Edit `/etc/tor/torrc` (Fedora / Ubuntu / Arch) and set:

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

Then:

```bash
sudo systemctl enable --now tor
sudo systemctl restart tor
```

### How cookie auth works with HashChat (no secret echoing)

1. HashChat opens the ControlPort on loopback.
2. It sends `PROTOCOLINFO` and reads `COOKIEFILE="…"` from Tor’s reply.
3. It reads that file and authenticates with cookie `AUTHENTICATE` only.
4. If the cookie file is missing or unreadable, it **fails closed** (refuses bare `AUTHENTICATE`). Cookie bytes are never meant to be logged.

**Typical cookie paths** (distribution defaults; confirm via Tor, not by publishing contents):

| Environment | Common cookie path |
|-------------|--------------------|
| Fedora / Arch / modern Tor | `/run/tor/control.authcookie` |
| Debian / Ubuntu | `/run/tor/control.authcookie` (alias `/var/run/tor/…`) |
| Some Tor layouts | `/var/lib/tor/control_auth_cookie` |
| Tails / Whonix | Under `/run/tor/` when ControlPort is exposed; often filtered |

**Permissions:** the OS user running `hashchat-tui` must be allowed to read the cookie file (commonly via `debian-tor` or `tor` group membership + re-login). Fix permissions/groups — do not copy cookie bytes into the home directory “for convenience.”

**Safe checks:**

```bash
systemctl is-active tor
ss -ltn | grep -E '9050|9051' || true
# Optional: confirm the cookie file exists and is readable *by you* without printing it:
test -r /run/tor/control.authcookie && echo "cookie file readable" || echo "cookie file not readable (fix group/permissions)"
```

### Sample `tor/torrc` in this repo

`tor/torrc` is an example hardened config. It may use `ControlPort auto` / a control socket for other deployments. The **desktop Rust TUI currently expects TCP ControlPort `9051`**. For HashChat desktop, prefer the minimal `SocksPort` / `ControlPort 9051` / `CookieAuthentication 1` stanza above unless you knowingly change both Tor and the client.

### Recommended environments

- **Best**: Tails (amnesic, Tor by default) — subject to ControlPort/`ADD_ONION` availability
- **Excellent**: Qubes disposable + Whonix — subject to onion-grater / ControlPort policy
- **Good**: Fedora / Arch / Ubuntu + hardened Tor + FDE + no swap

See `THREATMODEL.md` and `SECURITY.md`.

---

## Manual installation (any Linux)

### 1. System dependencies

Use the Fedora / Ubuntu / Arch dependency blocks above (or your distro’s equivalents for gcc/make, pkg-config, OpenSSL headers, ncurses, libffi, zlib, git, curl, **tor**).

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

Default Nix package / `devShell` is **Rust-only** (`hashchat-tui`). Cabal/GHC are **not** on the default shell PATH.

```bash
nix build .#hashchat-tui       # default package = Rust TUI wrapper
nix build .#hashchat-flatpak   # Pure Nix .flatpak (Rust prebuilts)
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat

nix develop                   # Rust + Tor + flatpak-builder (no Cabal)
# Transitional Cabal parity only:
nix develop .#haskellDev
```

**Host Tor is still required** — see Flatpak section.

### 5. Transitional Haskell desktop (NOT recommended)

Legacy Brick TUI over the Rust FFI — **transitional / not recommended**. Scripts and docs do not prefer this path. Kept in-tree so Cabal targets can still compile for parity checks until removal criteria are met.

```bash
# Opt-in only — not a user/release path (criterion 2 MET)
nix develop .#haskellDev          # optional Cabal/GHC shell
./build.sh --haskell              # or: ./build.sh tui --haskell
HASHCHAT_ALLOW_HASKELL=1 ./run-tui
```

---

## Desktop runtime notes (audio / hardening)

**Voice / audio (where supported)**

- Fedora 40+: PipeWire → `pw-record`
- Ubuntu 22.04+: PipeWire or Pulse → `pw-record` / `parecord`
- Arch: PipeWire common
- Tails / Qubes minimal: often `arecord` only

**Hardening hints**

- Tails & Qubes disposables: strongest OPSEC (amnesia + compartmentalization)
- Fedora / Arch: FDE + no swap + minimal services
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

**Host Tor is still required** — the Flatpak sandbox does not replace a system Tor daemon with ControlPort + cookie auth. See `flatpak/README.md`.

---

## Packaging notes (Arch / Fedora)

There is no in-tree PKGBUILD or RPM `.spec` yet. When packaging:

| Item | Value |
|------|--------|
| Desktop / binary name | `hashchat-tui` |
| Cargo features | `--features tui` for the desktop binary |
| Preferred build | `cargo build --release --locked --bin hashchat-tui --features tui` |
| Library (FFI / transitional Haskell) | `libhashchat_rust.so` |
| Runtime dependency | `tor` (SOCKS + ControlPort cookie auth) |
| Flatpak app-id | `org.hashchat.HashChat` |
| Icon name | `org.hashchat.HashChat` (hicolor) |

Arch PKGBUILD sketch: build with the preferred command above, install `target/release/hashchat-tui` to `/usr/bin/hashchat-tui`, depend on `tor`. Fedora: same binary name in `%build` / `%install`; `Requires: tor`. Document that the package does **not** ship Tor cookies and must not run post-install scripts that print ControlPort secrets.

---

## Android

Early development. Needs NDK, Rust / `cargo-ndk`, secure storage + JNI. See `./build-android.sh`.

---

## Troubleshooting

| Symptom | What to check |
|---------|----------------|
| No `hashchat-tui` | `cargo build --release --locked --bin hashchat-tui --features tui` |
| Missing `libhashchat_rust.so` (Haskell fallback) | `cargo build --release --locked` and copy into `rust-lib/` |
| Tor / `:listen` fails | Is `tor` active? Is TCP `9051` listening? Is `CookieAuthentication 1` set? Can your user **read** the cookie file (group membership)? Never log cookie bytes. |
| Cookie “unreadable” | Add user to `debian-tor` (Debian/Ubuntu) or `tor` (Fedora/Arch as applicable); re-login; confirm with `test -r` on the cookie path — do not `cat` it. |
| Tails / Whonix ControlPort denied | ControlPort may be filtered; HashChat needs cookie auth + `ADD_ONION`. Do not bypass via clearnet. |
| Cabal dependency hell (opt-in parity only) | See § Transitional Haskell; not needed for recommended installs |
| Wrong branch | `git checkout codeberg-primary && git pull` |

---

## Development

```bash
git checkout codeberg-primary
cargo test --lib
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

Prefer Qubes disposables or Tails for high-risk builds.


## Haskell desktop removal criteria

The Haskell tree (`hashchat.cabal`, `src/haskell/`, `app-desktop/`) is **not deleted** (still too risky as a drive-by). It remains compile-capable but **demoted**. Status below reflects the Rust-only release surface (criterion 2 MET) plus Extreme/TUI posture.

Remove the Haskell desktop path only when **all** of the following hold:

1. **MET** — Rust `hashchat-tui --features tui` covers the documented two-peer Tor path (`:listen`, contacts, send/recv, pending retry) without relying on Brick/Cabal.
2. **MET** — Distro installers, `./run-tui`, `./build.sh`, Flatpak/Nix default package + `devShell`, and CI no longer present Cabal as a user or release path. Remaining opt-in escape hatch only: `HASHCHAT_ALLOW_HASKELL=1`, `./build.sh --haskell`, and `nix develop .#haskellDev` (parity / transitional; documented here, not on the happy path).
3. **MET (current judgment)** — No open blocker that *requires* the Brick TUI for security review, release signing, or compatibility testing; Rust TUI is the review/demo path.
4. **OPEN** — A dedicated PR on `codeberg-primary` that documents deletion, updates SBOM/scripts that still mention Haskell, and confirms `cargo test --lib` + release TUI build stay green has **not** been filed.
5. **OPEN** — Maintainer has **not** explicitly approved tree removal.

Until then: keep Cabal targets building if present; never recommend them for new installs. Do **not** delete Haskell in overnight polish commits.

---
**Legal / funding**

The Linux/desktop version remains free and open source. An Android build may later be offered as a paid app to fund infrastructure; pricing would decrease with adoption.
