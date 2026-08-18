# Install HashChat

**Clone from Codeberg** (primary). GitHub is a mirror.

```bash
git clone https://codeberg.org/ichbinlucasv/HashChat.git
cd HashChat
```

## Fast path

```bash
chmod +x install.sh && ./install.sh
./run-tui
```

`install.sh` detects Fedora, Ubuntu/Debian, or Arch and runs the matching script. Those scripts install a C toolchain + rustup if needed, then:

```bash
cargo build --release --locked --features tui --bin hashchat-tui
```

Manual (any Linux with rustup):

```bash
sudo apt/dnf/pacman install …  # gcc, pkg-config, openssl headers, git, curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo build --release --locked --features tui --bin hashchat-tui
./run-tui
```

Nix (optional):

```bash
nix build .#hashchat-tui
./result/bin/hashchat-tui
```

There is **no GHC / Cabal** step.

## Tor (required for two devices)

`/etc/tor/torrc` (or user torrc):

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

Then:

```bash
sudo systemctl enable --now tor
```

Cookie file must be readable by your user. If `:listen` says auth failed:

- Debian/Ubuntu: add yourself to the `debian-tor` group, or copy cookie perms as documented by your distro
- Do not turn cookie auth off on a shared machine

Optional QR:

```bash
sudo apt/dnf/pacman install qrencode
```

## Two-device checklist

1. Tor running on both sides (9050 + 9051)
2. Both: `./run-tui` then `:listen`
3. Both: `:my-contact` and exchange the link
4. Both: `:add-contact <their link>`
5. Send. First circuit can take ~30s. `:retry` if one side was down.

Identity + onion key are stored under `hashchat_data/` (`machine.key` mode 0600 + `state.enc`). `w` deletes that. A seized unlocked disk can still read it — use a dedicated user or VM if that matters.

## Android

```bash
./build-android.sh
```

Produces `android/src/main/jniLibs/*/libhashchat_rust.so`. Kotlin still owns the screens. Two-device Tor on the phone is **not** finished (use Orbot + the desktop path for now).

## Tails / Qubes

Build in a disposable VM, copy only the `hashchat-tui` binary if you must. Point SOCKS at Whonix/sys-whonix if that is your Tor. `:set-proxy 127.0.0.1 9050` (or the Whonix socks port you actually use).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `:listen failed` + auth | Cannot read Tor cookie / ControlPort is not 9051 |
| `Tor send failed` | Peer not listening, or first HS descriptor not published yet — wait and `:retry` |
| `unknown sender` | You did not `:add-contact` their link |
| `peer has no onion` | They ran `:my-contact` before `:listen` |
