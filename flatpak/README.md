# HashChat Flatpak

Sandboxed distribution for the **Rust** desktop binary `hashchat-tui` (built with `--features tui`).

## Tor requirement (host)

The Flatpak **does not bundle Tor**. You must run a host Tor daemon with:

- SOCKS on loopback (typically `9050` or Tor Browser `9150`)
- `ControlPort 9051` + `CookieAuthentication 1`
- A ControlPort cookie file readable by the user running the app (typical path: `/run/tor/control.authcookie`)

HashChat discovers the cookie path via Tor `PROTOCOLINFO` (`COOKIEFILE=…`) and fail-closes if the cookie is missing or unreadable. There is **no silent clearnet fallback**.

**Never** paste ControlPort cookies or onion private keys into issues, chats, or screenshots. Do not `cat` / `hexdump` the cookie file when debugging — use `systemctl is-active tor`, `ss -ltn`, and `test -r` on the cookie path instead.

See root `INSTALL.md` for Fedora / Ubuntu / Arch / Tails / Qubes walkthroughs (including group membership for cookie read access and Whonix onion-grater caveats).

## Build (reproducible)

```bash
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

Preferred matching source build:

```bash
cargo build --release --locked --bin hashchat-tui --features tui
```

The manifest is **install-only**: Nix prebuilds `prebuilt/hashchat-tui` and the Rust library, then Flatpak packs them. Binary name inside the app: **`hashchat-tui`**.

## Icons (logo 2, black + gold)

Hicolor icons are under `icons/hicolor/` (scalable SVG + 64/128/256/512 PNG).
Desktop file and metainfo use `Icon=org.hashchat.HashChat`. See [ICONS.md](./ICONS.md).

## Brand / metainfo

- Black + gold Rust TUI; logo 2 chat-bubble / hash mark
- Metainfo documents the host-Tor requirement
- Screenshots remain placeholders until captured per `docs/SCREENSHOTS.md`

## Checklist

- [x] Install-only manifest + Nix prebuilts
- [x] Command / binary: `hashchat-tui` (Rust)
- [x] Logo 2 icons installed from hicolor
- [x] Tor requirement documented (README + metainfo + INSTALL.md)
- [ ] Real screenshots for Flathub
- [ ] Signed public release polish

## Contact

Open an issue on the Codeberg primary repository (`codeberg-primary` tip).
