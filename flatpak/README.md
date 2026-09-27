# HashChat Flatpak

Sandboxed distribution for the **Rust** desktop binary `hashchat-tui` (built with `--features tui`).

## Tor requirement (host)

The Flatpak **does not bundle Tor**. You must run a host Tor daemon with:

- SOCKS on loopback (typically `9050` or Tor Browser `9150`)
- `ControlPort 9051` + `CookieAuthentication 1` (HashChat authenticates with **SAFECOOKIE only**; no bare `AUTHENTICATE`)
- A ControlPort cookie file readable by the user running the app

HashChat reads the cookie path from Tor `PROTOCOLINFO` (`COOKIEFILE=…`) but only **trusts** the known system locations listed in [`docs/TOR_HOST_SETUP.md`](../docs/TOR_HOST_SETUP.md#trusted-cookie-paths-and-hashchat_tor_cookie_file) (e.g. `/run/tor/control.authcookie`, `/var/lib/tor/control_auth_cookie`). If Tor writes its cookie anywhere else, set `HASHCHAT_TOR_COOKIE_FILE` to the **absolute** path of Tor's own cookie file. A missing, unreadable, or untrusted cookie makes `:listen` **fail closed**. There is **no silent clearnet fallback**.

**Inside the Flatpak sandbox:** the only filesystem permission the manifest grants is `--filesystem=home`. It does **not** expose `/run/tor` or `/var/lib/tor`, so the app cannot read a system cookie until you grant read-only access to the cookie's directory yourself, for example:

```bash
flatpak override --user --filesystem=/run/tor:ro org.hashchat.HashChat        # or /var/lib/tor:ro, matching your Tor
flatpak override --user --env=HASHCHAT_TOR_COOKIE_FILE=/abs/path org.hashchat.HashChat   # only for a non-standard cookie path
```

A non-standard cookie path also needs its directory exposed read-only unless it is already under your home directory. Your user still needs host read permission on the cookie (group membership). Point at the file Tor itself writes; do not copy the cookie into your home directory to get around the sandbox.

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

- Product surface: Rust TUI (`hashchat-tui`); black + gold; logo 2 chat-bubble / hash mark
- Metainfo documents host Tor + fail-closed non-Tor (no silent clearnet fallback)
- Preview packaging only — not a production-readiness claim
- Screenshots remain placeholders until captured per `docs/SCREENSHOTS.md`

## Checklist

- [x] Install-only manifest + Nix prebuilts
- [x] Command / binary: `hashchat-tui` (Rust)
- [x] Logo 2 icons installed from hicolor
- [x] Tor requirement documented (README + metainfo + INSTALL.md)
- [x] Fail-closed / no silent clearnet fallback documented
- [ ] Real screenshots for Flathub
- [ ] Signed public release polish

## Contact

Open an issue on the Codeberg primary repository (`codeberg-primary` tip).
