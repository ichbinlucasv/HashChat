# Local Tor host setup for HashChat TUI

**Audience:** Operators running the Rust `hashchat-tui` against a **local** Tor daemon  
**Client:** Rust desktop TUI only (Haskell desktop is transitional / not recommended)  
**Companion install steps:** [`INSTALL.md`](../INSTALL.md) (Critical: Tor setup)  
**Maintainer validation:** [`TWO_PEER_VALIDATION.md`](TWO_PEER_VALIDATION.md)  
**OPSEC when filing bugs:** [`OPSEC_REPORTING.md`](OPSEC_REPORTING.md)

This note describes how to run **host Tor** so HashChat can use loopback SOCKS and a cookie-authenticated ControlPort. Transport is **Tor-only** and **fail-closed**: there is **no silent clearnet fallback**.

---

## What HashChat needs

| Need | Typical value | Notes |
|------|---------------|--------|
| SOCKS | `127.0.0.1:9050` (system Tor) or `127.0.0.1:9150` (Tor Browser) | **Loopback only** |
| ControlPort | TCP `9051` | Desktop TUI expects **9051** today |
| Auth | `CookieAuthentication 1` | Cookie only; **no** bare `AUTHENTICATE` |

HashChat discovers the cookie path via Tor `PROTOCOLINFO` (`COOKIEFILE=…`), reads that file, and authenticates with cookie `AUTHENTICATE` only. If the cookie is missing or unreadable, `:listen` / ControlPort use **fails closed**.

---

## Minimal `torrc` (system Tor)

Edit `/etc/tor/torrc` (Fedora / Ubuntu / Debian / Arch) and ensure:

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

Then enable and restart:

```bash
sudo systemctl enable --now tor
sudo systemctl restart tor
```

Distro-specific install and group notes: [`INSTALL.md`](../INSTALL.md) (Fedora / Ubuntu / Arch / Tails / Qubes sections).

### Sample hardened `tor/torrc` in this repo

`tor/torrc` is an example hardened config. It may use `ControlPort auto` / a control socket. The **desktop Rust TUI currently expects TCP ControlPort `9051`**. For HashChat desktop, prefer the minimal stanza above unless you knowingly change both Tor and the client.

---

## SOCKS: 9050 vs 9150

| Listener | Common source | Use |
|----------|---------------|-----|
| `127.0.0.1:9050` | System `tor` package | Default for HashChat desktop |
| `127.0.0.1:9150` | Tor Browser bundle | Optional if you point the TUI at Tor Browser’s SOCKS |

- Bind SOCKS to **loopback** only. Do not expose SOCKS on LAN interfaces for HashChat.
- Use `:set-proxy` only if your TUI build supports adjusting SOCKS — **never** point at clearnet.
- Tor Browser’s ControlPort layout differs from system Tor; for `:listen` / `ADD_ONION`, prefer a system Tor with ControlPort `9051` + cookie auth as above.

---

## ControlPort: cookie auth only

Required behavior:

1. Open ControlPort on **loopback** (TCP `9051` for the desktop TUI).
2. Set **`CookieAuthentication 1`**.
3. HashChat sends `PROTOCOLINFO`, reads `COOKIEFILE="…"`, then authenticates with the cookie.
4. **Do not** configure HashChat to use a bare password `AUTHENTICATE`, and do not weaken Tor to allow unauthenticated ControlPort access.

If cookie auth cannot succeed, HashChat **refuses** ControlPort operations (fail-closed). That is expected.

---

## Cookie file permissions and groups

**Typical paths** (confirm via Tor `PROTOCOLINFO`, not by publishing contents):

| Environment | Common cookie path |
|-------------|--------------------|
| Fedora / Arch / modern Tor | `/run/tor/control.authcookie` |
| Debian / Ubuntu | `/run/tor/control.authcookie` (alias `/var/run/tor/…`) |
| Some Tor layouts | `/var/lib/tor/control_auth_cookie` |
| Tails / Whonix | Under `/run/tor/` when ControlPort is exposed; often filtered |

**Permissions:** the OS user running `hashchat-tui` must be able to **read** the cookie file.

- Debian / Ubuntu: commonly add the user to the **`debian-tor`** group, then log out and back in.
- Fedora / Arch: commonly the **`tor`** group (as configured by the package), then re-login.
- Fix group/permissions — **do not** copy cookie bytes into the home directory “for convenience.”

**Safe checks** (never print cookie contents):

```bash
systemctl is-active tor
ss -ltn | grep -E '9050|9051|9150' || true
test -r /run/tor/control.authcookie && echo "cookie file readable" || echo "cookie file not readable (fix group/permissions)"
```

---

## IsolateSOCKSAuth (Tor default)

Tor’s **default** for `SocksPort` includes **`IsolateSOCKSAuth`**: distinct SOCKS username/password credentials get distinct circuits.

- Leave Tor’s default **enabled**. Do not disable `IsolateSOCKSAuth` for HashChat.
- The sample `tor/torrc` in this repo documents `IsolateSOCKSAuth` explicitly on `SocksPort`; a bare `SocksPort 9050` still keeps Tor’s default isolation behavior.
- HashChat may pass per-contact SOCKS credentials so Tor opens separate circuits (see `THREATMODEL.md`). That is a **best-effort Tor SOCKS feature**, not a substitute for separate Tor instances, bridges, or defending a compromised Tor client.
- Inbound hidden-service accept remains a single local listener; isolation applies to **outbound** SOCKS CONNECT.

---

## Fail-closed expectations

| Condition | Expected client behavior |
|-----------|--------------------------|
| Tor / SOCKS down | Send / retry refuse or queue; **no** clearnet path |
| ControlPort down or filtered | `:listen` / `ADD_ONION` fail; **no** workaround via clearnet |
| Cookie missing / unreadable | ControlPort auth fails closed (no bare `AUTHENTICATE`) |
| Non-Tor mode | Not a silent fallback; any alternate network must be an **explicit** user choice |

Tails and Whonix often **filter** ControlPort (e.g. onion-grater). If `ADD_ONION` is unavailable, document the limitation — do not invent clearnet bypasses. Details: [`INSTALL.md`](../INSTALL.md) (Tails / Qubes sections).

---

## OPSEC: never paste ControlPort secrets

Do **not** put any of the following into tickets, chat, screenshots, git commits, or shell history shared with others:

- Tor control **cookies** / cookie file bytes
- Cookie **paths that embed secrets**
- ControlPort passwords / hashed authenticators
- Onion **private keys** / `ED25519-V3:` blobs
- Full onion addresses or raw `hashchat://` contact links (when filing public bugs)

Safe to share: tip SHA, OS / Tor **versions**, `socks=ok|fail` / `control=ok|fail` from `:evidence`, and whether the cookie file is **readable** (boolean) — never the bytes.

Reporting guidance: [`OPSEC_REPORTING.md`](OPSEC_REPORTING.md). What `:evidence` prints: [`VALIDATION_EVIDENCE.md`](VALIDATION_EVIDENCE.md).

---

## Quick verification checklist

- [ ] `tor` is active (`systemctl is-active tor`)
- [ ] SOCKS listening on loopback `9050` and/or `9150`
- [ ] ControlPort listening on loopback `9051`
- [ ] `CookieAuthentication 1` in effect
- [ ] Cookie file **readable** by the HashChat user (`test -r`, no `cat`)
- [ ] `:listen` succeeds or fails closed with a clear error — never falls back to clearnet
- [ ] Optional: `:evidence` shows `socks=ok` / `control=ok` (metadata only)

For two-host maintainer exercises, continue with [`TWO_PEER_VALIDATION.md`](TWO_PEER_VALIDATION.md).
