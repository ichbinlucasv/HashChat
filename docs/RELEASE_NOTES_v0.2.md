# HashChat notes (2026-08-18)

Not a signed tag. Desktop is the Rust TUI.

## This tree

- Rust-only desktop (`hashchat-tui`)
- Haskell sources removed
- One crate for crypto + JNI (`--features android`)
- Two-device path: `:listen`, `:my-contact`, `:add-contact`, SOCKS send, HS recv
- Frame v2 includes sender DH
- Onion key + identity persisted under `hashchat_data/`
- Offline queue + `:retry`

## Not in this tree

- Signed `v0.2`
- Android two-device Tor
- Independent audit
- SimpleX GUI parity (never the goal of this TUI)

When you return: run two real machines, then consider a signed tag only after that works.
