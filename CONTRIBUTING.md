# Contributing to HashChat

HashChat is a Rust messenger (desktop TUI + shared crypto crate). Android UI is thin Kotlin over the same crate.

**Primary**: https://codeberg.org/ichbinlucasv/HashChat  
**Mirror**: https://github.com/ichbinlucasv/HashChat

## Setup

```bash
cargo build --release --features tui --bin hashchat-tui
./run-tui
```

## Layout

- `src/rust/` — ratchet, identity, session, wire, Tor SOCKS, JNI
- `src/bin/hashchat_tui.rs` — desktop TUI
- `android/` — Kotlin UI only

There is no Haskell. Do not add GHC/Cabal.

## Rules

- Never commit `tor/hidden_service/`, `hashchat_data/`, or compiled `.so`
- Crypto changes go in `src/rust/ratchet.rs` and need tests
- Run `./scripts/opsec-pre-push.sh` then push Codeberg (`origin`) first
