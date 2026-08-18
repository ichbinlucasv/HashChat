# Contributing

Primary development: **Codeberg** https://codeberg.org/ichbinlucasv/HashChat  
GitHub is a read-only mirror.

```bash
cargo test --features tui
cargo build --release --features tui --bin hashchat-tui
./scripts/opsec-pre-push.sh
git push origin main
git push github main
```

- `src/rust/` — crate
- `src/bin/hashchat_tui.rs` — desktop
- `android/` — Kotlin UI

Do not add Haskell, C/C++, or a second crypto crate. Security bugs go privately, not as public issues.
