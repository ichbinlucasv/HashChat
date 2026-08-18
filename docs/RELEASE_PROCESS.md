# Release process

1. `./scripts/opsec-pre-push.sh`
2. `cargo test --release --features tui`
3. `cargo audit` if installed
4. Two-device check from INSTALL.md
5. Signed tag from **Codeberg**, then `git push github main --tags`

Do not tag if `hashchat_data/` or HS keys are in the commit. Do not force-push `main` unless a secret leaked.
