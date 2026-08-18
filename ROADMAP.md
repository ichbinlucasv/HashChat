# HashChat plan

Primary: https://codeberg.org/ichbinlucasv/HashChat  
Mirror: https://github.com/ichbinlucasv/HashChat

Desktop is Rust. Android UI is Kotlin. No Haskell.

## Done

- One crypto crate (`src/rust/`) + JNI feature `android`
- Rust TUI (`hashchat-tui`)
- X25519 contact links, frame v2 with ephemeral DH, Tor `:listen` / SOCKS send / HS recv
- Encrypted local state + onion key reuse
- Offline send queue (`:retry`)
- Docs match the code (2026-08-18)

## When you come back

1. Run two real machines through INSTALL.md and fix whatever cookie/ControlPort issues you hit
2. Persist contacts (not only identity/onion) so `:add-contact` survives restart
3. Android: Orbot SOCKS + same contact link / send-recv (no second crate)
4. Frame-level tests against a live Tor if you have a spare VPS
5. `cargo audit` + one SBOM + signed tag only after (1)

## Do not start with

Mesh, Starlink, email DHT, Tauri as default, ML-KEM on by default, Flathub, or monetization.

## Remotes

```bash
./scripts/opsec-pre-push.sh
git push origin main          # Codeberg
git push github main          # mirror
```
