# HashChat plan

Primary: https://codeberg.org/ichbinlucasv/HashChat  
Mirror: https://github.com/ichbinlucasv/HashChat (push after Codeberg)

This is the working plan. Session diaries do not belong here.

## What is actually solid

- Rust Double Ratchet (DH + HKDF chains + skipped keys + zeroize)
- AES-256-GCM with a **fresh random nonce per seal** (wire: `nonce || ct || tag`)
- Argon2id + AES-GCM envelopes for ratchet / identity / blobs
- Long-term ed25519 + x25519 identity
- Brick TUI as the desktop UI
- Thin Kotlin UI + Rust JNI on Android
- Tor v3 hidden-service path on desktop (needs real two-device proof)

## What is not done (do not advertise)

- Mesh, Starlink, email DHT, public channels, self-host relay: stubs / demos
- Quantum hybrid: gated, unaudited `ml-kem`, Extreme should keep it off
- Tauri GUI: HTML stub
- Voice/calls: partial; Haskell `Call.hs` / `Voice.hs` are almost empty
- Two copies of the Rust crate (desktop `src/rust/` vs `android/src/main/rust/`)
- No signed tag. No independent audit.

## Work order (do these, in this order)

1. **OPSEC on every push** — `scripts/opsec-pre-push.sh`, Codeberg first, GitHub mirror second. Separate SSH keys when you rotate GitHub.
2. **One Rust crate** — delete the Android copy; JNI links `hashchat-rust`.
3. **Two-device Tor message** — profile → QR → send/recv → persist → wipe. Log it. That is the real v0.2 gate.
4. **FFI hygiene** — remaining unwraps, mlock honestly documented, no silent failures.
5. **Honest docs / icons / screenshots** — then a signed `v0.2` from Codeberg.

Do not start mesh, PQ-default, monetization, or Flathub until 1–4 are true.

## Remotes (this machine)

```
origin  git@codeberg.org:ichbinlucasv/HashChat.git
github  git@github.com:ichbinlucasv/HashChat.git
```

```bash
./scripts/opsec-pre-push.sh
git push origin main
git push github main
```
