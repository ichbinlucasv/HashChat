# HashChat threat model

**Version:** 0.2-dev  
**Date:** 2026-08-18

## Goals

- Metadata-resistant messaging (no phone numbers, no central user IDs)
- Forward secrecy and post-compromise security (Double Ratchet)
- Fast wipe when the device is about to be seized
- Small, auditable crypto boundary in Rust

## We do not claim to stop

- Kernel-level implant (Pegasus-class) on a live device
- Compiler / toolchain supply-chain compromise
- Physical access to an unlocked, powered-on machine
- CPU side channels unless the OS already mitigates them
- An operator who reuses identities or skips Tor

## Trust

The user runs Tor correctly, uses unique passphrases, and treats each profile as one context. Prefer Qubes disposable VM, Tails, or a dedicated machine.

## Cryptography (current)

| Piece | Status |
|---|---|
| Double Ratchet in Rust | Real (DH + HKDF + skipped keys + zeroize) |
| Message AEAD | AES-256-GCM, random 12-byte nonce prepended |
| Extra HMAC | HMAC-SHA256 with caller key (no hardcoded self-compare) |
| At-rest | Argon2id (64 MiB, 3 iter) + AES-256-GCM envelope |
| Long-term identity | ed25519 + x25519, same envelope |
| PQ / ML-KEM | Optional, unaudited, off by default |
| FFI stores | Mutex (no `static mut`) |

Ratchet message keys are still meant to be single-use. The nonce is random anyway so accidental key reuse is not an immediate GCM catastrophe.

## Transport

Default path is Tor v3 hidden services + SOCKS. Per-profile proxy exists. I2P / mesh / relay / Starlink are optional overlays and are **not** production. Extreme mode must force Tor-only.

A relay operator can see sizes and timing. Ciphertext must stay opaque. Do not treat a user-run relay as trusted.

## Device compromise

Panic wipe shreds ratchet state, `hashchat_data/`, and Tor HS keys, then zeroizes Rust objects. If the attacker already had code execution, keys may already be gone.

Android `mlock` is best-effort only. Real protections there are Keystore, short secret lifetime, and process death.

## Surfaces we added and then left half-built

These increase attack surface if enabled:

- Self-host relay (correlation)
- Public channels (spam + subscriber correlation)
- Tauri webview (XSS if capabilities leak)
- Mesh / UDP beacons (local network metadata)
- Unaudited PQ crate (do not ship as default)

Extreme mode should refuse all of the above.

## Supply chain

- Primary forge is Codeberg. GitHub is a mirror.
- Review `sbom/` before any signed tag. One SBOM tree is enough.
- `cargo audit` before tag. Do not commit pre-tag marker files.

## Language split

Rust owns keys, ratchets, AEAD, envelopes. Haskell owns TUI + Tor control. Kotlin is UI + JNI only. Do not add C/C++. Do not rewrite the TUI until the Rust core is one crate with tests.
