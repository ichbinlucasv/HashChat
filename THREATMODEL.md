# HashChat threat model

**Version:** 0.3-dev (Rust-only desktop)  
**Date:** 2026-08-18

## Goals

- No phone numbers or central accounts
- Forward secrecy after the first exchange (symmetric chain + later DH)
- Tor v3 only for network
- Fast wipe

## We do not stop

- Kernel implants on a live device
- Compiler / rustc supply chain
- A seized disk if `hashchat_data/machine.key` is there and the box is unlocked
- You reusing the same identity in two contexts

## Crypto (honest)

| Item | Reality |
|---|---|
| Message AEAD | AES-256-GCM, random 12-byte nonce |
| First messages | X25519 of long-term keys → `init_symmetric` |
| Later messages | Frame v2 carries sender DH; recv learns then ratchets |
| Onion reuse | Tor private key wrapped on disk |
| PQ | Gated, unaudited, off |

## Transport

Default: local Tor SOCKS 9050 + ControlPort 9051. Relays / mesh / I2P are not in this tree.

A network observer sees Tor. A malicious HS peer sees sizes and timing. Ciphertext is opaque.

## Trust

Use a dedicated user or Qubes/Tails for high-risk work. Exchange `hashchat://` links out of band. Never paste a private key.

## Language

Rust owns crypto, TUI, Tor control, persist. Kotlin is Android chrome only.
