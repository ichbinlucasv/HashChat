# Security policy

**Primary**: https://codeberg.org/ichbinlucasv/HashChat  
**Mirror**: https://github.com/ichbinlucasv/HashChat

Report vulnerabilities privately (Codeberg security advisory or the maintainer). Do not open a public issue for crypto bugs.

## Do not commit

- `tor/hidden_service/`, `hashchat_data/`, `*.onion` private keys
- `rust-lib/`, `target/`, compiled `.so`
- Tor control cookies, passphrases

## Crypto

Owned by `src/rust/ratchet.rs`, `longterm_identity.rs`, `wire.rs`.

- Double Ratchet, AES-256-GCM (random nonce prepended)
- Contact bootstrap: X25519 DH of long-term keys
- Later messages: ephemeral DH on frame v2
- At-rest: `hashchat_data/machine.key` (0600) wraps `state.enc`

`ml-kem` is optional, unaudited, off by default.

## Tor

`:listen` uses the control port (`ADD_ONION`) and **keeps that TCP connection open**. Closing the TUI drops a non-persisted onion; persisted keys are replayed on the next `:listen`.

## Wipe

`w` zeroizes ratchets and deletes `hashchat_data/` plus local HS material. If the device was already compromised, keys may already be gone.
