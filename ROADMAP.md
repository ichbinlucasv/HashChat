# HashChat Roadmap — Towards the Best Private Messenger

Goal: Build a SimplexChat-level (or better) anonymous messenger using only **Haskell + Rust**, with strong focus on security, forward secrecy, and metadata resistance.

## Phase 1 — Foundations (Current)
- [x] Rust secure primitives (zeroization, AEAD, constant time)
- [x] Functional black/yellow/white Brick TUI (Desktop) with real ratchet persistence + encrypted messaging foundation (Editor widget temporarily simplified for build stability across Brick versions)
- [x] Real AES-GCM + **Double Ratchet foundation** (KDF chains + DH ratcheting started)
- [x] Panic Wipe + Logout on Desktop and Android (prominent)
- [x] Easy build system (`./build.py` + launchers)
- [x] Ratchet FFI exposed to Haskell + live in TUI
- [x] Real Tor control port + onion persistence (basic working implementation with persistence)
- [x] Proper Android multi-screen UI (bottom nav: Chats/Contacts/Settings) + JNI bridge expanded
- [ ] Full production Double Ratchet (very close)
- [ ] Complete Tor + Android production integration

## Phase 2 — Core Security Features
1. **Proper Double Ratchet + per-contact ratchet state**
   - KDF chains
   - DH ratcheting
   - Skipped message keys
   - Header encryption

2. **Real Tor hidden service support**
   - Automatic .onion address generation
   - Hidden service descriptor management
   - Circuit isolation

3. **Self-destructing / disappearing messages**
   - Per-message TTL
   - Burn after reading

4. **Voice messages with forward secrecy**
   - Streaming encryption
   - Ratchet per chunk

5. **File transfer with streaming encryption**
   - Chunked + ratcheted encryption
   - Resume support

6. **"Burner" profiles / multiple identities**
   - Separate ratchet states per profile
   - Quick profile switching

## Phase 3 — Advanced
7. **Full Android with Rust backend + nice UI**
   - Proper JNI/NDK bridge
   - Material You dark theme matching the yellow/black aesthetic

8. **Group chats with proper metadata resistance**
   - Sender anonymity within groups
   - No central servers knowing who talks to whom

## Long Term / Cool Features
- Quantum-resistant options (post-quantum KEMs)
- Decentralized discovery (without leaking metadata)
- Plausible deniability modes
- Cross-device sync with ratchet state export (securely)

## Current Status (as of last build)
- Ratchet module exists in Rust with real KDF chains
- TUI demonstrates encrypt/decrypt roundtrips
- Wipe + Logout is prominent on both platforms

We are building this the right way: small trusted computing base, Haskell for correctness, Rust for performance/crypto.

Contributions welcome — especially in the Ratchet and Tor integration areas.
