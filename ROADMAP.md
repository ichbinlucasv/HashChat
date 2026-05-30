# HashChat Roadmap — Towards the Best Private Messenger

Goal: Build a SimplexChat-level (or better) anonymous messenger using only **Haskell + Rust**, with strong focus on security, forward secrecy, and metadata resistance.

## Phase 1 — Foundations (Current)
- [x] Rust secure primitives (zeroization, AEAD, constant time)
- [x] Functional black/yellow/white Brick TUI (Desktop) with real ratchet persistence + encrypted messaging foundation (Editor widget temporarily simplified for build stability across Brick versions)
- [x] Real AES-GCM + **Double Ratchet foundation** (KDF chains + DH ratcheting started)
- [x] Panic Wipe + Logout on Desktop and Android (prominent)
- [x] Easy build system (`./build.sh` + launchers) — pure Bash (no Python)
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

## SimplexChat Button & Feature Parity (Desktop TUI + Android) — Required for User Respect
The explicit goal is that both the Brick TUI and the Android Kotlin UI feel *very close* in look, keyboard/mouse/touch flow, and available actions to SimplexChat.

**Minimum button / action set that must exist and behave similarly on both platforms:**
- Contact list with status (blocked, last seen, E2EE badge)
- Long-press / 'a' key / overflow on contact → menu with:
  - Block user (persist, drop messages, show [BLOCKED])
  - Mute notifications
  - Delete chat (local wipe only)
  - Report suspicious / mark for review
  - Set disappearing message timer (integrate with ratchet key wipe)
  - View security info / verify (ratchet public key fingerprint, QR in future)
  - Export encrypted transcript (for backup / legal)
- Chat input bar (bottom on Android, bottom on TUI) with send (Enter)
- Global top / menu actions:
  - Switch / create burner profiles (p/n)
  - Decoy / plausible deniability mode (D)
  - Security Posture dashboard (live, dynamic)
  - Tor / Network status
  - Panic Wipe (prominent red, confirmation)
  - Settings (disappearing defaults, self-destruct on wipe, etc.)
- Message-level actions (long-press on a message): Delete this message, Make disappearing, Copy (redacted), View ratchet step used.
- Visual style: Black background (#000), gold/yellow accents (#FFD700), white text, clear [E2EE], [D] for disappearing, security score in title bar on both platforms.

All of the above have been started in the TUI (action menu, blocked list, decoy, dynamic posture) and Android layout (gold theme + action buttons + docs). Full RecyclerView chat + exact menu parity is the next concrete UI task.

This level of parity + the 8 major paranoid features is what gives the project "respect of users" comparable to SimplexChat.
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
