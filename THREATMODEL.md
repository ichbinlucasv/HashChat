# HashChat Threat Model

**Version:** 0.2 (Deep Work Phase)
**Date:** 2026

## Goals
- Maximum anonymity and metadata resistance
- Strong forward secrecy and post-compromise security
- Resistance to mass surveillance and targeted attacks
- Plausible deniability where possible
- Fast, reliable device compromise response (Pegasus-like threats)

## Trust Assumptions & Non-Goals

**We do NOT protect against:**
- Full device compromise with persistent kernel-level access (Pegasus, NSO, etc.). Once an attacker has code execution on your device, all bets are off.
- Supply chain attacks on your build environment or Haskell/Rust compiler.
- Physical access to a powered-on device without screen lock + fast wipe.
- Side-channel attacks on the CPU (Spectre-class, unless mitigated by OS).

**We assume the user practices good OPSEC:**
- Uses Tor properly.
- Never reuses identities across contexts.
- Uses strong, unique passphrases.
- Runs the app on a dedicated or well-hardened machine when possible.

## Core Protections

### 1. Cryptographic Protections
- Double Ratchet with DH ratcheting + KDF chains (forward + future secrecy).
- AES-256-GCM for all message encryption.
- Argon2id + AES-256-GCM for all persistent sensitive state (ratchets + message logs).
- Per-contact isolated ratchet state.
- Skipped message key handling for out-of-order delivery.

### 2. Metadata Resistance (Current State)
- All communication is intended to go over Tor hidden services (v3).
- No phone numbers, emails, or persistent user IDs.
- Burner profiles allow quick identity isolation.
- Group design aims for sender keys (server cannot easily tell who sent what).

**Current Gaps (Being Worked On):**
- No real transport layer yet (messages are local only in current demo).
- Tor integration is present in the library but not fully wired into the high-level message path.

### 3. Device Compromise / "Pegasus" Resistance
**Best we can do (and what we are building toward):**

- **Panic Wipe** (`w` key + confirmation):
  - Securely erases ratchet state (via Rust zeroization).
  - Deletes `hashchat_data/`, Tor hidden service keys, databases.
  - Destroys in-memory ratchet objects.

- Encrypted-at-rest everything (ratchets + messages) using user passphrase + Argon2id.
- Minimal attack surface: No network stack in the main process until transport is added. Pure local TUI + FFI to Rust.

**Limitations (Honest):**
- If an attacker has already compromised your device before you hit wipe, they may have already exfiltrated keys or memory.
- Memory dumps before wipe are still dangerous.
- The TUI process itself runs with your user privileges.

### 4. Deniability
- Current design has some deniability properties due to ratchet (you can claim you never had certain keys after they were advanced).
- Future goal: Add "decoy" profiles or hidden volumes (plausible deniability of existence of other identities).

## Recommended Hardened Usage (Against Advanced Adversaries)

1. Run HashChat inside a Qubes OS disposable VM or Whonix.
2. Never use the same machine for both high-risk and low-risk activities.
3. Use hardware 2FA (YubiKey) for the machine itself if possible.
4. Keep the app closed when not actively using it.
5. Use the panic wipe early and often when threat model changes.
6. Consider running on a dedicated cheap laptop that can be physically destroyed.

## Current Security Posture (2026)

**Strong:**
- Cryptography core (ratchet + encryption)
- Encrypted persistent state
- Panic wipe tooling
- No central servers or identifiers by design

**Needs Significant Work:**
- Real anonymous transport (Tor hidden services + queueing)
- Full group sender key implementation + forward secrecy in groups
- Streaming voice/file with ratchet
- Android side with proper secure storage + JNI hardening
- Formal verification or at least property-based testing of the ratchet
- Plausible deniability features

## Pegasus / Nation-State Resistance Philosophy

We cannot stop a targeted zero-day on your device.

**What we can do extremely well:**
- Make it extremely hard for mass surveillance to work.
- Make targeted surveillance expensive and noisy (they need a 0-day + reliable persistence).
- Give you a fast "nuclear option" (wipe) that destroys cryptographic material and data.
- Minimize what remains on disk even if the device is seized powered off.

This is the realistic "best possible" for a local application.

---

**"The best anonymous and private and safer security chat ever made"** is not a marketing claim. It is an engineering goal we pursue by being brutally honest about limitations while relentlessly improving the parts we *can* control.