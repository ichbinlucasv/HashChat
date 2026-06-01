# HashChat Threat Model

**Version:** 0.2 (Post Deep Expert Pass - Real Envelope + Android Parity)
**Date:** 2026 (updated after high-4 Argon2id envelope, full ratchet parity, med-10 tests, med-8 lifecycle, long-13 quantum gate)

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

**Current Gaps (Honest Assessment After Latest Pass):**
- Full bidirectional Tor v3 hidden service + framing is wired on desktop and partially on Android (receiver thread + JNI feed).
- Real Double Ratchet with skipped keys, zeroization, and full binary serialization is now present on **both** desktop and Android (high-4 completed for core).
- Android ratchet export now uses **real Argon2id + AES-256-GCM** envelope (v2) instead of demo XOR. This is a major OPSEC improvement for groups and cross-device.
- Voice chunking with per-chunk ratchet forward secrecy + real SeekBar + wipe on both sides.
- Group sender-key architecture + persistence with encrypted storage.
- Dynamic Security Posture gating actions on both platforms.
- Reproducible Nix paths (Flatpak strong, Android still requires cargo-ndk path but now fail-hard).

### Wave 8 Additions: Simplex-style Contact/Profile QR + Transport Expansion
- **ContactAddress / profile sharing**: Implemented hashchat://contact/v1/<onion>/<len:hexpub> links + parse/generate roundtrip in Haskell (Contact.hs). Wired into both thin CLI and real Brick TUI (app-desktop/TUI.hs) with :my-contact / :add-contact.
  - **Metadata reality**: Only public onion + public identity key in the QR/link. Private material never leaves device. Matches Simplex model and our burner philosophy.
  - **Wave 10 progress (Critical item)**: Real LongTermIdentity implemented in Rust (ed25519 + x25519 from seed, Argon2id+AES-GCM encrypted envelope reusing ratchet patterns, zeroize). FFI for new/get_public/export/import/wipe. Haskell Core wrappers + session-cached ID. TUI :my-contact now uses real ed25519 pub from the identity system instead of per-call random. Full per-profile encrypted storage + Android still to be wired (session demo for now). See docs/CONTACT_ADDRESS_LONGTERM_KEYS.md.
  - Extreme mode: generation should be refused (notes added; full gate pending deeper Android/TUI posture integration).
- **Transport (SOCKS5 foundation + I2P/bridges path)**: Generalized sendCiphertextOverTor + sendOverProxy(ProxyConfig) in Tor.hs. TUI and callsites updated to use it. Default = local Tor 9050. Per-profile proxy now fully functional (High #4): persist encrypted per profile in TUI (hashchat_data/proxies/<profile>.proxy.enc), UI shows in title/status, used in send/voice, Extreme refuses custom (forces default Tor-only). i2pProxyConfig added in Tor.hs, examples in :set-proxy and help (High #5 start: after i2pd, :set-proxy 127.0.0.1 4444 for I2P SOCKS).
  - **I2P**: Support started (SOCKS5 on 4444). Garlic routing for different metadata profile. Full .i2p addresses and i2pd launch in future.
  - **Tor bridges/pluggable**: User configures local Tor (torrc or Tor Browser bridges) with obfs4/snowflake; our SOCKS client just talks to the local port. No code change needed for basic support.
  - **Per-profile proxy**: Fully implemented and stable (persist, UI, send paths, Extreme gate). High-leverage for "use my VPN + Tor" or "I2P for this contact only" without global leak.
- **Extreme / posture expansion**: Full scoped ExtremeMode (per decision): Haskell IORef + Rust statics (desktop/Android), synced FFI set/get. TUI: :extreme on/off, getSecurityPosture returns EXTREME, isActionAllowed forces refuse for high-surface (groups/voice/contact/decoy/send etc), explicit gates in 'g'/'v'/'D'/'G', clear groups on enable, posture sync, title [EXTREME]. Android: setter, toggle in actions, hard if(EXTREME_MODE) for voice/groups/export/decoy/legacy/contact/member, ratchetNew errors on extreme. Rust: gates in ratchetNew (groups), VoiceStream new/process. Pre-tag enforces. Matches design: disables groups/voice/export/decoy/history, forces strict, aggressive wipes/minimal surface. See docs/EXTREME_PROFILE_DECISION.md + EXTREME_PROFILE.md.
- **Demo-pass surface**: Major progress in Wave 10 — legacy getInsecureGroupDemoPassphrase() and weak paths fully excised from MainActivity.kt. Group persistence now requires real HashChatKeystore-derived keys with hard failures in EXTREME/STRICT mode. Some migration notes remain; full replacement with proper Keystore flow is the remaining polish. Pre-tag checks treat any new demo-pass strings as hard failure.
- **Evidence / CI gates**: pre-tag-check.sh has hard exits for TESTING_EVIDENCE*.log and local .pre-tag-check-local-ran-<SHA> marker. Workflow audit step hardened (no more silent || true). Marker CI enforcement still future comment but pre-tag makes it blocking for any signed tag.
- **Supply chain**: cargo-binstall unpinned (CVSS 4.0 robust), ghcup SHA pinned, .so staging fail-hard. Still no reproducible Android .so or SBOM diff automation in CI.

These close more of the original expert table (transport priorities, Simplex QR alignment, pre-tag enforcement, demo surface pressure). Wave 10 progress: ContactAddress long-term keys full (Rust + TUI + Android parity for stable pub), Extreme scoped full in TUI (flag/cmd/gates/posture/state) + Android (setter/toggle/gates) + Rust (static/FFI/gates in ratchet/voice), VoiceStream advancing (per-stream elements + explicit end zeroize in Android Rust, call on playback). Remaining: full per-profile long-term persist + X3DH, complete VoiceStream per-stream + destroy everywhere, I2P actual, Android mlock full, real-hardware evidence logs (template ready), v0.2 tag.

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

**Needs Significant Work (Updated 2026 - after deep expert pass):**
- Real anonymous transport is now wired (bidirectional Tor v3 with proper framing).
- Full group sender key + persistence is implemented with encrypted storage.
- Streaming voice with per-chunk ratchet + SeekBar is working on both platforms.
- Android has Keystore + biometric gate + multi-screen + real export/import.
- Cross-device encrypted ratchet export is functional (with strong OPSEC warnings).
- Tests + CI now exercise many paranoid paths (wipe, posture, disappearing, export).

**Remaining Expert Priorities (v0.2 blocking + high polish):**
- Real professional icons (64/128/256/512 PNG + final SVG) + real screenshots (see ICONS.md + docs/SCREENSHOTS.md).
- Voice: real end-to-end chunking on both (Android mic now reads real bytes; TUI recording labeled demo).
- Android mlock: This is one of the most important remaining gaps. On Android, reliable mlockall(MCL_CURRENT | MCL_FUTURE) is not possible for unprivileged apps. The current implementation only does a best-effort libc::mlock on the single global ratchet store pointer and can (and frequently does) fail silently. Primary (and realistic) memory protections on Android are: Android Keystore (hardware-backed when available), app-private storage, short sensitive data lifetime via clearSensitiveScreenState + lifecycle, explicit ZeroizeOnDrop, and process death on wipe. This limitation is called out in the Rust source, the posture JNI response, RELEASE_NOTES_v0.2.md, and TESTING_STRATEGY.md. It should never be presented as strong memory protection on Android.
- Kotlin instrumented tests exercised regularly on real devices (not just emulators) with actual assertions.
- Move more logic (voice chunking, persistence helpers) into Rust while keeping JNI thin.
- SBOM / cargo-audit step before real release.
- Signed v0.2 tag execution after above + final clean + real-hardware test pass.

## Pegasus / Nation-State Resistance Philosophy

We cannot stop a targeted zero-day on your device.

**What we can do extremely well:**
- Make it extremely hard for mass surveillance to work.
- Make targeted surveillance expensive and noisy (they need a 0-day + reliable persistence).
- Give you a fast "nuclear option" (wipe) that destroys cryptographic material and data.
- Minimize what remains on disk even if the device is seized powered off.

This is the realistic "best possible" for a local application.

## Language & Architecture Choices vs Advanced Adversaries (MITRE ATT&CK, Nation-State, Cyber Kill Chain)

### Current Stack (Haskell + Rust core + thin Kotlin UI)
- **Rust** owns the entire security boundary: Double Ratchet, Argon2id envelopes, AES-GCM, zeroization, mlock hints, JNI export surface. This is the correct language for the "crown jewels."
- **Haskell** owns high-level protocol logic, state machines, TUI, group orchestration, Tor framing glue. Excellent for eliminating entire classes of logic bugs and injection-style issues (no raw string concatenation in critical paths, strong types).
- **Kotlin** (Android) is deliberately limited to UI + thin glue + Keystore/Biometric orchestration. All ratchet state and encryption is pushed across the JNI boundary into Rust.

### Attack Surface After Major Rust Migration on Android (2026 update — post strict mode + GroupSenderKey + Voice work)

Moving large amounts of sensitive logic into the Android Rust crate (Double Ratchet, GroupSenderKey with real HKDF-SHA256 advancement, VoiceStream per-chunk HKDF chains, Argon2id+AES-256-GCM export envelopes, strict mode environment checks, Tor receiver framing) is a net security win, but it changes the attack surface in specific, documented ways:

**Positive changes:**
- The "crown jewels" (ratchet material, sender keys, voice chunk keys, export blobs) now live in memory-safe Rust with zeroize, explicit wipe paths, and HKDF-based forward secrecy instead of Kotlin/Java.
- Strict mode (real checks for debug/emulator/root/qemu/test-keys + refusal gates on voice/groups/export/decoy) adds an active runtime control that did not exist before.
- Group forward secrecy for multi-party is now derived in Rust (not simulated count-fill).
- The JNI surface is intentionally kept thin and stable; most new logic is inside the Rust security boundary.

**Remaining / shifted risks (honest assessment):**
- The JNI boundary itself is now a higher-value target (type confusion, use-after-free in the FFI glue, or malicious Kotlin calling into Rust with bad state). We mitigate with very narrow function signatures and by moving as much logic as possible inside Rust.
- Android mlock remains fundamentally weak (best-effort only on the global store; no reliable MCL_CURRENT | MCL_FUTURE for unprivileged apps). Primary protections are still Keystore + app-private dirs + short lifetime + ZeroizeOnDrop + process death on wipe.
- Supply chain / build reproducibility on Android is harder than on desktop (NDK, gradle, Play Store signing if we ever go that route). We document this and prefer F-Droid + user-built paths.
- Dynamic posture + strict mode checks themselves can be bypassed on a fully compromised device (root + Frida + ptrace on the checks). They raise the bar for opportunistic malware and make casual analysis much harder, but they are not a root-of-trust against nation-state with physical access.
- Voice and group paths still have more Kotlin glue than ideal (MediaRecorder temp files, RecyclerView adapters, persistence helpers). Every new release must continue the migration.

This section must be re-read and updated after every significant Rust migration batch. The model assumes the attacker eventually gets code execution on the device; our job is to make extracting long-term keys, linking sessions, or surviving wipes as expensive and noisy as possible.

**ALL RECOMMENDATIONS deep wave status (current state):** 
- Simplex-style contact/profile QR: ContactAddress + ConnectionRequest foundation (public key model, Extreme awareness).
- Extreme profile: expanding hard gates (voice, groups, export, persistence, contact sharing).
- VoiceStream: real HKDF + zeroize + per-stream direction.
- Pre-tag: ultra-blocking with hard fails.
- demo-pass: final aggressive removal pressure.
- Transport: SOCKS5 foundation started.
Full ritual + force-with-lease + CI checks on every batch. See todo "ALL-Recs-Wave-Start" for parallel deep work on every item.

### Why This Is Strong Against the Threats You Mentioned

**Against nation-state / intelligence agencies / "branches" (Pegasus-class, Sandvine, etc.):**
- Memory-safe + type-safe core (Rust + Haskell) dramatically shrinks the bug surface that a 0-day would need to find.
- Cryptography is not in the "big unsafe language" (no C/C++ in the hot path).
- Aggressive zeroization + explicit wipe paths make post-exploitation key recovery harder.
- The architecture forces attackers to compromise two language runtimes + the JNI boundary if they want the ratchet material.

**DDoS / Availability (part of kill chain):**
- Tor v3 hidden services + no central infrastructure is the correct architectural choice. Changing language does almost nothing here — the transport model matters far more.
- Rust's async + Tokio (if we expand the receiver) would give better DoS resilience in the future than many alternatives.

**SQL Injection / Injection attacks (MITRE ATT&CK T1190, T1055, etc.):**
- Irrelevant in the current design. No SQL is exposed to any network input. If we ever add local SQLite, we will use the Rust `rusqlite` crate with parameterized queries only.
- Haskell's strong separation of code and data + Rust's ownership make classic injection bugs much harder to write by accident than in dynamic or weakly-typed languages.

**Full Cyber Kill Chain (Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions):**
- The current stack raises the bar at the **Exploit** and **Install** stages because there are fewer memory corruption primitives available to the attacker in the core.
- Post-exploitation (C2 + actions) is still game over on a fully compromised device — this is acknowledged in the model. The languages help most by making the initial foothold harder and the "actions on objectives" (stealing keys) noisier and less reliable.

### Expert Recommendation on Languages (No Hype)

**Do NOT do a big rewrite.** The current split is already close to optimal for a maximum-paranoid messenger in 2026:

1. **Keep Rust** as the sole owner of all cryptography, ratchet state, encrypted persistence, and low-level security primitives. If anything, move *more* logic into Rust over time (especially Android backend logic).

2. **Keep Haskell** for the high-level protocol, TUI, and correctness-critical orchestration. It is one of the best languages in existence for eliminating entire categories of bugs that nation-states love to exploit.

3. **For Android**: Stay with Kotlin for the UI layer, but **aggressively minimize** its privileges and surface. All new sensitive functionality (new persistence formats, more voice processing, future decentralized discovery) must go through the Rust JNI layer. This is already the direction.

4. **Never add** C, C++, Objective-C, or anything with manual memory management to the security boundary.

5. **Future considerations (only if expanding platforms)**:
   - iOS: Swift (much safer default than Kotlin for Apple).
   - Pure desktop TUI alternative: ratatui (Rust) would be a viable pure-Rust path if we ever want to deprecate the Haskell TUI.
   - Server components: Never. If we ever need any, Rust (or nothing).

**Bottom line for expert-level resistance**:
Language choice is important but **secondary** to:
- Attack surface minimization
- Cryptographic architecture (Double Ratchet + Tor v3 + no identifiers)
- Reproducible builds + clean supply chain (Nix + clean-security.sh ritual)
- User OPSEC + fast wipe
- Honest threat model

The current Haskell + Rust + thin Kotlin is a **strong** expert choice for the stated goals. Changing languages for the sake of "more expert" would most likely make things worse unless the entire architecture changed with it.

We should continue hardening the **boundaries** and **minimization** rather than chasing language fashion.

---

**"The best anonymous and private and safer security chat ever made"** is not a marketing claim. It is an engineering goal we pursue by being brutally honest about limitations while relentlessly improving the parts we *can* control.