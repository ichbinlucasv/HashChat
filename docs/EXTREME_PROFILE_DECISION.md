# Extreme Profile Decision — HashChat

**Status**: Draft — Decision Required Before v0.2  
**Owner**: ichbinlucasv  
**Date**: 2026-06  
**Related**: ROADMAP.md, THREATMODEL.md, TESTING_STRATEGY.md

---

## Background

HashChat already has a strong "burner + decoy profile" model with Dynamic Security Posture and nuclear wipe.

Some users (journalists, activists, high-value targets in very hostile environments) may need an even smaller attack surface than the current model allows.

The ROADMAP proposed an optional **"Extreme" profile** mode that deliberately disables large parts of the feature surface in exchange for minimal trusted computing base and metadata exposure.

This decision must be made explicitly before v0.2.

---

## The Core Question

Do we want to support a real, first-class **Extreme mode** (disabled by default, user must explicitly enable it), or is the current burner + decoy + strict mode sufficient for the project's threat model?

### Option A — Full Extreme Mode (Recommended in early roadmap thinking)

A dedicated, heavily restricted operating mode with the following hard gates:

- Groups completely disabled
- Voice recording and playback disabled
- Cross-device ratchet export / import disabled
- Decoy profiles disabled (only one burner profile allowed)
- No persistent contacts or message history beyond current session (or very short lifetime)
- Strict mode forced on at all times with no bypass
- Even more aggressive memory wiping + shorter key lifetimes
- Smaller attack surface on Android (if we ever split APKs)
- Possibly reduced transport options

**Goal**: Give the most paranoid users (Pegasus-class threats, airgapped or near-airgapped operation) a credible "ultra-stripped" tool.

**Implementation sketch**:
- Top-level `ExtremeMode` flag (compile-time feature or runtime profile setting)
- Gating logic in both TUI and Android
- Dedicated section in THREATMODEL.md
- Clear UX warning when enabling ("This mode is for extreme threat environments only")

**Pros**:
- Honest product differentiation for the highest-risk users
- Forces us to keep the core minimal and auditable
- Marketing / positioning value ("the most paranoid mode available")

**Cons**:
- Significant additional complexity and testing surface
- Maintenance burden (every new feature must consider Extreme mode)
- Risk of the mode becoming bitrotted if not used

---

### Option B — No Dedicated Extreme Mode

Keep only the current model:
- Burner profiles + optional decoy
- Dynamic Security Posture (Strict mode)
- Nuclear wipe as the main panic tool
- User education + documentation instead of code-level feature removal

**Pros**:
- Much simpler codebase and testing matrix
- Easier to maintain high quality on the features that exist
- Still extremely strong for most realistic threat models

**Cons**:
- Highest-risk users may feel the current model still has too much surface
- We may lose some very paranoid users to other tools (or to rolling their own minimal clients)

---

## Current Codebase State (as of 2026-06)

- Many features already have `isStrictModeEnabled()` checks.
- `EXTREME_MODE` constant / gating already exists in some Android paths (especially group persistence demo-pass).
- VoiceStream, groups, and export paths have partial posture gating.
- No unified `ExtremeMode` flag yet across the whole application.

---

## Recommendation (Current)

**Lean toward Option A (implement a real Extreme mode)**, but scoped carefully:

- Make it a **runtime profile setting** (not compile-time) for v0.2-preview.
- Gate the highest-risk features first: Groups, Voice, Cross-device export.
- Keep the implementation minimal in Wave 10/11.
- Document it very clearly as "for journalists and high-risk users in active targeting situations only".

This aligns with the project's philosophy of being honest about limitations and giving users real choices.

---

## Decision Required

**Final Decision**:

[X] Implement scoped Extreme mode (recommended above)  
[ ] Do not implement dedicated Extreme mode (rely on current burner + posture model)  
[ ] Defer decision until after v0.2-preview

**Date of Decision**: 2026-06  
**Decided by**: Lucas (ichbinlucasv@noreply.codeberg.org)

---

## Next Actions (once decision is made)

- [x] Create `ExtremeMode` flag in core (Haskell IORef, wired to TUI + synced to Rust FFI)
- [x] Wire gating into TUI (groups, voice, contact QR, decoy, 'G' send refused; command :extreme on/off; posture returns EXTREME string; isActionAllowed forces false; clear groups/history on enable; securityPosture sync; title [EXTREME])
- [x] Full Rust side ExtremeMode (static in desktop + Android crates; set/get FFI; gates in ratchetNew for groups, VoiceStream creation/process)
- [x] Wire gating into Android (setter JNI, toggle in actions menu, many hard if(EXTREME_MODE) for voice/groups/export/decoy/legacy/contact/member mgmt; ratchetNew errors on extreme)
- [x] Update THREATMODEL.md and EXTREME_PROFILE.md (status: TUI full core, Android+ Rust advancing to full per design)
- Pre-tag check added for Extreme impl.
- Add tests... (in progress via pre-tag)
- Document in README + SECURITY.md (partial via NOTES/THREATMODEL)

---

**This document will be updated once the decision is recorded.**