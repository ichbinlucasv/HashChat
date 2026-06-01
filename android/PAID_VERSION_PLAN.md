# Android Paid Version Plan

## Goals
- Keep full source code open on Codeberg (primary) and GitHub mirror for auditability and trust.
- Offer the Android app as a paid download (initially ~20 CHF, later cheaper) to help fund infrastructure.
- Maintain the strongest possible security and OPSEC on Android.

## Proposed Structure
- **Free / Open Source**: All source code lives in this repo under `android/`.
- **Paid Distribution**: APK or F-Droid (with donation) or direct paid download.
- **Billing**: Use Google Play Billing or a self-hosted license server (preferred for privacy).
- **Hardened Storage**:
  - Use Android Keystore for passphrase-derived keys.
  - Store encrypted ratchet state and message logs using the same Argon2id + AES pattern as desktop.
  - Avoid storing sensitive data in cleartext SharedPreferences or external storage.

## Security Requirements (Non-Negotiable)
- All sensitive operations go through the existing Rust FFI (same as desktop).
- Panic wipe must work reliably on Android (clear app data + zeroize in-memory).
- No unnecessary permissions.
- Strong protection against backup extraction (exclude from backups where possible).

## Next Steps (when development starts)
1. Set up proper Android NDK + Rust + cargo-ndk build.
2. Implement JNI bindings for the new Rust blob encryption functions (skeleton already started in `android/src/main/rust/`).
3. Add billing + license validation (keep it minimal and auditable).
4. Port the TUI concepts to a proper Android UI (Jetpack Compose or XML + RecyclerView for messages).
5. Implement per-profile isolated encrypted storage using the same Argon2id + AES pattern.

A basic Rust + JNI skeleton now exists under `android/src/main/rust/`.

## Monetization Philosophy (Updated Recommendation)

- **Linux / Desktop**: Always free and fully open source.
- **Android**: Source remains 100% public on Codeberg (primary) + GitHub mirror. Distribution can be:
  - Self-hosted F-Droid repository (recommended for privacy)
  - Direct APK with donation-based unlock (preferred over Google Play billing)
  - Optional paid unlock key for convenience

**Why this is better for privacy:**
- No Google Play dependency
- Users can audit the exact same code they run
- Donation model aligns incentives without forcing surveillance capitalism

This approach keeps the project sustainable while maintaining the highest possible integrity.
