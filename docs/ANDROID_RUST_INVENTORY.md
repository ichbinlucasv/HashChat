# Android: Kotlin inventory (maximum-Rust migration, step 1)

Source: `android/src/main/java/MainActivity.kt` (1091 lines) and the JNI crate in `android/src/main/rust/`.

## Must stay in the Kotlin shell
- `MainActivity` lifecycle: `onCreate`, `onResume`, `onPause`, `onStop`, `onBackPressed`, `onActivityResult`.
- Permissions and system APIs: microphone recording/playback, camera QR scan, `BiometricPrompt`, Android Keystore (`HashChatKeystore`), `Settings.Global`, `Build.*` and `SystemProperties` reads.
- `System.loadLibrary` and the `external fun` declarations.

## Movable to Rust
| Kotlin today | Rust target | Status |
|---|---|---|
| `isStrictModeEnabled`, `shouldRefuseInStrictMode`, `reEvaluateSecurityPosture`, `isActionAllowedInPosture` (signal interpretation and gating) | `hashchat_rust::device_posture` | **Done:** JNI `evaluatePostureFromSignals` / `isActionAllowedForSignals`; Kotlin collects signals only |
| `loadPersistedGroups`, `persistGroups`, member add/remove, leave group (group list state) | `hashchat_rust::group_store::GroupBook` | **Done:** Rust owns the list (validation, limits, legacy `name:ids` migration); JNI `groupBook*`; Kotlin only renders and wraps `groupBookExport()` with the Keystore. Per-member sender-key blobs are not persisted yet |
| `performCrossDeviceExport` (export flow logic) | `session_persist` | Open |
| `addMessage`, message list state, delivery state | `hashchat_rust::message_book::MessageBook` | **Done (2026-10-17):** Rust owns the transcript (stable ids, direction flag, delivery state, disappearing deadline, sanitised and capped text, 2000-entry bound, zeroize on removal); JNI `messageBook*`; Kotlin renders `messageBookTexts`/`messageBookMine` and Keystore-wraps `messageBookExport` into `messages.enc`; EXTREME/strict books are ephemeral (export nothing, file deleted). Bubble direction no longer comes from a `You:` text prefix |
| Decoy/extreme profile state (`onToggleDecoyProfile`, `EXTREME_MODE`) | `duress` | Open |
| Voice chunk queue and framing | JNI crate already holds crypto; queue logic open | Open |
| Screens (RecyclerView adapters, dialogs) | Rust UI pilot (Slint or egui), step 3 | Open |

## Notes
- The JNI crate depends on `hashchat-rust` (path) and calls shared `device_posture` / will grow toward other shared modules.
- Kotlin keeps collecting raw signals only; Rust decides. Unknown action names are refused.
- Next: decoy/extreme profile state (`duress`), then the export flow. Persisting group sender keys needs a user-derived key from profile unlock (still open).
