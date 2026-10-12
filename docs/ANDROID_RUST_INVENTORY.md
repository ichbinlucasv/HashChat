# Android: Kotlin inventory (maximum-Rust migration, step 1)

Source: `android/src/main/java/MainActivity.kt` (1091 lines) and the JNI crate in `android/src/main/rust/`.

## Must stay in the Kotlin shell
- `MainActivity` lifecycle: `onCreate`, `onResume`, `onPause`, `onStop`, `onBackPressed`, `onActivityResult`.
- Permissions and system APIs: microphone recording/playback, camera QR scan, `BiometricPrompt`, Android Keystore (`HashChatKeystore`), `Settings.Global`, `Build.*` and `SystemProperties` reads.
- `System.loadLibrary` and the `external fun` declarations.

## Movable to Rust
| Kotlin today | Rust target | Status |
|---|---|---|
| `isStrictModeEnabled`, `shouldRefuseInStrictMode`, `reEvaluateSecurityPosture`, `isActionAllowedInPosture` (signal interpretation and gating) | `hashchat_rust::device_posture` | Policy done and tested; JNI binding next |
| `loadPersistedGroups`, `persistGroups` (group list serialization) | shared storage module | Open |
| `performCrossDeviceExport` (export flow logic) | `session_persist` | Open |
| `addMessage`, message list state, delivery state | shared message model (as in the TUI) | Open |
| Decoy/extreme profile state (`onToggleDecoyProfile`, `EXTREME_MODE`) | `duress` | Open |
| Voice chunk queue and framing | JNI crate already holds crypto; queue logic open | Open |
| Screens (RecyclerView adapters, dialogs) | Rust UI pilot (Slint or egui), step 3 | Open |

## Notes
- The JNI crate does not depend on the root crate yet; making it depend on `hashchat-rust` (path dependency) is the next step, so desktop and phone share one policy.
- Kotlin keeps collecting raw signals only; Rust decides. Unknown action names are refused.
