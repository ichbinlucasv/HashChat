# HashChat - Exact SimpleX + Session mix, 100% open source, multi-platform

Supported: Fedora, Debian, Arch, Windows, Android.

No IDs. No phones. Random per-profile keys. Tor hidden service default. SMP queues. Double-ratchet E2EE + extra HMAC. Full files (1GB chunked). Voice/Audio/Video. 2-click Panic Wipe. Dark mode only.

Build on Fedora:
cargo build && cabal build && python3 build.py

Android APK:
cd android && ./gradlew assembleDebug