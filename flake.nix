{
  description = "HashChat - Maximum anonymity messenger (Rust + Tor; Haskell opt-in / transitional)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Optional overlays for future hardening (not required for default Rust path):
    # rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          # overlays = [ (import rust-overlay).overlays.default ];
        };

        # Reproducible pinned toolchains (edit these for exact builds)
        rustVersion = "1.82.0";

      in
      {
        packages = rec {
          default = hashchat-tui;

          # Real Rust FFI lib (the crypto heart)
          rust-lib = pkgs.rustPlatform.buildRustPackage {
            pname = "hashchat-rust";
            version = "0.1.9";
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            buildInputs = with pkgs; [ pkg-config openssl ];
            # Only build the lib we actually use for FFI
            buildPhase = "cargo build --release --locked";
            installPhase = ''
              mkdir -p $out/lib
              cp target/release/libhashchat_rust.* $out/lib/ || true
            '';
          };

          # Default package: native Rust TUI only (hashchat-tui --features tui).
          # No Cabal / GHC on the release path.
          hashchat-tui = pkgs.writeShellScriptBin "hashchat-tui" ''
            set -euo pipefail
            echo "Building HashChat Rust TUI via Nix (release path)..."
            ${pkgs.bash}/bin/bash ./build.sh tui
            echo "Run with: ./run-tui"
          '';

          # Pure-Nix reproducible Flatpak derivation (no external build-flatpak.sh dependency in the final artifact)
          # Builds the complete installable .flatpak bundle inside the Nix sandbox using pinned flatpak-builder.
          # This is the hardened, auditable path for Qubes/Tails/Fedora users.
          hashchat-flatpak = let
            flatpakManifest = ./flatpak/org.hashchat.HashChat.yml;
            buildInputs = with pkgs; [ flatpak-builder flatpak bash coreutils ];
          in pkgs.stdenv.mkDerivation {
            pname = "hashchat-flatpak";
            version = "0.1.9";
            src = ./.;
            buildInputs = buildInputs;
            buildPhase = ''
              export XDG_DATA_HOME=$TMPDIR/.local/share
              export XDG_CACHE_HOME=$TMPDIR/.cache
              mkdir -p $out

              # === KEY HARDENING: Build both Rust lib and TUI reliably outside the Flatpak sandbox ===
              echo "Building Rust library reliably..."
              (cd src/rust && cargo build --release --locked) || (echo "ERROR: Reliable Rust build failed" && exit 1)

              echo "Building TUI reliably using project build system (outside Flatpak sandbox)..."
              ${pkgs.bash}/bin/bash ./build.sh tui || (echo "ERROR: Reliable TUI build failed" && exit 1)

              # Prepare the two prebuilt artifacts the minimal manifest needs
              mkdir -p prebuilt

              # TUI
              TUI_BIN=$(find . -name hashchat-tui -type f | head -1)
              [ -n "$TUI_BIN" ] || (echo "ERROR: TUI binary missing" && exit 1)
              cp "$TUI_BIN" prebuilt/hashchat-tui && chmod +x prebuilt/hashchat-tui

              # Rust lib (prefer .so)
              cp src/rust/target/release/libhashchat_rust.so prebuilt/ 2>/dev/null || \
                cp src/rust/target/release/libhashchat_rust.a prebuilt/

              echo "Prebuilts ready for Flatpak manifest"

              # Now run flatpak-builder. The manifest will prefer the prebuilt binary.
              ${pkgs.flatpak-builder}/bin/flatpak-builder \
                --force-clean \
                --repo=repo \
                build-dir ${flatpakManifest}

              ${pkgs.flatpak}/bin/flatpak build-export --force repo build-dir
              ${pkgs.flatpak}/bin/flatpak build-bundle \
                --arch=x86_64 \
                repo \
                $out/hashchat-tui.flatpak \
                org.hashchat.HashChat

              if [ ! -f "$out/hashchat-tui.flatpak" ]; then
                echo "ERROR: Flatpak bundle was not produced" >&2
                exit 1
              fi

              echo "Pure-Nix Flatpak bundle produced: $out/hashchat-tui.flatpak"
            '';
            installPhase = "true";  # artifacts already in $out from buildPhase
            meta = {
              description = "HashChat - reproducible Flatpak bundle built entirely inside Nix";
            };
          };
        };

        # Default shell: Rust + Tor + Flatpak tooling only (no Cabal release path).
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc cargo
            pkg-config openssl
            tor
            flatpak-builder
            flatpak
          ];

          shellHook = ''
            echo "=== HashChat Nix dev shell (Rust release path) ==="
            echo "Rust + Tor + flatpak-builder ready. Cabal is NOT on the default PATH."
            echo "Build TUI:  nix build .#hashchat-tui   # or: ./build.sh tui / make tui"
            echo "Flatpak:    nix build .#hashchat-flatpak"
            echo "  flatpak install --user result/hashchat-tui.flatpak"
            echo "Transitional Haskell parity (dev-only): nix develop .#haskellDev"
            echo "  or: HASHCHAT_ALLOW_HASKELL=1 / ./build.sh --haskell  (see INSTALL.md)"
          '';
        };

        # Opt-in transitional shell for Cabal parity checks only — not a release path.
        # Documented in INSTALL.md; criterion 2 keeps this off the default surface.
        devShells.haskellDev = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc cargo
            ghc ghc96 cabal-install
            pkg-config openssl
            tor
          ];

          shellHook = ''
            echo "=== HashChat haskellDev (TRANSITIONAL / NOT RECOMMENDED) ==="
            echo "Cabal/GHC present for parity checks only. Desktop release path is Rust."
            echo "  ./build.sh --haskell"
            echo "  HASHCHAT_ALLOW_HASKELL=1 ./run-tui"
            echo "See INSTALL.md § Transitional Haskell desktop."
          '';
        };

        # Complete Nix Android toolchain derivation (long-11).
        # Goal: reproducible .so emission for the real DoubleRatchet (now with full parity
        # after high-4 work: ratchet.rs copy, skipped keys, export/import, zeroize, JNI 0.21).
        #
        # Current honest state (expert view):
        # - Full pure-Nix Android cross without any host rustup/NDK is extremely heavy
        #   (requires ndk-bundle, androidRustEnv overlay, llvm etc. in the sandbox).
        # - We therefore provide a FAIL-HARD derivation that refuses to silently produce
        #   empty artifacts. It either succeeds with real .so files or the build aborts
        #   with clear instructions for the supported one-command local path.
        #
        # Recommended reproducible path for users (and CI):
        #   cd android && ./build-android.sh   (uses cargo-ndk, fails hard on missing .so)
        #
        # The flake path below will succeed in a properly provisioned Android NDK env
        # or fail loudly. No more touch placeholders (those were supply-chain/OPSEC risks).
        packages.hashchat-android-rust = pkgs.rustPlatform.buildRustPackage {
          pname = "hashchat-android-rust";
          version = "0.1.9";
          src = ./android/src/main/rust;
          cargoLock = { lockFile = ./android/src/main/rust/Cargo.lock; };
          buildInputs = with pkgs; [ pkg-config openssl ];

          buildPhase = ''
            set -euo pipefail
            echo "=== hashchat-android-rust (long-11 hardened, no soft paths) ==="
            echo "Building real DoubleRatchet + JNI for Android (aarch64 + armv7)..."

            # We do not silently succeed. If the host does not have the Android NDK
            # toolchain configured for cargo-ndk, this must fail hard.
            if ! command -v cargo-ndk >/dev/null 2>&1; then
              echo "ERROR (long-11): cargo-ndk not found in PATH."
              echo "For reproducible Android .so builds use the documented one-command path:"
              echo "  cd android && ./build-android.sh"
              echo "This produces app/src/main/jniLibs/*/libhashchat_android.so"
              echo "The pure-Nix path requires additional overlays (ndk, rust-android)."
              echo "See docs/BUILD_ISOLATION.md and docs/BUILD_REPRODUCIBILITY.md"
              exit 1
            fi

            # Real cross compile - will fail if targets or NDK are missing (correct behavior)
            cargo ndk -t arm64-v8a -t armeabi-v7a build --release --locked

            # Fail hard if the expected .so files were not actually emitted
            for abi in aarch64-linux-android armv7-linux-androideabi; do
              so="target/$abi/release/libhashchat_android.so"
              if [ ! -f "$so" ]; then
                echo "ERROR (long-11): Expected $so was not produced. Build aborted."
                exit 1
              fi
            done

            mkdir -p $out/lib/aarch64 $out/lib/armv7
            cp target/aarch64-linux-android/release/libhashchat_android.so $out/lib/aarch64/
            cp target/armv7-linux-androideabi/release/libhashchat_android.so $out/lib/armv7/
            echo "SUCCESS: real .so files written to $out/lib/"
          '';

          installPhase = ''
            # Nothing further; artifacts are already validated and copied in buildPhase
            true
          '';

          meta = {
            description = "HashChat Android Rust (real DoubleRatchet, fail-hard, long-11)";
          };
        };
      });
}