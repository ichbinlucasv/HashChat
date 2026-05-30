{
  description = "HashChat - Maximum anonymity messenger (Haskell + Rust + Tor)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # For real reproducible Haskell + Rust in future:
    # rust-overlay.url = "github:oxalica/rust-overlay";
    # haskellNix.url = "github:input-output-hk/haskell.nix";
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
        ghcVersion  = "ghc96";

      in
      {
        packages = {
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

          # The TUI (requires the Rust lib to be in rust-lib/ at build time)
          hashchat-tui = pkgs.writeShellScriptBin "hashchat-tui" ''
            set -euo pipefail
            echo "Building HashChat TUI via Nix (reproducible path)..."
            # In a real flake we would use haskell.nix or cabal2nix + the rust-lib above
            # For now we call the audited build.sh (still the recommended path)
            ${pkgs.bash}/bin/bash ./build.sh tui
            echo "Run with: ./run-tui"
          '';

          # End-to-end Flatpak (the primary easy, sandboxed, installable distribution)
          # Builds the .flatpak bundle reproducibly (Fedora-first, Qubes/Tails friendly)
          hashchat-flatpak = pkgs.writeShellScriptBin "build-hashchat-flatpak" ''
            set -euo pipefail
            echo "=== HashChat Nix-driven Flatpak end-to-end build ==="
            ${pkgs.flatpak-builder}/bin/flatpak-builder --force-clean build-dir flatpak/org.hashchat.HashChat.yml
            ${pkgs.flatpak}/bin/flatpak build-export --force export-dir build-dir
            ${pkgs.flatpak}/bin/flatpak build-bundle --arch=x86_64 export-dir hashchat-tui.flatpak org.hashchat.HashChat
            echo "Installable bundle ready: hashchat-tui.flatpak"
            echo "flatpak install --user hashchat-tui.flatpak"
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc cargo
            ghc ghc96 cabal-install
            pkg-config openssl
            # For Tor testing
            tor
            # For end-to-end Flatpak builds (reproducible distribution)
            flatpak-builder
            flatpak
          ];

          shellHook = ''
            echo "=== HashChat Nix dev shell (maximum reproducible OPSEC) ==="
            echo "Rust + GHC + Cabal + flatpak-builder ready."
            echo "To build the full installable Flatpak end-to-end:"
            echo "  cd flatpak && ./build-flatpak.sh"
            echo "  # Produces hashchat-tui.flatpak (user-installable)"
            echo "Recommended: still use ./build.sh tui for the full paranoid build inside Tails/Qubes."
            echo "This flake now supports reproducible Flatpak as the primary easy distribution path."
          '';
        };

        # Future: checks, apps, cross-compilation for Android, etc.
      });
}