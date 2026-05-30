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
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc cargo
            ghc ghc96 cabal-install
            pkg-config openssl
            # For Tor testing
            tor
          ];

          shellHook = ''
            echo "=== HashChat Nix dev shell (maximum reproducible OPSEC) ==="
            echo "Rust + GHC + Cabal ready."
            echo "Recommended: still use ./build.sh tui for the full paranoid build inside Tails/Qubes."
            echo "The flake packages.hashchat-tui and rust-lib are the start of a 100% Nix path."
          '';
        };

        # Future: checks, apps, cross-compilation for Android, etc.
      });
}