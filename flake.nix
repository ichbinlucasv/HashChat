{
  description = "HashChat - Maximum anonymity messenger (Haskell + Rust)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [];
        };

        # Pinned versions would go here in a real flake
        rustVersion = "1.82.0";
        ghcVersion = "ghc96";

      in
      {
        packages = {
          # Placeholder — full Nix build coming in future
          hashchat-tui = pkgs.writeShellScriptBin "hashchat-tui" ''
            echo "Nix build for HashChat is work in progress."
            echo "For now, use ./build.sh inside a Qubes disposable VM or Tails."
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            ghc
            cabal-install
            pkg-config
            openssl
          ];

          shellHook = ''
            echo "HashChat development shell (Nix)"
            echo "Note: This is experimental. Prefer ./build.sh for now."
          '';
        };
      });
}