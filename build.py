#!/usr/bin/env python3
"""
HashChat build script.
Builds Rust FFI + Haskell (library + CLI by default).
Use `cabal build hashchat-tui` separately for the desktop TUI.
"""

import os
import subprocess
import platform

def run(cmd):
    print(f"→ {cmd}")
    subprocess.run(cmd, shell=True, check=True)

print(f"Building HashChat for {platform.system()}...\n")

run("cargo build --release")

# Stage the Rust library (needed for linking Haskell executables)
os.makedirs("rust-lib", exist_ok=True)
lib_name = "libhashchat_rust.so" if platform.system() != "Darwin" else "libhashchat_rust.dylib"
src = f"target/release/{lib_name}"
if os.path.exists(src):
    subprocess.run(f"cp {src} rust-lib/", shell=True)

run("cabal build -f-tui hashchat")      # library
run("cabal build -f-tui hashchat-cli")  # CLI

print("\nBuild finished successfully.")
print("For the TUI: cabal build hashchat-tui")
print("Launch TUI easily with: ./run-tui")