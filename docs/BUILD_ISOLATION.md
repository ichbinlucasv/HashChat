# Secure Build Isolation Guide

This document explains how to build HashChat in highly isolated environments for maximum resistance against supply-chain attacks, compromised build machines, and advanced adversaries.

## Recommended Environments (in order of preference)

### 1. Tails OS (Strongly Recommended for Paranoid Builds)

Tails is amnesic by design. Every boot is a clean slate.

**How to build in Tails:**

1. Boot Tails with persistence disabled (or use a new persistent volume only for tools).
2. Install build dependencies via `apt` (they will be wiped on shutdown).
3. Clone the repo.
4. Run `./build.sh`.

**Advantages:**
- No persistent malware from previous builds.
- All network traffic goes through Tor.
- Excellent for one-off high-security builds.

### 2. Qubes OS (Best Long-term Environment)

**Recommended setup:**

- Create a **disposable VM** based on Fedora or Debian.
- In that disposable VM:
  - Clone the repository
  - Install dependencies
  - Run `./build.sh`

**Even stronger (Qubes best practice):**
- Use a dedicated "build" AppVM that only has network access when you explicitly allow it.
- Use `qvm-copy` to move the resulting binaries to your main machine.

### 3. Minimal Virtual Machine (Good Compromise)

- Clean Fedora or Debian VM
- Snapshot before building
- Revert after building
- Never reuse the VM for daily activities

## General Hardening Rules

- Never build on your daily driver machine.
- Disable swap or use encrypted swap + `swapon -a` only when needed.
- Do not install unnecessary packages.
- Verify the git commit hash / signed tags before building.
- Consider building inside a container or VM even on Tails/Qubes for extra layers.

## Future Direction

We are moving toward official Nix flakes + Qubes/Tails build scripts so that a single command can produce a fully reproducible and isolated build.

---

**"If you wouldn't run the resulting binary on your machine, you shouldn't build it on your machine either."** — HashChat OPSEC philosophy