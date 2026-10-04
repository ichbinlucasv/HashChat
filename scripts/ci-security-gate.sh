#!/usr/bin/env bash
#
# HashChat CI security gate (deterministic, no network / no Tor daemon).
#
# Fail-closed checks for crypto/Tor OPSEC regressions that must block every
# push/PR on codeberg-primary. Safe to run offline in Forgejo or locally.
#
# Usage:
#   ./scripts/ci-security-gate.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v rg >/dev/null 2>&1; then
  SEARCH=(rg -n --glob '!**/target/**' --glob '!**/.git/**')
else
  echo "FATAL: ripgrep (rg) is required for the CI security gate"
  exit 1
fi

fail() {
  echo ""
  echo "!!! CI SECURITY GATE FAILED: $*"
  exit 1
}

pass() {
  echo "  OK: $*"
}

echo "================================================================"
echo "  HashChat CI security gate (fail-closed, offline)"
echo "================================================================"

# ---------------------------------------------------------------------------
# 1) Messenger transport: Clearnet/I2P must remain explicit refusals.
#    Prefer policy anchors over fragile TcpStream greps (tests/bind use TCP).
# ---------------------------------------------------------------------------
echo "[1/6] NetMode fail-closed anchors (Clearnet/I2P + TUI gate)..."

"${SEARCH[@]}" 'ClearnetRefused' src/rust/net_mode.rs >/dev/null \
  || fail "NetModeError::ClearnetRefused missing from src/rust/net_mode.rs"
pass "ClearnetRefused present"

"${SEARCH[@]}" 'I2pNotImplemented' src/rust/net_mode.rs >/dev/null \
  || fail "NetModeError::I2pNotImplemented missing from src/rust/net_mode.rs"
pass "I2pNotImplemented present"

"${SEARCH[@]}" 'fn require_messenger_transport' src/rust/net_mode.rs >/dev/null \
  || fail "require_messenger_transport missing from net_mode.rs"
pass "require_messenger_transport defined"

# TUI must call the transport gate (send/listen refuse non-Tor).
if ! "${SEARCH[@]}" 'require_messenger_transport' src/bin/hashchat_tui.rs >/dev/null; then
  fail "hashchat_tui.rs does not reference require_messenger_transport"
fi
pass "TUI references require_messenger_transport"

# Tor SOCKS helpers must still refuse non-loopback / non-onion (policy functions).
"${SEARCH[@]}" 'fn is_loopback_host' src/rust/tor_socks.rs >/dev/null \
  || fail "is_loopback_host missing from tor_socks.rs"
"${SEARCH[@]}" 'fn is_onion_destination' src/rust/tor_socks.rs >/dev/null \
  || fail "is_onion_destination missing from tor_socks.rs"
"${SEARCH[@]}" 'fn socks_isolation_credentials' src/rust/tor_socks.rs >/dev/null \
  || fail "socks_isolation_credentials missing from tor_socks.rs"
"${SEARCH[@]}" 'fn socks_isolation_for_contact' src/rust/tor_socks.rs >/dev/null \
  || fail "socks_isolation_for_contact missing from tor_socks.rs"
"${SEARCH[@]}" 'fn socks_isolation_for_onion' src/rust/tor_socks.rs >/dev/null \
  || fail "socks_isolation_for_onion missing from tor_socks.rs"
"${SEARCH[@]}" 'struct SocksIsolationCreds' src/rust/tor_socks.rs >/dev/null \
  || fail "SocksIsolationCreds missing from tor_socks.rs"
"${SEARCH[@]}" 'REDACTED' src/rust/tor_socks.rs >/dev/null \
  || fail "SocksIsolationCreds Debug redaction missing"
"${SEARCH[@]}" '0x02' src/rust/tor_socks.rs >/dev/null \
  || fail "SOCKS username/password method (0x02) missing from tor_socks.rs"
"${SEARCH[@]}" 'socks_isolation_enabled' src/rust/net_mode.rs >/dev/null \
  || fail "socks_isolation_enabled missing from net_mode.rs"
"${SEARCH[@]}" 'ExtremeSocksIsolation' src/rust/net_mode.rs >/dev/null \
  || fail "ExtremeSocksIsolation missing from net_mode.rs"
if ! "${SEARCH[@]}" 'socks_isolation_for_contact' src/bin/hashchat_tui.rs >/dev/null; then
  fail "hashchat_tui.rs does not wire socks_isolation_for_contact"
fi
pass "tor_socks loopback + onion + IsolateSOCKSAuth helpers present"

# Lightweight smell: no TcpStream connect/connect_timeout to well-known clearnet
# literals in production sources (tests may use loopback only).
CLEAR_HITS="$("${SEARCH[@]}" 'TcpStream::connect(?:_timeout)?\([^;]*"(?:8\.8\.8\.8|1\.1\.1\.1|example\.com|google\.com)'     src/rust src/bin 2>/dev/null || true)"
if [[ -n "${CLEAR_HITS}" ]]; then
  echo "$CLEAR_HITS"
  fail "suspicious clearnet TcpStream::connect literal in src/rust or src/bin"
fi
pass "no obvious clearnet TcpStream connect literals"

# ---------------------------------------------------------------------------
# 2) HASHCHAT_INSECURE_DEV_PERSIST must remain opt-in (never production default).
# ---------------------------------------------------------------------------
echo "[2/6] Insecure-dev persist remains opt-in..."

"${SEARCH[@]}" 'HASHCHAT_INSECURE_DEV_PERSIST' src/rust/session_persist.rs >/dev/null \
  || fail "HASHCHAT_INSECURE_DEV_PERSIST reference missing from session_persist.rs"

# from_flags must gate on explicit insecure_dev OR env — not always-on.
if ! "${SEARCH[@]}" 'insecure_dev \|\| std::env::var_os\("HASHCHAT_INSECURE_DEV_PERSIST"\)' \
    src/rust/session_persist.rs >/dev/null; then
  fail "PersistMode::from_flags no longer requires explicit insecure_dev/env opt-in"
fi
pass "from_flags still requires insecure_dev || env opt-in"

# Production TUI path must be passphrase-derived: unlock via unlock_session
# (Argon2id once, then a zeroizing StoreKey) and never the insecure machine key.
if ! "${SEARCH[@]}" 'unlock_session\(' src/bin/hashchat_tui.rs >/dev/null; then
  fail "hashchat_tui.rs does not unlock via unlock_session (passphrase-derived key)"
fi
if "${SEARCH[@]}" 'InsecureDevMachineKey' src/bin/hashchat_tui.rs >/dev/null; then
  fail "hashchat_tui.rs references InsecureDevMachineKey"
fi
# TUI must refuse running when insecure env is set (passphrase-only production).
if ! "${SEARCH[@]}" 'HASHCHAT_INSECURE_DEV_PERSIST' src/bin/hashchat_tui.rs >/dev/null; then
  fail "hashchat_tui.rs no longer mentions HASHCHAT_INSECURE_DEV_PERSIST refuse path"
fi
pass "TUI passphrase-only + insecure-env refuse path present"

# Fail if code *sets* the env var or defaults PersistMode to insecure (docs may mention =1).
SET_HITS="$("${SEARCH[@]}" 'set_var\(\s*"HASHCHAT_INSECURE_DEV_PERSIST"' src/rust src/bin 2>/dev/null || true)"
if [[ -n "${SET_HITS}" ]]; then
  echo "$SET_HITS"
  fail "code sets HASHCHAT_INSECURE_DEV_PERSIST via set_var (must remain caller/env opt-in)"
fi
# Default impl must not be InsecureDevMachineKey.
if "${SEARCH[@]}" 'impl Default for PersistMode' src/rust/session_persist.rs >/dev/null 2>&1; then
  DEF="$("${SEARCH[@]}" -A6 'impl Default for PersistMode' src/rust/session_persist.rs || true)"
  if echo "$DEF" | grep -q 'InsecureDevMachineKey'; then
    fail "PersistMode::Default appears to select InsecureDevMachineKey"
  fi
fi
pass "insecure persist not force-enabled in Rust sources"

# ---------------------------------------------------------------------------
# 3) Tor ControlPort: cookie AUTHENTICATE only (refuse bare AUTHENTICATE).
# ---------------------------------------------------------------------------
echo "[3/6] Tor control cookie AUTHENTICATE fail-closed..."

"${SEARCH[@]}" 'fn authenticate_cookie_only' src/rust/hidden_service.rs >/dev/null \
  || fail "authenticate_cookie_only missing from hidden_service.rs"
pass "authenticate_cookie_only present"

"${SEARCH[@]}" 'refusing bare AUTHENTICATE' src/rust/hidden_service.rs >/dev/null \
  || fail "fail-closed 'refusing bare AUTHENTICATE' string missing"
pass "refusing bare AUTHENTICATE string present"

"${SEARCH[@]}" 'COOKIEFILE' src/rust/hidden_service.rs >/dev/null \
  || fail "COOKIEFILE handling missing from hidden_service.rs"
pass "COOKIEFILE handling present"

# Cookie auth must send AUTHENTICATE {hex}, not a bare AUTHENTICATE command.
"${SEARCH[@]}" 'AUTHENTICATE \{hex\}' src/rust/hidden_service.rs >/dev/null \
  || fail "AUTHENTICATE {hex} cookie path missing from hidden_service.rs"
pass "AUTHENTICATE {hex} cookie path present"

# Fail if a bare AUTHENTICATE string literal appears as a complete command arg.
if "${SEARCH[@]}" '"AUTHENTICATE"' src/rust 2>/dev/null | grep -q .; then
  fail "bare AUTHENTICATE string literal found under src/rust (cookie-only required)"
fi
# Also catch AUTHENTICATE with only trailing whitespace inside quotes.
if "${SEARCH[@]}" '"AUTHENTICATE[[:space:]]*"' src/rust 2>/dev/null | grep -q .; then
  fail "whitespace-only AUTHENTICATE string literal found under src/rust"
fi
pass "no bare AUTHENTICATE command literals under src/rust"

# ControlPort peer must prove cookie knowledge (SAFECOOKIE) before we authenticate,
# and the advertised COOKIEFILE must resolve to an allowed location.
"${SEARCH[@]}" 'AUTHCHALLENGE SAFECOOKIE' src/rust/hidden_service.rs >/dev/null \
  || fail "SAFECOOKIE AUTHCHALLENGE missing from hidden_service.rs"
"${SEARCH[@]}" 'ct_eq\(&server_hash\)' src/rust/hidden_service.rs >/dev/null \
  || fail "constant-time SAFECOOKIE server hash check missing"
"${SEARCH[@]}" 'fn resolve_cookie_path' src/rust/hidden_service.rs >/dev/null \
  || fail "COOKIEFILE location allowlist missing"
pass "SAFECOOKIE mutual proof + COOKIEFILE allowlist present"

# HS accept path must keep bounded queue + strict inbound frame max (DoS backpressure).
"${SEARCH[@]}" 'MAX_HS_INBOUND_FRAME' src/rust/hidden_service.rs >/dev/null \
  || fail "MAX_HS_INBOUND_FRAME missing from hidden_service.rs"
pass "MAX_HS_INBOUND_FRAME present"

"${SEARCH[@]}" 'HS_INBOUND_QUEUE_CAP' src/rust/hidden_service.rs >/dev/null \
  || fail "HS_INBOUND_QUEUE_CAP missing from hidden_service.rs"
pass "HS_INBOUND_QUEUE_CAP present"

"${SEARCH[@]}" 'sync_channel' src/rust/hidden_service.rs >/dev/null \
  || fail "bounded sync_channel missing from hidden_service.rs"
pass "HS sync_channel (bounded inbound queue) present"

# One slow peer must not stall others: per-connection threads under a cap, and
# total-time (not per-read) frame deadlines.
"${SEARCH[@]}" 'HS_MAX_CONCURRENT_CONNS' src/rust/hidden_service.rs >/dev/null \
  || fail "HS_MAX_CONCURRENT_CONNS missing from hidden_service.rs"
"${SEARCH[@]}" 'fn read_frame_with_deadlines' src/rust/hidden_service.rs >/dev/null \
  || fail "deadline-bounded HS frame reader missing"
pass "HS concurrent connection cap + frame deadlines present"


# Best-effort memory lock: TUI must call mlockall after unlock (desktop anti-swap).
"${SEARCH[@]}" 'mlockall_current' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs does not call mlockall_current (best-effort anti-swap)"
pass "TUI references mlockall_current"

# Idle / manual lock: TUI must clear RAM secrets and return to unlock (local UI defense).
"${SEARCH[@]}" 'fn lock_ui' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs missing lock_ui (idle/:lock RAM clear)"
pass "TUI references lock_ui"

# Core dumps off + non-dumpable before any secret exists (best-effort).
"${SEARCH[@]}" 'disable_core_dumps_best_effort\(\)' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs does not disable core dumps at startup"
pass "TUI disables core dumps at startup"

# Panic path must install the best-effort scrub hook before entering the TUI.
"${SEARCH[@]}" 'install_panic_scrub_hook' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs does not install the panic scrub hook"
pass "TUI installs panic scrub hook"

# At-rest state files: owner-only, symlink-refusing, atomic writes.
"${SEARCH[@]}" 'O_NOFOLLOW' src/rust/private_fs.rs >/dev/null \
  || fail "private_fs.rs no longer opens state files with O_NOFOLLOW"
"${SEARCH[@]}" 'TooPermissive' src/rust/private_fs.rs >/dev/null \
  || fail "private_fs.rs no longer refuses group/other-accessible state files"
"${SEARCH[@]}" 'private_fs::read_private_file' src/rust/session_persist.rs >/dev/null \
  || fail "session_persist.rs does not load state through private_fs"
"${SEARCH[@]}" 'check_state_storage' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs does not check state storage before unlock"
pass "state files owner-only + O_NOFOLLOW + TUI pre-unlock storage check"

# Contact key change must drop SAS verification (no trust carry-over).
"${SEARCH[@]}" 'fn upsert_contact_from_link' src/rust/session_persist.rs >/dev/null \
  || fail "upsert_contact_from_link missing from session_persist.rs"
"${SEARCH[@]}" 'upsert_contact_from_link' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs does not add contacts via upsert_contact_from_link"
if "${SEARCH[@]}" 'Keep existing verified/unverified status on update' src/bin/hashchat_tui.rs >/dev/null; then
  fail "hashchat_tui.rs reintroduced verified-status carry-over on contact update"
fi
pass "contact identity change resets SAS verification"

# Untrusted text must be sanitised before any ratatui widget sees it.
"${SEARCH[@]}" 'fn sanitize_for_terminal' src/rust/term_sanitize.rs >/dev/null \
  || fail "sanitize_for_terminal missing from term_sanitize.rs"
"${SEARCH[@]}" 'sanitize_for_terminal\(&lossy\)' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs does not sanitise decrypted peer text"
"${SEARCH[@]}" 'terminal_safe_owned\(text.into\(\)\)' src/bin/hashchat_tui.rs >/dev/null \
  || fail "hashchat_tui.rs ChatLine no longer sanitises stored transcript text"
pass "TUI sanitises peer text and transcript before render"

# ---------------------------------------------------------------------------
# 4) Workflow wires this script + cargo audit (I-1).
# ---------------------------------------------------------------------------
echo "[4/6] Forgejo workflow wires this gate + cargo audit..."

WF=".forgejo/workflows/build.yml"
if [[ ! -f "$WF" ]]; then
  fail "$WF missing"
fi
if ! grep -q 'ci-security-gate.sh' "$WF"; then
  fail "build.yml does not invoke scripts/ci-security-gate.sh"
fi
pass "Forgejo build.yml invokes ci-security-gate.sh"

# Required job still runs cargo test --lib and TUI build.
if ! grep -q 'cargo test --lib' "$WF"; then
  fail "build.yml missing cargo test --lib"
fi
if ! grep -E -q 'hashchat-tui.*features tui|features tui.*hashchat-tui' "$WF"; then
  # Also accept split across lines: --bin hashchat-tui and --features tui nearby
  if ! grep -q 'hashchat-tui' "$WF" || ! grep -q -- '--features tui' "$WF"; then
    fail "build.yml missing hashchat-tui --features tui build"
  fi
fi
pass "required cargo test --lib + TUI build still present"

# I-1: CI must run cargo audit; known ratatui transitive warnings live in .cargo/audit.toml.
if ! grep -q 'cargo audit' "$WF"; then
  fail "build.yml missing cargo audit (I-1 supply-chain gate)"
fi
pass "Forgejo build.yml invokes cargo audit"

AUDIT_TOML=".cargo/audit.toml"
if [[ ! -f "$AUDIT_TOML" ]]; then
  fail "$AUDIT_TOML missing (I-1 known ratatui advisory ignores)"
fi
for id in RUSTSEC-2024-0436 RUSTSEC-2026-0002 RUSTSEC-2026-0253; do
  if ! grep -q "$id" "$AUDIT_TOML"; then
    fail "$AUDIT_TOML missing documented ignore $id"
  fi
done
pass ".cargo/audit.toml documents ratatui transitive ignores (I-1)"

# Soft cargo audit when the tool + advisory DB are already present (offline-friendly).
# Missing tool/DB must NOT fail this offline gate — Forgejo installs/fetches them.
if command -v cargo >/dev/null 2>&1 && cargo audit --version >/dev/null 2>&1; then
  ADVISORY_DB="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
  if [[ -d "$ADVISORY_DB" ]]; then
    if cargo audit --deny warnings --no-fetch --stale >/tmp/hashchat-cargo-audit.out 2>&1; then
      pass "cargo audit --deny warnings clean (offline, ignores applied)"
    else
      echo "---- cargo audit output ----"
      cat /tmp/hashchat-cargo-audit.out || true
      fail "cargo audit found vulnerabilities or new denied warnings"
    fi
  else
    pass "cargo-audit present but advisory DB missing — soft-skip (Forgejo fetches)"
  fi
else
  pass "cargo-audit not installed locally — soft-skip (Forgejo installs)"
fi
# Do not require clippy — optional and must not introduce flaky failures.

# ---------------------------------------------------------------------------
# 5) Quantum stub honesty (I-8): never claim production PQ in release notes.
# ---------------------------------------------------------------------------
echo "[5/6] Quantum stub must not be marketed as production PQ (I-8)..."

RN="docs/RELEASE_NOTES_v0.2.md"
RP="docs/RELEASE_PROCESS.md"
if [[ ! -f "$RN" ]]; then
  fail "$RN missing"
fi
# Positive anchors: release notes must keep the stub disclaimer.
if ! grep -qi 'not production PQ' "$RN"; then
  fail "$RN must keep an explicit 'not production PQ' disclaimer (I-8)"
fi
pass "RELEASE_NOTES keep 'not production PQ' disclaimer"

if [[ -f "$RP" ]] && ! grep -qi 'not production PQ' "$RP"; then
  fail "$RP must keep an explicit 'not production PQ' disclaimer (I-8)"
fi
pass "RELEASE_PROCESS keeps 'not production PQ' disclaimer"

# Negative: refuse absolute PQ-secure marketing language without stub context.
# Match lines that claim production/secure PQ without nearby stub/skeleton/not-yet wording.
PQ_BAD="$("${SEARCH[@]}" -i 'post-quantum secure|PQ-secure|quantum[- ]resistant messenger|production PQ security' \
  docs/RELEASE_NOTES_v0.2.md docs/RELEASE_PROCESS.md README.md SECURITY.md 2>/dev/null || true)"
if [[ -n "${PQ_BAD}" ]]; then
  # Allow if the same line also contains stub/skeleton/not
  CLEANED="$(echo "$PQ_BAD" | grep -ivE 'stub|skeleton|not yet|not production|no production' || true)"
  if [[ -n "${CLEANED}" ]]; then
    echo "$CLEANED"
    fail "release/docs claim production PQ without stub disclaimer (I-8)"
  fi
fi
pass "no unguarded production-PQ marketing claims in release docs"

# Feature must remain opt-in (empty quantum = [] in Cargo.toml).
if ! grep -E -q '^quantum = \[\]' Cargo.toml; then
  fail "Cargo.toml quantum feature must remain an empty opt-in gate (quantum = [])"
fi
pass "quantum Cargo feature remains empty opt-in stub gate"

# ---------------------------------------------------------------------------
# 6) Summary
# ---------------------------------------------------------------------------
echo "[6/6] Gate complete."
echo ""
echo "CI security gate PASSED (offline, deterministic)."
exit 0
