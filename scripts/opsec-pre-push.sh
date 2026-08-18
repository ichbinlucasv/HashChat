#!/usr/bin/env bash
# Light OPSEC gate before commit/push. Does NOT wipe cargo/ghcup caches.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "OPSEC FAIL: $*" >&2; exit 1; }

echo "=== HashChat OPSEC pre-push ==="

# 1. Remotes must be Codeberg origin + GitHub mirror
origin_url=$(git remote get-url origin)
github_url=$(git remote get-url github 2>/dev/null || true)
[[ "$origin_url" == git@codeberg.org:ichbinlucasv/HashChat.git ]] || fail "origin is not Codeberg SSH ($origin_url)"
[[ "$github_url" == git@github.com:ichbinlucasv/HashChat.git ]] || fail "github remote missing or not SSH ($github_url)"
echo "  remotes: origin=Codeberg, github=mirror"

# 2. Identity is local-only
email=$(git config --local user.email || true)
[[ "$email" == "ichbinlucasv@noreply.codeberg.org" ]] || fail "local user.email must be ichbinlucasv@noreply.codeberg.org"
echo "  committer: $(git config --local user.name) <$email>"

# 3. Forbidden paths in the index / worktree
if git ls-files | grep -E '(^|/)(tor/hidden_service/|rust-lib/|hashchat_data/|\.onion$|\.pem$|id_ed25519|id_rsa)' >/dev/null; then
  fail "tracked secret-like path"
fi
for p in tor/hidden_service rust-lib hashchat_data; do
  [[ -e "$p" ]] && fail "untracked sensitive path present: $p (clean it)"
done
echo "  no HS keys / rust-lib / hashchat_data"

# 4. No private-key armor or obvious tokens in staged+tracked source
# Pattern is split so this file does not match itself.
pat='BEGIN (OPENSSH|RSA|EC) PRIVATE|ghp_[A-Za-z0-9]{20,}|github''_pat_|AKIA[0-9A-Z]{16}'
if git grep -I -n -E "$pat" -- ':!sbom/**' ':!Cargo.lock' >/dev/null 2>&1; then
  fail "possible secret string in tree"
fi
echo "  no private-key / token strings"

# 5. No ritual junk staged
if git ls-files --stage | grep -E 'pre-tag-check-local-ran-|sbom-continue-|sage \(Core\)' >/dev/null; then
  fail "ritual junk still tracked"
fi
echo "  no marker / sbom-continue / sage junk"

echo "=== OPSEC OK — review git status, then: git push origin main && git push github main ==="
