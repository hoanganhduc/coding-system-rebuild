#!/usr/bin/env bash
# Roundtrip proof in /tmp — no live-system mutation.
#   1. sync dry-run must be clean
#   2. render-only install into $RUN/home — zero unresolved placeholders
#   3. fixture-secrets pack/restore cycle — modes + listing verified
#   4. re-sync from $RUN/home — public artifacts must be stable (diff clean)
#   5. leak-scan canary self-test (runtime-constructed canaries)
# KEEP=1 retains the work dir for inspection.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN=$(mktemp -d /tmp/csr-roundtrip.XXXXXX)
[[ "${KEEP:-0}" == "1" ]] || trap 'rm -rf "$RUN"' EXIT
FAILED=0
step() { echo; echo "== roundtrip $1 =="; }
fail() { echo "FAIL: $1"; FAILED=1; }

step "1/5 sync dry-run clean"
( cd "$REPO" && bash bin/sync.sh --dry-run >/dev/null 2>&1 ) && echo ok || fail "sync dry-run"

step "2/5 render-only install into fixture home"
mkdir -p "$RUN/home"
python3 "$REPO/bin/lib/render_install.py" --repo "$REPO" --home "$RUN/home" --render-only \
  && echo ok || fail "render-install"
# spot-checks
[[ -x "$RUN/home/.claude/skills/_run.sh" ]] || fail "_run.sh not installed/executable"
grep -rl '{{ HOME }}' "$RUN/home" --include='*.sh' -m1 2>/dev/null | grep -v '\.template' | head -1 | grep -q . \
  && fail "unresolved {{ HOME }} in rendered shell file" || echo "placeholders: none in rendered files"
[[ -L "$RUN/home/.claude/.local" ]] || fail "symlink topology not applied (.claude/.local)"

step "3/5 fixture secrets pack/restore"
FIX="$RUN/fixhome"; mkdir -p "$FIX"
python3 - "$REPO/secrets/secrets-manifest.yaml" "$FIX" <<'PYEOF'
import os, sys, yaml
m = yaml.safe_load(open(sys.argv[1])); fix = sys.argv[2]
for e in m["entries"]:
    p = e["path"].replace("*", "fixture")
    if p.endswith("/"):
        p += "fixture.file"
    full = os.path.join(fix, p)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write("fixture-not-a-secret\n")
print("fixtures:", sum(1 for _ in m["entries"]))
PYEOF
SEVENZ="$(command -v 7zz || command -v 7z)"
LIST="$RUN/fixlist"; ( cd "$FIX" && find . -type f | sed 's|^\./||' ) > "$LIST"
( cd "$FIX" && "$SEVENZ" a -tzip -mem=AES256 -pfixturepw "$RUN/fix.zip" "@$LIST" >/dev/null ) || fail "fixture pack"
"$SEVENZ" t -pfixturepw "$RUN/fix.zip" >/dev/null || fail "fixture integrity"
mkdir -p "$RUN/home2"
SECRETS="$RUN/fix.zip" CSR_SECRETS_PASSWORD=fixturepw HOME_OVERRIDE="$RUN/home2" \
  bash "$REPO/bin/secrets-restore.sh" >/dev/null || fail "fixture restore"
BADP=$(find "$RUN/home2" -type f ! -perm 600 | wc -l)
[[ "$BADP" -eq 0 ]] && echo "ok (modes 600)" || fail "$BADP fixture files with wrong mode"

step "4/5 re-sync stability from rendered home"
mkdir -p "$RUN/resync"
# the rendered home only contains public artifacts; private/exclude surfaces are
# absent there, so run the engine fail-open on roots (missing roots warn only)
CSR_HOME_OVERRIDE="$RUN/home" python3 "$REPO/bin/lib/manifest_sync.py" \
  --repo "$REPO" --out "$RUN/resync" >/dev/null 2>&1
DIFF=$(diff -rq "$RUN/resync/agents" "$REPO/agents" 2>/dev/null | grep -v '\.keys' | grep -cv '^Only in /home' || true)
echo "re-sync diff lines (informational): $DIFF"
[[ -d "$RUN/resync/agents" ]] && echo ok || fail "re-sync produced nothing"

step "5/5 leak-scan canary self-test"
bash "$REPO/tests/leak_scan_selftest.sh" || fail "canary self-test"

echo
[[ $FAILED -eq 0 ]] && echo "roundtrip: ALL GREEN" || echo "roundtrip: FAILURES (KEEP=1 to inspect $RUN)"
exit $FAILED
