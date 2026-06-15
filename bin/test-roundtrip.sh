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
printf '%s\n' '# fixture pre-existing bashrc' > "$RUN/home/.bashrc"
printf '%s\n' '# fixture pre-existing profile' > "$RUN/home/.profile"
python3 "$REPO/bin/lib/render_install.py" --repo "$REPO" --home "$RUN/home" --render-only \
  && echo ok || fail "render-install"
# spot-checks
[[ -f "$RUN/home/.bashrc.pre-coding-system" ]] || fail "bashrc backup not created"
[[ -f "$RUN/home/.profile.pre-coding-system" ]] || fail "profile backup not created"
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
OUT="$RUN/out"; mkdir -p "$OUT"
CSR_SECRETS_HOME="$FIX" CSR_SECRETS_PASSWORD=fixturepw CSR_NO_OFFSITE=1 \
  bash "$REPO/bin/secrets-pack.sh" "$OUT" >/dev/null || fail "fixture pack via secrets-pack"
ZIP=$(ls "$OUT"/coding-system-secrets-*.zip 2>/dev/null | head -1)
[[ -n "${ZIP:-}" ]] || fail "fixture pack did not produce a zip"
LIST="$RUN/fixlist"
CSR_SECRETS_HOME="$FIX" python3 "$REPO/bin/lib/secrets_tool.py" expand "$REPO/secrets/secrets-manifest.yaml" | sort > "$LIST"
mkdir -p "$RUN/home2"
SECRETS="$ZIP" CSR_SECRETS_PASSWORD=fixturepw HOME="$RUN/home2" \
  bash "$REPO/bin/secrets-restore.sh" >/dev/null || fail "fixture restore"
( cd "$RUN/home2" && find . -type f | sed 's|^\./||' | sort ) > "$RUN/restored-list"
comm -3 "$LIST" "$RUN/restored-list" > "$RUN/list-diff"
[[ ! -s "$RUN/list-diff" ]] && echo "ok (listing)" || fail "restored listing differs"
while read -r f; do
  [[ -z "$f" ]] && continue
  cmp -s "$FIX/$f" "$RUN/home2/$f" || { fail "restored content differs: $f"; break; }
done < "$LIST"
CSR_SECRETS_HOME="$RUN/home2" python3 "$REPO/bin/lib/secrets_tool.py" verify "$REPO/secrets/secrets-manifest.yaml" >/dev/null \
  && echo "ok (manifest modes)" || fail "fixture permissions/manifest verify"

step "4/5 re-sync stability from rendered home"
mkdir -p "$RUN/resync"
# the rendered home only contains public artifacts; private/exclude surfaces are
# absent there, so run the engine fail-open on roots (missing roots warn only)
CSR_HOME_OVERRIDE="$RUN/home" python3 "$REPO/bin/lib/manifest_sync.py" \
  --repo "$REPO" --out "$RUN/resync" >/dev/null 2>&1
diff -rq "$RUN/resync/agents" "$REPO/agents" 2>/dev/null | grep -v '\.keys' > "$RUN/resync.diff" || true
[[ -d "$RUN/resync/agents" ]] || fail "re-sync produced nothing"
[[ ! -s "$RUN/resync.diff" ]] && echo "ok (diff clean)" || fail "re-sync diff not clean"

step "5/5 leak-scan canary self-test"
bash "$REPO/tests/leak_scan_selftest.sh" || fail "canary self-test"

echo
[[ $FAILED -eq 0 ]] && echo "roundtrip: ALL GREEN" || echo "roundtrip: FAILURES (KEEP=1 to inspect $RUN)"
exit $FAILED
