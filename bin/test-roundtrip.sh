#!/usr/bin/env bash
# Roundtrip proof in /tmp — no live-system mutation.
#   1. render-only install into $RUN/home — zero unresolved placeholders
#   2. sync dry-run from an explicit canonical override, or the fixture by default
#   3. fixture-secrets pack/restore cycle — modes + listing verified
#   4. re-sync from $RUN/home — public artifacts must be stable (diff clean)
#   5. leak-scan canary self-test (runtime-constructed canaries)
# KEEP=1 retains the work dir for inspection.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CALLER_SYNC_HOME="${CSR_HOME_OVERRIDE:-}"
# CSR_HOME_OVERRIDE is a sync input, not ambient roundtrip state.  Preserve an
# explicit caller choice for step 2 only; every other step sets its own fixture.
unset CSR_HOME_OVERRIDE
RUN=$(mktemp -d /tmp/csr-roundtrip.XXXXXX)
[[ "${KEEP:-0}" == "1" ]] || trap 'rm -rf "$RUN"' EXIT
FAILED=0
step() { echo; echo "== roundtrip $1 =="; }
fail() { echo "FAIL: $1"; FAILED=1; }

step "1/5 render-only install into fixture home"
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

step "2/5 sync dry-run from explicit canonical override or rendered fixture"
if [[ -n "$CALLER_SYNC_HOME" ]]; then
  SYNC_HOME="$CALLER_SYNC_HOME"
  ( cd "$REPO" && CSR_HOME_OVERRIDE="$SYNC_HOME" bash bin/sync.sh --dry-run >/dev/null 2>&1 ) \
    && echo "ok (explicit canonical override)" || fail "sync dry-run from explicit canonical override"
else
  SYNC_HOME="$RUN/home"
  ( cd "$REPO" && CSR_HOME_OVERRIDE="$RUN/home" bash bin/sync.sh --dry-run >/dev/null 2>&1 ) \
    && echo "ok (rendered fixture default)" || fail "sync dry-run from rendered fixture"
fi

step "3/5 synthetic recovery-set/2-of-4 restore"
(
  cd "$REPO"
  python3 -B -m unittest \
    tests.test_recovery_tool.RecoverySetRoundTripTests.test_create_validate_restore_and_conflict_refusal
) && echo "ok (authenticated recovery-set roundtrip)" \
  || fail "authenticated recovery-set roundtrip"

step "4/5 re-sync stability from rendered home"
mkdir -p "$RUN/resync"
# the rendered home only contains public artifacts; private/exclude surfaces are
# absent there, so run the engine fail-open on roots (missing roots warn only)
CSR_HOME_OVERRIDE="$RUN/home" python3 "$REPO/bin/lib/manifest_sync.py" \
  --repo "$REPO" --out "$RUN/resync" >/dev/null 2>&1
# the delegated Claude skills are owned by the shared ai-agents-skills runtime,
# so render_install.py keeps them out of home and a re-sync cannot reproduce
# them; their repo copies stay only as the byte-identical reference that
# retire_stale_claude_runtime compares against.  Other agents still roundtrip.
diff -rq "$RUN/resync/agents" "$REPO/agents" 2>/dev/null \
  | grep -v '\.keys' \
  | grep -vE 'agents/claude/skills(/|: )(calibre|modal-research-compute|vnthuquan|zotero)' \
  > "$RUN/resync.diff" || true
[[ -d "$RUN/resync/agents" ]] || fail "re-sync produced nothing"
[[ ! -s "$RUN/resync.diff" ]] && echo "ok (diff clean)" || fail "re-sync diff not clean"
diff -rq \
  --exclude='.planning' \
  --exclude='.learnings' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.pytest_cache' \
  "$RUN/resync/system/grok-proxy" "$REPO/system/grok-proxy" \
  > "$RUN/grok-resync.diff" 2>/dev/null || true
[[ -d "$RUN/resync/system/grok-proxy" ]] || fail "Grok re-sync produced nothing"
[[ ! -s "$RUN/grok-resync.diff" ]] \
  && echo "ok (Grok source/backup diff clean)" \
  || fail "Grok source/backup roundtrip differs"

step "5/5 leak-scan canary self-test"
bash "$REPO/tests/leak_scan_selftest.sh" || fail "canary self-test"

echo
[[ $FAILED -eq 0 ]] && echo "roundtrip: ALL GREEN" || echo "roundtrip: FAILURES (KEEP=1 to inspect $RUN)"
exit $FAILED
