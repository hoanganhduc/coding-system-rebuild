#!/usr/bin/env bash
# Post-install health checks. DEGRADED=1 relaxes secret-dependent checks.
# --smoke runs only the quick CLI version checks.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/system/packages"
SMOKE_ONLY=0; [[ "${1:-}" == "--smoke" ]] && SMOKE_ONLY=1
PASS=0; FAILN=0; SKIP=0
ok()   { printf 'OK    %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf 'FAIL  %s\n' "$1"; FAILN=$((FAILN+1)); }
skp()  { printf 'SKIP  %s\n' "$1"; SKIP=$((SKIP+1)); }

echo "--- agent CLI versions vs pins ---"
declare -A BIN=( ["@anthropic-ai/claude-code"]="claude" ["@github/copilot"]="copilot"
                 ["@openai/codex"]="codex" ["codewhale"]="codewhale"
                 ["openclaw"]="openclaw" ["opencode-ai"]="opencode" ["pnpm"]="pnpm"
                 ["clawhub"]="clawhub" )
# authoritative pin check = npm-installed version (copilot/codewhale SELF-UPDATE,
# so their --version output legitimately drifts from the npm pin)
NPMG=$(npm ls -g --depth=0 2>/dev/null || true)
while read -r pkg; do
  [[ -z "$pkg" || "$pkg" == \#* ]] && continue
  name="${pkg%@*}"; ver="${pkg##*@}"; bin="${BIN[$name]:-}"
  inst=$(echo "$NPMG" | grep -oE "$(printf '%s' "$name" | sed 's/[@/]/./g')@[0-9][^ ]*" | head -1 | sed 's/.*@//' || true)
  [[ "$inst" == "$ver" ]] && ok "npm $name@$inst" || bad "npm $name@${inst:-absent} != pin $ver"
  [[ -n "$bin" ]] && { command -v "$bin" >/dev/null && ok "bin $bin present" || bad "bin $bin missing"; }
done < "$PKG/npm-globals.txt"
[[ $SMOKE_ONLY -eq 1 ]] && { echo "smoke: $PASS ok, $FAILN fail"; exit $((FAILN>0)); }

echo "--- symlink topology ---"
while IFS=$'\t' read -r link target; do
  [[ -z "$link" || "$link" == \#* ]] && continue
  l="${link//\{\{ HOME \}\}/$HOME}"; t="${target//\{\{ HOME \}\}/$HOME}"
  if [[ -L "$l" && "$(readlink "$l")" == "$t" ]]; then ok "symlink $l"; else bad "symlink $l -> $t"; fi
done < "$REPO/system/symlinks.tsv"

echo "--- systemd units vs units.state ---"
while IFS=$'\t' read -r unit want; do
  [[ -z "$unit" ]] && continue
  have=$(systemctl --user is-enabled "$unit" 2>/dev/null) || true
  [[ -n "$have" ]] || have="absent"
  [[ "$have" == "$want" ]] && ok "unit $unit ($have)" || bad "unit $unit: $have != $want"
done < "$REPO/system/systemd/units.state"
if [[ "${DEGRADED:-0}" == "1" ]]; then
  skp "gateway active check (degraded)"
else
  systemctl --user is-active openclaw-gateway >/dev/null 2>&1 \
    && ok "openclaw-gateway active" || bad "openclaw-gateway not active"
fi

echo "--- crontab ---"
N=$(crontab -l 2>/dev/null | grep -cvE '^\s*(#|$)' || true)
[[ "$N" -ge 3 ]] && ok "crontab has $N jobs" || bad "crontab has $N jobs (<3)"

echo "--- secrets ---"
bash "$REPO/bin/secrets-verify.sh" | grep -E 'MISSING\(required\)' && bad "required secrets missing" || ok "required secrets present"

echo "--- skill smokes ---"
if [[ "${DEGRADED:-0}" == "1" ]]; then
  skp "zotero doctor / digest / sage (degraded)"
else
  if [[ -x "$HOME/.claude/skills/_run.sh" ]]; then
    timeout 120 bash "$HOME/.claude/skills/_run.sh" skills/zotero/run_zot.sh doctor >/dev/null 2>&1 \
      && ok "zotero doctor" || bad "zotero doctor"
  else
    bad "~/.claude/skills/_run.sh missing"
  fi
  if [[ "$(uname -m)" == "aarch64" ]] && command -v docker >/dev/null; then
    timeout 180 "$HOME/.local/bin/sage" -c 'print(2**10)' 2>/dev/null | grep -q 1024 \
      && ok "sage docker smoke" || bad "sage docker smoke"
  else
    skp "sage (non-arm64 or no docker)"
  fi
fi

echo "--- components ---"
for c in openclaw-bot ai-agents-skills; do
  [[ -e "$REPO/external/$c" ]] && ok "component present: $c" || skp "component absent: $c (run make components)"
done

echo
echo "verify: $PASS ok, $FAILN fail, $SKIP skipped"
exit $((FAILN>0))
