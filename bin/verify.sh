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

# --- environment probes ----------------------------------------------------------
# The live arm64 host has a user systemd session, cron, restored secrets, and the npm
# global bin on PATH (via login shells). The Codespaces/CI replica has none of these.
# Detect them so the SAME `make verify` is clean in the replica yet still runs full
# checks on the host. An explicit DEGRADED=1 is always honored.
# /run/systemd/system exists iff systemd is the init (this is how sd_booted() works).
# `systemctl --user` returns 0 even in containers where systemd is NOT running, so it is
# not a usable probe — check the directory instead.
have_user_systemd() { [[ -d /run/systemd/system ]]; }
have_cron()         { pgrep -x cron >/dev/null 2>&1 || pgrep -x crond >/dev/null 2>&1; }
# put the npm global bin dir on PATH so agent-CLI bins resolve from this non-login shell
for d in "$(npm config get prefix 2>/dev/null)/bin" "$HOME/.npm-global/bin"; do
  [[ -d "$d" ]] && case ":$PATH:" in *":$d:"*) ;; *) PATH="$d:$PATH";; esac
done
# no user systemd session ⇒ this is the non-live replica (also implies degraded)
DEGRADED="${DEGRADED:-0}"; have_user_systemd || DEGRADED=1

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
if ! have_user_systemd; then
  skp "systemd user units + gateway (no user systemd session — container/CI)"
else
  while IFS=$'\t' read -r unit want; do
    [[ -z "$unit" ]] && continue
    have=$(systemctl --user is-enabled "$unit" 2>/dev/null) || true
    [[ -n "$have" ]] || have="absent"
    [[ "$have" == "$want" ]] && ok "unit $unit ($have)" || bad "unit $unit: $have != $want"
  done < "$REPO/system/systemd/units.state"
  if [[ "$DEGRADED" == "1" ]]; then
    skp "gateway active check (degraded)"
  else
    systemctl --user is-active openclaw-gateway >/dev/null 2>&1 \
      && ok "openclaw-gateway active" || bad "openclaw-gateway not active"
  fi
fi

echo "--- crontab ---"
if have_cron; then
  N=$(crontab -l 2>/dev/null | grep -cvE '^\s*(#|$)' || true)
  [[ "$N" -ge 3 ]] && ok "crontab has $N jobs" || bad "crontab has $N jobs (<3)"
else
  skp "crontab (no cron daemon — container/CI)"
fi

echo "--- secrets ---"
if [[ "$DEGRADED" == "1" ]]; then
  skp "required secrets (degraded)"
else
  if bash "$REPO/bin/secrets-verify.sh" >/dev/null; then
    ok "required secrets present"
  else
    bad "required secrets verification failed"
  fi
fi

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
  if [[ "$c" == "ai-agents-skills" ]]; then
    pin=$(/usr/bin/sed -n 's|^ai-agents-skills=.*@\([0-9a-f]\{40\}\)$|\1|p' "$REPO/components.lock")
    if [[ -d "$HOME/$c/.git" && "$pin" =~ ^[0-9a-f]{40}$ ]] \
      && /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/nonexistent \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git --no-replace-objects --no-optional-locks \
          -C "$HOME/$c" cat-file -e "$pin^{commit}" 2>/dev/null; then
      ok "component object present: ~/$c@${pin:0:12}"
    else
      skp "component object absent: ~/$c (run make components)"
    fi
    helper_digest=$(/usr/bin/sed -n 's/^  AAS_HELPER_SHA256="\([0-9a-f]\{64\}\)"$/\1/p' "$REPO/bin/install.sh")
    helper="/usr/local/libexec/coding-system/install-helpers/aas-component-$helper_digest.py"
    immutable="/usr/local/libexec/coding-system/components/ai-agents-skills/$pin"
    if [[ "$helper_digest" =~ ^[0-9a-f]{64}$ && -e "$helper" ]]; then
      helper_hash=$(/usr/bin/sha256sum "$helper" 2>/dev/null | /usr/bin/cut -d' ' -f1 || true)
      if [[ -f "$helper" && ! -L "$helper" \
          && "$(/usr/bin/stat -c '%u:%g:%a:%h' "$helper" 2>/dev/null)" == "0:0:444:1" \
          && "$helper_hash" == "$helper_digest" ]]; then
        ok "component materializer bound: ${helper_digest:0:12}"
      else
        bad "component materializer authority/hash invalid"
      fi
    else
      skp "component materializer not installed"
    fi
    if [[ "$pin" =~ ^[0-9a-f]{40}$ && -e "$immutable" ]]; then
      if [[ -d "$immutable" && ! -L "$immutable" \
          && "$(/usr/bin/stat -c '%u:%g:%a' "$immutable" 2>/dev/null)" == "0:0:555" \
          && -f "$immutable/installer/bootstrap.sh" \
          && ! -L "$immutable/installer/bootstrap.sh" \
          && "$(/usr/bin/stat -c '%u:%g:%a:%h' "$immutable/installer/bootstrap.sh" 2>/dev/null)" == "0:0:555:1" ]]; then
        ok "component immutable authority: ${pin:0:12}"
      else
        bad "component immutable authority invalid: ${pin:0:12}"
      fi
    else
      skp "component immutable authority not installed"
    fi
  else
    [[ -d "$REPO/external/$c/.git" ]] && ok "component present: external/$c" || skp "component absent: external/$c (run make components)"
  fi
done

echo
echo "verify: $PASS ok, $FAILN fail, $SKIP skipped"
exit $((FAILN>0))
