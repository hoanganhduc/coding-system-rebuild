#!/usr/bin/env bash
# Full restore orchestrator for a fresh Ubuntu machine (12 gated phases).
# Usage: SECRETS=/path/to/secrets.zip bin/install.sh   (degraded without SECRETS)
# Env:   PHASE=n  resume from phase n;  SKIP_* forwarded to prepare.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START="${PHASE:-1}"
DEGRADED_MODE=0
[[ -z "${SECRETS:-}" ]] && DEGRADED_MODE=1
export DEGRADED_MODE

phase() { echo; echo "########## PHASE $1: $2 ##########"; }
gate()  { echo "---- gate: $1"; }
skip_enabled() { [[ "${!1:-0}" == "1" ]]; }

if [[ $DEGRADED_MODE -eq 1 ]]; then
  echo "*** DEGRADED MODE: no SECRETS archive provided ***"
  echo "*** the following features will not work until secrets are restored: ***"
  bash "$REPO/bin/secrets-verify.sh" --degraded || true
fi

# 1 ─ bootstrap checks
if (( START <= 1 )); then
  phase 1 "doctor preflight"
  bash "$REPO/bin/doctor.sh"
  mkdir -p "$HOME/.config/coding-system"
fi

# 2 ─ system software
if (( START <= 2 )); then
  phase 2 "prepare (software + images; SKIP_* toggles apply)"
  bash "$REPO/bin/prepare.sh"
  gate "binaries respond"
  for b in git jq pandoc python3; do command -v "$b" >/dev/null || { echo "FAIL: $b missing"; exit 2; }; done
  skip_enabled SKIP_NODE || command -v node >/dev/null || { echo "FAIL: node missing"; exit 2; }
  { skip_enabled SKIP_NODE || skip_enabled SKIP_NPM_GLOBALS; } || command -v npm >/dev/null || { echo "FAIL: npm missing"; exit 2; }
  skip_enabled SKIP_DOCKER || command -v docker >/dev/null || { echo "FAIL: docker missing"; exit 2; }
fi

# 3 ─ secrets
if (( START <= 3 )); then
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    phase 3 "restore secrets"
    SECRETS="$SECRETS" bash "$REPO/bin/secrets-restore.sh"
    gate "required secrets present"
    bash "$REPO/bin/secrets-verify.sh"
    if [[ -f "$HOME/.config/coding-system/tailscale.env" ]]; then
      # shellcheck disable=SC1091
      . "$HOME/.config/coding-system/tailscale.env"
      # TS_HOSTNAME keeps the funnel URLs (https://<name>.<tailnet>.ts.net/...)
      # working after restore — the webhook channels depend on the node name
      [[ -n "${TS_AUTHKEY:-}" ]] && \
        sudo tailscale up --authkey "$TS_AUTHKEY" ${TS_HOSTNAME:+--hostname "$TS_HOSTNAME"} || true
    fi
  else
    phase 3 "restore secrets — SKIPPED (degraded)"
  fi
fi

# 4 ─ (toolchains are part of prepare.sh; placeholder retained for numbering)

# 5 ─ components
if (( START <= 5 )); then
  phase 5 "components (openclaw-bot, ai-agents-skills)"
  bash "$REPO/bin/components.sh" || [[ $DEGRADED_MODE -eq 1 ]]
fi

# 6 ─ render public configs
if (( START <= 6 )); then
  phase 6 "render-install (configs, shell blocks, scripts, symlinks, atomic Grok release)"
  bash "$REPO/bin/render-install.sh"
  gate "grok-proxy user/root selectors name one validated immutable release"
  # ~/.local/bin wrappers from system/bin
  mkdir -p "$HOME/.local/bin"
  for f in "$REPO"/system/bin/*; do
    [[ -f "$f" && "$(basename "$f")" != usr-local-bin.tsv ]] || continue
    sed "s|{{ HOME }}|$HOME|g" "$f" > "$HOME/.local/bin/$(basename "$f")"
    chmod +x "$HOME/.local/bin/$(basename "$f")"
  done
fi

# 7 ─ OpenClaw slice (delegated component)
if (( START <= 7 )); then
  phase 7 "OpenClaw slice via openclaw-bot"
  if [[ -x "$REPO/external/openclaw-bot/install.sh" ]]; then
    SHA_BEFORE=$(sha256sum "$HOME/.openclaw/secrets.json" 2>/dev/null | cut -d' ' -f1 || true)
    bash "$REPO/external/openclaw-bot/install.sh" --prefix "$HOME/.openclaw" --skip-docker --skip-services --skip-config
    # the "don't clobber restored secrets" gate only applies when secrets were
    # actually restored (non-degraded); in degraded mode there is no live
    # secrets.json to protect and the component renders one from its template.
    if [[ $DEGRADED_MODE -eq 0 ]]; then
      gate "restored secrets untouched"
      SHA_AFTER=$(sha256sum "$HOME/.openclaw/secrets.json" 2>/dev/null | cut -d' ' -f1 || true)
      [[ "$SHA_BEFORE" == "$SHA_AFTER" ]] || { echo "FAIL: openclaw-bot install clobbered restored secrets.json"; exit 2; }
    fi
    if [[ -d "$HOME/.openclaw/npm/projects" ]]; then
      for p in "$HOME/.openclaw/npm/projects"/*/; do
        [[ -f "$p/package.json" ]] && (cd "$p" && npm install --silent || echo "WARN: npm install failed in $p")
      done
    fi
    gate "openclaw config has no dangling openclaw-src references"
    grep -q 'openclaw-src' "$HOME/.openclaw/openclaw.json" 2>/dev/null && { echo "FAIL: openclaw.json references openclaw-src"; exit 2; } || true
  else
    echo "WARN: openclaw-bot component unavailable — OpenClaw slice skipped"
  fi
fi

# 8 ─ skills via ai-agents-skills
if (( START <= 8 )); then
  phase 8 "skills via ai-agents-skills installer"
  AAS_HOME="$HOME/ai-agents-skills"
  if [[ -x "$AAS_HOME/installer/bootstrap.sh" ]]; then
    # ai-agents-skills is the single source of truth, cloned to ~/ai-agents-skills by
    # components.sh; install from there so the installer-created SKILL.md symlinks
    # resolve against the same source. Apply the research_compute broker to each
    # target's runtime root so the installer is the propagation path (update the repo
    # -> reinstall). `--apply` needs a confirmation phrase (piped for a non-interactive
    # restore); real-home writes need `--real-system`; `--backup-replace` updates any
    # pre-existing runtime files. Broker-scoped for now; other skills still come from
    # the rendered home until their run-model is migrated.
    AAS_PHRASE="I understand the installation and uninstall process"
    printf '%s\n' "$AAS_PHRASE" | bash "$AAS_HOME/installer/bootstrap.sh" install \
      --skills modal-research-compute --runtime-profile auto --apply --real-system --backup-replace \
      || echo "WARN: ai-agents-skills broker install reported issues"
    bash "$AAS_HOME/installer/bootstrap.sh" verify || echo "WARN: ai-agents-skills verify reported issues"
  else
    echo "WARN: ~/ai-agents-skills installer unavailable — skills installer skipped"
  fi
  phase 8b "re-overlay zip secrets (idempotent re-extract) + clobber checks"
  if [[ $DEGRADED_MODE -eq 0 ]]; then
    SECRETS="$SECRETS" bash "$REPO/bin/secrets-restore.sh"
  fi
  gate "_run.sh intact"
  if [[ -f "$HOME/.config/coding-system/run_sh.sha256" && -f "$HOME/.claude/skills/_run.sh" ]]; then
    want=$(cat "$HOME/.config/coding-system/run_sh.sha256")
    have=$(sha256sum "$HOME/.claude/skills/_run.sh" | cut -d' ' -f1)
    [[ "$want" == "$have" ]] || { echo "FAIL: _run.sh changed during phase 8"; exit 2; }
  fi
fi

# 9 ─ python environments
if (( START <= 9 )); then
  phase 9 "python environments from pip freezes"
  RQ="$REPO/system/packages/requirements"
  mkdir -p "$HOME/.openclaw/workspace/.local"
  [[ -s "$RQ/workspace-local.txt" ]] && python3 -m pip install -q --target "$HOME/.openclaw/workspace/.local" -r "$RQ/workspace-local.txt" || true
  if [[ -s "$RQ/venvs.txt" ]]; then
    [[ -d "$HOME/.venvs" ]] || python3 -m venv "$HOME/.venvs"
    "$HOME/.venvs/bin/pip" install -q -r "$RQ/venvs.txt" || true
  fi
  if [[ -s "$RQ/docling-venv.txt" ]]; then
    [[ -d "$HOME/.local/share/docling-venv" ]] || python3 -m venv "$HOME/.local/share/docling-venv"
    "$HOME/.local/share/docling-venv/bin/pip" install -q -r "$RQ/docling-venv.txt" || true
  fi
  if [[ -s "$RQ/lean-explore.txt" ]]; then
    LV="$HOME/.codex/runtime/workspace/.venvs/lean-explore"
    [[ -d "$LV" ]] || python3 -m venv "$LV"
    "$LV/bin/pip" install -q -r "$RQ/lean-explore.txt" || true
  fi
  gate "import smoke"
  PYTHONPATH="$HOME/.openclaw/workspace/.local" python3 -c 'import requests' || { echo "FAIL: workspace-local imports broken"; exit 2; }
fi

# 10 ─ docker images (already handled by prepare; re-check)
if (( START <= 10 )); then
  phase 10 "docker images check"
  if skip_enabled SKIP_DOCKER || skip_enabled SKIP_DOCKER_IMAGES; then
    echo "(skipped via SKIP_DOCKER/SKIP_DOCKER_IMAGES)"
  else
    ARCH="$(uname -m)"
    command -v docker >/dev/null || { echo "FAIL: docker missing"; exit 2; }
    while IFS='|' read -r img cond; do
      [[ -z "$img" || "$img" == \#* ]] && continue
      case "$cond" in
        arm64) [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] || continue ;;
        amd64) [[ "$ARCH" == "x86_64" ]] || continue ;;
      esac
      docker image inspect "$img" >/dev/null 2>&1 || { echo "FAIL: docker image missing: $img"; exit 2; }
    done < "$REPO/system/packages/docker-images.txt"
  fi
fi

# 11 ─ services + cron
if (( START <= 11 )); then
  phase 11 "systemd user units + crontab (apply recorded enable states)"
  mkdir -p "$HOME/.config/systemd/user"
  for f in "$REPO"/system/systemd/user/* ; do
    [[ -f "$f" ]] || { # drop-in dirs
      [[ -d "$f" ]] && { mkdir -p "$HOME/.config/systemd/user/$(basename "$f")"; \
        for g in "$f"/*; do sed "s|{{ HOME }}|$HOME|g" "$g" > "$HOME/.config/systemd/user/$(basename "$f")/$(basename "$g")"; done; }; continue; }
    sed "s|{{ HOME }}|$HOME|g" "$f" > "$HOME/.config/systemd/user/$(basename "$f")"
  done
  # tolerate the absence of a user systemd/DBUS session (CI runners, containers):
  # units are still rendered to disk; only the live registration is skipped.
  if systemctl --user daemon-reload 2>/dev/null; then
    while IFS=$'\t' read -r unit want; do
      [[ -z "$unit" ]] && continue
      case "$want" in
        enabled)  systemctl --user enable "$unit" >/dev/null 2>&1 || true ;;
        disabled) systemctl --user disable "$unit" >/dev/null 2>&1 || true ;;
      esac
    done < "$REPO/system/systemd/units.state"
  else
    echo "WARN: no user systemd session — units rendered to ~/.config/systemd/user but not registered"
  fi
  sudo loginctl enable-linger "$USER" 2>/dev/null || true
  if [[ "${CSR_NO_GATEWAY:-0}" == "1" ]]; then
    echo "(CSR_NO_GATEWAY=1: services rendered, gateway NOT started — start it manually for a live demo)"
  elif [[ $DEGRADED_MODE -eq 0 ]]; then
    systemctl --user start openclaw-gateway 2>/dev/null || echo "WARN: gateway did not start (check journalctl --user -u openclaw-gateway)"
  else
    echo "(degraded: services rendered + enable-states applied, nothing started)"
  fi
  # crontab inside a marker block, preserving any user lines outside it
  if command -v crontab >/dev/null; then
    TMP=$(mktemp)
    { { crontab -l 2>/dev/null || true; } | sed '/# >>> coding-system >>>/,/# <<< coding-system <<</d'
      echo "# >>> coding-system >>>"
      grep -v '^#' "$REPO/system/cron/crontab.template" | sed "s|{{ HOME }}|$HOME|g"
      echo "# <<< coding-system <<<"
    } > "$TMP"
    crontab "$TMP" 2>/dev/null || echo "WARN: could not install crontab (no cron daemon?)"
    rm -f "$TMP"
  else
    echo "WARN: crontab not available — skipping host cron install"
  fi
fi

# 12 ─ verification
if (( START <= 12 )); then
  phase 12 "post-install fixes note + verify"
  cat <<'EONOTE'
Post-install manual verifications (see docs/TROUBLESHOOTING.md):
  * Google Chat threading: VERIFY by sending a threaded message before applying
    any unthread patch (live extension may already handle it).
  * Zulip stays disabled by default; re-enable runbook is in TROUBLESHOOTING.
  * Zalo net.js shim: only if gateway logs show the missing-module error.
EONOTE
  DEGRADED="$DEGRADED_MODE" bash "$REPO/bin/verify.sh"
  if [[ $DEGRADED_MODE -eq 1 ]]; then
    echo; echo "*** install finished in DEGRADED MODE — missing features: ***"
    bash "$REPO/bin/secrets-verify.sh" --degraded || true
  fi
fi
echo; echo "install: done"
