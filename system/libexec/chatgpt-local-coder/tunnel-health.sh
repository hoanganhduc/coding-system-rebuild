#!/usr/bin/env bash
# Tunnel liveness watchdog for chatgpt-local-coder.
#
# Why this exists: chatgpt-local-coder-tunnel.service is Type=oneshot with
# RemainAfterExit=yes, and the tunnel-client runtime it starts lives in a tmux
# session created by the vendor binary itself (pkg/codexplugin/session.StartTmux)
# on the *shared* default tmux socket, alongside clc-5, forms-0 and openclaw-4.
# The runtime therefore escapes the unit's cgroup: if that tmux server dies, the
# ChatGPT tunnel dies while systemd still reports the unit active, and nothing
# else on this host notices.
#
# Restarting is safe with respect to the connector. `tunnel connect` passes
# --tunnel-id from the persisted OPENAI_TUNNEL_ID, so a reconnect reuses the
# same tunnel id and the connector already registered in ChatGPT keeps working;
# the user does not have to re-add it.
#
# Conservative by construction. A restart still drops the registration for a few
# seconds, so it must never fire on a blip: it takes FAIL_THRESHOLD consecutive
# failed probes (~15 min at the timer's 5 min period), and it does nothing at
# all unless the MCP service itself is up, because restarting the tunnel against
# a dead server is churn rather than recovery.
#
# Not owned by `service install`: the generator renders only
# chatgpt-local-coder.service and chatgpt-local-coder-tunnel.service and works
# off explicit paths, so these files survive a reinstall — and are equally NOT
# removed by `service uninstall`. Remove them by hand.

set -uo pipefail

ALIAS=chatgpt-local-coder
NODE=/usr/bin/node
# A restored host has the locked Node under ~/.npm-global instead.
[[ -x "$NODE" ]] || NODE={{ HOME }}/.npm-global/bin/node
ENTRY={{ HOME }}/chatgpt-local-coder/dist/cli/main.js
SERVICE=chatgpt-local-coder.service
TUNNEL_UNIT=chatgpt-local-coder-tunnel.service
FAIL_THRESHOLD=3

STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/chatgpt-local-coder"
COUNT_FILE="$STATE_DIR/tunnel-health.failures"
LOG="$STATE_DIR/tunnel-health.log"

mkdir -p "$STATE_DIR"

log() { printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG"; }

read_failures() {
  local prev
  prev=$(cat "$COUNT_FILE" 2>/dev/null || true)
  case "$prev" in
    '' | *[!0-9]*) printf '0' ;;
    *) printf '%s' "$prev" ;;
  esac
}

# A dead MCP server is not a tunnel fault, and reconnecting at one would only
# churn the registration while --wait-for-server blocked on a server that is
# not coming back on its own.
if ! systemctl --user is-active --quiet "$SERVICE"; then
  log "skip: $SERVICE is not active"
  exit 0
fi

status_json=$(timeout 60 "$NODE" "$ENTRY" tunnel status --alias "$ALIAS" --json 2>/dev/null)

# `healthy` is the client's own verdict; anything else — non-JSON, a timeout, a
# crashed probe — counts as unhealthy rather than as an excuse to skip.
healthy=$(printf '%s' "$status_json" | python3 -c '
import json, sys
try:
    print("yes" if json.load(sys.stdin).get("healthy") is True else "no")
except Exception:
    print("no")
' 2>/dev/null)

if [ "$healthy" = yes ]; then
  prev=$(read_failures)
  [ "$prev" -gt 0 ] && log "recovered after $prev failed probe(s)"
  : >"$COUNT_FILE"
  exit 0
fi

fails=$(( $(read_failures) + 1 ))
printf '%s' "$fails" >"$COUNT_FILE"
log "probe reports unhealthy ($fails/$FAIL_THRESHOLD)"

if [ "$fails" -lt "$FAIL_THRESHOLD" ]; then
  exit 0
fi

log "restarting $TUNNEL_UNIT after $fails consecutive failures"
: >"$COUNT_FILE"

if systemctl --user restart "$TUNNEL_UNIT"; then
  # tunnel connect --wait-for-server polls status until the runtime reports
  # healthy, so reaching here already means more than "systemd exited 0";
  # re-probe anyway, because the restart is the whole point of the watchdog and
  # a silent failed recovery is the state this exists to prevent.
  after=$(timeout 60 "$NODE" "$ENTRY" tunnel status --alias "$ALIAS" --json 2>/dev/null |
    python3 -c '
import json, sys
try:
    print("healthy" if json.load(sys.stdin).get("healthy") is True else "still unhealthy")
except Exception:
    print("still unhealthy")
' 2>/dev/null)
  log "restart finished: $after"
else
  log "restart FAILED: systemctl exited $?"
fi
