#!/usr/bin/bash -p
# Apply the raw Tailscale authority without putting its value in shell or argv.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ $# -eq 2 && "$1" == "--home" && "$2" == /* ]] \
  || { echo "usage: apply-tailscale-authority.sh --home ABSOLUTE_HOME" >&2; exit 2; }
APPLY_HOME="$2"
AUTHKEY_PATH="$APPLY_HOME/.config/coding-system/tailscale-authkey"
REPORT="$APPLY_HOME/.local/state/coding-system/restore/tailscale-readiness.json"
TAILSCALE_BIN="${CSR_TAILSCALE_BIN:-tailscale}"
SUDO_BIN="${CSR_SUDO_BIN:-sudo}"

install -d -m 0700 "$(dirname "$REPORT")"
if [[ ! -e "$AUTHKEY_PATH" && ! -L "$AUTHKEY_PATH" ]]; then
  /usr/bin/python3 -I -B "$REPO/bin/verify-tailscale-readiness.py" \
    --home "$APPLY_HOME" --tailscale-command "$TAILSCALE_BIN" --output "$REPORT" || status=$?
  [[ "${status:-1}" == "1" ]] || exit "${status:-2}"
  echo "Tailscale readiness: NOT_CONFIGURED (no portable auth-key authority)"
  exit 1
fi

TAILSCALE_HOSTNAME="$(
  /usr/bin/python3 -I -B "$REPO/bin/verify-tailscale-readiness.py" \
    --home "$APPLY_HOME" --emit-hostname
)" || { echo "Tailscale readiness: TECHNICAL_FAIL" >&2; exit 2; }

"$TAILSCALE_BIN" up --help 2>&1 | grep -Fq 'file:' \
  || { echo "Tailscale readiness: TECHNICAL_FAIL (file auth-key unsupported)" >&2; exit 2; }

attempt_failed=0
if ! "$SUDO_BIN" "$TAILSCALE_BIN" up \
  --auth-key="file:$AUTHKEY_PATH" --hostname "$TAILSCALE_HOSTNAME" \
  >/dev/null 2>&1; then
  attempt_failed=1
fi

readiness_args=(--home "$APPLY_HOME" --tailscale-command "$TAILSCALE_BIN" --output "$REPORT")
(( attempt_failed == 0 )) || readiness_args+=(--auth-attempt-failed)
set +e
/usr/bin/python3 -I -B "$REPO/bin/verify-tailscale-readiness.py" "${readiness_args[@]}"
status=$?
set -e
case "$status" in
  0) echo "Tailscale readiness: PASS" ;;
  1) echo "Tailscale readiness: REAUTH_REQUIRED" >&2 ;;
  *) echo "Tailscale readiness: TECHNICAL_FAIL" >&2 ;;
esac
exit "$status"
