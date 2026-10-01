#!/usr/bin/bash -p
# Safely restore an authenticated recovery-set directory into HOME.
# Only protected share file paths are accepted; secret/share values are never
# accepted in environment variables or command arguments.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO/secrets/secrets-manifest.yaml"
SET_DIR="${RECOVERY_SET:-${SECRETS:-}}"
DESTINATION="${HOME_OVERRIDE:-$HOME}"

[[ -n "$SET_DIR" ]] || {
  echo "ERROR: set RECOVERY_SET to the recovery-set directory" >&2
  exit 2
}
if [[ ! -d "$SET_DIR" ]]; then
  echo "ERROR: RECOVERY_SET is not a directory." >&2
  if [[ "$SET_DIR" == *.zip ]]; then
    echo "Legacy ZIPs are never restored directly; use bin/secrets-import-legacy-zip.sh first." >&2
  fi
  exit 2
fi

SHARE_1="${CSR_ESCROW_SHARE_1_FILE:-}"
SHARE_2="${CSR_ESCROW_SHARE_2_FILE:-}"
[[ -n "$SHARE_1" && -n "$SHARE_2" ]] || {
  echo "ERROR: set CSR_ESCROW_SHARE_1_FILE and CSR_ESCROW_SHARE_2_FILE to protected share files" >&2
  exit 2
}

COMMON_ARGS=(
  --set-dir "$SET_DIR"
  --manifest "$MANIFEST"
  --share-file "$SHARE_1"
  --share-file "$SHARE_2"
)
if [[ -n "${CSR_EXPECTED_RECOVERY_COMMIT:-}" ]]; then
  COMMON_ARGS+=(--expected-component-commit "$CSR_EXPECTED_RECOVERY_COMMIT")
fi

# Authenticate, decrypt, and validate the complete set before stopping a live
# service or rejecting an interactive client. The restore command authenticates
# it again after quiescence, so no unchecked bytes cross the mutation boundary.
/usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
  "$REPO/bin/lib/recovery_tool.py" validate-set "${COMMON_ARGS[@]}"

DESTINATION_REAL="$(/usr/bin/realpath -e -- "$DESTINATION")" || {
  echo "ERROR: restore destination is unavailable" >&2
  exit 2
}
HOME_REAL="$(/usr/bin/realpath -e -- "$HOME")" || {
  echo "ERROR: HOME is unavailable" >&2
  exit 2
}
LIVE_RESTORE=0
RESTORE_COMMITTED=0
LIVE_REVALIDATED=0
PRECOMMIT_RESUME=0
SERVICE_LIFECYCLE_COMPLETE=0
SERVICE_STATE_FILE=""
RESTORE_CREDENTIAL_REPORT=""

restore_service_exit() {
  local status=$?
  trap - EXIT
  if [[ $LIVE_RESTORE -eq 1 && $SERVICE_LIFECYCLE_COMPLETE -eq 0 ]]; then
    if [[ $PRECOMMIT_RESUME -eq 1 ]]; then
      if ! /usr/bin/bash -p "$REPO/bin/secret-restore-quiescence.sh" \
        --resume --state-file "$SERVICE_STATE_FILE"; then
        echo "FAIL: pre-commit restore cleanup could not resume the recorded services; state retained at $SERVICE_STATE_FILE" >&2
        status=2
      fi
    elif [[ $RESTORE_COMMITTED -eq 1 && $LIVE_REVALIDATED -eq 0 ]]; then
      echo "FAIL: restored credentials were committed but live revalidation did not complete; services remain stopped and state is retained at $SERVICE_STATE_FILE" >&2
    elif [[ $RESTORE_COMMITTED -eq 1 ]]; then
      echo "FAIL: restored credentials passed revalidation, but service resume did not complete; state is retained at $SERVICE_STATE_FILE" >&2
    fi
  fi
  exit "$status"
}

if [[ "$DESTINATION_REAL" == "$HOME_REAL" ]]; then
  LIVE_RESTORE=1
  _service_state_nonce="$(
    /usr/bin/python3 -I -B -c 'import secrets; print(secrets.token_hex(16))'
  )"
  [[ "$_service_state_nonce" =~ ^[0-9a-f]{32}$ ]] || {
    echo "ERROR: could not create restore service-state identifier" >&2
    exit 2
  }
  SERVICE_STATE_FILE="$HOME/.local/state/coding-system/restore/service-state-${_service_state_nonce}.state"
  RESTORE_CREDENTIAL_REPORT="$HOME/.local/state/coding-system/restore/credential-restore-${_service_state_nonce}.json"
  PRECOMMIT_RESUME=1
  trap restore_service_exit EXIT
  /usr/bin/bash -p "$REPO/bin/secret-restore-quiescence.sh" \
    --quiesce --state-file "$SERVICE_STATE_FILE"
fi

ARGS=(restore "${COMMON_ARGS[@]}" --destination-home "$DESTINATION")
[[ "${CSR_RESTORE_REPLACE:-0}" == "1" ]] && ARGS+=(--replace)
if /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
  "$REPO/bin/lib/recovery_tool.py" "${ARGS[@]}"; then
  :
else
  _restore_status=$?
  if [[ $LIVE_RESTORE -eq 1 ]]; then
    # A nonzero child status cannot prove whether process death happened before
    # or just after the durable commit. Resolve the journal first; it rolls an
    # uncommitted transaction back and preserves a committed transaction. Only
    # the resulting stable credential state may authorize service resumption.
    PRECOMMIT_RESUME=0
    if /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
      "$REPO/bin/lib/recovery_tool.py" recover-transaction \
      --destination-home "$DESTINATION" \
      && HOME_OVERRIDE="$DESTINATION" /usr/bin/bash -p \
        "$REPO/bin/materialize-openclaw-runtime.sh" --skip-secret-projections \
      && /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
        "$REPO/bin/verify-skill-credentials.py" \
        --home "$DESTINATION_REAL" --repository "$REPO" \
        --expect-source-capabilities \
          "$DESTINATION_REAL/.config/coding-system/skill-credential-source-contract.json" \
        --output "$RESTORE_CREDENTIAL_REPORT"; then
      LIVE_REVALIDATED=1
      if /usr/bin/bash -p "$REPO/bin/secret-restore-quiescence.sh" \
        --resume --state-file "$SERVICE_STATE_FILE"; then
        SERVICE_LIFECYCLE_COMPLETE=1
        trap - EXIT
      else
        echo "FAIL: recovered credentials passed revalidation, but the recorded services could not be resumed; state retained at $SERVICE_STATE_FILE" >&2
      fi
    else
      echo "FAIL: restore outcome could not be recovered and revalidated; services remain stopped and state is retained at $SERVICE_STATE_FILE" >&2
    fi
  fi
  exit "$_restore_status"
fi
if [[ $LIVE_RESTORE -eq 1 ]]; then
  RESTORE_COMMITTED=1
  PRECOMMIT_RESUME=0
fi

# Credential migrations, projections, legacy scrubs, and stale deletions were
# committed with the authorities by recovery_tool. Only non-secret runtime
# artifacts remain for this post-commit materialization pass.
HOME_OVERRIDE="$DESTINATION" /usr/bin/bash -p "$REPO/bin/materialize-openclaw-runtime.sh" \
  --skip-secret-projections

if [[ $LIVE_RESTORE -eq 1 ]]; then
  # A successful commit does not authorize credential owners to restart.  Bind
  # the live projections and installed resolvers to the metadata-only source
  # capability contract before resuming exactly the pre-restore active set.
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/verify-skill-credentials.py" \
    --home "$DESTINATION_REAL" --repository "$REPO" \
    --expect-source-capabilities \
      "$DESTINATION_REAL/.config/coding-system/skill-credential-source-contract.json" \
    --output "$RESTORE_CREDENTIAL_REPORT"
  LIVE_REVALIDATED=1

  if ! /usr/bin/bash -p "$REPO/bin/secret-restore-quiescence.sh" \
    --resume --state-file "$SERVICE_STATE_FILE"; then
    echo "FAIL: live credentials passed revalidation, but the recorded services could not be resumed; state retained at $SERVICE_STATE_FILE" >&2
    exit 2
  fi
  SERVICE_LIFECYCLE_COMPLETE=1
  trap - EXIT
fi
echo "secrets/private state restored from recovery set: $SET_DIR"
