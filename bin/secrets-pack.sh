#!/usr/bin/bash -p
# Create one immutable recovery-set generation. Secret values are read only
# from protected files and inherited FDs inside recovery_tool.py.
#
# Usage: CSR_RECOVERY_MASTER_KEY_FILE=/protected/master.key \
#        CSR_ESCROW_GENERATION=/protected/escrow-generation.json \
#        bin/secrets-pack.sh [OUT_ROOT]
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR \
  GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_DIR GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_WORK_TREE
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
  GIT_TERMINAL_PROMPT=0 XDG_CONFIG_HOME=/nonexistent

REPO="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
OPENCLAW_LOADER="$HOME/.local/share/coding-system/openclaw-launchers/loader.py"
OPENCLAW_EXECUTABLE_HELPER=""
OPENCLAW_EXECUTABLE_CONTRACT=""
resolve_openclaw_paths() {
  local report
  report="$(/usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --resolve-json)" || return 2
  mapfile -t paths < <(/usr/bin/python3 -I -B -c '
import json, sys
value = json.load(sys.stdin)
print(value.get("helper", "")); print(value.get("contract", ""))
' <<<"$report")
  [[ ${#paths[@]} -eq 2 ]] || return 2
  OPENCLAW_EXECUTABLE_HELPER="${paths[0]}"
  OPENCLAW_EXECUTABLE_CONTRACT="${paths[1]}"
}
openclaw_exact() {
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$OPENCLAW_LOADER" --home "$HOME" --exec -- "$@"
}
print_usage() {
  echo "usage: bin/secrets-pack.sh [OUT_ROOT]"
  echo "create one signed immutable recovery-set generation"
}
case "${1:-}" in
  -h|--help)
    print_usage
    exit 0
    ;;
  -*)
    echo "ERROR: unsupported option: $1" >&2
    print_usage >&2
    exit 2
    ;;
esac
[[ "$#" -le 1 ]] || {
  echo "ERROR: expected at most one recovery-set output root" >&2
  print_usage >&2
  exit 2
}
safe_release_git() {
  /usr/bin/git --no-optional-locks \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    -c credential.helper= "$@"
}
MANIFEST="$REPO/secrets/secrets-manifest.yaml"
OUT_ROOT="${1:-$HOME/secrets-out}"
MASTER_KEY_FILE="${CSR_RECOVERY_MASTER_KEY_FILE:-$HOME/.config/coding-system/recovery-master.key}"
ESCROW_GENERATION="${CSR_ESCROW_GENERATION:-$HOME/.config/coding-system/escrow/current/escrow-generation.json}"

[[ -f "$MASTER_KEY_FILE" ]] || {
  echo "ERROR: protected recovery master is missing: $MASTER_KEY_FILE" >&2
  echo "Create a new immutable 2-of-4 generation with bin/escrow-passphrase.sh create-generation." >&2
  exit 2
}
[[ -f "$ESCROW_GENERATION" ]] || {
  echo "ERROR: escrow generation manifest is missing: $ESCROW_GENERATION" >&2
  exit 2
}
/usr/bin/mkdir -p "$OUT_ROOT"
[[ ! -L "$OUT_ROOT" && -d "$OUT_ROOT" ]] || {
  echo "ERROR: unsafe recovery-set output root" >&2
  exit 2
}
OUT_ROOT="$(cd -- "$OUT_ROOT" && pwd -P)"
read -r out_uid out_mode < <(/usr/bin/stat -c '%u %a' -- "$OUT_ROOT")
[[ "$out_uid" == "$(/usr/bin/id -u)" && $((8#$out_mode & 8#022)) -eq 0 ]] || {
  echo "ERROR: recovery-set output root must be owned by the caller and not group/world writable" >&2
  exit 2
}

if [[ -n "$(safe_release_git -C "$REPO" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "ERROR: repository worktree/index is not clean; cannot bind a recovery set to HEAD" >&2
  exit 2
fi
/usr/bin/bash -p "$REPO/bin/verify-published-head.sh"
/usr/bin/python3 -I -B "$REPO/bin/verify-recovery-release.py"

COMMIT="$(safe_release_git -C "$REPO" rev-parse --verify 'HEAD^{commit}')"
[[ "$COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || {
  echo "ERROR: repository HEAD is not an immutable Git commit" >&2
  exit 2
}
NONCE="$(/usr/bin/tr -d '-' < /proc/sys/kernel/random/uuid | /usr/bin/cut -c1-16)"
SET_ID="csr-$(/usr/bin/date -u +%Y%m%dt%H%M%Sz)-$NONCE"
FINAL_SET_DIR="$OUT_ROOT/$SET_ID"
SET_DIR="$OUT_ROOT/.stage-$SET_ID"
SOURCE_HOME="${CSR_SECRETS_HOME:-$HOME}"
SET_PUBLISHED=0
OWNER_STAGE=""
OWNER_VERIFY_DIR=""
OWNER_VERIFY_ROOT=""
[[ ! -e "$FINAL_SET_DIR" && ! -L "$FINAL_SET_DIR" \
    && ! -e "$SET_DIR" && ! -L "$SET_DIR" ]] || {
  echo "ERROR: recovery-set generation path already exists" >&2
  exit 2
}
cleanup_set() {
  if [[ -n "$OWNER_VERIFY_DIR" ]]; then
    owner_verify_name="${OWNER_VERIFY_DIR##*/}"
    if [[ -n "$OWNER_VERIFY_ROOT" \
        && "$OWNER_VERIFY_DIR" == "$OWNER_VERIFY_ROOT/$owner_verify_name" \
        && "$owner_verify_name" == csr-owner-review-* \
        && -d "$OWNER_VERIFY_DIR" && ! -L "$OWNER_VERIFY_DIR" ]]; then
      /usr/bin/rm -rf -- "$OWNER_VERIFY_DIR"
    else
      echo "ERROR: refusing unsafe owner verification cleanup" >&2
    fi
  fi
  if [[ -n "$OWNER_STAGE" ]]; then
    case "$OWNER_STAGE" in
      "$OUT_ROOT"/.owner-stage-csr-*)
        [[ ! -L "$OWNER_STAGE" ]] && /usr/bin/rm -rf -- "$OWNER_STAGE"
        ;;
      *) echo "ERROR: refusing unsafe owner snapshot cleanup" >&2 ;;
    esac
  fi
  if [[ "$SET_PUBLISHED" == 0 ]]; then
    case "$SET_DIR" in
      "$OUT_ROOT"/.stage-csr-*)
        [[ ! -L "$SET_DIR" ]] && /usr/bin/rm -rf -- "$SET_DIR"
        ;;
      *) echo "ERROR: refusing unsafe incomplete recovery-set cleanup" >&2 ;;
    esac
  fi
}
trap cleanup_set EXIT

# Converge supported legacy shell assignments on every backup. This prevents a
# one-command pack from depending on a remembered init-private step and also
# sanitizes protected rollback copies before discovery or archive enumeration.
/usr/bin/python3 -I -B "$REPO/bin/migrate-owner-settings.py" \
  --home "$SOURCE_HOME"

# Promote legacy Claude VNU and Zulip fields into their dedicated authorities
# once, then converge all derived copies. Only authorities are archived.
/usr/bin/python3 -I -B "$REPO/bin/materialize-secret-projections.py" \
  --home "$SOURCE_HOME" --migrate-vnu-legacy --migrate-remote-bridge-legacy \
  --migrate-aas-legacy

# Do not publish a recovery set whose authorities exist but are unreachable
# through the selected agent/runtime entrypoints. Optional accounts remain
# NOT_CONFIGURED and quota state is deliberately outside this offline gate.
SOURCE_CAPABILITY_CONTRACT="$SOURCE_HOME/.config/coding-system/skill-credential-source-contract.json"
/usr/bin/python3 -I -B "$REPO/bin/verify-skill-credentials.py" \
  --home "$SOURCE_HOME" --repository "$REPO" \
  --output "$SOURCE_CAPABILITY_CONTRACT"

# Database rows, runtime IDs, counters, and next-wake timestamps are not
# portable scheduler state.  On a live source home, export the logical v2
# declarations through the supported CLI immediately before archiving them.
if [[ "${CSR_RECOVERY_SKIP_SCHEDULER_SNAPSHOT:-0}" != "1" \
    && "$SOURCE_HOME" == "$HOME" \
    && -f "$HOME/.openclaw/openclaw.json" ]]; then
  openclaw_exact health --json >/dev/null 2>&1 || {
    echo "ERROR: OpenClaw gateway is not healthy; refusing a backup without a current scheduler snapshot" >&2
    exit 2
  }
  SCHEDULER_DIR="$HOME/.config/coding-system"
  [[ ! -L "$SCHEDULER_DIR" ]] || {
    echo "ERROR: unsafe OpenClaw scheduler snapshot directory" >&2
    exit 2
  }
  /usr/bin/install -d -m 0700 "$SCHEDULER_DIR"
  resolve_openclaw_paths || {
    echo "ERROR: OpenClaw launcher selector is unavailable" >&2
    exit 2
  }
  /usr/bin/python3 -I -B "$REPO/bin/openclaw-cron-v2.py" \
    --home "$HOME" --openclaw-helper "$OPENCLAW_EXECUTABLE_HELPER" \
    --openclaw-contract "$OPENCLAW_EXECUTABLE_CONTRACT" export \
    --output "$SCHEDULER_DIR/openclaw-cron.v2.json"
  /usr/bin/chmod 0600 "$SCHEDULER_DIR/openclaw-cron.v2.json"
fi

# Native owner backup is deliberately non-mutating. Normalize bounded legacy
# per-agent auth into the canonical SQLite stores before source-state binding,
# so the HMAC and native snapshot describe the same complete authority set.
OPENCLAW_COMPONENT=""
EXPECTED_OPENCLAW_VERSION=""
resolve_openclaw_owner_component() {
  [[ -n "$OPENCLAW_COMPONENT" ]] && return 0
  OPENCLAW_COMPONENT="$(/usr/bin/python3 -I -B \
    "$REPO/bin/lib/component_paths.py" --repository "$REPO" --home "$HOME" \
    --source-fallback --require openclaw-bot)" || return 2
  [[ -x "$OPENCLAW_COMPONENT/backup.sh" \
      && -f "$OPENCLAW_COMPONENT/scripts/owner_archive.py" \
      && ! -L "$OPENCLAW_COMPONENT/scripts/owner_archive.py" \
      && -f "$OPENCLAW_COMPONENT/scripts/openclaw_auth_closure.py" \
      && ! -L "$OPENCLAW_COMPONENT/scripts/openclaw_auth_closure.py" ]] \
    || return 2
  EXPECTED_OPENCLAW_VERSION="$(/usr/bin/python3 -I -S -B - \
    "$OPENCLAW_COMPONENT/REBUILD-MANIFEST.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], "rb") as stream:
    value = json.load(stream)
version = value.get("openclaw", {}).get("observed_version")
if not isinstance(version, str) or re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+~_-]{0,127}", version) is None:
    raise SystemExit(2)
print(version)
PY
)" || return 2
}

if [[ -d "$SOURCE_HOME/.openclaw" && ! -L "$SOURCE_HOME/.openclaw" ]]; then
  resolve_openclaw_owner_component || {
    echo "ERROR: immutable OpenClaw component is unavailable for owner normalization" >&2
    exit 2
  }
  /usr/bin/python3 -I -S -B \
    "$OPENCLAW_COMPONENT/scripts/openclaw_auth_closure.py" materialize-legacy \
    --prefix "$SOURCE_HOME/.openclaw" \
    --expected-version "$EXPECTED_OPENCLAW_VERSION" >/dev/null || {
      echo "ERROR: legacy OpenClaw owner auth could not be materialized before capture" >&2
      exit 2
    }
fi

owner_source_state() {
  /usr/bin/python3 -I -B "$REPO/bin/lib/recovery_tool.py" \
    inspect-owner-source \
    --source-home "$SOURCE_HOME" \
    --master-key-file "$MASTER_KEY_FILE" \
  | /usr/bin/python3 -I -S -B -c '
import json, re, sys
value = json.load(sys.stdin)
if set(value) != {"configured", "source_state_hmac_sha256"}:
    raise SystemExit(2)
configured = value["configured"]
digest = value["source_state_hmac_sha256"]
if type(configured) is not bool or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit(2)
print("1" if configured else "0", digest)
'
}

owner_extracted_state() {
  local extraction_root="$1"
  /usr/bin/python3 -I -B "$REPO/bin/lib/recovery_tool.py" \
    inspect-owner-extracted-source \
    --extraction-root "$extraction_root" \
    --master-key-file "$MASTER_KEY_FILE" \
  | /usr/bin/python3 -I -S -B -c '
import json, re, sys
value = json.load(sys.stdin)
if set(value) != {"configured", "source_state_hmac_sha256"}:
    raise SystemExit(2)
configured = value["configured"]
digest = value["source_state_hmac_sha256"]
if type(configured) is not bool or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit(2)
print("1" if configured else "0", digest)
'
}

read -r OWNER_REQUIRED OWNER_SOURCE_HMAC < <(owner_source_state) || {
  echo "ERROR: OpenClaw owner source could not be classified" >&2
  exit 2
}
[[ "$OWNER_REQUIRED" =~ ^[01]$ && "$OWNER_SOURCE_HMAC" =~ ^[0-9a-f]{64}$ ]] || {
  echo "ERROR: OpenClaw owner source classification is invalid" >&2
  exit 2
}

INCLUDE_OWNER_HISTORY="${CSR_INCLUDE_OWNER_HISTORY:-0}"
[[ "$INCLUDE_OWNER_HISTORY" =~ ^[01]$ ]] || {
  echo "ERROR: CSR_INCLUDE_OWNER_HISTORY must be 0 or 1" >&2
  exit 2
}
REVIEWED_OWNER_ARCHIVE="${CSR_REVIEWED_OWNER_DATA_ARCHIVE:-}"
REVIEWED_CONFIRMATION="${CSR_OWNER_DATA_OVERRIDE_CONFIRMATION:-}"
if [[ -n "$REVIEWED_OWNER_ARCHIVE" ]]; then
  [[ "$REVIEWED_CONFIRMATION" == "USE_REVIEWED_PREBUILT_OWNER_ARCHIVE" ]] || {
    echo "ERROR: a prebuilt owner archive requires the exact reviewed override confirmation" >&2
    exit 2
  }
  [[ "$INCLUDE_OWNER_HISTORY" == 0 ]] || {
    echo "ERROR: select either fresh history capture or a reviewed prebuilt owner archive" >&2
    exit 2
  }
elif [[ -n "$REVIEWED_CONFIRMATION" ]]; then
  echo "ERROR: owner-data override confirmation has no reviewed archive" >&2
  exit 2
fi

OWNER_DATA_ARCHIVE=""
OWNER_CAPTURE_POLICY=""
OWNER_DATA_ARGS=()
if [[ "$OWNER_REQUIRED" == 1 || "$INCLUDE_OWNER_HISTORY" == 1 \
    || -n "$REVIEWED_OWNER_ARCHIVE" ]]; then
  OWNER_PASSPHRASE_FILE="${OPENCLAW_BACKUP_PASSPHRASE_FILE:-$SOURCE_HOME/.config/coding-system/openclaw-owner-backup-passphrase.txt}"
  resolve_openclaw_owner_component || {
      echo "ERROR: immutable OpenClaw component is unavailable for owner capture" >&2
      exit 2
    }
  [[ -f "$OWNER_PASSPHRASE_FILE" && ! -L "$OWNER_PASSPHRASE_FILE" ]] || {
    echo "ERROR: protected OpenClaw owner archive passphrase is unavailable" >&2
    exit 2
  }

  if [[ -n "$REVIEWED_OWNER_ARCHIVE" ]]; then
    OWNER_DATA_ARCHIVE="$REVIEWED_OWNER_ARCHIVE"
    OWNER_CAPTURE_POLICY="reviewed-prebuilt-override"
  else
    OWNER_STAGE="$OUT_ROOT/.owner-stage-$SET_ID"
    /usr/bin/install -d -m 0700 -- "$OWNER_STAGE"
    OPENCLAW_BACKUP_PASSPHRASE_FILE="$OWNER_PASSPHRASE_FILE" \
      /usr/bin/bash -p "$OPENCLAW_COMPONENT/backup.sh" \
        --prefix "$SOURCE_HOME/.openclaw" \
        --output "$OWNER_STAGE" \
        --verify
    mapfile -d '' OWNER_ARCHIVES < <(
      /usr/bin/find -P "$OWNER_STAGE" -mindepth 1 -maxdepth 1 -type f \
        -name 'openclaw-private-????????T??????Z.tar.gz.gpg' -print0
    )
    [[ "${#OWNER_ARCHIVES[@]}" == 1 ]] || {
      echo "ERROR: fresh owner capture did not publish exactly one canonical archive" >&2
      exit 2
    }
    OWNER_DATA_ARCHIVE="${OWNER_ARCHIVES[0]}"
    OWNER_CAPTURE_POLICY="fresh-native-snapshot"
    read -r OWNER_REQUIRED_AFTER OWNER_SOURCE_HMAC_AFTER \
      < <(owner_source_state) || {
        echo "ERROR: OpenClaw owner source could not be reclassified after capture" >&2
        exit 2
      }
    [[ "$OWNER_REQUIRED_AFTER" == "$OWNER_REQUIRED" \
        && "$OWNER_SOURCE_HMAC_AFTER" == "$OWNER_SOURCE_HMAC" ]] || {
      echo "ERROR: OpenClaw owner source changed during fresh capture" >&2
      exit 2
    }
  fi
  OWNER_VERIFY_DIR="$(/usr/bin/python3 -I -B \
    "$REPO/bin/lib/secure_temp.py" create --prefix csr-owner-review-)" || {
      echo "ERROR: secure owner archive verification staging is unavailable" >&2
      exit 2
    }
  OWNER_VERIFY_ROOT="$(/usr/bin/dirname -- "$OWNER_VERIFY_DIR")"
  [[ "${OWNER_VERIFY_DIR##*/}" == csr-owner-review-* \
      && "$OWNER_VERIFY_DIR" == "$OWNER_VERIFY_ROOT/${OWNER_VERIFY_DIR##*/}" \
      && -d "$OWNER_VERIFY_DIR" && ! -L "$OWNER_VERIFY_DIR" ]] || {
    echo "ERROR: secure owner archive verification staging is invalid" >&2
    exit 2
  }
  REVIEW_PLAINTEXT="$OWNER_VERIFY_DIR/owner.tar.gz"
  REVIEW_EXTRACTION="$OWNER_VERIFY_DIR/extracted"
  /usr/bin/install -d -m 0700 -- "$REVIEW_EXTRACTION"
  /usr/bin/python3 -I -S -B \
    "$OPENCLAW_COMPONENT/scripts/owner_archive.py" decrypt \
    --source "$OWNER_DATA_ARCHIVE" --output "$REVIEW_PLAINTEXT" \
    --passphrase-file "$OWNER_PASSPHRASE_FILE"
  /usr/bin/python3 -I -S -B \
    "$OPENCLAW_COMPONENT/scripts/owner_archive.py" verify-extract \
    --archive "$REVIEW_PLAINTEXT" --destination "$REVIEW_EXTRACTION" \
    --expected-runtime-version "$EXPECTED_OPENCLAW_VERSION" >/dev/null
  read -r OWNER_ARCHIVE_REQUIRED OWNER_ARCHIVE_SOURCE_HMAC \
    < <(owner_extracted_state "$REVIEW_EXTRACTION") || {
      echo "ERROR: verified OpenClaw owner archive state could not be classified" >&2
      exit 2
    }
  [[ "$OWNER_ARCHIVE_REQUIRED" == "$OWNER_REQUIRED" \
      && "$OWNER_ARCHIVE_SOURCE_HMAC" == "$OWNER_SOURCE_HMAC" ]] || {
    echo "ERROR: verified OpenClaw owner archive does not match the live source capability state" >&2
    exit 2
  }
  OWNER_DATA_ARGS=(
    --owner-data-archive "$OWNER_DATA_ARCHIVE"
    --expected-owner-source-state-hmac "$OWNER_SOURCE_HMAC"
    --owner-data-capture-policy "$OWNER_CAPTURE_POLICY"
  )
fi

/usr/bin/python3 -I -B "$REPO/bin/lib/recovery_tool.py" create-set \
  --manifest "$MANIFEST" \
  --source-home "$SOURCE_HOME" \
  --output-dir "$SET_DIR" \
  --master-key-file "$MASTER_KEY_FILE" \
  --escrow-manifest "$ESCROW_GENERATION" \
  --component-commit "$COMMIT" \
  --set-id "$SET_ID" \
  "${OWNER_DATA_ARGS[@]}"
/usr/bin/bash -p "$REPO/bin/sign-recovery-set.sh" "$SET_DIR"
/usr/bin/mv -T --no-clobber -- "$SET_DIR" "$FINAL_SET_DIR"
/usr/bin/python3 -I -S -B - "$OUT_ROOT" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
SET_PUBLISHED=1
cleanup_set
OWNER_STAGE=""
OWNER_VERIFY_DIR=""
OWNER_VERIFY_ROOT=""
trap - EXIT
SET_DIR="$FINAL_SET_DIR"

echo "Recovery-set pointer (publish/copy this directory only after offsite share checks):"
echo "  $SET_DIR"
