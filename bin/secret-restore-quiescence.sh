#!/usr/bin/bash -p
# Establish a fail-closed boundary before replacing live authentication state.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

ACTION=""
STATE_FILE=""
case "${1:-}" in
  --quiesce|--resume) ACTION=${1#--}; shift ;;
  *) echo "usage: secret-restore-quiescence.sh --quiesce|--resume --state-file FILE" >&2; exit 2 ;;
esac
[[ "${1:-}" == --state-file && $# -eq 2 ]] || {
  echo "usage: secret-restore-quiescence.sh --quiesce|--resume --state-file FILE" >&2
  exit 2
}
STATE_FILE=$2

state_helper() {
  local operation=$1
  shift
  /usr/bin/python3 -I -B - "$operation" "$STATE_FILE" "$@" <<'PY'
import json
import os
from pathlib import Path
import re
import stat
import sys

operation, supplied, *units = sys.argv[1:]
home = Path.home().absolute()
expected_parent = home / ".local/state/coding-system/restore"
path = Path(supplied).absolute()
if (
    path.parent != expected_parent
    or re.fullmatch(r"service-state-[0-9a-f]{32}\.state", path.name) is None
):
    raise SystemExit("service state path is outside the managed restore boundary")
allowed = (
    "send-queue-worker.service",
    "openclaw-zulip-delivery-worker.service",
    "openclaw-zalo-delivery-worker.service",
    "openclaw-googlechat-delivery-worker.service",
    "openclaw-whatsapp-delivery-worker.service",
    "openclaw-sage-worker.service",
    "openclaw-manim-worker.service",
    "openclaw-email-worker.service",
    "openclaw-gateway.service",
)
if len(units) != len(set(units)) or any(unit not in allowed for unit in units):
    raise SystemExit("service state contains an unsupported unit")

current = home
for component in (".local", "state", "coding-system", "restore"):
    current = current / component
    try:
        info = current.lstat()
    except FileNotFoundError:
        current.mkdir(mode=0o700)
        info = current.lstat()
    if (
        current.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
    ):
        raise SystemExit("service state directory is unsafe")
    current.chmod(0o700)

if operation == "prepare":
    payload = (
        json.dumps(
            {
                "activeUnits": [unit for unit in allowed if unit in units],
                "schema": "coding-system.secret-restore-services/v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise SystemExit("could not persist service state")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
elif operation in {"read", "remove"}:
    try:
        linked = path.lstat()
    except FileNotFoundError:
        raise SystemExit(3)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > 4096
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise SystemExit("service state file is unsafe")
        chunks = []
        remaining = 4097
        while remaining:
            block = os.read(descriptor, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("service state file is invalid") from None
    if (
        not isinstance(document, dict)
        or set(document) != {"activeUnits", "schema"}
        or document.get("schema") != "coding-system.secret-restore-services/v1"
        or not isinstance(document.get("activeUnits"), list)
        or document["activeUnits"] != [
            unit for unit in allowed if unit in document["activeUnits"]
        ]
        or len(document["activeUnits"]) != len(set(document["activeUnits"]))
    ):
        raise SystemExit("service state file is invalid")
    if operation == "read":
        print("\n".join(document["activeUnits"]))
    else:
        path.unlink()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
else:
    raise SystemExit("unsupported service state operation")
PY
}

if [[ "$ACTION" == resume ]]; then
  if _recorded_units="$(state_helper read)"; then
    :
  else
    _state_status=$?
    [[ $_state_status -eq 3 ]] && exit 0
    exit "$_state_status"
  fi
  for _openclaw_unit in openclaw-gateway.service send-queue-worker.service \
      openclaw-zulip-delivery-worker.service openclaw-zalo-delivery-worker.service \
      openclaw-googlechat-delivery-worker.service \
      openclaw-whatsapp-delivery-worker.service \
      openclaw-sage-worker.service openclaw-manim-worker.service \
      openclaw-email-worker.service; do
    if /usr/bin/grep -Fxq -- "$_openclaw_unit" <<<"$_recorded_units"; then
      /usr/bin/systemctl --user start "$_openclaw_unit" || {
        echo "FAIL: could not resume $_openclaw_unit" >&2
        exit 2
      }
    fi
  done
  state_helper remove
  echo "secret restore services: resumed"
  exit 0
fi

# Native clients may refresh or rewrite their own session stores. A recovery
# must be launched from an ordinary shell after interactive clients have
# exited; replacing credentials beneath a running client is unsafe.
/usr/bin/python3 -I -B - <<'PY'
import os
from pathlib import Path


CLIENTS = {
    "antigravity",
    "claude",
    "codewhale",
    "codex",
    "copilot",
    "deepseek",
    "gcloud",
    "gemini",
    "gh",
    "github-copilot",
    "grok",
    "kimi",
    "kimi-cli",
    "lean-explore",
    "opencode",
    "rclone",
    "wrangler",
}
INTERPRETERS = {"bash", "node", "python", "python3", "sh"}
GROK_SIDECAR_STATE = (
    Path.home() / ".local/state/grok-proxy/iphone/tailscaled.state"
).resolve()


def executable_name(value: str) -> str:
    return Path(value).name.lower()


current_uid = os.getuid()
matches: list[tuple[str, int]] = []
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        if entry.stat().st_uid != current_uid:
            continue
        raw = (entry / "cmdline").read_bytes()
    except OSError:
        continue
    arguments = [
        item.decode("utf-8", "replace") for item in raw.split(b"\0") if item
    ]
    if not arguments:
        continue
    candidates = [executable_name(arguments[0])]
    program_argument = ""
    if candidates[0] in INTERPRETERS and len(arguments) > 1:
        # Inspect only the interpreter's program argument. Never scan prompts
        # or arbitrary later arguments, which can contain client names as text.
        program_argument = arguments[1]
        program_name = executable_name(program_argument)
        candidates.extend((program_name, Path(program_name).stem))
    client = next((name for name in candidates if name in CLIENTS), None)
    if client is None and "/@github/copilot/" in program_argument:
        client = "copilot"
    if client is None and "/@openai/codex/" in program_argument:
        client = "codex"
    if (
        client is None
        and candidates[0] in {"python", "python3"}
        and len(arguments) > 2
        and arguments[1] == "-m"
        and arguments[2] == "lean_explore.mcp.server"
    ):
        client = "lean-explore"
    if (
        client is None
        and candidates[0] in {"python", "python3"}
        and "-c" in arguments[:5]
        and any(
            "from lean_explore.api import ApiClient" in argument
            for argument in arguments[:5]
        )
    ):
        client = "lean-explore"
    if client is None and candidates[0] == "tailscaled":
        expected = f"--state={GROK_SIDECAR_STATE}"
        if expected in arguments[1:]:
            client = "grok-tailscaled"
    if client is not None:
        matches.append((client, int(entry.name)))

if matches:
    summary = ",".join(
        f"{client}:{pid}" for client, pid in sorted(matches, key=lambda item: item[1])
    )
    raise SystemExit(
        "FAIL: active credential owner(s) must exit before restore: " + summary
    )
PY

_active_units=()
for _openclaw_unit in send-queue-worker.service \
    openclaw-zulip-delivery-worker.service openclaw-zalo-delivery-worker.service \
    openclaw-googlechat-delivery-worker.service \
    openclaw-whatsapp-delivery-worker.service \
    openclaw-sage-worker.service \
    openclaw-manim-worker.service openclaw-email-worker.service \
    openclaw-gateway.service; do
  _load_state="$(
    /usr/bin/systemctl --user show "$_openclaw_unit" \
      --property=LoadState --value
  )" || {
    echo "FAIL: could not inspect $_openclaw_unit before secret restore" >&2
    exit 2
  }
  case "$_load_state" in
    not-found) continue ;;
    loaded) ;;
    *)
      echo "FAIL: unsafe load state for $_openclaw_unit: $_load_state" >&2
      exit 2
      ;;
  esac
  _active_state="$(
    /usr/bin/systemctl --user show "$_openclaw_unit" \
      --property=ActiveState --value
  )" || {
    echo "FAIL: could not inspect $_openclaw_unit before secret restore" >&2
    exit 2
  }
  case "$_active_state" in
    active) _active_units+=("$_openclaw_unit") ;;
    inactive|failed) ;;
    *)
      echo "FAIL: $_openclaw_unit is changing state ($_active_state); retry restore after it settles" >&2
      exit 2
      ;;
  esac
done

# Persist the exact pre-restore active set before issuing the first stop.  If
# any later pre-commit step fails, the caller can safely resume only this set.
state_helper prepare "${_active_units[@]}"
for _openclaw_unit in "${_active_units[@]}"; do
  /usr/bin/systemctl --user stop "$_openclaw_unit" || {
    echo "FAIL: could not quiesce $_openclaw_unit" >&2
    exit 2
  }
done

credential_writer_is_running() {
  local uid
  uid="$(/usr/bin/id -u)"
  /usr/bin/pgrep -u "$uid" -f -- \
    '/node_modules/openclaw/dist/index\.js[[:space:]]+gateway([[:space:]]|$)' \
    >/dev/null \
    || /usr/bin/pgrep -u "$uid" -f -- \
      '(^|[ /])openclaw-gateway([[:space:]]|$)' >/dev/null \
    || /usr/bin/pgrep -u "$uid" -f -- \
      '/\.openclaw/workspace/scripts/job_queue_worker\.sh([[:space:]]|$)' \
      >/dev/null
}

for _wait_attempt in {1..40}; do
  credential_writer_is_running || break
  /usr/bin/sleep 0.25
done
if credential_writer_is_running; then
  echo "FAIL: an OpenClaw gateway or job_queue_worker process survived quiescence" >&2
  exit 2
fi

echo "secret restore services: quiesced"
