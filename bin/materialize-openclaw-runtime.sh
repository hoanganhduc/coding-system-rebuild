#!/usr/bin/bash -p
# Materialize derived OpenClaw runtime files from restored authorities.
set -euo pipefail
if [[ $- != *p* ]]; then
  exec /usr/bin/bash -p "$0" "$@"
fi
umask 077
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP \
  LD_PRELOAD LD_LIBRARY_PATH

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TARGET_HOME="${HOME_OVERRIDE:-$HOME}"
TEMPORARY=""
ALLOW_MISSING_CLASSROOM50=0
SKIP_SECRET_PROJECTIONS=0
while (($#)); do
  case "$1" in
    --allow-missing-classroom50) ALLOW_MISSING_CLASSROOM50=1 ;;
    --skip-secret-projections) SKIP_SECRET_PROJECTIONS=1 ;;
    *)
      echo "usage: materialize-openclaw-runtime.sh [--allow-missing-classroom50] [--skip-secret-projections]" >&2
      exit 2
      ;;
  esac
  shift
done
[[ $# -eq 0 ]] || {
  echo "usage: materialize-openclaw-runtime.sh [--allow-missing-classroom50] [--skip-secret-projections]" >&2
  exit 2
}
trap '[[ -z "${TEMPORARY:-}" ]] || rm -f "$TEMPORARY"' EXIT

if [[ $SKIP_SECRET_PROJECTIONS -eq 0 ]]; then
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/materialize-secret-projections.py" --home "$TARGET_HOME"
fi
if [[ -x "$TARGET_HOME/.local/share/gh/extensions/gh-teacher/gh-teacher" ]]; then
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null \
    "$REPO/bin/materialize-openclaw-classroom50.py" \
    --repository "$REPO" --home "$TARGET_HOME"
elif [[ $ALLOW_MISSING_CLASSROOM50 -eq 1 ]]; then
  echo "materialize-openclaw-runtime: Classroom50 source absent in optional test mode"
else
  echo "materialize-openclaw-runtime: locked Classroom50 source is unavailable" >&2
  exit 2
fi

locked_image_for_role() {
  local role="$1" platform
  case "$(uname -m)" in
    aarch64|arm64) platform="linux/arm64" ;;
    x86_64|amd64) platform="linux/amd64" ;;
    *) echo "materialize-openclaw-runtime: unsupported architecture: $(uname -m)" >&2; return 2 ;;
  esac
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null - \
    "$REPO/system/software/images.lock.json" "$platform" "$role" <<'PY'
import json
import re
import sys

lock_path, platform, role = sys.argv[1:]
value = json.load(open(lock_path, encoding="utf-8"))
matches = [
    image["reference"]
    for image in value.get("images", [])
    if role in image.get("roles", []) and platform in image.get("platforms", {})
]
if len(matches) != 1 or re.fullmatch(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}", matches[0]) is None:
    raise SystemExit(f"image lock does not select exactly one immutable {role} image for {platform}")
print(matches[0])
PY
}

materialize_zotero_translation_runtime() {
  local image source_helper openclaw_root skill_root compose helper count
  image="$(locked_image_for_role zotero-translation-server)"
  source_helper="$REPO/agents/claude/skills/zotero/scripts/start-translation-server.sh"
  [[ -f "$source_helper" && ! -L "$source_helper" ]] || {
    echo "materialize-openclaw-runtime: locked Translation Server helper is unavailable" >&2
    return 2
  }
  openclaw_root="$TARGET_HOME/.openclaw/workspace/skills/zotero"
  count=0
  for skill_root in \
    "$openclaw_root" \
    "$TARGET_HOME/.codex/runtime/workspace/skills/zotero" \
    "$TARGET_HOME/.local/share/ai-agents-skills/runtime/workspace/skills/zotero"; do
    [[ -d "$skill_root" ]] || continue
    [[ ! -L "$skill_root" ]] || {
      echo "materialize-openclaw-runtime: refusing symlink Zotero runtime: $skill_root" >&2
      return 2
    }
    compose="$skill_root/docker-compose.yml"
    helper="$skill_root/scripts/start-translation-server.sh"
    [[ ! -L "$compose" && ! -L "$helper" ]] || {
      echo "materialize-openclaw-runtime: refusing symlink Translation Server destination" >&2
      return 2
    }
    install -d -m 0755 "$skill_root/scripts"
    TEMPORARY="$(mktemp "$skill_root/.docker-compose.yml.XXXXXX")"
    cat > "$TEMPORARY" <<'EOF'
services:
  translation-server:
    image: ${ZOTERO_TS_IMAGE:?ZOTERO_TS_IMAGE must be set}
    container_name: zotero-translation-server
    ports:
      - "1969:1969"
    restart: unless-stopped
    mem_limit: 1g
EOF
    chmod 0644 "$TEMPORARY"
    mv -f "$TEMPORARY" "$compose"
    TEMPORARY=""
    if [[ "$skill_root" == "$openclaw_root" ]]; then
      install -m 0755 "$source_helper" "$helper"
    else
      # Codex/shared runtime helpers are owned and integrity-verified by the
      # pinned ai-agents-skills component. Only supply their untracked Compose
      # input; overwriting the helper would invalidate managed-state proof.
      [[ -f "$helper" && ! -L "$helper" && -x "$helper" ]] || {
        echo "materialize-openclaw-runtime: AAS-managed Translation Server helper is unavailable" >&2
        return 2
      }
    fi
    # Every helper must select this same digest by architecture. Keeping the
    # selected reference out of Compose prevents a direct invocation from
    # silently falling back to a mutable tag.
    grep -Fq "$image" "$helper" || {
      echo "materialize-openclaw-runtime: helper/image lock disagreement" >&2
      return 2
    }
    count=$((count + 1))
  done
  echo "materialize-openclaw-runtime: locked Translation Server runtimes materialized: $count"
}

materialize_zotero_translation_runtime
