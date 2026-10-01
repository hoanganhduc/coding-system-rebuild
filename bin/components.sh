#!/usr/bin/env bash
# Materialize pinned components per components.lock.
#   url@<sha>           -> clone via HTTPS, checkout sha, verify HEAD
#   url@LOCAL:<path>    -> symlink external/<name> to the live checkout (pre-publish mode)
# LOCAL=1 forces live checkouts for ALL components when present.
set -euo pipefail
umask 077
# The caller's npm, found before PATH is narrowed, builds JavaScript components
# when neither the locked Node closure nor /usr/bin provides one (CI runners).
CALLER_NPM="$(command -v npm || true)"
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR \
  GIT_CONFIG_COUNT GIT_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_WORK_TREE \
  LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONHOME
REPO="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
COMPONENT_ROOT="$HOME/.local/share/coding-system/components"
/usr/bin/mkdir -p "$COMPONENT_ROOT"
/usr/bin/chmod 0700 "$HOME/.local/share/coding-system" "$COMPONENT_ROOT"
safe_git() {
  /usr/bin/env -i HOME=/ PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 XDG_CONFIG_HOME=/dev/null \
    /usr/bin/git --no-optional-locks \
      -c core.hooksPath=/dev/null -c core.fsmonitor=false \
      -c protocol.allow=never -c protocol.https.allow=always \
      -c protocol.ext.allow=never -c protocol.file.allow=never \
      -c credential.helper= -c core.sshCommand=/bin/false "$@"
}
# The live host reaches the chatgpt-local-coder CLI the way `npm link` sets it
# up: ~/.npm-global/lib/node_modules/chatgpt-local-coder points at the checkout
# and each bin that package.json declares is linked in ~/.npm-global/bin.
link_local_coder_cli() {
  local dest="$1" modules="$HOME/.npm-global/lib/node_modules"
  local bins="$HOME/.npm-global/bin" bin_map bin_name bin_path linked=0
  [[ "$dest" == "$HOME/chatgpt-local-coder" ]] || return 1
  [[ -d "$modules" && ! -L "$modules" && -d "$bins" && ! -L "$bins" ]] || {
    echo "ERROR: no npm global root to link the chatgpt-local-coder CLI into" >&2
    return 1
  }
  bin_map="$(/usr/bin/python3 -I -B -c '
import json, re, sys
from pathlib import PurePosixPath
bins = json.load(open(sys.argv[1], encoding="utf-8")).get("bin")
if not isinstance(bins, dict) or not bins:
    raise SystemExit("chatgpt-local-coder declares no bin map")
for name, value in sorted(bins.items()):
    path = PurePosixPath(value) if isinstance(value, str) else None
    if (path is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None
            or path.is_absolute() or ".." in path.parts or path.parts[:1] != ("dist",)):
        raise SystemExit("chatgpt-local-coder bin map is unsafe")
    print(f"{name}\t{path.as_posix()}")
' "$dest/package.json")" || return 1
  [[ -L "$modules/chatgpt-local-coder" || ! -e "$modules/chatgpt-local-coder" ]] || {
    echo "ERROR: $modules/chatgpt-local-coder exists and is not a link" >&2
    return 1
  }
  /usr/bin/ln -sfn ../../../chatgpt-local-coder "$modules/chatgpt-local-coder"
  while IFS=$'\t' read -r bin_name bin_path; do
    [[ -f "$dest/$bin_path" && ! -L "$dest/$bin_path" ]] || {
      echo "ERROR: chatgpt-local-coder bin target is missing: $bin_path" >&2
      return 1
    }
    [[ -x "$dest/$bin_path" ]] || /usr/bin/chmod 0755 "$dest/$bin_path"
    [[ -L "$bins/$bin_name" || ! -e "$bins/$bin_name" ]] || {
      echo "ERROR: $bins/$bin_name exists and is not a link" >&2
      return 1
    }
    /usr/bin/ln -sfn "../lib/node_modules/chatgpt-local-coder/$bin_path" "$bins/$bin_name"
    linked=$((linked + 1))
  done <<< "$bin_map"
  (( linked > 0 ))
}
RC=0
while IFS='=' read -r name rest; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  url="${rest%@*}"; ref="${rest##*@}"
  # ai-agents-skills remains at the compatibility path used by existing skill
  # references.  An existing development checkout is never checked out or
  # cleaned here: phase 8 executes a root-owned materialization of the exact
  # pinned object instead of mutable worktree bytes.
  case "$name" in
    ai-agents-skills|chatgpt-local-coder) dest="$HOME/$name" ;;
    vnu-eoffice) dest="$HOME/.openclaw/workspace/vnueoffice_repo" ;;
    openclaw-bot|course_management_toolkit)
      /usr/bin/install -d -m 0700 "$COMPONENT_ROOT/$name"
      dest="$COMPONENT_ROOT/$name/$ref"
      ;;
    *) echo "ERROR: unsupported component name: $name" >&2; RC=1; continue ;;
  esac
  if [[ "$ref" == LOCAL:* || "${LOCAL:-0}" == "1" ]]; then
    path="${ref#LOCAL:}"; path="${path/#\~/$HOME}"
    if [[ "$name" == "openclaw-bot" || "$name" == "course_management_toolkit" ]]; then
      dest="$COMPONENT_ROOT/$name/development"
      [[ ! -e "$dest" || -L "$dest" ]] \
        || { echo "ERROR: refusing to replace immutable development component: $dest" >&2; RC=1; continue; }
    fi
    if [[ -d "$path" ]]; then
      ln -sfn "$path" "$dest"
      echo "component $name -> live checkout $path"
    else
      echo "WARN: $name live path missing: $path" >&2; RC=1
    fi
    continue
  fi
  if [[ "$name" == "openclaw-bot" || "$name" == "course_management_toolkit" ]]; then
    [[ "$ref" =~ ^[0-9a-f]{40}$ ]] \
      || { echo "ERROR: $name requires one exact commit pin" >&2; RC=1; continue; }
    if [[ -e "$dest" || -L "$dest" ]]; then
      /usr/bin/python3 -I -B "$REPO/bin/verify-exact-checkout.py" \
        --repository "$dest" --commit "$ref" >/dev/null \
        || { echo "ERROR: immutable $name checkout is unsafe or divergent" >&2; RC=1; continue; }
      head=$(safe_git -C "$dest" rev-parse --verify 'HEAD^{commit}')
      [[ "$head" == "$ref" ]] \
        || { echo "ERROR: immutable $name HEAD differs from lock" >&2; RC=1; continue; }
      echo "component $name @ ${ref:0:12} (immutable current)"
      continue
    fi
    stage=$(/usr/bin/mktemp -d "$COMPONENT_ROOT/$name/.stage-${ref}.XXXXXXXX") \
      || { echo "ERROR: cannot stage immutable $name" >&2; RC=1; continue; }
    /usr/bin/chmod 0700 "$stage"
    if ! safe_git init -q "$stage" \
        || ! safe_git -C "$stage" remote add origin "$url" \
        || ! safe_git -C "$stage" fetch -q --depth 1 origin "$ref" \
        || ! safe_git -C "$stage" checkout -q --detach FETCH_HEAD \
        || ! /usr/bin/python3 -I -B "$REPO/bin/verify-exact-checkout.py" \
          --repository "$stage" --commit "$ref" >/dev/null; then
      /usr/bin/rm -rf -- "$stage"
      echo "ERROR: cannot authenticate immutable $name@$ref" >&2
      RC=1
      continue
    fi
    if ! /usr/bin/mv -T --no-clobber -- "$stage" "$dest"; then
      /usr/bin/rm -rf -- "$stage"
      echo "ERROR: cannot publish immutable $name@$ref" >&2
      RC=1
      continue
    fi
    echo "component $name @ ${ref:0:12} (immutable installed)"
    continue
  fi
  if [[ "$name" == "chatgpt-local-coder" && "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    # The owner develops in this checkout: an existing one is left as it is; a
    # fresh host gets the pinned commit, built once for its user services.
    if [[ -L "$dest" || ( -e "$dest" && ! -d "$dest" ) ]]; then
      echo "ERROR: $name checkout is unsafe: $dest" >&2
      RC=1
      continue
    fi
    if [[ -d "$dest/.git" ]]; then
      echo "component $name: existing checkout preserved"
      link_local_coder_cli "$dest" \
        || { echo "ERROR: cannot link the $name CLI" >&2; RC=1; }
      continue
    fi
    safe_git clone -q "$url" "$dest" \
      || { echo "WARN: clone failed for $name ($url) — skipping (degraded)" >&2; RC=1; continue; }
    safe_git -C "$dest" checkout -q --detach "$ref" \
      || { echo "ERROR: cannot checkout fresh $name@$ref" >&2; RC=1; continue; }
    npm_bin="$HOME/.npm-global/bin/npm"
    [[ -x "$npm_bin" ]] || npm_bin=/usr/bin/npm
    [[ -x "$npm_bin" ]] || npm_bin="$CALLER_NPM"
    [[ -n "$npm_bin" && -x "$npm_bin" ]] \
      || { echo "ERROR: no npm to build $name@$ref" >&2; RC=1; continue; }
    # NODE_ENV=production in the caller's environment would omit the compiler.
    ( cd "$dest" && unset NODE_ENV && export PATH="$(/usr/bin/dirname "$npm_bin"):$PATH" \
        && "$npm_bin" ci --include=dev --ignore-scripts --no-audit --no-fund \
        && "$npm_bin" run build ) \
      || { echo "ERROR: cannot build $name@$ref" >&2; RC=1; continue; }
    link_local_coder_cli "$dest" \
      || { echo "ERROR: cannot link the $name CLI" >&2; RC=1; continue; }
    echo "component $name @ ${ref:0:12} (cloned, built and linked)"
    continue
  fi
  if [[ "$name" == "ai-agents-skills" && "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    if [[ -L "$dest" || ( -e "$dest" && ! -d "$dest" ) ]]; then
      echo "ERROR: ai-agents-skills compatibility checkout is unsafe: $dest" >&2
      RC=1
      continue
    fi
    if [[ ! -d "$dest/.git" ]]; then
      /usr/bin/git clone -q "$url" "$dest" \
        || { echo "WARN: clone failed for $name ($url) — skipping (degraded)" >&2; RC=1; continue; }
      /usr/bin/git -C "$dest" checkout -q --detach "$ref" \
        || { echo "ERROR: cannot checkout fresh $name@$ref" >&2; RC=1; continue; }
    elif ! GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git --no-replace-objects \
      -C "$dest" cat-file -e "$ref^{commit}" 2>/dev/null; then
      /usr/bin/git -C "$dest" fetch -q --no-tags origin "$ref" \
        || { echo "ERROR: cannot fetch pinned $name object $ref" >&2; RC=1; continue; }
    fi
    object=$(GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git --no-replace-objects \
      -C "$dest" rev-parse --verify "$ref^{commit}" 2>/dev/null) \
      || { echo "ERROR: cannot resolve pinned $name object" >&2; RC=1; continue; }
    [[ "$object" == "$ref" ]] \
      && echo "component $name object ${ref:0:12} available (worktree preserved)" \
      || { echo "ERROR: $name object != lock" >&2; RC=1; }
    continue
  fi
  if [[ ! -d "$dest/.git" ]]; then
    safe_git clone -q "$url" "$dest" || { echo "WARN: clone failed for $name ($url) — skipping (degraded)" >&2; RC=1; continue; }
  else
    safe_git -C "$dest" fetch -q origin || true
  fi
  safe_git -C "$dest" checkout -q "$ref" || { echo "ERROR: cannot checkout $name@$ref" >&2; RC=1; continue; }
  head=$(safe_git -C "$dest" rev-parse HEAD)
  [[ "$head" == "$ref"* ]] && echo "component $name @ ${head:0:12}" || { echo "ERROR: $name HEAD != lock" >&2; RC=1; }
done < "$REPO/components.lock"

# Compatibility for older host-side OpenClaw launchers that predate the
# sandbox-visible workspace checkout path.
VNU_REPO="$HOME/.openclaw/workspace/vnueoffice_repo"
VNU_LEGACY="$HOME/vnueoffice"
if [[ -d "$VNU_REPO/.git" ]]; then
  if [[ -L "$VNU_LEGACY" ]]; then
    ln -sfn "$VNU_REPO" "$VNU_LEGACY"
  elif [[ ! -e "$VNU_LEGACY" ]]; then
    ln -s "$VNU_REPO" "$VNU_LEGACY"
  else
    echo "WARN: preserving existing non-symlink $VNU_LEGACY" >&2
  fi
fi
exit $RC
