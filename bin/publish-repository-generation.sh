#!/usr/bin/env bash
# Publish one commit of a checkout as the owner's sealed repository generation
# and point the repository selector at it.  Scheduled jobs run through that
# selector, so updating the code they run needs no root.
#
# Usage: bin/publish-repository-generation.sh [--repository DIR] [--commit REV]
#   --repository  Git checkout to publish from (default: this checkout)
#   --commit      revision to publish (default: HEAD); only committed content is
#                 published, never the working tree
set -euo pipefail

REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REVISION=HEAD
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repository) REPOSITORY="$(cd "$2" && pwd -P)"; shift 2 ;;
    --commit) REVISION="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "usage: $0 [--repository DIR] [--commit REV]" >&2; exit 2 ;;
  esac
done
[[ "$(id -u)" != 0 ]] || { echo "ERROR: run this as the owner, never as root" >&2; exit 2; }

GIT_ENV=(
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C HOME=/nonexistent
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0
)
commit="$("${GIT_ENV[@]}" /usr/bin/git -C "$REPOSITORY" rev-parse --verify "$REVISION^{commit}")"
tree="$("${GIT_ENV[@]}" /usr/bin/git -C "$REPOSITORY" rev-parse --verify "$commit^{tree}")"
helper="$REPOSITORY/bin/lib/repository_generation.py"
generation="$(
  set -o pipefail
  /usr/bin/python3 -I -B -X pycache_prefix=/dev/null "$helper" emit \
    --repository "$REPOSITORY" --commit "$commit" --tree "$tree" \
  | /usr/bin/python3 -I -B -X pycache_prefix=/dev/null "$helper" publish --owner \
    --commit "$commit" --tree "$tree"
)"
[[ "$generation" == "$HOME/.local/share/coding-system/repository-generations/$commit-$tree" ]] \
  || { echo "ERROR: published generation path differs from its identity" >&2; exit 2; }

selector="$HOME/.local/share/coding-system/repository"
[[ ! -e "$selector" || -L "$selector" ]] \
  || { echo "ERROR: repository selector is not a symlink: $selector" >&2; exit 2; }
temporary="$(mktemp -u "$HOME/.local/share/coding-system/.repository.XXXXXXXX")"
ln -s -- "$generation" "$temporary"
mv -fT -- "$temporary" "$selector"
echo "repository selector -> ${generation/#$HOME/\~} (commit ${commit:0:12})"
echo "If this commit changed scheduled jobs, run: python3 $selector/bin/reconcile-host-schedules.py"
