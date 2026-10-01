#!/usr/bin/env bash
# Prove HEAD is the exact published upstream branch tip before binding recovery media to it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
die() { echo "published-head: $*" >&2; exit 2; }
safe_git() {
  /usr/bin/env -i \
    HOME=/nonexistent PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 XDG_CONFIG_HOME=/nonexistent \
    /usr/bin/git --no-optional-locks \
      -c core.fsmonitor=false -c core.hooksPath=/dev/null \
      -c credential.helper= -c protocol.allow=never \
      -c protocol.https.allow=always "$@"
}

[[ -z "$(safe_git -C "$REPO" status --porcelain=v1 --untracked-files=all)" ]] \
  || die "worktree/index is not clean"
branch="$(safe_git -C "$REPO" symbolic-ref --quiet --short HEAD)" \
  || die "recovery sets must be created from a named branch"
upstream="$(safe_git -C "$REPO" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" \
  || die "current branch has no configured upstream"
remote="${upstream%%/*}"
remote_branch="${upstream#*/}"
[[ -n "$remote" && -n "$remote_branch" && "$upstream" == */* ]] \
  || die "configured upstream is invalid"
[[ "$branch" == "$remote_branch" ]] \
  || die "current branch $branch does not track its same-named default branch ($upstream)"
remote_url="$(safe_git -C "$REPO" remote get-url "$remote")" \
  || die "cannot resolve the upstream remote"
expected_url="${CSR_REPOSITORY_URL:-https://github.com/hoanganhduc/coding-system-rebuild.git}"
case "$remote_url" in
  "$expected_url"|"${expected_url%.git}") ;;
  *) die "upstream URL differs from the Stage-0 repository authority" ;;
esac

safe_git -C "$REPO" fetch --quiet --no-tags "$remote" \
  "+refs/heads/$remote_branch:refs/remotes/$remote/$remote_branch" \
  || die "cannot refresh the upstream branch"
head_commit="$(safe_git -C "$REPO" rev-parse --verify 'HEAD^{commit}')"
remote_commit="$(safe_git -C "$REPO" rev-parse --verify "$upstream^{commit}")"
[[ "$head_commit" == "$remote_commit" ]] \
  || die "HEAD is not published at $upstream; review and run make push first"
echo "published-head: $head_commit is the exact $upstream tip"
