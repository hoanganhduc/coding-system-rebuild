#!/usr/bin/env bash
# Redundant escrow for the backup passphrase (fixes the single-machine SPOF).
#
# Splits ~/.config/coding-system/zip-password.txt into a 2-of-4 Shamir set
# (bin/lib/shamir.py) and distributes one share per independent location:
#   local   ~/.config/coding-system/passphrase-share-local.txt
#   dropbox <CSR_RCLONE_DEST>/escrow/passphrase-share-dropbox.txt
#   gdrive  <CSR_ESCROW_GDRIVE>/escrow/passphrase-share-gdrive.txt
#   github  private repo <CSR_ESCROW_GH_REPO> : passphrase-share-github.txt
# Any single location reveals nothing; any TWO reconstruct the passphrase.
# A local manifest records sha256(passphrase) so rotation auto-re-escrows.
#
# Usage: escrow-passphrase.sh ensure   (default; idempotent, self-healing)
#        escrow-passphrase.sh check    (read-only presence+freshness, exit 1 on gap)
#        escrow-passphrase.sh recover FILE_OR_SHARE FILE_OR_SHARE  (prints passphrase)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$HOME/.config/coding-system"
PWFILE="$CFG/zip-password.txt"
LOCAL_SHARE="$CFG/passphrase-share-local.txt"
MANIFEST="$CFG/escrow-manifest.json"
SHAMIR="$REPO/bin/lib/shamir.py"
DROPBOX_DEST="${CSR_RCLONE_DEST:-dropbox:Misc/coding-system-backups}"
GDRIVE_DEST="${CSR_ESCROW_GDRIVE:-gdrive:Misc/coding-system-backups}"
GH_REPO="${CSR_ESCROW_GH_REPO:-hoanganhduc/key-escrow}"
MODE="${1:-ensure}"

pw_hash() { sha256sum "$PWFILE" | awk '{print $1}'; }

notify() {
  [ -f "$HOME/.secrets.env" ] && . "$HOME/.secrets.env"
  [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] && \
    curl -s -m 20 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d chat_id="${TELEGRAM_CHAT_ID}" -d text="$1" >/dev/null || true
}

gh_put() { # gh_put <path-in-repo> <local-file>
  local path="$1" file="$2" sha args
  sha=$(gh api "repos/$GH_REPO/contents/$path" --jq .sha 2>/dev/null || true)
  args=(-f message="escrow: update $path" -f content="$(base64 -w0 "$file")")
  [ -n "$sha" ] && args+=(-f sha="$sha")
  gh api -X PUT "repos/$GH_REPO/contents/$path" "${args[@]}" >/dev/null
}

case "$MODE" in
  recover)
    shift
    [ $# -ge 2 ] || { echo "recover needs two share files/strings" >&2; exit 2; }
    for s in "$@"; do [ -f "$s" ] && cat "$s" || echo "$s"; done | python3 "$SHAMIR" combine
    echo
    exit 0 ;;

  check)
    rc=0
    [ -s "$PWFILE" ] || { echo "check: passphrase file missing"; exit 1; }
    [ -s "$LOCAL_SHARE" ] || { echo "check: local share missing"; rc=1; }
    if [ -s "$MANIFEST" ]; then
      grep -q "\"sha256\": \"$(pw_hash)\"" "$MANIFEST" || { echo "check: passphrase rotated since escrow"; rc=1; }
    else
      echo "check: manifest missing"; rc=1
    fi
    rclone lsf "$DROPBOX_DEST/escrow/passphrase-share-dropbox.txt" >/dev/null 2>&1 || { echo "check: dropbox share missing"; rc=1; }
    gh api "repos/$GH_REPO/contents/passphrase-share-github.txt" --jq .sha >/dev/null 2>&1 || { echo "check: github share missing"; rc=1; }
    if grep -q '"gdrive"' "$MANIFEST" 2>/dev/null; then
      rclone lsf "$GDRIVE_DEST/escrow/passphrase-share-gdrive.txt" >/dev/null 2>&1 || { echo "check: gdrive share missing"; rc=1; }
      n_loc=4
    else
      n_loc=3
      timeout 20 rclone lsf "$GDRIVE_DEST" --max-depth 1 >/dev/null 2>&1 &&         echo "check: NOTE gdrive is reachable but not escrowed yet - next ensure upgrades to 2-of-4"
    fi
    [ "$rc" -eq 0 ] && echo "escrow check: ok (2-of-$n_loc across local+dropbox+github$( [ "$n_loc" -eq 4 ] && echo '+gdrive'))"
    exit "$rc" ;;

  ensure)
    [ -s "$PWFILE" ] || { echo "ensure: passphrase file missing: $PWFILE" >&2; exit 2; }
    if bash "$0" check >/dev/null 2>&1; then
      echo "escrow: current (2-of-4 shares present, hash matches)"
      exit 0
    fi
    # Location set is dynamic: local + dropbox + github always; gdrive joins
    # automatically once its rclone token is reconnected (2-of-3 -> 2-of-4).
    HAVE_GDRIVE=0
    timeout 20 rclone lsf "$GDRIVE_DEST" --max-depth 1 >/dev/null 2>&1 && HAVE_GDRIVE=1
    N=$((3 + HAVE_GDRIVE))
    echo "escrow: (re)distributing 2-of-$N shares"
    umask 077
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    tr -d '\n' < "$PWFILE" | python3 "$SHAMIR" split 2 "$N" > "$tmp/shares" || exit 2
    sed -n 1p "$tmp/shares" > "$LOCAL_SHARE"
    sed -n 2p "$tmp/shares" > "$tmp/dropbox.txt"
    sed -n 3p "$tmp/shares" > "$tmp/github.txt"
    chmod 600 "$LOCAL_SHARE"
    rclone copyto "$tmp/dropbox.txt" "$DROPBOX_DEST/escrow/passphrase-share-dropbox.txt" || { echo "ensure: dropbox upload failed" >&2; exit 2; }
    gh repo view "$GH_REPO" >/dev/null 2>&1 || gh repo create "$GH_REPO" --private -d "Shamir escrow shares (threshold 2; each share alone reveals nothing)" >/dev/null
    gh_put "passphrase-share-github.txt" "$tmp/github.txt" || { echo "ensure: github upload failed" >&2; exit 2; }
    LOCS='"local", "dropbox", "github:'"$GH_REPO"'"'
    if [ "$HAVE_GDRIVE" -eq 1 ]; then
      sed -n 4p "$tmp/shares" > "$tmp/gdrive.txt"
      rclone copyto "$tmp/gdrive.txt" "$GDRIVE_DEST/escrow/passphrase-share-gdrive.txt" || { echo "ensure: gdrive upload failed" >&2; exit 2; }
      LOCS="$LOCS"', "gdrive"'
    else
      echo "escrow: NOTE gdrive token dead - running 2-of-3; reconnect with 'rclone config reconnect gdrive:' to auto-upgrade to 2-of-4"
    fi
    printf '{\n  "schema": "csr-escrow-v1",\n  "k": 2,\n  "n": %s,\n  "sha256": "%s",\n  "locations": [%s],\n  "updated": "%s"\n}\n' \
      "$N" "$(pw_hash)" "$LOCS" "$(date -u +%FT%TZ)" > "$MANIFEST"
    chmod 600 "$MANIFEST"
    gh_put "escrow-manifest.json" "$MANIFEST" || true
    notify "coding-system escrow updated on $(hostname): backup passphrase split 2-of-$N across local disk, Dropbox$( [ "$HAVE_GDRIVE" -eq 1 ] && echo ', Google Drive,' || echo ' and') private GitHub repo $GH_REPO. Any two shares recover it (bin/escrow-passphrase.sh recover <share> <share>); no single location can."
    echo "escrow: done (2-of-$N)"
    exit 0 ;;

  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
