#!/usr/bin/env bash
# Create a history-free, public-safe export from an allowlisted repository tree.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-/usr/bin/python3}"
OUTPUT=""
REF="HEAD"

usage() {
  cat >&2 <<'EOF'
Usage:
  bin/public-export.sh --output /absolute/path/to/export [--ref REF]

Creates a history-free public export. The default REF is HEAD and refuses a
dirty source tree. Use an exact commit hash to verify/export the last committed
state while local work is in progress.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "public-export: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$OUTPUT" || -z "$REF" ]]; then
  usage
  exit 2
fi

exec "$PYTHON" -I -B "$REPO/bin/lib/public_export.py" export \
  --repo "$REPO" \
  --output "$OUTPUT" \
  --ref "$REF"
