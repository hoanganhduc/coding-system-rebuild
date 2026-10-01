#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# Ensure workspace-local site-packages are visible (needed in sandbox containers)
for sp in "${HOME}/.local/lib"/python*/site-packages; do
  [[ -d "$sp" ]] && export PYTHONPATH="${sp}:${PYTHONPATH:-}" && break
done
if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/rss_news_digest.py" "$@"
elif [[ -x "{{ HOME }}/.venvs/bin/python" ]]; then
  exec "{{ HOME }}/.venvs/bin/python" "$SCRIPT_DIR/rss_news_digest.py" "$@"
fi
exec python3 "$SCRIPT_DIR/rss_news_digest.py" "$@"
