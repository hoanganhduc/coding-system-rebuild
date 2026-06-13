#!/usr/bin/env bash
# Start the optional secret-upload form (port 8099) if it is not already running.
#
# Idempotent and safe to call repeatedly — from the postStart/postAttach lifecycle
# hooks and by hand. Codespaces kills processes backgrounded directly from the
# create-time postStart scope, so this is also the reliable manual path: run it from
# an integrated terminal and the form stays up.
#   bash .devcontainer/start-form.sh
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# already serving? nothing to do
if curl -fsS -o /dev/null --max-time 3 http://localhost:8099/ 2>/dev/null; then
  echo "secret-upload form already running on :8099"
  exit 0
fi

# pick a python that actually has flask (system python gets it from python3-flask;
# the feature python from the pip install in bootstrap.sh)
PY=""
for c in /usr/bin/python3 "$(command -v python3 || true)"; do
  [[ -n "$c" ]] || continue
  if "$c" -c 'import flask' 2>/dev/null; then PY="$c"; break; fi
done
if [[ -z "$PY" ]]; then
  echo "ERROR: no python with flask found (run: sudo apt-get install -y python3-flask)" >&2
  exit 1
fi

nohup setsid "$PY" "$REPO/.devcontainer/upload-server.py" \
  >/tmp/upload-server.log 2>&1 </dev/null &
sleep 2

if curl -fsS -o /dev/null --max-time 5 http://localhost:8099/ 2>/dev/null; then
  echo "secret-upload form started on :8099 (open the forwarded port to upload secrets)"
else
  echo "form launch attempted but :8099 is not responding yet — see /tmp/upload-server.log" >&2
fi
