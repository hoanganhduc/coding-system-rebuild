#!/usr/bin/env bash
set -euo pipefail

# SageMath execution via job queue.
# Usage:
#   run_sage.sh "<sage_code>"                     — execute Sage code (5min timeout)
#   run_sage.sh --timeout 1800 "<sage_code>"      — custom timeout (seconds)
#   run_sage.sh --file /workspace/script.sage     — execute a Sage script file
#   run_sage.sh --save "label" "<sage_code>"      — execute and save result
#   run_sage.sh --plot "<sage_code>"              — execute and return image
#   run_sage.sh --session "name" "<sage_code>"    — append to session and run
#   run_sage.sh --cancel <job_id>                 — cancel a running job

WS="${OPENCLAW_WORKSPACE:-/workspace}"
QUEUE_DIR="$WS/data/job-queue"
SAGE_DIR="$WS/data/research/sagemath"
SESSION_DIR="$SAGE_DIR/sessions"
TIMEOUT=300
SAVE_LABEL=""
MODE="code"
CODE=""
FILE_PATH=""
PLOT=false
SESSION_NAME=""
CANCEL_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --file)
      MODE="file"
      FILE_PATH="$2"
      shift 2
      ;;
    --save)
      SAVE_LABEL="$2"
      shift 2
      ;;
    --plot)
      PLOT=true
      shift
      ;;
    --session)
      SESSION_NAME="$2"
      shift 2
      ;;
    --cancel)
      CANCEL_ID="$2"
      shift 2
      ;;
    *)
      CODE="$1"
      shift
      ;;
  esac
done

# Cancel mode
if [[ -n "$CANCEL_ID" ]]; then
  echo "cancel" > "$QUEUE_DIR/${CANCEL_ID}.cancel"
  echo '{"status":"ok","message":"Cancel request sent for '"$CANCEL_ID"'"}'
  exit 0
fi

if [[ "$MODE" == "file" && -z "$FILE_PATH" ]]; then
  echo '{"status":"error","message":"--file requires a path"}'
  exit 1
fi

if [[ "$MODE" == "code" && -z "$CODE" ]]; then
  echo '{"status":"error","message":"No Sage code provided"}'
  exit 1
fi

mkdir -p "$QUEUE_DIR" "$SAGE_DIR" "$SESSION_DIR"
JOB_ID="sage-$(date -u +%Y%m%dT%H%M%S)-$$"
JOB_FILE="$QUEUE_DIR/${JOB_ID}.json"
RESULT_FILE="$QUEUE_DIR/${JOB_ID}.result"

# Session mode: append code to session file, run the full session
if [[ -n "$SESSION_NAME" && "$MODE" == "code" ]]; then
  SESSION_FILE="$SESSION_DIR/${SESSION_NAME}.sage"
  # Check session size (cap at 100KB)
  if [[ -f "$SESSION_FILE" ]]; then
    SESSION_SIZE=$(stat -c %s "$SESSION_FILE" 2>/dev/null || stat -f %z "$SESSION_FILE" 2>/dev/null || echo 0)
    if [[ "$SESSION_SIZE" -gt 102400 ]]; then
      echo '{"status":"error","message":"Session '"$SESSION_NAME"' exceeds 100KB limit. Clear it with --session '"$SESSION_NAME"' --file /dev/null"}'
      exit 1
    fi
  fi
  echo "$CODE" >> "$SESSION_FILE"
  MODE="file"
  FILE_PATH="$SESSION_DIR/${SESSION_NAME}.sage"
fi

# Plot mode: wrap code to save the plot object
if [[ "$PLOT" == "true" && "$MODE" == "code" ]]; then
  PLOT_PATH="$QUEUE_DIR/${JOB_ID}.png"
  CODE="_sage_plot_result = None
${CODE}
_sage_plot_result = _sage_plot_result or locals().get('p') or locals().get('P') or locals().get('plot_obj')
if _sage_plot_result is not None and hasattr(_sage_plot_result, 'save'):
    _sage_plot_result.save('$PLOT_PATH', dpi=150)
    print('PLOT_SAVED:$PLOT_PATH')
elif 'G' in dir() and hasattr(G, 'plot'):
    G.plot().save('$PLOT_PATH', dpi=150)
    print('PLOT_SAVED:$PLOT_PATH')
"
fi

python3 -c "
import json
job = {
    'id': '$JOB_ID',
    'type': 'sage',
    'mode': '$MODE',
    'timeout': $TIMEOUT,
    'save_label': '$SAVE_LABEL',
    'plot': $( [[ "$PLOT" == "true" ]] && echo "True" || echo "False" ),
    'status': 'pending'
}
if '$MODE' == 'file':
    job['file'] = '$FILE_PATH'
with open('$JOB_FILE', 'w') as f:
    json.dump(job, f)
"

# Write code to a separate file to avoid JSON escaping issues
if [[ "$MODE" == "code" ]]; then
  echo "$CODE" > "$QUEUE_DIR/${JOB_ID}.sage"
fi

# Wait for result (poll, max timeout + 30s buffer)
MAX_WAIT=$((TIMEOUT + 30))
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
  if [[ -f "$RESULT_FILE" ]]; then
    cat "$RESULT_FILE"
    rm -f "$JOB_FILE" "$RESULT_FILE" "$QUEUE_DIR/${JOB_ID}.sage" "$QUEUE_DIR/${JOB_ID}.cancel"
    # Don't remove .png — the bot needs it for sending
    exit 0
  fi
  sleep 2
  WAITED=$((WAITED + 2))
done

# Timeout
rm -f "$JOB_FILE" "$QUEUE_DIR/${JOB_ID}.sage" "$QUEUE_DIR/${JOB_ID}.cancel"
echo '{"status":"error","message":"Job queue timeout. Host worker may not be running.","job_id":"'"$JOB_ID"'"}'
exit 1
