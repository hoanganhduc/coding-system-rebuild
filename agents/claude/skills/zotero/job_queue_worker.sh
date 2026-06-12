#!/usr/bin/env bash
set -euo pipefail

# Unified host-side job queue worker.
# Handles: file sending (type=send) and SageMath execution (type=sage).
# Watches two directories for .json job files.
#
# Run as: systemctl --user start send-queue-worker
# Or manually: ./job_queue_worker.sh

WORKSPACE="${OPENCLAW_WORKSPACE:-{{ HOME }}/.openclaw/workspace}"
SEND_QUEUE="$WORKSPACE/data/send-queue"
JOB_QUEUE="$WORKSPACE/data/job-queue"
SAGE_OUTPUT="$WORKSPACE/data/research/sagemath"
SAGE_LOG="$SAGE_OUTPUT/run-log.jsonl"
SAGE_IMAGE="ghcr.io/hoanganhduc/sagemath:10.8"
SAGE_CONTAINER="sagemath-worker"
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
OUTPUT_MAX_BYTES=1048576  # 1MB

mkdir -p "$SEND_QUEUE" "$JOB_QUEUE" "$SAGE_OUTPUT"

log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }

# --- File sending (existing logic) ---

process_send_job() {
  local job_file="$1"
  local job_id
  job_id=$(basename "$job_file" .json)
  local result_file="$SEND_QUEUE/${job_id}.result"

  local channel target media caption
  channel=$(python3 -c "import json; print(json.load(open('$job_file'))['channel'])")
  target=$(python3 -c "import json; print(json.load(open('$job_file'))['target'])")
  media=$(python3 -c "import json; print(json.load(open('$job_file'))['media'])")
  caption=$(python3 -c "import json; print(json.load(open('$job_file')).get('caption',''))")

  local host_media="${media/\/workspace/$WORKSPACE}"

  if [[ ! -f "$host_media" ]]; then
    echo '{"status":"error","message":"File not found on host: '"$host_media"'"}' > "$result_file"
    log "SEND FAIL $job_id: file not found $host_media"
    return
  fi

  log "SEND $job_id: $channel -> $target ($(basename "$host_media"))"

  local cmd=("$OPENCLAW_BIN" message send --channel "$channel" --target "$target" --media "$host_media")
  if [[ -n "$caption" ]]; then
    cmd+=(-m "$caption")
  fi

  local output
  if output=$("${cmd[@]}" 2>&1); then
    echo '{"status":"ok","channel":"'"$channel"'","target":"'"$target"'","file":"'"$(basename "$host_media")"'"}' > "$result_file"
    log "SEND OK $job_id"
  else
    echo '{"status":"error","channel":"'"$channel"'","message":"send failed","output":"'"$(echo "$output" | head -1)"'"}' > "$result_file"
    log "SEND FAIL $job_id: $output"
  fi
}

# --- SageMath execution ---

ensure_sage_container() {
  if ! docker inspect "$SAGE_CONTAINER" >/dev/null 2>&1; then
    log "SAGE starting persistent container"
    docker run -d --name "$SAGE_CONTAINER" --restart=unless-stopped \
      --cpus=3 --memory=16g --network=none -e SAGE_NUM_THREADS=3 \
      -v "$WORKSPACE:/workspace" \
      "$SAGE_IMAGE" tail -f /dev/null >/dev/null 2>&1
    sleep 2
  elif [[ "$(docker inspect -f '{{.State.Running}}' "$SAGE_CONTAINER" 2>/dev/null)" != "true" ]]; then
    log "SAGE restarting stopped container"
    docker start "$SAGE_CONTAINER" >/dev/null 2>&1
    sleep 2
  fi
}

process_sage_job() {
  local job_file="$1"
  local job_id
  job_id=$(basename "$job_file" .json)
  local result_file="$JOB_QUEUE/${job_id}.result"
  local sage_file="$JOB_QUEUE/${job_id}.sage"
  local cancel_file="$JOB_QUEUE/${job_id}.cancel"
  local plot_file="$JOB_QUEUE/${job_id}.png"
  local start_time
  start_time=$(date +%s)

  local mode job_timeout save_label is_plot
  mode=$(python3 -c "import json; print(json.load(open('$job_file'))['mode'])")
  job_timeout=$(python3 -c "import json; print(json.load(open('$job_file'))['timeout'])")
  save_label=$(python3 -c "import json; print(json.load(open('$job_file')).get('save_label',''))")
  is_plot=$(python3 -c "import json; print(json.load(open('$job_file')).get('plot', False))")

  log "SAGE $job_id: mode=$mode timeout=${job_timeout}s plot=$is_plot"

  ensure_sage_container

  # Run sage in background so we can check for cancellation
  local output exit_code
  local tmp_output="$JOB_QUEUE/${job_id}.stdout"

  if [[ "$mode" == "file" ]]; then
    local file_path
    file_path=$(python3 -c "import json; print(json.load(open('$job_file'))['file'])")
    local host_file="${file_path/\/workspace/$WORKSPACE}"
    if [[ ! -f "$host_file" ]]; then
      echo '{"status":"error","message":"Sage file not found: '"$file_path"'"}' > "$result_file"
      log "SAGE FAIL $job_id: file not found"
      return
    fi
    timeout "$job_timeout" docker exec "$SAGE_CONTAINER" sage "$file_path" > "$tmp_output" 2>&1 &
  else
    if [[ ! -f "$sage_file" ]]; then
      echo '{"status":"error","message":"Sage code file missing"}' > "$result_file"
      log "SAGE FAIL $job_id: no .sage file"
      return
    fi
    local container_sage="/workspace/data/job-queue/${job_id}.sage"
    timeout "$job_timeout" docker exec "$SAGE_CONTAINER" sage "$container_sage" > "$tmp_output" 2>&1 &
  fi

  local bg_pid=$!

  # Poll for completion or cancellation
  while kill -0 "$bg_pid" 2>/dev/null; do
    if [[ -f "$cancel_file" ]]; then
      kill "$bg_pid" 2>/dev/null || true
      wait "$bg_pid" 2>/dev/null || true
      rm -f "$cancel_file" "$tmp_output"
      echo '{"status":"cancelled","job_id":"'"$job_id"'","message":"Job cancelled by user"}' > "$result_file"
      log "SAGE CANCEL $job_id"
      return
    fi
    sleep 1
  done

  wait "$bg_pid" 2>/dev/null
  exit_code=$?
  output=$(cat "$tmp_output" 2>/dev/null || echo "")
  rm -f "$tmp_output"

  exit_code="${exit_code:-0}"
  local end_time duration
  end_time=$(date +%s)
  duration=$((end_time - start_time))

  # Truncate output if too large
  local output_bytes
  output_bytes=$(echo -n "$output" | wc -c)
  local truncated=false
  if [[ "$output_bytes" -gt "$OUTPUT_MAX_BYTES" ]]; then
    output=$(echo "$output" | head -c "$OUTPUT_MAX_BYTES")
    output="${output}
... [truncated: output exceeded 1MB limit]"
    truncated=true
  fi

  # Detect plot file
  local has_plot=false
  local plot_path=""
  if [[ -f "$plot_file" ]]; then
    has_plot=true
    plot_path="$plot_file"
  fi

  # Build result
  if [[ "$exit_code" -eq 0 ]]; then
    python3 -c "
import json, sys
result = {
    'status': 'ok',
    'job_id': '$job_id',
    'duration_seconds': $duration,
    'truncated': $( [[ "$truncated" == "true" ]] && echo "True" || echo "False" ),
    'plot': '$plot_path' if '$has_plot' == 'true' else None,
    'output': sys.stdin.read()
}
with open('$result_file', 'w') as f:
    json.dump(result, f)
" <<< "$output"
    log "SAGE OK $job_id (${duration}s)$( [[ "$has_plot" == "true" ]] && echo " [plot]" )"
  elif [[ "$exit_code" -eq 124 ]]; then
    echo '{"status":"error","message":"Computation timed out after '"$job_timeout"'s. Try --timeout with a larger value or reduce input size.","job_id":"'"$job_id"'","duration_seconds":'"$duration"'}' > "$result_file"
    log "SAGE TIMEOUT $job_id (${duration}s)"
  elif [[ "$exit_code" -eq 137 ]]; then
    echo '{"status":"error","message":"Computation killed (likely out of memory). Try a smaller input or a less memory-intensive algorithm.","job_id":"'"$job_id"'","duration_seconds":'"$duration"'}' > "$result_file"
    log "SAGE OOM $job_id (${duration}s)"
  else
    # Other error — add actionable suggestions
    local suggestion=""
    if echo "$output" | grep -qi "SyntaxError\|NameError\|TypeError"; then
      suggestion=" Check Sage syntax — see /workspace/skills/sagemath/sage_reference.md"
    elif echo "$output" | grep -qi "MemoryError\|Killed"; then
      suggestion=" Try a smaller graph or less memory-intensive method."
    fi
    python3 -c "
import json, sys
result = {
    'status': 'error',
    'job_id': '$job_id',
    'exit_code': $exit_code,
    'duration_seconds': $duration,
    'message': 'SageMath error (exit code $exit_code).$suggestion',
    'output': sys.stdin.read()
}
with open('$result_file', 'w') as f:
    json.dump(result, f)
" <<< "$output"
    log "SAGE FAIL $job_id (exit $exit_code, ${duration}s)"
  fi

  # Clean up cancel file if it exists
  rm -f "$cancel_file"

  # Log to run log
  python3 -c "
import json, datetime
entry = {
    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
    'job_id': '$job_id',
    'mode': '$mode',
    'duration_seconds': $duration,
    'exit_code': $exit_code,
    'save_label': '$save_label' or None
}
with open('$SAGE_LOG', 'a') as f:
    f.write(json.dumps(entry) + '\n')
" 2>/dev/null || true

  # Save result if --save was used
  if [[ -n "$save_label" && "$exit_code" -eq 0 ]]; then
    cp "$result_file" "$SAGE_OUTPUT/${save_label}.json" 2>/dev/null || true
    log "SAGE SAVED $job_id -> ${save_label}.json"
  fi
}

# --- Health check for persistent container ---
HEALTH_CHECK_INTERVAL=150  # every ~5 minutes (150 * 2s sleep)
health_counter=0

check_sage_health() {
  if docker inspect "$SAGE_CONTAINER" >/dev/null 2>&1; then
    if ! timeout 10 docker exec "$SAGE_CONTAINER" sage -c "print(1)" >/dev/null 2>&1; then
      log "SAGE HEALTH: container unresponsive, restarting"
      docker restart "$SAGE_CONTAINER" >/dev/null 2>&1 || true
    fi
  fi
}

# --- Main loop ---

log "Job queue worker started"
log "  Send queue: $SEND_QUEUE"
log "  Job queue:  $JOB_QUEUE"
log "  Sage image: $SAGE_IMAGE"

while true; do
  # Process send queue
  for job_file in "$SEND_QUEUE"/*.json; do
    [[ -f "$job_file" ]] || continue
    process_send_job "$job_file"
  done

  # Process job queue (SageMath)
  for job_file in "$JOB_QUEUE"/*.json; do
    [[ -f "$job_file" ]] || continue
    process_sage_job "$job_file"
  done

  # Periodic health check
  health_counter=$((health_counter + 1))
  if [[ $health_counter -ge $HEALTH_CHECK_INTERVAL ]]; then
    check_sage_health
    health_counter=0
  fi

  sleep 2
done
