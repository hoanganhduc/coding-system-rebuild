#!/usr/bin/env bash
# Materialize derived OpenClaw runtime files from restored authorities.
set -euo pipefail

TARGET_HOME="${HOME_OVERRIDE:-$HOME}"
TEMPORARY=""
trap '[[ -z "${TEMPORARY:-}" ]] || rm -f "$TEMPORARY"' EXIT

materialize_research_config() {
  local source destination
  source="$TARGET_HOME/.local/share/ai-agents-skills/runtime/workspace/config/research-compute.toml"
  destination="$TARGET_HOME/.openclaw/workspace/config/research-compute.toml"

  if [[ ! -f "$source" ]]; then
    echo "materialize-openclaw-runtime: optional source absent: $source"
    return
  fi

  mkdir -p "$(dirname "$destination")"
  TEMPORARY="$(mktemp "$(dirname "$destination")/.research-compute.toml.XXXXXX")"
  if grep -Eq '^broker_state_root[[:space:]]*=' "$source"; then
    sed \
      's|^broker_state_root[[:space:]]*=.*$|broker_state_root = "data/research/research-compute"|' \
      "$source" > "$TEMPORARY"
  else
    awk '
      BEGIN { inserted = 0 }
      /^\[/ && !inserted {
        print "broker_state_root = \"data/research/research-compute\""
        print ""
        inserted = 1
      }
      { print }
      END {
        if (!inserted) {
          print "broker_state_root = \"data/research/research-compute\""
        }
      }
    ' "$source" > "$TEMPORARY"
  fi
  chmod 600 "$TEMPORARY"
  if ! grep -Fqx 'broker_state_root = "data/research/research-compute"' "$TEMPORARY"; then
    echo "materialize-openclaw-runtime: failed to derive broker_state_root" >&2
    exit 2
  fi
  if [[ -f "$destination" ]] && cmp -s "$TEMPORARY" "$destination"; then
    chmod 600 "$destination"
    rm -f "$TEMPORARY"
    TEMPORARY=""
    echo "materialize-openclaw-runtime: current: $destination"
    return
  fi
  mv -f "$TEMPORARY" "$destination"
  TEMPORARY=""
  echo "materialize-openclaw-runtime: installed: $destination"
}

materialize_getscipapers_credentials() {
  local source destination credential relative service service_destination count
  source="$TARGET_HOME/.config/getscipapers"
  destination="$TARGET_HOME/.openclaw/workspace/secrets/getscipapers"
  count=0

  if [[ ! -d "$source" ]]; then
    echo "materialize-openclaw-runtime: optional source absent: $source"
    return
  fi

  mkdir -p "$destination"
  chmod 700 "$destination"
  while IFS= read -r -d '' credential; do
    relative="${credential#"$source"/}"
    service="${relative%%/*}"
    [[ "$relative" == "$service/credentials.json" ]] || continue
    [[ "$service" =~ ^[A-Za-z0-9._-]+$ ]] || {
      echo "materialize-openclaw-runtime: invalid GetSciPapers service name" >&2
      exit 2
    }
    service_destination="$destination/$service"
    mkdir -p "$service_destination"
    chmod 700 "$service_destination"
    TEMPORARY="$(mktemp "$service_destination/.credentials.json.XXXXXX")"
    install -m 600 "$credential" "$TEMPORARY"
    if [[ -f "$service_destination/credentials.json" ]] \
      && cmp -s "$TEMPORARY" "$service_destination/credentials.json"; then
      chmod 600 "$service_destination/credentials.json"
      rm -f "$TEMPORARY"
    else
      mv -f "$TEMPORARY" "$service_destination/credentials.json"
    fi
    TEMPORARY=""
    count=$((count + 1))
  done < <(find "$source" -mindepth 2 -maxdepth 2 -type f -name credentials.json -print0)
  echo "materialize-openclaw-runtime: GetSciPapers credentials materialized: $count"
}

materialize_modal_credentials() {
  local source destination
  source="$TARGET_HOME/.modal.toml"
  destination="$TARGET_HOME/.openclaw/workspace/.modal.toml"

  if [[ ! -f "$source" ]]; then
    echo "materialize-openclaw-runtime: optional source absent: $source"
    return
  fi

  mkdir -p "$(dirname "$destination")"
  chmod 700 "$(dirname "$destination")"
  TEMPORARY="$(mktemp "$(dirname "$destination")/.modal.toml.XXXXXX")"
  install -m 600 "$source" "$TEMPORARY"
  if [[ -f "$destination" ]] && cmp -s "$TEMPORARY" "$destination"; then
    chmod 600 "$destination"
    rm -f "$TEMPORARY"
    TEMPORARY=""
    echo "materialize-openclaw-runtime: current: $destination"
    return
  fi
  mv -f "$TEMPORARY" "$destination"
  TEMPORARY=""
  echo "materialize-openclaw-runtime: installed: $destination"
}

materialize_research_config
materialize_getscipapers_credentials
materialize_modal_credentials
