#!/usr/bin/env bash
# PreToolUse safety hook for Bash — blocks dangerous commands.
# Exit 0 = allow, Exit 2 = block (stderr shown to Claude as feedback).
# Input: JSON on stdin with tool_name, tool_input, etc.
set -euo pipefail

INPUT=$(cat)
[[ -z "$INPUT" ]] && exit 0

PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
if [[ -n "$PY" ]]; then
  cmd=$(echo "$INPUT" | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null || echo "")
else
  cmd=$(echo "$INPUT" | grep -oP '"command"\s*:\s*"[^"]*"' | head -1 | sed 's/"command"\s*:\s*"//;s/"$//' || echo "")
fi
[[ -z "$cmd" ]] && exit 0

# ---- F6: skip pattern scans when command is a file write ----
# cat/tee/printf/echo + redirect (>, >>) or heredoc (<<, <<-) means the
# remainder is data being written, not executed. Avoids false-positives on
# heredoc content.
first_tok=$(echo "$cmd" | awk '{print $1}')
cmd_is_write=0
case "$first_tok" in
  cat|tee|printf|echo)
    if echo "$cmd" | grep -qE '(>>?|<<-?)'; then
      cmd_is_write=1
    fi
    ;;
esac

# ---- rm check ----
# Only when cmd is executing, not writing data.
if [[ $cmd_is_write == 0 ]]; then
  scan_cmd="$cmd"
  scan_first="$first_tok"
  if [[ "$first_tok" == "sudo" ]]; then
    scan_cmd=$(echo "$cmd" | sed 's/^[[:space:]]*sudo[[:space:]]\+//')
    scan_first=$(echo "$scan_cmd" | awk '{print $1}')
  fi

  if [[ "$scan_first" == "rm" ]]; then
    has_destructive=0
    targets=()
    # shellcheck disable=SC2206
    read -ra tokens <<< "$scan_cmd"
    i=1
    while (( i < ${#tokens[@]} )); do
      t="${tokens[$i]}"
      case "$t" in
        --recursive|--force|--recursive=*|--force=*)
          has_destructive=1
          ;;
        --)
          j=$((i+1))
          while (( j < ${#tokens[@]} )); do
            targets+=("${tokens[$j]}")
            j=$((j+1))
          done
          break
          ;;
        --*)
          : # unknown long flag, ignore
          ;;
        -*)
          if [[ "$t" == *[rRf]* ]]; then has_destructive=1; fi
          ;;
        *)
          targets+=("$t")
          ;;
      esac
      i=$((i+1))
    done

    if [[ $has_destructive == 1 && ${#targets[@]} -gt 0 ]]; then
      for tgt in "${targets[@]}"; do
        # Strip surrounding quotes if present
        t="$tgt"
        t="${t#\"}"; t="${t%\"}"
        t="${t#\'}"; t="${t%\'}"
        case "$t" in
          '/'|'/*'|'/.'|\
          '/home'|'/home/'|'/home/*'|\
          '~'|'~/'|'~/*'|\
          '$HOME'|'$HOME/'|'$HOME/*'|\
          '.'|'./'|'./*'|'..'|'../'|'../*'|\
          '/etc'|'/etc/'|'/etc/*'|\
          '/usr'|'/usr/'|'/usr/*'|\
          '/var'|'/var/'|'/var/*'|\
          '/boot'|'/boot/'|'/boot/*'|\
          '/bin'|'/bin/'|'/bin/*'|\
          '/sbin'|'/sbin/'|'/sbin/*'|\
          '/lib'|'/lib/'|'/lib/*'|\
          '/lib64'|'/lib64/'|'/lib64/*')
            echo "BLOCKED: destructive rm on hazardous target '$tgt'. Use a more specific path." >&2
            exit 2
            ;;
        esac
      done
    fi
  fi

  # ---- pipe-to-shell ----
  if echo "$cmd" | grep -qE '(curl|wget)\s+[^|]*\|\s*(ba)?sh'; then
    echo "BLOCKED: pipe-to-shell is dangerous. Download first, inspect, then execute." >&2
    exit 2
  fi

  # ---- DROP DATABASE/TABLE ----
  if echo "$cmd" | grep -qiE 'DROP\s+(DATABASE|TABLE)\s'; then
    echo "BLOCKED: DROP DATABASE/TABLE detected. Confirm with user first." >&2
    exit 2
  fi
fi

# ---- force push to main/master (scanned always; unlikely in heredocs) ----
if echo "$cmd" | grep -qE 'git\s+push\s+.*--force(-with-lease)?\b.*\s+(origin\s+)?(main|master)\b'; then
  echo "BLOCKED: force push to main/master. Use a feature branch or ask the user." >&2
  exit 2
fi

exit 0
