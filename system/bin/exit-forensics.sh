#!/bin/bash
# Records the state of the machine at the moment the systemd --user manager is
# told to exit, so the caller of `systemctl --user exit` (or of a targeted
# SIGTERM to the manager) can be identified after the fact.
#
# Run by exit-forensics.service, which is ordered Before=systemd-exit.service
# and pulled in by exit.target. Must finish fast: the manager waits for it.
#
# Context: on 2026-08-12 09:21 the user manager reached exit.target with no
# recorded caller, taking down every user service and the tmux server with it.
set -u

out_dir="${HOME}/.local/state/exit-forensics"
mkdir -p "$out_dir"
chmod 700 "$out_dir"
report="${out_dir}/$(date -u +%Y%m%dT%H%M%SZ).txt"

echo "exit-forensics: writing report to ${report}" >&2
exec >"$report" 2>&1

echo "=== exit.target tripwire ==="
echo "recorded    : $(date -Is)"
echo "manager pid : ${MANAGERPID:-unknown}"
echo "boot id     : $(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "uptime      : $(uptime)"

# The decisive evidence: `systemctl --user exit` blocks until the job completes,
# so the calling process and its whole ancestry are still alive right now.
echo
echo "=== ancestry of any live systemctl/loginctl/busctl process ==="
found=0
for pid in $(pgrep -f 'systemctl|loginctl|busctl' 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    found=1
    echo "--- candidate pid ${pid} ---"
    cur="$pid"
    depth=0
    while [ -n "$cur" ] && [ "$cur" -gt 1 ] 2>/dev/null && [ "$depth" -lt 20 ]; do
        printf '  %-8s %-12s %s\n' \
            "$cur" \
            "$(ps -o user= -p "$cur" 2>/dev/null | tr -d ' ')" \
            "$(tr '\0' ' ' < "/proc/${cur}/cmdline" 2>/dev/null | cut -c1-200)"
        cur="$(ps -o ppid= -p "$cur" 2>/dev/null | tr -d ' ')"
        depth=$((depth + 1))
    done
done
[ "$found" = 0 ] && echo "(none live - exit was likely a direct SIGTERM to the manager, not a systemctl call)"

echo
echo "=== full process tree ==="
ps -eo pid,ppid,user,lstart,stat,etimes,cmd --forest 2>/dev/null

echo
echo "=== user manager jobs ==="
timeout 5 systemctl --user list-jobs --no-pager 2>&1

echo
echo "=== sessions ==="
timeout 5 loginctl list-sessions --no-pager 2>&1
timeout 5 loginctl show-user "$(id -un)" --no-pager 2>&1 | grep -E 'Linger|State|Sessions'

echo
echo "=== tmux servers ==="
timeout 5 tmux ls 2>&1
timeout 5 tmux -L system ls 2>&1

echo
echo "=== journal tail ==="
timeout 10 journalctl -n 300 --no-pager 2>&1

sync

# Keep the last 20 reports; each is ~180K.
ls -1t "${out_dir}"/*.txt 2>/dev/null | tail -n +21 | xargs -r rm -f
