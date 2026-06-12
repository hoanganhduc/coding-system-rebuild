#!/bin/bash
# Set up cron jobs for Zotero skill automation.
# Run this script on a system with crontab available.

VENV="{{ HOME }}/.venvs/bin/python3"
WORKSPACE="{{ HOME }}/.openclaw/workspace"
ZOT="$WORKSPACE/skills/zotero/zot.py"
POLLER="$WORKSPACE/skills/zotero/scripts/watch-poller.py"
LOG_DIR="$WORKSPACE/data/research/zotero"

mkdir -p "$LOG_DIR"

(crontab -l 2>/dev/null; cat <<CRON
# Zotero watch poller — check for found watches every 4 hours
17 */4 * * * $VENV $POLLER >> $LOG_DIR/watch-poller.log 2>&1

# Zotero cache sync — full library pull daily at 3:07am
7 3 * * * $VENV $ZOT sync-cache >> $LOG_DIR/sync-cache.log 2>&1
CRON
) | sort -u | crontab -

echo "Cron jobs installed:"
crontab -l | grep -i zotero
