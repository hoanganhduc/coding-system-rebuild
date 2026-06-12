#!/usr/bin/env bash
# One-time (idempotent) private-side initialization on the SOURCE machine.
# Performs the four live mutations required before the first `make backup`:
#   (a) install a 7-Zip CLI (7zip + 7zip-standalone when available)
#   (b) move secret/personal exports out of ~/.bashrc into ~/.secrets.env,
#       leaving a managed marker block that sources it
#   (c) create + seed ~/.config/coding-system/leak-denylist.txt from live IDs
#   (d) record systemd user-unit enable states into system/systemd/units.state
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARK_BEGIN="# >>> coding-system secrets >>>"
MARK_END="# <<< coding-system secrets <<<"

echo "== (a) 7-Zip CLI =="
if command -v 7zz >/dev/null || command -v 7z >/dev/null; then
  echo "already present: $(command -v 7zz || command -v 7z)"
else
  if sudo -n true 2>/dev/null; then
    sudo apt-get install -y 7zip >/dev/null
    sudo apt-get install -y 7zip-standalone >/dev/null 2>&1 || true
    echo "installed: $(command -v 7zz || command -v 7z)"
  else
    echo "ERROR: need sudo to apt install 7zip — run: sudo apt-get install -y 7zip" >&2
    exit 2
  fi
fi

echo "== (b) bashrc secret split =="
python3 - "$MARK_BEGIN" "$MARK_END" <<'PYEOF'
import os, re, shutil, sys
MARK_BEGIN, MARK_END = sys.argv[1], sys.argv[2]
home = os.path.expanduser("~")
bashrc = os.path.join(home, ".bashrc")
envfile = os.path.join(home, ".secrets.env")
text = open(bashrc).read()
if MARK_BEGIN in text:
    print("managed block already present — skipping")
    sys.exit(0)
MOVE_RE = re.compile(
    r'^export (TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|OCRSPACE_API_KEY|'
    r'LEANEXPLORE_API_KEY|MOLTBOOK_[A-Z_]+|MOLBOOK_[A-Z_]+)=')
lines = text.splitlines(keepends=True)
moved, kept, insert_at = [], [], None
for i, line in enumerate(lines):
    if MOVE_RE.match(line):
        moved.append(line if line.endswith("\n") else line + "\n")
        if insert_at is None:
            insert_at = len(kept)
    else:
        kept.append(line)
if not moved:
    print("no movable exports found — inserting empty managed block at end")
    insert_at = len(kept)
shutil.copy2(bashrc, bashrc + ".pre-coding-system")
block = [MARK_BEGIN + "\n",
         '[ -f ~/.secrets.env ] && . ~/.secrets.env\n',
         MARK_END + "\n"]
out = kept[:insert_at] + block + kept[insert_at:]
existing = open(envfile).read() if os.path.exists(envfile) else ""
with open(envfile, "a") as fh:
    if existing and not existing.endswith("\n"):
        fh.write("\n")
    for line in moved:
        if line not in existing:
            fh.write(line)
os.chmod(envfile, 0o600)
open(bashrc, "w").write("".join(out))
print("moved %d exports to ~/.secrets.env; backup at ~/.bashrc.pre-coding-system"
      % len(moved))
PYEOF
bash -n "$HOME/.bashrc" || { echo "ERROR: bashrc syntax broken — restore ~/.bashrc.pre-coding-system" >&2; exit 2; }
bash -c '. ~/.bashrc >/dev/null 2>&1; [ -n "${TELEGRAM_BOT_TOKEN:-}" ]' \
  || { echo "ERROR: sourcing smoke failed (TELEGRAM_BOT_TOKEN empty after . ~/.bashrc)" >&2; exit 2; }
echo "bashrc sources cleanly; secrets resolve via ~/.secrets.env"

echo "== (c) leak denylist =="
mkdir -p "$HOME/.config/coding-system" && chmod 700 "$HOME/.config/coding-system"
DL="$HOME/.config/coding-system/leak-denylist.txt"
python3 - "$DL" <<'PYEOF'
import json, os, re, sys
home = os.path.expanduser("~")
dl_path = sys.argv[1]
ids = set()
# live personal IDs, extracted (never hardcoded here)
env = {}
envfile = os.path.join(home, ".secrets.env")
if os.path.exists(envfile):
    for line in open(envfile):
        m = re.match(r'export ([A-Z_]+)=["\']?([^"\'\n]+)', line)
        if m:
            env[m.group(1)] = m.group(2)
if env.get("TELEGRAM_CHAT_ID"):
    ids.add(env["TELEGRAM_CHAT_ID"])
if env.get("MOLBOOK_AGENT_ID"):
    ids.add(env["MOLBOOK_AGENT_ID"])
for cfg in (".claude/skills/zotero/config.json", ".claude/skills/calibre/config.json"):
    p = os.path.join(home, cfg)
    if os.path.exists(p):
        try:
            d = json.load(open(p))
        except ValueError:
            continue
        for k, v in d.items():
            if isinstance(v, (str, int)) and re.search(
                    r'(user_id|folder_id|library_id)', k):
                s = str(v)
                if len(s) >= 6:
                    ids.add(s)
# tailnet name (derived from live funnel URLs in openclaw.json) + Google Chat SA app id
oc = os.path.join(home, ".openclaw/openclaw.json")
if os.path.exists(oc):
    for m in re.finditer(r'https://[a-z0-9-]+\.(tail[0-9a-f]+)\.ts\.net', open(oc).read()):
        ids.add(m.group(1))
sa_dir = os.path.join(home, ".config/openclaw/google-chat")
if os.path.isdir(sa_dir):
    for f in os.listdir(sa_dir):
        m = re.match(r'(.+)-[0-9a-f]{12}\.json$', f)
        if m:
            ids.add(m.group(1))
existing = set()
if os.path.exists(dl_path):
    existing = {l.strip() for l in open(dl_path) if l.strip()}
with open(dl_path, "a") as fh:
    for i in sorted(ids - existing):
        fh.write(i + "\n")
os.chmod(dl_path, 0o600)
print("denylist has %d entries" % len(ids | existing))
PYEOF

echo "== (d) systemd units.state =="
mkdir -p "$REPO/system/systemd"
: > "$REPO/system/systemd/units.state"
for u in openclaw-gateway.service send-queue-worker.service \
         rss_news_digest_bot.service rss_news_digest_bot.timer \
         moltbook-relay.service moltbook-relay.timer xvfb-99.service; do
  state=$(systemctl --user is-enabled "$u" 2>/dev/null) || true
  [[ -n "$state" ]] || state="absent"
  printf '%s\t%s\n' "$u" "$state" >> "$REPO/system/systemd/units.state"
done
cat "$REPO/system/systemd/units.state"
echo "init-private: all four mutations complete"
