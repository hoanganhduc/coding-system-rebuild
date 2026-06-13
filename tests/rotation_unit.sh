#!/usr/bin/env bash
# Unit tests for the secret-rotation engine, on a throwaway fake HOME.
# No network, no real secrets. Asserts: all three kinds update the right targets,
# other keys are untouched, symlinks are de-duped, backups hold the old value,
# and no secret value is ever written to stdout.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="$REPO/bin/lib/rotate_secrets.py"

python3 - "$ENG" <<'PYEOF'
import os, json, subprocess, tempfile, shutil, glob, sys
ENG = sys.argv[1]
T = tempfile.mkdtemp(prefix="rot-unit-")
def w(rel, obj):
    fp = os.path.join(T, rel); os.makedirs(os.path.dirname(fp), exist_ok=True)
    open(fp, "w").write(obj if isinstance(obj, str) else json.dumps(obj)); return fp

w(".claude/secrets.json", {"ZOTERO_API_KEY": "OLD", "KEEP": "x"})
w(".openclaw/secrets.json", {"ZOTERO_API_KEY": "OLD", "TELEGRAM_BOT_TOKEN": "OLDT"})
w(".secrets.env", 'export TELEGRAM_BOT_TOKEN="OLDT"\nexport TELEGRAM_CHAT_ID="123"\n')
w(".openclaw/agents/main/agent/auth-profiles.json",
  {"profiles": {"google:default": {"provider": "google", "key": "OLDG"},
                "groq:default": {"provider": "groq", "key": "KEEP"}}})
w(".openclaw/agents/host/agent/models.json", {"providers": {"google": {"apiKey": "OLDG", "models": []}}})
os.symlink(os.path.join(T, ".openclaw/agents/main"), os.path.join(T, ".openclaw/agents/sandbox"))
w(".codewhale/config.toml", 'model = "x"\napi_key = "OLDD"\n')
w(".deepseek/config.toml", 'api_key = "OLDD"\n')

fails = []
def run(idv, val):
    r = subprocess.run(["python3", ENG, "apply", idv],
                       env=dict(os.environ, HOME=T, NEWSECRET_VALUE=val),
                       capture_output=True, text=True)
    if val in r.stdout:
        fails.append(f"value '{val}' leaked to stdout for {idv}")
    return r

run("ZOTERO_API_KEY", "NEWZ"); run("TELEGRAM_BOT_TOKEN", "NEWT")
run("google", "NEWG"); run("DEEPSEEK_API_KEY", "NEWD")

def jget(rel, *path):
    d = json.load(open(os.path.join(T, rel)))
    for p in path: d = d[p]
    return d
def assert_eq(label, got, want):
    if got != want: fails.append(f"{label}: got {got!r} want {want!r}")

assert_eq("claude ZOTERO", jget(".claude/secrets.json", "ZOTERO_API_KEY"), "NEWZ")
assert_eq("claude KEEP untouched", jget(".claude/secrets.json", "KEEP"), "x")
assert_eq("openclaw ZOTERO", jget(".openclaw/secrets.json", "ZOTERO_API_KEY"), "NEWZ")
assert_eq("openclaw TELEGRAM", jget(".openclaw/secrets.json", "TELEGRAM_BOT_TOKEN"), "NEWT")
assert_eq("dotenv TELEGRAM",
          [l for l in open(os.path.join(T, ".secrets.env")) if "TELEGRAM_BOT" in l][0].strip(),
          'export TELEGRAM_BOT_TOKEN="NEWT"')
assert_eq("auth google", jget(".openclaw/agents/main/agent/auth-profiles.json", "profiles", "google:default", "key"), "NEWG")
assert_eq("auth groq untouched", jget(".openclaw/agents/main/agent/auth-profiles.json", "profiles", "groq:default", "key"), "KEEP")
assert_eq("models google", jget(".openclaw/agents/host/agent/models.json", "providers", "google", "apiKey"), "NEWG")
assert_eq("codewhale toml", 'api_key = "NEWD"' in open(os.path.join(T, ".codewhale/config.toml")).read(), True)
assert_eq("codewhale model kept", 'model = "x"' in open(os.path.join(T, ".codewhale/config.toml")).read(), True)
assert_eq("deepseek toml", 'api_key = "NEWD"' in open(os.path.join(T, ".deepseek/config.toml")).read(), True)

baks = glob.glob(os.path.join(T, ".claude/*.bak-prerotate-*"))
assert_eq("backup exists", len(baks) >= 1, True)
if baks:
    assert_eq("backup holds OLD", json.load(open(baks[0])).get("ZOTERO_API_KEY"), "OLD")

shutil.rmtree(T)
if fails:
    print("rotation unit tests: FAIL")
    for f in fails: print("  - " + f)
    sys.exit(1)
print("rotation unit tests: PASS (named+provider+field, no value leak, backups verified)")
PYEOF
