#!/usr/bin/env python3
"""Set the GitHub Actions secrets the rehearsal workflow uses, sourcing each
value from its WORKING deployed location. Values are piped to `gh secret set`
via stdin (never argv/ps) and encrypted client-side by gh. No value is printed.

  set_ci_secrets.py [--dry-run] [--repo OWNER/REPO]

Mapping (CI secret name <- source):
  ZOTERO_API_KEY     <- secrets.json[ZOTERO_API_KEY]
  TELEGRAM_BOT_TOKEN <- secrets.json[TELEGRAM_BOT_TOKEN]
  TELEGRAM_CHAT_ID   <- ~/.secrets.env TELEGRAM_CHAT_ID
  GROQ_KEY           <- auth-profiles groq:default.key      (working key, not the stale secrets.json one)
  ZAI_KEY            <- auth-profiles zai:default.key
  GOOGLE_KEY         <- auth-profiles google:default.key
  DEEPSEEK_KEY       <- auth-profiles deepseek:default.key   (fallback: .codewhale/config.toml api_key)
  OPENROUTER_KEY     <- auth-profiles openrouter:default.key
"""
import glob
import json
import os
import re
import subprocess
import sys

HOME = os.path.expanduser("~")
NOTE = {}


def authkey(prov):
    for f in sorted(glob.glob(os.path.join(HOME, ".openclaw/agents/*/agent/auth-profiles.json"))):
        try:
            d = json.load(open(f))
        except ValueError:
            continue
        pr = d.get("profiles", {}).get(prov + ":default")
        if isinstance(pr, dict) and pr.get("key"):
            return pr["key"]
    return None


def secj(name):
    for f in (".claude/secrets.json", ".openclaw/secrets.json"):
        p = os.path.join(HOME, f)
        if os.path.exists(p):
            try:
                d = json.load(open(p))
            except ValueError:
                continue
            if d.get(name):
                return d[name]
    return None


def envv(name):
    p = os.path.join(HOME, ".secrets.env")
    if os.path.exists(p):
        m = re.search(r'^(?:export\s+)?%s="?([^"\n]+)' % re.escape(name), open(p).read(), re.M)
        if m:
            return m.group(1)
    return None


def toml_apikey(rel):
    p = os.path.join(HOME, rel)
    if os.path.exists(p):
        m = re.search(r'^\s*api_key\s*=\s*"([^"]+)"', open(p).read(), re.M)
        if m:
            return m.group(1)
    return None


def main():
    dry = "--dry-run" in sys.argv
    repo = "hoanganhduc/coding-system-rebuild"
    if "--repo" in sys.argv:
        repo = sys.argv[sys.argv.index("--repo") + 1]

    mapping = [
        ("ZOTERO_API_KEY",     "secrets.json",            secj("ZOTERO_API_KEY")),
        ("TELEGRAM_BOT_TOKEN", "secrets.json",            secj("TELEGRAM_BOT_TOKEN")),
        ("TELEGRAM_CHAT_ID",   ".secrets.env",            envv("TELEGRAM_CHAT_ID")),
        ("GROQ_KEY",           "auth-profiles groq",      authkey("groq")),
        ("ZAI_KEY",            "auth-profiles zai",       authkey("zai")),
        ("GOOGLE_KEY",         "auth-profiles google",    authkey("google")),
        ("DEEPSEEK_KEY",       "auth-profiles deepseek",  authkey("deepseek") or toml_apikey(".codewhale/config.toml")),
        ("OPENROUTER_KEY",     "auth-profiles openrouter", authkey("openrouter")),
    ]

    print(f"repo: {repo}{'  (DRY-RUN)' if dry else ''}\n")
    ok = skip = 0
    for name, src, val in mapping:
        tag = f"  [{NOTE[name]}]" if name in NOTE else ""
        if not val:
            print(f"SKIP {name:20} (no value at {src}){tag}")
            skip += 1
            continue
        if dry:
            print(f"WOULD-SET {name:20} <- {src} ({len(val)} chars){tag}")
            ok += 1
            continue
        r = subprocess.run(["gh", "secret", "set", name, "--repo", repo],
                           input=val, text=True, capture_output=True)
        if r.returncode == 0:
            print(f"SET  {name:20} <- {src}{tag}")
            ok += 1
        else:
            print(f"FAIL {name:20} {r.stderr.strip()}")
    print(f"\n{'would set' if dry else 'set'}: {ok}, skipped: {skip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
