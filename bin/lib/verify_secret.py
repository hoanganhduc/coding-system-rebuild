#!/usr/bin/env python3
"""Verify a (rotated) secret actually works by making one cheap, read-only call.

Usage:
  verify_secret.py <id>          # value from env VERIFY_VALUE, else read live config

Prints exactly one line: PASS / FAIL(<detail>) / SKIP(<reason>) / ERROR(<reason>).
Never prints the secret value. All network calls use a short timeout and fail soft.
"""
import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
TIMEOUT = 12
FLAT_JSON = [".claude/secrets.json", ".openclaw/secrets.json",
             ".openclaw/workspace/.secrets.json"]
AUTH_GLOB = ".openclaw/agents/*/agent/models.json"


def http(url, headers=None, method="GET", data=None):
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(2048).decode("utf-8", "replace") if e.fp else "")
    except Exception as e:  # noqa: BLE001 - network/DNS/TLS all fail soft
        return None, str(e)


def secrets_lookup(name):
    for f in FLAT_JSON:
        p = os.path.join(HOME, f)
        if os.path.exists(p):
            try:
                d = json.load(open(p))
                if name in d and d[name]:
                    return d[name]
            except ValueError:
                pass
    return None


def provider_baseurl(prov):
    for f in glob.glob(os.path.join(HOME, AUTH_GLOB)):
        try:
            d = json.load(open(f))
        except ValueError:
            continue
        pd = d.get("providers", {}).get(prov)
        if isinstance(pd, dict) and pd.get("baseUrl"):
            return pd["baseUrl"].rstrip("/")
    return None


def read_deployed(idv):
    """Read the live value for an id (named / provider / field)."""
    v = secrets_lookup(idv)
    if v:
        return v
    # provider: profiles.<prov>:default.key in any auth-profiles
    for f in glob.glob(os.path.join(HOME, ".openclaw/agents/*/agent/auth-profiles.json")):
        try:
            d = json.load(open(f))
        except ValueError:
            continue
        prof = d.get("profiles", {}).get(f"{idv}:default")
        if isinstance(prof, dict) and prof.get("key"):
            return prof["key"]
    # field secrets (toml api_key)
    if idv == "DEEPSEEK_API_KEY":
        for t in (".codewhale/config.toml", ".deepseek/config.toml"):
            p = os.path.join(HOME, t)
            if os.path.exists(p):
                m = re.search(r'^\s*api_key\s*=\s*"([^"]+)"', open(p).read(), re.M)
                if m:
                    return m.group(1)
    # dotenv
    p = os.path.join(HOME, ".secrets.env")
    if os.path.exists(p):
        m = re.search(r'^\s*(?:export\s+)?%s="?([^"\n]+)' % re.escape(idv), open(p).read(), re.M)
        if m:
            return m.group(1)
    return None


# ---- per-secret verifiers: return (status, detail) -------------------------
def v_openai_models(base, key):
    if not base:
        return "SKIP", "no baseUrl in config"
    code, _ = http(base + "/models", {"Authorization": "Bearer " + key})
    if code == 200:
        return "PASS", "200 /models"
    if code in (401, 403):
        return "FAIL", "auth rejected (%s)" % code
    if code is None:
        return "ERROR", "network"
    return "FAIL", "HTTP %s" % code


def v_anthropic_models(base, key):
    if not base:
        return "SKIP", "no baseUrl"
    code, _ = http(base.rstrip("/") + "/models",
                   {"x-api-key": key, "anthropic-version": "2023-06-01"})
    return ("PASS", "200") if code == 200 else \
        ("FAIL", "auth rejected (%s)" % code) if code in (401, 403) else \
        ("ERROR", "network") if code is None else ("FAIL", "HTTP %s" % code)


def verify(idv, key):
    # OpenClaw providers (lowercase ids)
    OPENAI_PROVS = {"deepseek", "groq", "laozhang", "openrouter", "arcee", "zai"}
    if idv in OPENAI_PROVS:
        return v_openai_models(provider_baseurl(idv), key)
    if idv == "taphoaapi":
        return v_anthropic_models(provider_baseurl(idv) or "https://taphoaapi.info.vn/v1", key)
    if idv == "google":
        code, _ = http("https://generativelanguage.googleapis.com/v1beta/models?key=" + key)
        return ("PASS", "200 gemini models") if code == 200 else \
            ("FAIL", "rejected (%s)" % code) if code in (400, 401, 403) else \
            ("ERROR", "network") if code is None else ("FAIL", "HTTP %s" % code)
    if idv in ("github-copilot", "ollama", "codex", "openai-codex", "openai"):
        return "SKIP", "no automated test (OAuth/local/unsupported)"

    # named / field secrets
    if idv == "ZOTERO_API_KEY":
        code, _ = http("https://api.zotero.org/keys/current", {"Zotero-API-Key": key})
        return ("PASS", "200 key valid") if code == 200 else ("FAIL", "HTTP %s" % code) if code else ("ERROR", "network")
    if idv == "TELEGRAM_BOT_TOKEN":
        code, body = http("https://api.telegram.org/bot%s/getMe" % key)
        if code == 200 and '"ok":true' in body.replace(" ", ""):
            return "PASS", "getMe ok"
        return ("FAIL", "HTTP %s" % code) if code else ("ERROR", "network")
    if idv == "GROQ_API_KEY":
        return v_openai_models(provider_baseurl("groq") or "https://api.groq.com/openai/v1", key)
    if idv == "ZULIP_API_KEY":
        org = secrets_lookup("ZULIP_ORG_URL"); email = secrets_lookup("ZULIP_EMAIL")
        if not (org and email):
            return "SKIP", "need ZULIP_ORG_URL + ZULIP_EMAIL"
        import base64
        tok = base64.b64encode(("%s:%s" % (email, key)).encode()).decode()
        code, _ = http(org.rstrip("/") + "/api/v1/users/me", {"Authorization": "Basic " + tok})
        return ("PASS", "users/me 200") if code == 200 else ("FAIL", "HTTP %s" % code) if code else ("ERROR", "network")
    if idv == "DEEPSEEK_API_KEY":
        return v_openai_models("https://api.deepseek.com/v1", key)
    if idv == "OCRSPACE_API_KEY":
        code, body = http("https://api.ocr.space/parse/imageurl?apikey=%s&url=https://i.imgur.com/fwxooMv.png" % key)
        if code == 200 and '"OCRExitCode"' in body and "Invalid API key" not in body:
            return "PASS", "parse ok"
        return ("FAIL", "invalid/blocked") if code == 200 else ("ERROR", "network") if code is None else ("FAIL", "HTTP %s" % code)

    return "SKIP", "no automated test defined — verify manually"


def main():
    if len(sys.argv) < 2:
        print("usage: verify_secret.py <id>", file=sys.stderr); return 2
    idv = sys.argv[1]
    key = os.environ.get("VERIFY_VALUE") or read_deployed(idv)
    if not key:
        print("SKIP(no deployed value found)"); return 0
    try:
        status, detail = verify(idv, key)
    except Exception as e:  # noqa: BLE001
        status, detail = "ERROR", "verifier exception: %s" % type(e).__name__
    print("%s(%s)" % (status, detail))
    return 0 if status in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
