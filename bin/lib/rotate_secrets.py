#!/usr/bin/env python3
"""Generalized secret rotation across the whole system.

Three kinds of rotatable secret, all updated in EVERY place they live:
  named     - a NAME (e.g. ZOTERO_API_KEY) mirrored across the flat secrets.json
              files and ~/.secrets.env
  provider  - an OpenClaw provider (e.g. google, taphoaapi) whose key lives in
              auth-profiles.json (profiles.<prov>:default.key) AND models.json
              (providers.<prov>.apiKey)
  field     - an arbitrary field in a specific file (e.g. .codewhale/config.toml
              api_key), declared in secrets/rotation-extra-targets.yaml

Targets are resolved BY STRUCTURE / NAME, never by matching the old value.
New values arrive via env NEWSECRET_VALUE (never argv), so they don't hit `ps`.
Files are de-duplicated by realpath and backed up once before editing.
No secret value is ever printed.

Subcommands:
  list                      print every rotatable id (grouped), no values
  kind <id>                 print the resolved kind + target count for <id>
  apply <id>                update <id> everywhere (value from NEWSECRET_VALUE)
"""
import glob
import json
import os
import re
import shutil
import sys
import time

HOME = os.path.expanduser("~")

FLAT_JSON = [".claude/secrets.json",
             ".openclaw/secrets.json",
             ".openclaw/workspace/.secrets.json"]
DOTENV = [".secrets.env"]
AUTH_GLOB = ".openclaw/agents/*/agent/auth-profiles.json"
MODELS_GLOB = ".openclaw/agents/*/agent/models.json"
SECRETISH = re.compile(r"(key|token|secret|password|credential|auth)", re.I)


def p(rel):
    return os.path.join(HOME, rel)


def load_extra():
    cat = p("../coding-system-rebuild/secrets/rotation-extra-targets.yaml")
    # locate relative to this file instead
    here = os.path.dirname(os.path.abspath(__file__))
    cat = os.path.join(here, "..", "..", "secrets", "rotation-extra-targets.yaml")
    if not os.path.exists(cat):
        return {}
    import yaml
    with open(cat) as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("secrets", {})


def discover_named():
    names = {}
    for f in FLAT_JSON:
        ap = p(f)
        if os.path.exists(ap):
            try:
                for k in json.load(open(ap)):
                    names.setdefault(k, []).append(f)
            except ValueError:
                pass
    for f in DOTENV:
        ap = p(f)
        if os.path.exists(ap):
            for line in open(ap):
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=", line)
                if m and SECRETISH.search(m.group(1)):
                    names.setdefault(m.group(1), []).append(f)
    return names


def discover_providers():
    provs = {}
    for f in sorted(glob.glob(p(AUTH_GLOB))):
        try:
            d = json.load(open(f))
        except ValueError:
            continue
        for prof in d.get("profiles", {}):
            provs.setdefault(prof.split(":")[0], 0)
    return sorted(provs)


def set_json_top(path, key, val):
    d = json.load(open(path))
    if key not in d:
        return False
    if d[key] == val:
        return None
    d[key] = val
    json.dump(d, open(path, "w"), indent=2)
    return True


def set_dotenv(path, key, val):
    lines = open(path).read().splitlines(keepends=True)
    out, hit = [], False
    pat = re.compile(r"^(\s*(?:export\s+)?%s=).*$" % re.escape(key))
    for ln in lines:
        m = pat.match(ln)
        if m:
            out.append(m.group(1) + '"%s"\n' % val)
            hit = True
        else:
            out.append(ln)
    if not hit:
        return False
    open(path, "w").writelines(out)
    return True


def set_toml(path, key, val):
    text = open(path).read()
    pat = re.compile(r'^(\s*%s\s*=\s*).*$' % re.escape(key), re.M)
    if not pat.search(text):
        return False
    new = pat.sub(lambda m: m.group(1) + '"%s"' % val, text, count=1)
    if new == text:
        return None
    open(path, "w").write(new)
    return True


def set_json_path(path, dotted, val):
    """dotted path with literal segments; supports 'providers.google.apiKey'
    and 'profiles.google:default.key'."""
    d = json.load(open(path))
    cur = d
    segs = dotted.split(".")
    for s in segs[:-1]:
        if not isinstance(cur, dict) or s not in cur:
            return False
        cur = cur[s]
    last = segs[-1]
    if not isinstance(cur, dict) or last not in cur:
        return False
    if cur[last] == val:
        return None
    cur[last] = val
    json.dump(d, open(path, "w"), indent=2)
    return True


def resolve(idv, named, provs, extra):
    if idv in extra:
        return "field"
    if idv in provs:
        return "provider"
    if idv in named:
        return "named"
    return None


def apply_target(kind, idv, val, named, extra, stamp, changed):
    if kind == "named":
        for f in named[idv]:
            ap = p(f)
            if f.endswith(".env"):
                _safe_set(ap, lambda x: set_dotenv(x, idv, val), stamp, changed)
            else:
                _safe_set(ap, lambda x: set_json_top(x, idv, val), stamp, changed)
    elif kind == "provider":
        for f in sorted(glob.glob(p(AUTH_GLOB))):
            _safe_set(f, lambda x: set_json_path(x, f"profiles.{idv}:default.key", val), stamp, changed)
        for f in sorted(glob.glob(p(MODELS_GLOB))):
            _safe_set(f, lambda x: set_json_path(x, f"providers.{idv}.apiKey", val), stamp, changed)
    elif kind == "field":
        for t in extra[idv].get("targets", []):
            ap = p(t["file"])
            typ = t.get("type", "toml")
            key = t["key"]
            if typ == "toml":
                _safe_set(ap, lambda x: set_toml(x, key, val), stamp, changed)
            elif typ == "json":
                _safe_set(ap, lambda x: set_json_path(x, key, val), stamp, changed)
            elif typ == "dotenv":
                _safe_set(ap, lambda x: set_dotenv(x, key, val), stamp, changed)


_realdone = set()


def _safe_set(path, fn, stamp, changed):
    real = os.path.realpath(path)
    if real in _realdone or not os.path.exists(path):
        return
    _realdone.add(real)
    # back up BEFORE mutating
    tmpbak = f"{path}.bak-prerotate-{stamp}"
    had = os.path.exists(tmpbak)
    if not had:
        shutil.copy2(path, tmpbak)
    try:
        r = fn(path)
    except (OSError, ValueError) as e:
        print(f"WARN: {path}: {e}", file=sys.stderr)
        r = False
    if r:
        changed.append(os.path.relpath(path, HOME))
    elif not had:
        os.remove(tmpbak)  # nothing changed -> drop the needless backup


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    cmd = sys.argv[1]
    named = discover_named()
    provs = discover_providers()
    extra = load_extra()

    if cmd == "list":
        print("# Rotatable secrets (use: make rotate-keys SECRET=<id>  or  PROVIDER=<id>)\n")
        print("## named secrets (mirrored across secrets.json / .secrets.env)")
        for n in sorted(named):
            print(f"  {n:24} -> {len(named[n])} file(s)")
        if extra:
            print("\n## field-in-file secrets")
            for n in sorted(extra):
                print(f"  {n:24} -> {len(extra[n].get('targets', []))} target(s)")
        print("\n## OpenClaw providers (auth-profiles + models.json)")
        print("  " + "  ".join(provs))
        return 0

    if cmd == "kind":
        idv = sys.argv[2]
        k = resolve(idv, named, provs, extra)
        print(k or "unknown")
        return 0 if k else 3

    if cmd == "apply":
        idv = sys.argv[2]
        val = os.environ.get("NEWSECRET_VALUE")
        if not val:
            print("ERROR: NEWSECRET_VALUE not set", file=sys.stderr); return 2
        k = resolve(idv, named, provs, extra)
        if not k:
            print(f"ERROR: unknown secret '{idv}' (try: list)", file=sys.stderr); return 3
        changed = []
        apply_target(k, idv, val, named, extra, str(int(time.time())), changed)
        changed = sorted(set(changed))
        print(f"{idv} ({k}): updated {len(changed)} file(s)")
        for c in changed:
            print(f"    ~/{c}")
        if not changed:
            print("NOTE: nothing changed (already current, or no matching target)")
        return 0

    print("unknown command", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
