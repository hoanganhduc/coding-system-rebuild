#!/usr/bin/env python3
"""Update one or more OpenClaw provider API keys in every agent's config.

Targets BY STRUCTURE (never by matching the old value, so coincidental hex in
library files is never touched):
  - ~/.openclaw/agents/<agent>/agent/auth-profiles.json : profiles["<prov>:default"]["key"]
  - ~/.openclaw/agents/<agent>/agent/models.json        : providers["<prov>"]["apiKey"]

New key values are read from environment variables NEWKEY_<PROVIDER_UPPER>
(never argv/stdin args), so they don't appear in `ps`. Files are de-duplicated by
realpath (sandbox -> main) and backed up once before editing. No key value is printed.
"""
import glob
import json
import os
import re
import sys
import time

HOME = os.path.expanduser("~")
AGENTS = os.path.join(HOME, ".openclaw", "agents")


def load(path):
    with open(path) as fh:
        return json.load(fh)


def save(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def backup_once(path, stamp):
    bak = f"{path}.bak-prerotate-{stamp}"
    if not os.path.exists(bak):
        import shutil
        shutil.copy2(path, bak)
    return bak


def main():
    providers = [p.strip() for p in sys.argv[1:] if p.strip()]
    if not providers:
        print("usage: rotate_provider_keys.py <provider> [provider...]", file=sys.stderr)
        return 2
    newkeys = {}
    for p in providers:
        v = os.environ.get("NEWKEY_" + p.upper())
        if not v:
            print(f"ERROR: env NEWKEY_{p.upper()} not set", file=sys.stderr)
            return 2
        newkeys[p] = v

    stamp = str(int(time.time()))
    seen_real = set()
    changed = {p: [] for p in providers}

    files = sorted(glob.glob(os.path.join(AGENTS, "*", "agent", "auth-profiles.json"))) \
        + sorted(glob.glob(os.path.join(AGENTS, "*", "agent", "models.json")))

    for f in files:
        real = os.path.realpath(f)
        if real in seen_real:
            continue          # skip symlink duplicates (sandbox -> main)
        seen_real.add(real)
        try:
            data = load(f)
        except (OSError, ValueError) as e:
            print(f"WARN: skip unreadable {f}: {e}", file=sys.stderr)
            continue

        dirty = False
        if f.endswith("auth-profiles.json"):
            profiles = data.get("profiles", {})
            for prov, newval in newkeys.items():
                prof = profiles.get(f"{prov}:default")
                if isinstance(prof, dict) and "key" in prof:
                    if prof["key"] != newval:
                        prof["key"] = newval
                        dirty = True
                        changed[prov].append(os.path.relpath(f, HOME))
        else:  # models.json
            provs = data.get("providers", {})
            for prov, newval in newkeys.items():
                pd = provs.get(prov)
                if isinstance(pd, dict) and "apiKey" in pd:
                    if pd["apiKey"] != newval:
                        pd["apiKey"] = newval
                        dirty = True
                        changed[prov].append(os.path.relpath(f, HOME))

        if dirty:
            backup_once(f, stamp)
            save(f, data)

    total = 0
    for prov in providers:
        files_done = sorted(set(changed[prov]))
        total += len(files_done)
        print(f"{prov}: updated {len(files_done)} file(s)")
        for fp in files_done:
            print(f"    ~/{fp}")
    if total == 0:
        print("NOTE: nothing changed (no matching provider profiles, or keys already current)")
    print(f"backups: *.bak-prerotate-{stamp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
