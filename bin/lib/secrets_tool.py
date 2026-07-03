#!/usr/bin/env python3
"""Secrets-manifest helper: expand file lists, verify presence/perms, emit meta.

Subcommands (all print to stdout, never secret values):
  expand           print $HOME-relative file list (one per line) for packing
  verify           table of OK/MISSING/BAD-PERM against the live $HOME
  verify-zip LIST  same against a newline-separated archive listing on stdin
  meta             JSON metadata (utc, manifest snapshot, per-file sha256)
  fixperms         chmod files + dirs to manifest modes (used by restore)
  degraded         markdown table: missing entry -> broken feature
"""

import glob
import hashlib
import fnmatch
import json
import os
import stat
import sys
from datetime import datetime, timezone

import yaml

HOME = os.environ.get("CSR_SECRETS_HOME") or os.path.expanduser("~")


def load(manifest_path):
    with open(manifest_path) as fh:
        return yaml.safe_load(fh)


def expand_entry(path, excludes=()):
    """Return list of existing $HOME-relative files for a manifest path.
    excludes: fnmatch globs applied to the home-relative path and basename
    (volatile files like .gnupg/random_seed that must not gate pack/verify)."""
    rel = path.rstrip("/")
    abs_p = os.path.join(HOME, rel)
    out = []
    if "*" in rel:
        for hit in glob.glob(abs_p):
            if os.path.isdir(hit) and not os.path.islink(hit):
                for dp, dns, fns in os.walk(hit):
                    out += [os.path.join(dp, f) for f in fns]
            elif os.path.isfile(hit):
                out.append(hit)
    elif path.endswith("/") or os.path.isdir(abs_p):
        if os.path.isdir(abs_p):
            for dp, dns, fns in os.walk(abs_p):
                out += [os.path.join(dp, f) for f in fns]
    elif os.path.isfile(abs_p):
        out.append(abs_p)
    seen, uniq = set(), []
    for f in out:
        rp = os.path.realpath(f)
        if rp not in seen:
            seen.add(rp)
            uniq.append(os.path.relpath(f, HOME))
    if excludes:
        uniq = [f for f in uniq
                if not any(fnmatch.fnmatch(f, pat) or
                           fnmatch.fnmatch(os.path.basename(f), pat)
                           for pat in excludes)]
    return uniq


def match_archive_path(pattern, rel):
    pattern = pattern.strip().rstrip("/")
    rel = rel.strip().rstrip("/")
    if not pattern or not rel:
        return False
    if rel == pattern:
        return True
    if pattern.endswith("/**") and (
            rel == pattern[:-3] or rel.startswith(pattern[:-3] + "/")):
        return True
    if "*" in pattern:
        return fnmatch.fnmatch(rel, pattern)
    if pattern.endswith("/") or rel.startswith(pattern + "/"):
        return rel.startswith(pattern.rstrip("/") + "/")
    return False


def unsafe_archive_path(rel):
    parts = rel.split("/")
    return rel.startswith("/") or any(p in ("", ".", "..") for p in parts)


def main():
    cmd = sys.argv[1]
    manifest = load(sys.argv[2])
    entries = manifest["entries"]
    dir_perms = manifest.get("dir_perms", {})

    if cmd == "expand":
        missing_required = []
        all_files = []
        for e in entries:
            files = expand_entry(e["path"], e.get("exclude") or ())
            if not files and e.get("required"):
                missing_required.append(e["path"])
            all_files += files
        for f in sorted(set(all_files)):
            print(f)
        if missing_required and os.environ.get("ALLOW_MISSING") != "1":
            print("ERROR: required secrets missing (set ALLOW_MISSING=1 to demote):",
                  file=sys.stderr)
            for p in missing_required:
                print("  " + p, file=sys.stderr)
            return 2
        for p in missing_required:
            print("WARN: required secret missing: %s" % p, file=sys.stderr)
        return 0

    if cmd in ("verify", "verify-zip"):
        listing = None
        if cmd == "verify-zip":
            listing = set(l.strip().rstrip("/") for l in sys.stdin if l.strip())
            unknown = []
            for member in listing:
                if unsafe_archive_path(member) or not any(
                        match_archive_path(e["path"], member) for e in entries):
                    unknown.append(member)
            if unknown:
                for member in sorted(unknown)[:20]:
                    print("%-70s UNKNOWN" % member)
                return 1
        bad = 0
        for e in entries:
            files = expand_entry(e["path"], e.get("exclude") or ())
            if cmd == "verify-zip":
                missing_live = sorted(f for f in files if f not in listing)
                if missing_live:
                    status = "MISSING(live:%d)" % len(missing_live)
                    bad += 1
                    print("%-70s %s" % (e["path"], status))
                    continue
                present = [f for f in files if f in listing] if files else []
                if not files:
                    # nothing live to compare; check any zip member under the path
                    present = [m for m in listing if match_archive_path(e["path"], m)]
                status = "OK" if present else (
                    "MISSING(required)" if e.get("required") else "missing")
                if status == "MISSING(required)":
                    bad += 1
                print("%-70s %s" % (e["path"], status))
                continue
            if not files:
                status = "MISSING(required)" if e.get("required") else "missing"
                if e.get("required"):
                    bad += 1
                print("%-70s %s" % (e["path"], status))
                continue
            want = int(e.get("mode", "0600"), 8)
            badperm = []
            for f in files:
                have = stat.S_IMODE(os.stat(os.path.join(HOME, f)).st_mode)
                if have & 0o077 and not want & 0o077:
                    badperm.append("%s %o->%o" % (f, have, want))
            status = "OK(%d)" % len(files)
            if badperm:
                status += " BAD-PERM[" + "; ".join(badperm[:3]) + "]"
                bad += 1
            print("%-70s %s" % (e["path"], status))
        return 1 if bad else 0

    if cmd == "meta":
        meta = {"packed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "schema": manifest.get("schema"), "files": {}}
        for e in entries:
            for f in expand_entry(e["path"]):
                p = os.path.join(HOME, f)
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                meta["files"][f] = {"sha256": h.hexdigest(),
                                    "size": os.path.getsize(p)}
        print(json.dumps(meta, indent=1))
        return 0

    if cmd == "fixperms":
        for d, m in dir_perms.items():
            p = os.path.join(HOME, d)
            if os.path.isdir(p):
                os.chmod(p, int(m, 8))
        for e in entries:
            want = int(e.get("mode", "0600"), 8)
            for f in expand_entry(e["path"]):
                os.chmod(os.path.join(HOME, f), want)
        print("permissions applied")
        return 0

    if cmd == "degraded":
        print("| Missing | Broken until provided |")
        print("|---|---|")
        for e in entries:
            if not expand_entry(e["path"]):
                feat = " ".join(str(e.get("feature", "")).split())
                print("| `%s` | %s |" % (e["path"], feat))
        return 0

    print("unknown subcommand", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
