#!/usr/bin/env python3
"""Manifest-driven capture engine for coding-system-rebuild.

Reads MANIFEST.yaml, walks the fail-closed roots, and renders sanitized public
artifacts into an output tree (.staging/ for --dry-run, the repo for --apply).

Hard rules (exit 2 on violation):
  * every top-level entry of every root must be matched by >=1 manifest entry
  * no ELF binary may enter a public class
  * no '/home/<user>' literal may survive in a rendered public text file
  * bashrc managed-secret markers must exist; secret-shaped exports outside the
    managed block abort the run
  * private-archive paths must exist and be covered by secrets-manifest

Symlinks are never copied: they are recorded (delegated if they point into the
ai-agents-skills repo, topology otherwise) and compared against system/symlinks.tsv.
"""

import argparse
import fnmatch
import json
import os
import re
import shutil
import stat
import sys

import yaml

HOME = os.environ.get("CSR_HOME_OVERRIDE") or os.path.expanduser("~")
MARK_BEGIN = "# >>> coding-system secrets >>>"
MARK_END = "# <<< coding-system secrets <<<"
SECRET_NAME_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API|CHAT_ID)", re.I
)
PERSONAL_PREFIX_RE = re.compile(r"^(MOLTBOOK|MOLBOOK)_")
EXPORT_RE = re.compile(r'^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$')


class SyncError(Exception):
    pass


def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def is_binary(data):
    return b"\x00" in data[:8192]


def read_text(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if is_binary(data):
        return None
    return data.decode("utf-8", errors="surrogateescape")


def home_substitute(text, placeholder):
    return text.replace(HOME, placeholder)


def key_redact(text, ext, keys):
    for key in keys:
        ph = "{{ %s }}" % key.upper()
        if ext in (".toml", ".ini", ".cfg", ".env"):
            text = re.sub(
                r'^(\s*%s\s*=\s*)("[^"]*"|\'[^\']*\'|\S+)' % re.escape(key),
                lambda m: m.group(1) + '"%s"' % ph,
                text, flags=re.M)
        elif ext == ".json":
            text = re.sub(
                r'("%s"\s*:\s*)"(?:[^"\\]|\\.)*"' % re.escape(key),
                lambda m: m.group(1) + '"%s"' % ph,
                text)
        else:
            text = re.sub(
                r'(%s\s*[=:]\s*)\S+' % re.escape(key),
                lambda m: m.group(1) + ph,
                text)
    return text


def split_bashrc(text, errors):
    """Replace the managed secrets block with a sourcing line; flag strays."""
    lines = text.splitlines(keepends=True)
    begin = end = None
    for i, line in enumerate(lines):
        if line.strip() == MARK_BEGIN:
            begin = i
        elif line.strip() == MARK_END:
            end = i
    if begin is None or end is None or end < begin:
        errors.append(
            "bashrc managed-secret markers missing or malformed; "
            "run bin/init-private.sh first")
        return None
    sanitized = lines[:begin] + [
        "# coding-system: personal/secret exports live in ~/.secrets.env "
        "(restored from the encrypted archive)\n",
        '[ -f ~/.secrets.env ] && . ~/.secrets.env\n',
    ] + lines[end + 1:]
    # scan OUTSIDE the managed block for secret-shaped or personal exports
    strays = []
    for i, line in enumerate(lines):
        if begin <= i <= end:
            continue
        m = EXPORT_RE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip().strip('"').strip("'")
        if not value or value.startswith("$") or value.startswith("~"):
            continue
        if PERSONAL_PREFIX_RE.match(name) or (
                SECRET_NAME_RE.search(name) and len(value) >= 8
                and "/" not in value):
            strays.append("line %d: export %s=..." % (i + 1, name))
    if strays:
        errors.append(
            "secret/personal exports found OUTSIDE the bashrc managed block "
            "(move them inside the markers):\n    " + "\n    ".join(strays))
        return None
    return "".join(sanitized)


def emit_keys(src_path):
    try:
        with open(src_path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if isinstance(data, dict):
        return "\n".join(sorted(data.keys())) + "\n"
    return None


def match_glob(rel, pattern):
    """fnmatch where '**' crosses path separators and a bare dir name matches
    the dir itself and everything below it."""
    if rel == pattern:
        return True
    if fnmatch.fnmatch(rel, pattern):
        return True
    # 'a/**' style and plain-dir prefixes
    if pattern.endswith("/**") and (
            rel == pattern[:-3] or rel.startswith(pattern[:-3] + "/")):
        return True
    if rel.startswith(pattern.rstrip("/") + "/") and "*" not in pattern:
        return True
    # '**/x/**' interior matching via fnmatch on every suffix
    if "**" in pattern:
        regex = fnmatch.translate(pattern.replace("**", "\0"))
        regex = regex.replace("\0", ".*")
        if re.match(regex, rel):
            return True
    return False


def first_segment(glob_pat):
    return glob_pat.split("/")[0]


def load_secrets_paths(repo):
    sm = os.path.join(repo, "secrets", "secrets-manifest.yaml")
    if not os.path.exists(sm):
        return None
    with open(sm) as fh:
        data = yaml.safe_load(fh)
    return [e["path"] for e in data.get("entries", [])]


def covered_by_secrets(rel_home_path, secret_paths):
    for sp in secret_paths:
        sp_n = sp.rstrip("/")
        if rel_home_path == sp_n or rel_home_path.startswith(sp_n + "/"):
            return True
        if "*" in sp_n and match_glob(rel_home_path, sp_n):
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--out", default=None,
                    help="output tree (default: <repo>/.staging for dry-run, <repo> for apply)")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    manifest_path = args.manifest or os.path.join(repo, "MANIFEST.yaml")
    out = args.out or (repo if args.apply else os.path.join(repo, ".staging"))

    with open(manifest_path) as fh:
        manifest = yaml.safe_load(fh)
    placeholder = manifest.get("home_placeholder", "{{ HOME }}")
    entries = manifest["entries"]
    roots = manifest["roots"]

    errors, warnings = [], []
    symlinks = []          # (home-rel link, target, disposition)
    claimed = set()        # home-relative paths already handled
    report = {"entries": {}, "orphans": [], "private": [], "outputs": 0}

    # ---------------- fail-closed: every top-level entry of a root is matched
    for root in roots:
        root_abs = os.path.join(HOME, root)
        if not os.path.isdir(root_abs):
            warnings.append("root missing on this machine: %s" % root)
            continue
        tops = sorted(os.listdir(root_abs))
        ent_for_root = [e for e in entries if e.get("root") == root]
        for top in tops:
            ok = any(
                fnmatch.fnmatch(top, first_segment(g))
                for e in ent_for_root for g in e["match"])
            if not ok:
                report["orphans"].append(os.path.join(root, top))
    if report["orphans"]:
        errors.append(
            "unclassified paths (fail-closed):\n    "
            + "\n    ".join(report["orphans"]))

    secret_paths = load_secrets_paths(repo)

    # ---------------- per-entry capture, first-match-wins on file level
    for entry in entries:
        eid = entry["id"]
        root = entry.get("root", "")
        cls = entry["class"]
        verbs = entry.get("template", []) or []
        stats_e = {"captured": 0, "skipped": 0}
        report["entries"][eid] = stats_e
        root_abs = os.path.join(HOME, root) if root else HOME

        # gather candidate files for this entry
        cands = []
        for g in entry["match"]:
            base = os.path.join(root_abs, g)
            hits = []
            if any(ch in g for ch in "*?["):
                top = first_segment(g)
                parent = root_abs
                if "/" in g:
                    # deep glob: walk and fnmatch full relpaths
                    for dp, dns, fns in os.walk(root_abs):
                        dns[:] = [d for d in dns
                                  if not os.path.islink(os.path.join(dp, d))]
                        for fn in fns + [d for d in dns]:
                            p = os.path.join(dp, fn)
                            rel = os.path.relpath(p, root_abs)
                            if match_glob(rel, g):
                                hits.append(p)
                else:
                    for name in os.listdir(parent) if os.path.isdir(parent) else []:
                        if fnmatch.fnmatch(name, g):
                            hits.append(os.path.join(parent, name))
            elif os.path.lexists(base):
                hits.append(base)
            cands.extend(hits)

        record_links = not cls.startswith("exclude")

        def note_link(p):
            rel_home_l = os.path.relpath(p, HOME)
            if rel_home_l in claimed:
                return
            claimed.add(rel_home_l)
            if not record_links:
                return
            target = os.readlink(p)
            disp = ("delegated" if os.path.realpath(p).startswith(
                os.path.join(HOME, "ai-agents-skills")) else "topology")
            symlinks.append((rel_home_l, target, disp))

        files = []
        for c in cands:
            if os.path.islink(c):
                note_link(c)
                continue
            if os.path.isdir(c):
                for dp, dns, fns in os.walk(c):
                    # nested git repos are never captured (skill dirs may be repos)
                    dns[:] = [d for d in dns if d != ".git"]
                    # record symlinked dirs, do not descend
                    keep = []
                    for d in dns:
                        p = os.path.join(dp, d)
                        if os.path.islink(p):
                            note_link(p)
                        else:
                            keep.append(d)
                    dns[:] = keep
                    for fn in fns:
                        files.append(os.path.join(dp, fn))
            else:
                files.append(c)

        inc = entry.get("include")
        exc = entry.get("exclude", []) or []
        for f in files:
            rel_root = os.path.relpath(f, root_abs)
            rel_home = os.path.relpath(f, HOME)
            if rel_home in claimed:
                continue
            if inc and not any(match_glob(rel_root, g) for g in inc):
                stats_e["skipped"] += 1
                continue
            if any(match_glob(rel_root, g) for g in exc):
                stats_e["skipped"] += 1
                claimed.add(rel_home)
                continue
            claimed.add(rel_home)

            if os.path.islink(f):
                if record_links:
                    target = os.readlink(f)
                    disp = ("delegated" if os.path.realpath(f).startswith(
                        os.path.join(HOME, "ai-agents-skills")) else "topology")
                    symlinks.append((rel_home, target, disp))
                continue

            if cls.startswith("exclude") or cls == "delegate":
                stats_e["skipped"] += 1
                continue

            if cls == "private-archive":
                report["private"].append(rel_home)
                if secret_paths is not None and not covered_by_secrets(
                        rel_home, secret_paths):
                    warnings.append(
                        "private-archive path NOT covered by secrets-manifest: %s"
                        % rel_home)
                if "emit-keys" in verbs and f.endswith(".json"):
                    keys_text = emit_keys(f)
                    if keys_text and entry.get("dest_dir"):
                        dest = os.path.join(
                            out, entry["dest_dir"],
                            os.path.basename(f).lstrip(".") + ".keys")
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "w") as fh:
                            fh.write(keys_text)
                        report["outputs"] += 1
                stats_e["captured"] += 1
                continue

            # ---- public classes
            if is_elf(f):
                errors.append("ELF binary in public class (%s): %s" % (eid, rel_home))
                continue
            if entry.get("dest"):
                dest = os.path.join(out, entry["dest"])
            else:
                dest = os.path.join(out, entry["dest_dir"], rel_root)
                if cls == "public-template" and entry.get("dest_dir") and (
                        "key-redact" in verbs):
                    dest += ".template" if not dest.endswith(".template") else ""

            text = read_text(f)
            if text is None:
                # binary asset (image, db...) — copy raw, no substitution
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(f, dest)
                stats_e["captured"] += 1
                report["outputs"] += 1
                continue

            if "secret-env-split" in verbs:
                text = split_bashrc(text, errors)
                if text is None:
                    continue
            if "key-redact" in verbs:
                text = key_redact(text, os.path.splitext(f)[1],
                                  entry.get("keys", []))
            # implicit home-substitute on ALL public text files
            text = home_substitute(text, placeholder)
            if HOME in text:
                errors.append("home path survived render: %s" % rel_home)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", errors="surrogateescape") as fh:
                fh.write(text)
            if os.access(f, os.X_OK):
                os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR
                         | stat.S_IXGRP | stat.S_IXOTH)
            stats_e["captured"] += 1
            report["outputs"] += 1

    # ---------------- symlink topology comparison
    obs_path = os.path.join(out, ".staging-symlinks-observed.tsv") \
        if args.apply else os.path.join(out, "symlinks-observed.tsv")
    os.makedirs(os.path.dirname(obs_path), exist_ok=True)
    with open(obs_path, "w") as fh:
        for link, target, disp in sorted(symlinks):
            fh.write("%s\t%s\t%s\n" % (
                link.replace(HOME, placeholder),
                target.replace(HOME, placeholder), disp))
    tsv = os.path.join(repo, "system", "symlinks.tsv")
    if os.path.exists(tsv):
        known = set()
        with open(tsv) as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    known.add(line.split("\t")[0].strip())
        for link, _t, disp in symlinks:
            l = link.replace(HOME, placeholder)
            ph_link = "{{ HOME }}/" + link
            if disp == "topology" and l not in known and ph_link not in known:
                warnings.append("symlink not in system/symlinks.tsv: %s" % link)
    else:
        warnings.append("system/symlinks.tsv missing — observed symlinks written to %s"
                        % os.path.relpath(obs_path, repo))

    if secret_paths is None:
        warnings.append("secrets/secrets-manifest.yaml missing — private cross-check skipped")

    # ---------------- report
    report["symlinks"] = len(symlinks)
    report["warnings"] = warnings
    report["errors"] = errors
    rpt_dir = os.path.join(repo, ".staging")
    os.makedirs(rpt_dir, exist_ok=True)
    with open(os.path.join(rpt_dir, "sync-report.json"), "w") as fh:
        json.dump(report, fh, indent=1)

    print("sync: %d files rendered, %d symlinks recorded, %d private paths verified"
          % (report["outputs"], len(symlinks), len(report["private"])))
    for w in warnings:
        print("WARN: %s" % w)
    if errors:
        for e in errors:
            print("ERROR: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
