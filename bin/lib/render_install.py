#!/usr/bin/env python3
"""Reverse of manifest_sync: render repo artifacts back into a home directory.

Rules:
  * mapping derived from MANIFEST.yaml (dest/dest_dir -> root)
  * '{{ HOME }}' -> target home in every text file
  * *.keys files are informational, never installed
  * *.template files install with the suffix stripped and are SKIP-IF-EXISTS
    (the real file normally arrives from the secrets zip; the template is the
    placeholder fallback a new user fills in)
  * system/shell/bashrc.block.sh -> ~/.bashrc, profile.block.sh -> ~/.profile
    (existing file backed up to <name>.pre-coding-system once)
  * exec bits preserved; symlink topology applied from system/symlinks.tsv
  * zero unresolved '{{ ... }}' placeholders may remain in non-template installs
"""

import argparse
import os
import re
import shutil
import stat
import sys

import yaml

# only {{ HOME }} is render-install's own placeholder; key-redact placeholders
# live exclusively in *.template files, and captured content (e.g. get-shit-done
# workflow templates) legitimately uses {{ VAR }} moustache syntax of its own
PLACEHOLDER_RE = re.compile(r"\{\{ *HOME *\}\}")


def read(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="surrogateescape")


def write_conflict_preview(dst, data, binary, mode, report):
    preview = dst + ".new"
    if binary:
        with open(preview, "wb") as fh:
            fh.write(data)
    else:
        with open(preview, "w", errors="surrogateescape") as fh:
            fh.write(data)
    os.chmod(preview, mode)
    report["conflicts"].append((dst, preview))


def install_file(src, dst, home, report, skip_if_exists=False):
    if src.endswith(".keys"):
        return
    if skip_if_exists and os.path.exists(dst):
        report["skipped_existing"].append(dst)
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    text = read(src)
    mode = os.stat(src).st_mode
    if text is None:
        with open(src, "rb") as fh:
            data = fh.read()
        if os.path.exists(dst):
            with open(dst, "rb") as fh:
                if fh.read() == data:
                    report["installed"] += 1
                    return
            write_conflict_preview(dst, data, True, stat.S_IMODE(mode), report)
            return
        shutil.copy2(src, dst)
    else:
        rendered = text.replace("{{ HOME }}", home)
        if os.path.exists(dst):
            try:
                with open(dst, "r", errors="surrogateescape") as fh:
                    if fh.read() == rendered:
                        report["installed"] += 1
                        return
            except UnicodeError:
                pass
            write_conflict_preview(dst, rendered, False, stat.S_IMODE(mode), report)
            return
        with open(dst, "w", errors="surrogateescape") as fh:
            fh.write(rendered)
        if not src.endswith(".template") and PLACEHOLDER_RE.search(rendered):
            report["placeholders"].append(dst)
        if os.access(src, os.X_OK):
            os.chmod(dst, os.stat(dst).st_mode | stat.S_IXUSR
                     | stat.S_IXGRP | stat.S_IXOTH)
    report["installed"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--home", default=os.path.expanduser("~"))
    ap.add_argument("--render-only", action="store_true",
                    help="no sudo actions (usr-local-bin symlinks skipped)")
    args = ap.parse_args()
    repo, home = os.path.abspath(args.repo), os.path.abspath(args.home)

    with open(os.path.join(repo, "MANIFEST.yaml")) as fh:
        manifest = yaml.safe_load(fh)

    report = {"installed": 0, "skipped_existing": [], "placeholders": [],
              "symlinks": 0, "blocked_symlinks": [], "conflicts": []}

    # --- shell files (whole-file installs with one-time backup) -------------
    shell_map = {
        "system/shell/bashrc.block.sh": ".bashrc",
        "system/shell/profile.block.sh": ".profile",
        "system/npmrc.template": ".npmrc",
    }
    for src_rel, dst_rel in shell_map.items():
        src = os.path.join(repo, src_rel)
        if not os.path.exists(src):
            continue
        dst = os.path.join(home, dst_rel)
        if os.path.exists(dst) and not os.path.exists(dst + ".pre-coding-system"):
            shutil.copy2(dst, dst + ".pre-coding-system")
        skip = src_rel.endswith(".template") and os.path.exists(dst) \
            and ".npmrc" in dst_rel
        install_file(src, dst, home, report, skip_if_exists=skip)

    # --- manifest-driven agent/system trees ---------------------------------
    handled_dests = set(shell_map)
    for entry in manifest["entries"]:
        root = entry.get("root", "")
        cls = entry["class"]
        if not cls.startswith("public"):
            continue
        if entry.get("dest"):
            src = os.path.join(repo, entry["dest"])
            if entry["dest"] in handled_dests or not os.path.exists(src):
                continue
            name = entry["match"][0]
            dst = os.path.join(home, root, name) if root else os.path.join(home, name)
            install_file(src, dst, home, report,
                         skip_if_exists=entry["dest"].endswith(".template"))
            handled_dests.add(entry["dest"])
        elif entry.get("dest_dir"):
            dd = os.path.join(repo, entry["dest_dir"])
            if not os.path.isdir(dd):
                continue
            key = (entry["dest_dir"], root)
            if key in handled_dests:
                continue
            handled_dests.add(key)
            for dp, dns, fns in os.walk(dd):
                for fn in fns:
                    src = os.path.join(dp, fn)
                    rel = os.path.relpath(src, dd)
                    if fn.endswith(".keys"):
                        continue
                    skip = fn.endswith(".template")
                    dst_rel = rel[:-len(".template")] if skip else rel
                    dst = os.path.join(home, root, dst_rel)
                    install_file(src, dst, home, report, skip_if_exists=skip)

    # --- symlink topology ----------------------------------------------------
    tsv = os.path.join(repo, "system", "symlinks.tsv")
    if os.path.exists(tsv):
        for line in open(tsv):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            link, target = [p.replace("{{ HOME }}", home)
                            for p in line.split("\t")[:2]]
            os.makedirs(os.path.dirname(link), exist_ok=True)
            if not os.path.exists(target) and not os.path.islink(link):
                # create target dir so the link resolves post-install
                if "." not in os.path.basename(target):
                    os.makedirs(target, exist_ok=True)
            if os.path.islink(link) or os.path.exists(link):
                if os.path.islink(link) and os.readlink(link) == target:
                    continue
                if os.path.islink(link):
                    os.unlink(link)
                else:
                    report["blocked_symlinks"].append((link, target))
                    continue  # real file/dir in the way — leave it, report
            os.symlink(target, link)
            report["symlinks"] += 1

    # --- /usr/local/bin (sudo) ----------------------------------------------
    if not args.render_only:
        tsv2 = os.path.join(repo, "system", "bin", "usr-local-bin.tsv")
        if os.path.exists(tsv2):
            import subprocess
            for line in open(tsv2):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                link, target = [p.replace("{{ HOME }}", home)
                                for p in line.split("\t")[:2]]
                subprocess.run(["sudo", "-n", "ln", "-sfn", target, link],
                               check=False)

    # --- record _run.sh sha for the phase-8b clobber check -------------------
    runsh = os.path.join(home, ".claude", "skills", "_run.sh")
    if os.path.exists(runsh):
        import hashlib
        sha = hashlib.sha256(open(runsh, "rb").read()).hexdigest()
        state_dir = os.path.join(home, ".config", "coding-system")
        os.makedirs(state_dir, exist_ok=True)
        with open(os.path.join(state_dir, "run_sh.sha256"), "w") as fh:
            fh.write(sha + "\n")

    print("render-install: %d files, %d symlinks, %d skipped-existing"
          % (report["installed"], report["symlinks"],
             len(report["skipped_existing"])))
    if report["conflicts"]:
        for dst, preview in report["conflicts"][:10]:
            print("ERROR: existing file differs; preserved %s and wrote %s"
                  % (dst, preview), file=sys.stderr)
        return 2
    if report["blocked_symlinks"]:
        for link, target in report["blocked_symlinks"][:10]:
            print("ERROR: symlink blocked by existing real path: %s -> %s"
                  % (link, target), file=sys.stderr)
        return 2
    if report["placeholders"]:
        for p in report["placeholders"][:10]:
            print("ERROR: unresolved placeholder in %s" % p, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
