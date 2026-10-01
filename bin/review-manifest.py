#!/usr/bin/env python3
"""Owner review of the capture contract in MANIFEST.yaml.

manifest_sync.py --apply publishes only when every manifest entry, the entry
order, roots and home placeholder (manifest-layout), the global_exclude list and
the leak scan's reviewed exceptions (scanner-exceptions) match the digests
recorded in MANIFEST.review.json.  Without options this tool lists what still
needs review and exits 2 when anything does.  --approve records a review after
an interactive confirmation.

The lock makes widening the public tree a deliberate step at a terminal.  It is
a process control, not a security boundary: anything running as the same user
can write MANIFEST.review.json.

Usage: bin/review-manifest.py [--repo DIR] [--approve ID... | --approve all]
"""

import argparse
import json
import os
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import manifest_sync  # noqa: E402


def definitions(manifest, repo):
    entries = manifest.get("entries", [])
    found = {e["id"]: e for e in entries}
    found["global_exclude"] = {"global_exclude": manifest.get("global_exclude") or []}
    found["manifest-layout"] = {"order": [e.get("id") for e in entries],
                                "roots": manifest.get("roots"),
                                "home_placeholder": manifest.get("home_placeholder")}
    exceptions = None
    path = os.path.join(repo, "leak-scan-exceptions.yaml")
    if os.path.exists(path):
        with open(path) as fh:
            exceptions = fh.read()
    found["scanner-exceptions"] = {"leak-scan-exceptions.yaml": exceptions}
    return found


def show(key, definition, reviewed):
    print("--- %s (%s)" % (key, "changed" if key in reviewed else "new"))
    print(yaml.safe_dump(definition, sort_keys=False).rstrip())


def write_review(repo, entries):
    path = os.path.join(repo, manifest_sync.REVIEW_FILE)
    raw = json.dumps({"schema": manifest_sync.REVIEW_SCHEMA,
                      "entries": dict(sorted(entries.items()))}, indent=1) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".review-", dir=repo)
    try:
        with os.fdopen(descriptor, "w") as fh:
            fh.write(raw)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--approve", nargs="+", metavar="ID",
                    help="record the owner review of these items ('all' = every pending item)")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    with open(os.path.join(repo, "MANIFEST.yaml")) as fh:
        manifest = yaml.safe_load(fh)
    problems = manifest_sync.validate_manifest(manifest)
    if problems:
        for problem in problems:
            print("ERROR: %s" % problem, file=sys.stderr)
        return 2
    items = manifest_sync.review_items(manifest, repo)
    try:
        reviewed = manifest_sync.load_public_review(repo)
    except manifest_sync.SyncError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    pending = sorted(k for k, v in items.items() if reviewed.get(k) != v)
    defs = definitions(manifest, repo)

    if not args.approve:
        if not pending:
            print("manifest review: every item is owner-reviewed")
            return 0
        for key in pending:
            show(key, defs[key], reviewed)
        print("%d item(s) need owner review: bin/review-manifest.py --approve ID..." % len(pending))
        return 2

    chosen = pending if args.approve == ["all"] else args.approve
    unknown = [k for k in chosen if k not in items]
    if unknown:
        print("ERROR: not a review item: %s" % ", ".join(unknown), file=sys.stderr)
        return 2
    if not chosen:
        print("manifest review: nothing pending")
        return 0
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("ERROR: approval is interactive; run it in a terminal", file=sys.stderr)
        return 2
    for key in chosen:
        show(key, defs[key], reviewed)
    answer = input("Type APPROVE to record the owner review of %d item(s): " % len(chosen))
    if answer.strip() != "APPROVE":
        print("not approved; nothing recorded")
        return 2
    entries = {k: v for k, v in reviewed.items() if k in items}
    entries.update({k: items[k] for k in chosen})
    write_review(repo, entries)
    print("recorded the owner review of: %s" % ", ".join(chosen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
