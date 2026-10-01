#!/usr/bin/env python3
"""Manifest-driven capture engine for coding-system-rebuild.

Reads MANIFEST.yaml, walks the fail-closed roots, and renders sanitized public
artifacts into an output tree (.staging/ for --dry-run, the repo for --apply).

Hard rules (exit 2 on violation):
  * the manifest must be well formed: known classes, safe roots and
    destinations, unique entry ids
  * no ELF binary may enter a public class, and no other binary file except
    images and fonts
  * no database, history, session, feedback, installation-id, owner/tunnel file
    or unrendered '{{ ... }}' path may enter a public class, nor anything the
    leak scan does not read (node_modules, files over 20 MiB)
  * no private denylist entry may enter a rendered public file, and captured
    content may not carry the scanner's LEAKSCAN-EXEMPT marker (authoritative
    mirrors of owner-authored source excepted)
  * no '/home/<user>' literal may survive in a rendered public text file
  * bashrc managed-secret markers must exist; secret-shaped exports outside the
    managed block abort the run
  * private-archive paths must exist and be covered by secrets-manifest
  * the rendered tree must pass bin/leak-scan.sh; --apply renders into a private
    stage and publishes nothing unless that scan passes
  * --apply needs the private denylist and an owner review of every entry,
    the entry order, the global exclusions and the scanner's exceptions
    (MANIFEST.review.json, bin/review-manifest.py); it publishes only bytes
    that match the digests taken before the scan

Top-level paths no manifest entry matches (orphans) are never captured; they are
listed as warnings until they are classified.  Files matching global_exclude
never enter a public class.  *.template outputs carry {{ EMAIL }} and
{{ <KIND>_ID }} placeholders instead of email addresses and identifier values.

Symlinks are never copied: they are recorded (delegated if they point into the
ai-agents-skills repo, topology otherwise) and compared against system/symlinks.tsv.
"""

import argparse
import atexit
import ctypes
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

import yaml

HOME = os.environ.get("CSR_HOME_OVERRIDE") or os.path.expanduser("~")
MARK_BEGIN = "# >>> coding-system secrets >>>"
MARK_END = "# <<< coding-system secrets <<<"
# A line that sources the owner-settings data file as shell (bin/migrate-owner-settings.py
# removes the known forms; any other form must be removed by hand before capture).
SHELL_SOURCE_RE = re.compile(
    r"""(?:^|[\s;&|({])(?:\.|source)\s+["']?(?:~|\$HOME|\$\{HOME\})/\.secrets\.env(?:["'\s;&|)]|$)"""
)
SECRET_NAME_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API|CHAT_ID)", re.I
)
PERSONAL_PREFIX_RE = re.compile(r"^(MOLTBOOK|MOLBOOK)_")
EXPORT_RE = re.compile(r'^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
PUBLIC_CLASSES = ("public-copy", "public-template")
MANIFEST_CLASSES = PUBLIC_CLASSES + (
    "private-archive", "exclude-cache", "exclude-private-data", "exclude-generated", "delegate")
REVIEW_FILE = "MANIFEST.review.json"
REVIEW_SCHEMA = "coding-system.manifest-review.v1"
SQLITE_MAGIC = b"SQLite format 3\x00"
# Binary files enter a public class only as images or fonts; any other file
# holding a NUL byte could hide text from the leak scan, which reads no binary.
BINARY_ASSET_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2")
# bin/leak-scan.sh reads neither these trees nor larger files, so neither may be
# published.
UNSCANNED_DIRS = ("node_modules", "secrets-out", ".git")
SCAN_MAX_BYTES = 20 * 1024 * 1024
EXEMPT_MARKER = "LEAKSCAN-EXEMPT"
# File kinds that never belong in the public tree, whatever an entry matches:
# databases, histories, sessions, feedback drafts, installation IDs, and the
# owner/tunnel records of machine-local services.  Names compare in lower case.
FORBIDDEN_PUBLIC_NAMES = (
    ("database", ("*.db", "*.db-*", "*.sqlite", "*.sqlite-*", "*.sqlite3", "*.sqlite3-*")),
    ("history", ("history", "history.json", "history.jsonl", "history.txt", "*_history",
                 "*_history.json", "*_history.jsonl", "*_history.txt", "*-history.jsonl",
                 "command-history*")),
    ("session", ("session-store*", "session_index.jsonl", "*.session")),
    ("feedback", ("feedback", "feedback.json", "feedback.jsonl")),
    ("installation id", ("installation_id", "installation-id", "installation_id.*")),
    ("owner/tunnel", ("*.owner", "*.owner.json", "owner.json", ".tunnel.*", "tunnel.json",
                      "*-tunnel.json", "*tunnel*.env")),
)
FORBIDDEN_PUBLIC_DIRS = {
    "sessions": "session", "session-state": "session", "session-env": "session",
    "sidebar-sessions-state": "session", "history": "history", "feedback": "feedback",
}
# The key set of public_export.ID_FIELD_RE, widened for templates: prefixed keys
# (zotero_user_id, telegram_chat_id), values of four or more characters, and a
# leading minus (group chat IDs).  Groups: key and separator, kind, value quote.
TEMPLATE_ID_RE = re.compile(
    r"((?<![A-Za-z0-9])[\"']?(?:[A-Za-z0-9]+[_-])*"
    r"(account|app|application|chat|client|course|document|owner|tenant|user|workspace)"
    r"[_-]?id[\"']?\s*[:=]\s*)([\"']?)-?[A-Za-z0-9][A-Za-z0-9_.:+/-]{3,}",
    re.IGNORECASE,
)


class SyncError(Exception):
    pass


def _raise_sync_walk_error(error):
    raise SyncError(
        "cannot inspect authoritative tree %s: %s"
        % (error.filename, error.strerror)
    ) from error


class AuthoritativeRecoveryRequired(SyncError):
    """Publication failed after exchange and the old tree must be retained."""


AT_FDCWD = -100
RENAME_EXCHANGE = 2


def _fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise SyncError("fsync target is not a directory: %s" % path)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_real_tree(path):
    """Persist a staged real tree before it becomes the public snapshot."""
    for directory, dirnames, filenames in os.walk(
        path, topdown=False, onerror=_raise_sync_walk_error
    ):
        for name in filenames:
            child = os.path.join(directory, name)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(child, flags)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise SyncError("staged output is not a regular file: %s" % child)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for name in dirnames:
            child = os.path.join(directory, name)
            info = os.lstat(child)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SyncError("staged output is not a real directory: %s" % child)
        _fsync_directory(directory)


def _rename_exchange(left, right):
    """Atomically exchange two paths; never fall back to a two-rename gap."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise SyncError("renameat2(RENAME_EXCHANGE) is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(left),
        AT_FDCWD,
        os.fsencode(right),
        RENAME_EXCHANGE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), "%s <-> %s" % (left, right))


def _acquire_capture_lock(repo):
    """Serialize dry-run/apply staging and publication for one repository."""
    staging = os.path.join(repo, ".staging")
    if os.path.lexists(staging):
        info = os.lstat(staging)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SyncError("capture staging path is unsafe: %s" % staging)
    else:
        os.mkdir(staging, 0o700)
    lock_path = os.path.join(staging, "capture.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise SyncError("capture lock has unsafe owner or mode")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    atexit.register(os.close, descriptor)
    return descriptor


def _acquire_authoritative_source_locks(entries):
    """Exclude capture from a resumable authoring-source restore transaction."""
    descriptors = []
    try:
        for entry in entries:
            if not entry.get("authoritative"):
                continue
            lock_rel = entry.get("source_transaction_lock")
            marker_rel = entry.get("source_transaction_marker")
            if lock_rel is None and marker_rel is None:
                continue
            root = safe_relative_path(entry.get("root"))
            lock_rel = safe_relative_path(lock_rel)
            marker_rel = safe_relative_path(marker_rel)
            if root is None or lock_rel is None or marker_rel is None:
                raise SyncError(
                    "authoritative source transaction paths must be safe literals"
                )
            root_abs = os.path.join(HOME, root)
            lock_path = os.path.join(root_abs, lock_rel)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(lock_path, flags, 0o600)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise SyncError("authoritative source transaction lock is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                marker = os.path.join(root_abs, marker_rel)
                if os.path.lexists(marker):
                    raise SyncError(
                        "authoritative source restore is incomplete: %s" % marker
                    )
            except BaseException:
                os.close(descriptor)
                raise
            descriptors.append(descriptor)
        for descriptor in descriptors:
            atexit.register(os.close, descriptor)
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _reset_default_dry_run_tree(repo, out, apply):
    """Clean shared dry-run outputs only after the shared lock is held."""
    staging = os.path.join(repo, ".staging")
    if apply or os.path.abspath(out) != os.path.abspath(staging):
        return
    for name in os.listdir(staging):
        if name == "capture.lock" or name.startswith("authoritative-"):
            continue
        path = os.path.join(staging, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    _fsync_directory(staging)


def _leak_scan(repo, target, require_denylist):
    """Run the repository's artifact scanner on ``target``; True when it is clean.

    A missing scanner counts as a failed scan.  Findings print as file:line only.
    """
    scanner = os.path.join(repo, "bin", "leak-scan.sh")
    if not os.path.isfile(scanner):
        print("ERROR: leak scanner missing: %s" % scanner, file=sys.stderr)
        return False
    env = dict(os.environ)
    if require_denylist:
        env["CSR_REQUIRE_DENYLIST"] = "1"
    sys.stdout.flush()
    result = subprocess.run(
        ["/bin/bash", scanner, target],
        stdin=subprocess.DEVNULL,
        env=env,
        check=False,
    )
    return result.returncode == 0


def _scan_authoritative_stage(repo, stage_root, entry):
    """Run the repository's artifact scanner before public-tree publication."""
    dest_rel = safe_relative_path(entry.get("dest_dir"))
    if dest_rel is None:
        raise SyncError("unsafe authoritative destination")
    if not _leak_scan(repo, os.path.join(stage_root, dest_rel), require_denylist=True):
        raise SyncError("authoritative staged output failed the leak scan")


def _read_nofollow(path):
    """Bytes and mode of a regular file, opened without following a link."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SyncError("rendered output is not a regular file: %s" % path)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), stat.S_IMODE(info.st_mode)
    finally:
        os.close(descriptor)


def _tree_digests(root):
    """sha256 of every file under ``root``; a link anywhere is an error."""
    digests = {}
    for directory, dirnames, names in os.walk(root):
        for name in dirnames + names:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                raise SyncError("rendered tree holds a link: %s"
                                % os.path.relpath(path, root))
        for name in names:
            path = os.path.join(directory, name)
            data, _mode = _read_nofollow(path)
            digests[os.path.relpath(path, root)] = hashlib.sha256(data).hexdigest()
    return digests


def _check_publish_destination(publish_root, rel):
    """Refuse a destination whose parents are not real directories or which is one."""
    current = publish_root
    for part in rel.split(os.sep)[:-1]:
        current = os.path.join(current, part)
        if os.path.lexists(current) and (
                os.path.islink(current) or not os.path.isdir(current)):
            raise SyncError("publication path is not a real directory: %s" % current)
    destination = os.path.join(publish_root, rel)
    if os.path.isdir(destination) and not os.path.islink(destination):
        raise SyncError("publication target is a directory: %s" % destination)


def _publish_rendered_tree(render_root, publish_root, digests):
    """Copy the scanned render tree into place, one atomic rename per file.

    ``digests`` were taken before the leak scan: every file published must still
    hash to them, and every destination is checked before the first write.
    """
    if set(_tree_digests(render_root)) != set(digests):
        raise SyncError("rendered tree changed after the leak scan")
    for rel in sorted(digests):
        _check_publish_destination(publish_root, rel)
    for rel in sorted(digests):
        data, mode = _read_nofollow(os.path.join(render_root, rel))
        if hashlib.sha256(data).hexdigest() != digests[rel]:
            raise SyncError("rendered output changed after the leak scan: %s" % rel)
        destination = os.path.join(publish_root, rel)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".capture-", dir=os.path.dirname(destination))
        try:
            with os.fdopen(descriptor, "wb") as target:
                target.write(data)
            os.chmod(temporary, mode)
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def _write_json_atomic(path, value):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".sync-report-", dir=directory)
    try:
        raw = (json.dumps(value, sort_keys=True, indent=1) + "\n").encode("utf-8")
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SyncError("short write while publishing sync report")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _output_record(path):
    data, _executable = _stable_regular_bytes(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SyncError("captured output is not a regular file: %s" % path)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": stat.S_IMODE(info.st_mode),
    }


def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def is_binary(data):
    return b"\x00" in data


def home_substitute(text, placeholder):
    return text.replace(HOME, placeholder)


def excluded_globally(rel, patterns):
    """global_exclude: a glob without '/' matches any path component, and a glob
    with '/' matches the path from any component down."""
    parts = rel.split("/")
    suffixes = ["/".join(parts[i:]) for i in range(len(parts))]
    for pattern in patterns:
        if "/" in pattern:
            if any(match_glob(suffix, pattern) for suffix in suffixes):
                return True
        elif any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def unscannable_reason(rel, size):
    """Why bin/leak-scan.sh would not read this output, or None."""
    if any(part in UNSCANNED_DIRS for part in rel.split("/")[:-1]):
        return "inside a tree the leak scan skips"
    if size > SCAN_MAX_BYTES:
        return "larger than the leak scan reads"
    return None


def forbidden_public_reason(rel, path=None, is_dir=False):
    """Name the rule that keeps ``rel`` out of every public class, or None."""
    parts = rel.split("/")
    if any("{{" in part or "}}" in part for part in parts):
        return "unrendered placeholder"
    for part in (parts if is_dir else parts[:-1]):
        rule = FORBIDDEN_PUBLIC_DIRS.get(part.lower())
        if rule:
            return rule
    if not is_dir:
        name = parts[-1].lower()
        for rule, patterns in FORBIDDEN_PUBLIC_NAMES:
            if any(fnmatch.fnmatchcase(name, p) for p in patterns):
                return rule
    if path is not None:
        try:
            with open(path, "rb") as fh:
                if fh.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC:
                    return "database"
        except OSError:
            pass
    return None


def denylist_path():
    return os.environ.get("CSR_DENYLIST") or os.path.join(
        os.path.expanduser("~"), ".config", "coding-system", "leak-denylist.txt")


def load_denylist(path):
    """Private denylist entries, or None when the file is missing or empty."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            entries = [line.strip() for line in fh
                       if line.strip() and not line.lstrip().startswith("#")]
    except FileNotFoundError:
        return None
    return entries or None


def denylist_lines(text, entries):
    """Line numbers holding a denylist entry.  Captured content cannot exempt
    itself: LEAKSCAN-EXEMPT marks repository-authored scanner lines only."""
    return [number for number, line in enumerate(text.splitlines(), 1)
            if any(e in line for e in entries)]


def redact_template_identities(text):
    """Replace email addresses and identifier values in a *.template output.

    Only templates may carry placeholders: render-install copies them
    skip-if-exists, and the real file comes from the private recovery set.
    Reserved example domains, noreply addresses and git@host remotes stay.
    """
    def email(match):
        local = match.group(0).split("@", 1)[0].lower()
        domain = match.group(1).lower()
        if (public_export.is_reserved_email(domain) or local == "git"
                or local.startswith("noreply") or domain.endswith("noreply.github.com")):
            return match.group(0)
        return "{{ EMAIL }}"

    # the scanner's own email pattern and reserved domains, imported only here so
    # the engine still runs where no template needs redaction
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import public_export
    finally:
        sys.path.pop(0)
    text = public_export.EMAIL_RE.sub(email, text)

    def identifier(match):
        placeholder = "{{ %s_ID }}" % match.group(2).upper()
        if match.group(3):  # quoted value: its closing quote stays in the text
            return match.group(1) + match.group(3) + placeholder
        return match.group(1) + '"%s"' % placeholder

    return TEMPLATE_ID_RE.sub(identifier, text)


def review_items(manifest, repo):
    """Digests an owner review pins: every entry and the entry order (first
    match wins), the roots and home placeholder, the global exclusions, and the
    leak scan's reviewed exceptions."""
    def digest(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    entries = manifest.get("entries", [])
    try:
        with open(os.path.join(repo, "leak-scan-exceptions.yaml"), "rb") as fh:
            exceptions = hashlib.sha256(fh.read()).hexdigest()
    except FileNotFoundError:
        exceptions = None
    items = {
        "global_exclude": digest(sorted(manifest.get("global_exclude") or [])),
        "manifest-layout": digest({
            "order": [entry.get("id") for entry in entries],
            "roots": manifest.get("roots"),
            "home_placeholder": manifest.get("home_placeholder"),
        }),
        "scanner-exceptions": digest(exceptions),
    }
    for entry in entries:
        items[entry["id"]] = digest({k: v for k, v in entry.items() if k != "note"})
    return items


def load_public_review(repo):
    """Reviewed digests from MANIFEST.review.json; empty when nothing was reviewed."""
    path = os.path.join(repo, REVIEW_FILE)
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        raise SyncError("%s is not valid JSON: %s" % (REVIEW_FILE, exc)) from exc
    if (not isinstance(data, dict) or data.get("schema") != REVIEW_SCHEMA
            or not isinstance(data.get("entries"), dict)):
        raise SyncError("%s does not follow %s" % (REVIEW_FILE, REVIEW_SCHEMA))
    return data["entries"]


def unreviewed_items(repo, manifest):
    reviewed = load_public_review(repo)
    return sorted(key for key, value in review_items(manifest, repo).items()
                  if reviewed.get(key) != value)


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
                r'("%s"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|-?\d[\d.eE+-]*)' % re.escape(key),
                lambda m: m.group(1) + '"%s"' % ph,
                text)
        else:
            text = re.sub(
                r'(%s\s*[=:]\s*)\S+' % re.escape(key),
                lambda m: m.group(1) + ph,
                text)
    return text


def _json_loads_lenient(text):
    """json.loads, retried without // and /* */ comments and trailing commas (JSONC)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    out, i, n, in_string = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_string = ch != '"'
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif ch == "," and re.match(r"\s*[}\]]", text[i + 1:]):
            i += 1
        else:
            out.append(ch)
            i += 1
    return json.loads("".join(out))


def _home_string(value):
    return isinstance(value, str) and (
        value.startswith(HOME) or value == "~" or value.startswith("~/"))


def _holds_home(node):
    if isinstance(node, dict):
        return any(_home_string(k) or _holds_home(v) for k, v in node.items())
    if isinstance(node, list):
        return any(_holds_home(v) for v in node)
    return _home_string(node)


def strip_projects(text, ext):
    """Drop per-machine project/location trust records that would otherwise leak
    local directory names. TOML: every [projects."..."] table. JSON (comments
    allowed): dict keys that are home paths (the editor/agent "locations" trust
    ledger) and items of lists under a "trusted..." key (trustedFolders,
    trustedWorkspaces) that hold a home or ~ path. Returns None for JSON it
    cannot parse that mentions a home path, so the caller refuses the file.
    Other formats, and files without such records, pass through unchanged so
    the verb is a safe no-op on the rest of a multi-file entry."""
    if ext == ".toml":
        lines = text.splitlines(keepends=True)
        hdr = re.compile(r'^\s*\[projects\."[^"]*"\]\s*$')
        out, i, n = [], 0, len(lines)
        while i < n:
            if hdr.match(lines[i]):
                i += 1
                while i < n and not lines[i].lstrip().startswith("["):
                    i += 1
                continue
            out.append(lines[i])
            i += 1
        return "".join(out)
    if ext == ".json":
        try:
            data = _json_loads_lenient(text)
        except ValueError:
            if HOME in text or '"~/' in text or '"~"' in text:
                return None
            return text
        removed = [False]

        def scrub(node):
            if isinstance(node, dict):
                for k in [k for k in node if _home_string(k)]:
                    del node[k]
                    removed[0] = True
                for k, v in node.items():
                    if (isinstance(k, str) and k.lower().startswith("trusted")
                            and isinstance(v, list)):
                        kept = [x for x in v if not _holds_home(x)]
                        if len(kept) != len(v):
                            v[:] = kept
                            removed[0] = True
                for v in node.values():
                    scrub(v)
            elif isinstance(node, list):
                for v in node:
                    scrub(v)

        scrub(data)
        if not removed[0]:
            return text
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
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
    def find_strays(scan_lines, skip_lo=None, skip_hi=None):
        out = []
        for i, line in enumerate(scan_lines):
            if skip_lo is not None and skip_lo <= i <= skip_hi:
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
                out.append("line %d: export %s=..." % (i + 1, name))
        return out

    outside = [line for i, line in enumerate(lines)
               if begin is None or end is None or not begin <= i <= end]
    if any(not line.lstrip().startswith("#") and SHELL_SOURCE_RE.search(line.rstrip("\r\n"))
           for line in outside):
        errors.append("bashrc sources ~/.secrets.env as shell outside the managed block; "
                      "run bin/migrate-owner-settings.py first")
        return None
    if begin is None or end is None or end < begin:
        # markers absent: only an error if the file actually holds secrets to
        # protect. A clean bashrc (e.g. a fresh machine / CI runner) has nothing
        # to split — emit it unchanged so capture/roundtrip still work anywhere.
        strays = find_strays(lines)
        if strays:
            errors.append(
                "bashrc has secret/personal exports but no managed markers; "
                "run bin/init-private.sh first:\n    " + "\n    ".join(strays))
            return None
        return "".join(lines)
    sanitized = lines[:begin] + [
        MARK_BEGIN + "\n",
        "# coding-system: private owner settings are data, never executable shell.\n",
        "CSR_OWNER_SETTINGS_STATUS=NOT_CONFIGURED\n",
        "CSR_OWNER_SETTINGS_RC=0\n",
        'if [ -e "$HOME/.secrets.env" ]; then\n',
        "  _csr_owner_status=0\n",
        "  _csr_owner_keys=()\n",
        "  _csr_owner_values=()\n",
        "  if exec {_csr_owner_fd}< <(\n",
        "    /usr/bin/python3 -I -B \\\n",
        '      "$HOME/.local/share/coding-system/repository/bin/lib/owner_settings.py" emit0 \\\n',
        '      --path "$HOME/.secrets.env"\n',
        "  ); then\n",
        "    _csr_owner_pid=$!\n",
        "    while IFS= read -r -d '' -u \"$_csr_owner_fd\" _csr_owner_key; do\n",
        "      if ! IFS= read -r -d '' -u \"$_csr_owner_fd\" _csr_owner_value; then\n",
        "        _csr_owner_status=2\n",
        "        break\n",
        "      fi\n",
        '      case "$_csr_owner_key" in\n',
        "        CLASSROOM50_ORG_ALLOWLIST|TELEGRAM_CHAT_ID|MOLBOOK_AGENT_ID|MOLTBOOK_ALLOWLIST|MOLTBOOK_AUTONOMOUS|MOLTBOOK_COLOR|MOLTBOOK_PROFILE|MOLTBOOK_URL|MOLTBOOK_WORKSPACE|CSR_OWNER_TIMEZONE|CSR_RSS_DIGEST_ONCALENDAR|CSR_RCLONE_DEST|CSR_OWNER_RCLONE_DEST|CSR_ESCROW_GDRIVE|CSR_ESCROW_GH_REPO) ;;\n",
        "        *) _csr_owner_status=2; continue ;;\n",
        "      esac\n",
        '      _csr_owner_keys+=("$_csr_owner_key")\n',
        '      _csr_owner_values+=("$_csr_owner_value")\n',
        "    done\n",
        '    if ! wait "$_csr_owner_pid"; then\n',
        "      _csr_owner_status=2\n",
        "    fi\n",
        "    exec {_csr_owner_fd}<&-\n",
        "  else\n",
        "    _csr_owner_status=2\n",
        "  fi\n",
        "  if (( _csr_owner_status == 0 )); then\n",
        '    for _csr_owner_index in "${!_csr_owner_keys[@]}"; do\n',
        '      printf -v "${_csr_owner_keys[$_csr_owner_index]}" \'%s\' \\\n',
        '        "${_csr_owner_values[$_csr_owner_index]}"\n',
        '      export "${_csr_owner_keys[$_csr_owner_index]}"\n',
        "    done\n",
        "    CSR_OWNER_SETTINGS_STATUS=READY\n",
        "  else\n",
        "    CSR_OWNER_SETTINGS_STATUS=INVALID\n",
        "    CSR_OWNER_SETTINGS_RC=2\n",
        "    printf '%s\\n' 'coding-system: private owner settings are invalid; none were loaded' >&2\n",
        "  fi\n",
        "  unset _csr_owner_fd _csr_owner_index _csr_owner_key _csr_owner_keys\n",
        "  unset _csr_owner_pid _csr_owner_status _csr_owner_value _csr_owner_values\n",
        "fi\n",
        "export CSR_OWNER_SETTINGS_STATUS CSR_OWNER_SETTINGS_RC\n",
        MARK_END + "\n",
    ] + lines[end + 1:]
    # scan OUTSIDE the managed block for secret-shaped or personal exports
    strays = find_strays(lines, begin, end)
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


def validate_manifest(manifest):
    """Structural checks that must pass before any path is read or written."""
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        return ["MANIFEST.yaml needs a mapping with an entries list"]
    errors = []
    for key in ("roots", "global_exclude"):
        values = manifest.get(key) or []
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            errors.append("%s must be a list of strings" % key)
            continue
        if key == "roots":
            errors.extend("unsafe root: %r" % v for v in values
                          if safe_relative_path(v) is None)
    seen = set()
    for index, entry in enumerate(manifest["entries"], 1):
        eid = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(eid, str) or not eid:
            errors.append("manifest entry #%d has no id" % index)
            continue
        if eid in seen:
            errors.append("duplicate manifest entry id: %s" % eid)
        seen.add(eid)
        cls = entry.get("class")
        if cls not in MANIFEST_CLASSES:
            errors.append("%s has an unknown class: %r" % (eid, cls))
        root = entry.get("root", "")
        if root != "" and safe_relative_path(root) is None:
            errors.append("%s has an unsafe root: %r" % (eid, root))
        for field in ("dest", "dest_dir"):
            if field in entry and safe_relative_path(entry[field]) is None:
                errors.append("%s has an unsafe %s: %r" % (eid, field, entry[field]))
        if cls in PUBLIC_CLASSES and bool(entry.get("dest")) == bool(entry.get("dest_dir")):
            errors.append("%s needs exactly one of dest and dest_dir" % eid)
        if not isinstance(entry.get("match"), list) or not entry["match"]:
            errors.append("%s has no match list" % eid)
        for field in ("match", "include", "exclude"):
            values = entry.get(field) or []
            if not isinstance(values, list):
                errors.append("%s: %s must be a list" % (eid, field))
                continue
            for pattern in values:
                if (not isinstance(pattern, str) or not pattern or pattern.startswith("/")
                        or ".." in pattern.split("/")):
                    errors.append("%s has an unsafe %s pattern: %r" % (eid, field, pattern))
    return errors


def safe_relative_path(value):
    """Return a normalized manifest path or ``None`` when it can escape."""
    if not isinstance(value, str) or not value or os.path.isabs(value):
        return None
    normalized = os.path.normpath(value)
    if normalized in ("", ".", "..") or normalized.startswith(".." + os.sep):
        return None
    if any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return normalized


def validate_real_tree(path, label, errors):
    """Require a source/preserved tree made only of real dirs and files."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        errors.append("cannot inspect %s: %s" % (label, exc))
        return
    if stat.S_ISLNK(info.st_mode):
        errors.append("%s must not be a symlink" % label)
        return
    if stat.S_ISREG(info.st_mode):
        return
    if not stat.S_ISDIR(info.st_mode):
        errors.append("%s must be a regular file or directory" % label)
        return
    def record_walk_error(error):
        errors.append("cannot inspect authoritative tree: %s" % error)

    for dp, dns, fns in os.walk(
        path, followlinks=False, onerror=record_walk_error
    ):
        for name in dns + fns:
            child = os.path.join(dp, name)
            try:
                child_info = os.lstat(child)
            except OSError as exc:
                errors.append("cannot inspect %s: %s" % (child, exc))
                continue
            if stat.S_ISLNK(child_info.st_mode):
                errors.append("authoritative source contains a symlink: %s" % child)
            elif not (stat.S_ISDIR(child_info.st_mode) or
                      stat.S_ISREG(child_info.st_mode)):
                errors.append("authoritative source contains a special file: %s" % child)


def preflight_authoritative_entries(entries):
    """Validate exact-mirror entries before any repository output is written."""
    errors = []
    for entry in entries:
        if not entry.get("authoritative"):
            continue
        eid = entry.get("id", "<unknown>")
        if entry.get("class") != "public-copy" or not entry.get("dest_dir") \
                or entry.get("dest"):
            errors.append(
                "authoritative entry %s must be a public-copy dest_dir mapping" % eid)
            continue
        root = safe_relative_path(entry.get("root"))
        dest_dir = safe_relative_path(entry.get("dest_dir"))
        if root is None or dest_dir is None:
            errors.append("authoritative entry %s has an unsafe root or dest_dir" % eid)
            continue
        root_abs = os.path.join(HOME, root)
        if not os.path.lexists(root_abs):
            errors.append("authoritative source root is missing: %s" % root_abs)
            continue
        try:
            root_info = os.lstat(root_abs)
        except OSError as exc:
            errors.append("cannot inspect authoritative source root %s: %s"
                          % (root_abs, exc))
            continue
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            errors.append("authoritative source root must be a real directory: %s"
                          % root_abs)
            continue
        for pattern in entry.get("match", []):
            rel = safe_relative_path(pattern)
            if rel is None or any(ch in pattern for ch in "*?["):
                errors.append(
                    "authoritative entry %s requires literal safe match paths: %r"
                    % (eid, pattern))
                continue
            source = os.path.join(root_abs, rel)
            if not os.path.lexists(source):
                errors.append("authoritative source path is missing: %s" % source)
                continue
            validate_real_tree(source, "authoritative source path %s" % source,
                               errors)
        for preserved in entry.get("preserve_dest", []) or []:
            if safe_relative_path(preserved) is None \
                    or any(ch in preserved for ch in "*?["):
                errors.append(
                    "authoritative entry %s has unsafe preserve_dest path: %r"
                    % (eid, preserved))
    return errors


def preflight_authoritative_classification(entries):
    """Require one effective class for every path under authoritative roots."""
    errors = []
    roots = {
        entry.get("root")
        for entry in entries
        if entry.get("authoritative")
    }
    for root in sorted(value for value in roots if isinstance(value, str)):
        root_abs = os.path.join(HOME, root)
        if not os.path.isdir(root_abs) or os.path.islink(root_abs):
            continue
        root_entries = [entry for entry in entries if entry.get("root") == root]
        def record_classification_walk_error(error):
            errors.append(
                "cannot classify authoritative source tree %s: %s"
                % (root_abs, error)
            )

        for directory, dirnames, filenames in os.walk(
            root_abs,
            followlinks=False,
            onerror=record_classification_walk_error,
        ):
            for name in dirnames + filenames:
                rel = os.path.relpath(
                    os.path.join(directory, name), root_abs
                ).replace(os.sep, "/")
                matches = []
                for entry in root_entries:
                    if not any(
                        match_glob(rel, pattern)
                        for pattern in entry.get("match", [])
                    ):
                        continue
                    if any(
                        match_glob(rel, pattern)
                        for pattern in entry.get("exclude", []) or []
                    ):
                        continue
                    matches.append(entry.get("id", "<unknown>"))
                if len(matches) != 1:
                    disposition = (
                        "unclassified" if not matches else "multiply classified"
                    )
                    errors.append(
                        "authoritative source path is %s: %s/%s"
                        % (disposition, root, rel)
                    )
    return errors


def _stable_regular_bytes(path):
    """Read one path without accepting replacement or mutation during the read."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SyncError("authoritative source is not a regular file: %s" % path)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    linked = os.lstat(path)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        stat.S_IMODE(value.st_mode),
    )
    if (
        not stat.S_ISREG(linked.st_mode)
        or identity(before) != identity(after)
        or identity(after) != identity(linked)
    ):
        raise SyncError("authoritative source changed during capture: %s" % path)
    return b"".join(chunks), bool(stat.S_IMODE(after.st_mode) & 0o111)


def _authoritative_source_records(entry, placeholder, global_exclude=()):
    """Render one fresh, stable source view into comparable file records."""
    root = safe_relative_path(entry.get("root"))
    if root is None:
        raise SyncError("unsafe authoritative source root")
    root_abs = os.path.join(HOME, root)
    candidates = set()
    for pattern in entry.get("match", []):
        rel = safe_relative_path(pattern)
        if rel is None or any(character in pattern for character in "*?["):
            raise SyncError("authoritative source match is not literal: %r" % pattern)
        source = os.path.join(root_abs, rel)
        info = os.lstat(source)
        if stat.S_ISREG(info.st_mode):
            candidates.add(source)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SyncError("authoritative source path is unsafe: %s" % source)
        for directory, dirnames, filenames in os.walk(
            source, followlinks=False, onerror=_raise_sync_walk_error
        ):
            for name in dirnames:
                child = os.path.join(directory, name)
                child_info = os.lstat(child)
                if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISDIR(
                    child_info.st_mode
                ):
                    raise SyncError("authoritative source directory is unsafe: %s" % child)
            for name in filenames:
                candidates.add(os.path.join(directory, name))

    records = {}
    excludes = entry.get("exclude", []) or []
    for path in sorted(candidates):
        rel = os.path.relpath(path, root_abs).replace(os.sep, "/")
        if any(match_glob(rel, pattern) for pattern in excludes) or excluded_globally(
                rel, global_exclude):
            continue
        data, executable = _stable_regular_bytes(path)
        if data.startswith(b"\x7fELF"):
            raise SyncError("ELF binary in authoritative public source: %s" % path)
        if not is_binary(data):
            text = data.decode("utf-8", errors="surrogateescape")
            text = home_substitute(text, placeholder)
            if HOME in text:
                raise SyncError("home path survived authoritative render: %s" % path)
            data = text.encode("utf-8", errors="surrogateescape")
        records[rel] = (hashlib.sha256(data).hexdigest(), len(data), executable)
    return records


def _authoritative_stage_records(stage_root, entry):
    dest_rel = safe_relative_path(entry.get("dest_dir"))
    if dest_rel is None:
        raise SyncError("unsafe authoritative destination")
    root = os.path.join(stage_root, dest_rel)
    records = {}
    for directory, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=_raise_sync_walk_error
    ):
        for name in dirnames:
            child = os.path.join(directory, name)
            info = os.lstat(child)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SyncError("authoritative staging directory is unsafe: %s" % child)
        for name in filenames:
            child = os.path.join(directory, name)
            data, executable = _stable_regular_bytes(child)
            rel = os.path.relpath(child, root).replace(os.sep, "/")
            records[rel] = (hashlib.sha256(data).hexdigest(), len(data), executable)
    return records


def validate_authoritative_snapshot(stage_root, entry, placeholder, global_exclude=()):
    """Require staged bytes to equal two consecutive stable source views."""
    first = _authoritative_source_records(entry, placeholder, global_exclude)
    second = _authoritative_source_records(entry, placeholder, global_exclude)
    if first != second:
        raise SyncError("authoritative source changed during final validation")
    if _authoritative_stage_records(stage_root, entry) != second:
        raise SyncError("authoritative source changed while the snapshot was rendered")


def copy_real_tree(source, destination):
    """Copy without following links; used only for repository-local preserves."""
    info = os.lstat(source)
    if stat.S_ISLNK(info.st_mode):
        raise SyncError("preserved destination path must not be a symlink: %s" % source)
    if stat.S_ISREG(info.st_mode):
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copy2(source, destination)
        return
    if not stat.S_ISDIR(info.st_mode):
        raise SyncError("preserved destination path is not a real tree: %s" % source)
    os.makedirs(destination, exist_ok=True)
    with os.scandir(source) as scan:
        for item in scan:
            copy_real_tree(item.path, os.path.join(destination, item.name))
    # Child creation mutates the containing directory's timestamps, so apply
    # directory metadata only after the complete subtree has been copied.
    shutil.copystat(source, destination)


def real_tree_snapshot(path):
    """Fingerprint a real preserved tree without accepting links or special files."""
    records = {}

    def visit(current, rel):
        info = os.lstat(current)
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            raise SyncError("preserved destination path must not be a symlink: %s" % current)
        if stat.S_ISREG(info.st_mode):
            data, executable = _stable_regular_bytes(current)
            records[rel] = (
                "file",
                hashlib.sha256(data).hexdigest(),
                len(data),
                mode,
                info.st_mtime_ns,
                executable,
            )
            return
        if not stat.S_ISDIR(info.st_mode):
            raise SyncError("preserved destination path is not a real tree: %s" % current)
        records[rel] = ("directory", mode, info.st_mtime_ns)
        with os.scandir(current) as scan:
            for item in sorted(scan, key=lambda value: value.name):
                child_rel = item.name if rel == "." else rel + "/" + item.name
                visit(item.path, child_rel)

    visit(path, ".")
    return records


def publish_authoritative_entry(repo, stage_root, entry):
    """Publish one durable snapshot without ever making the destination absent."""
    dest_rel = safe_relative_path(entry["dest_dir"])
    if dest_rel is None:
        raise SyncError("unsafe authoritative destination")
    staged = os.path.join(stage_root, dest_rel)
    destination = os.path.join(repo, dest_rel)
    if not os.path.isdir(staged) or os.path.islink(staged):
        raise SyncError("authoritative staging tree is missing: %s" % staged)
    parent = os.path.dirname(destination)
    if not os.path.isdir(parent) or os.path.islink(parent):
        raise SyncError("authoritative destination parent is unsafe: %s" % parent)

    destination_existed = os.path.lexists(destination)
    if destination_existed:
        destination_info = os.lstat(destination)
        if stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISDIR(
            destination_info.st_mode
        ):
            raise SyncError(
                "authoritative destination must be a real directory: %s" % destination
            )

    preserved_snapshots = {}
    for preserved in entry.get("preserve_dest", []) or []:
        source = os.path.join(destination, preserved)
        target = os.path.join(staged, preserved)
        if not os.path.lexists(source):
            continue
        if os.path.lexists(target):
            raise SyncError(
                "preserved destination overlaps authoritative output: %s" % preserved)
        before = real_tree_snapshot(source)
        copy_real_tree(source, target)
        after = real_tree_snapshot(source)
        copied = real_tree_snapshot(target)
        if before != after or after != copied:
            raise SyncError(
                "preserved destination changed during capture: %s" % preserved
            )
        preserved_snapshots[preserved] = before

    _fsync_real_tree(staged)
    for preserved, expected in preserved_snapshots.items():
        if (
            real_tree_snapshot(os.path.join(destination, preserved)) != expected
            or real_tree_snapshot(os.path.join(staged, preserved)) != expected
        ):
            raise SyncError(
                "preserved destination changed before publication: %s" % preserved
            )
    staged_parent = os.path.dirname(staged)
    published = False
    try:
        if destination_existed:
            # After this single kernel transaction, `destination` is the new
            # tree and `staged` is the old one. A kill cannot land in an absent
            # gap.
            _rename_exchange(staged, destination)
        else:
            os.replace(staged, destination)
        published = True
        _fsync_directory(parent)
        if os.path.realpath(staged_parent) != os.path.realpath(parent):
            _fsync_directory(staged_parent)
        for preserved, expected in preserved_snapshots.items():
            if (
                real_tree_snapshot(os.path.join(staged, preserved)) != expected
                or real_tree_snapshot(os.path.join(destination, preserved)) != expected
            ):
                raise SyncError(
                    "preserved destination changed during publication: %s" % preserved
                )
    except BaseException as original:
        if published:
            try:
                if destination_existed:
                    _rename_exchange(staged, destination)
                else:
                    os.replace(destination, staged)
                _fsync_directory(parent)
                if os.path.realpath(staged_parent) != os.path.realpath(parent):
                    _fsync_directory(staged_parent)
            except BaseException as rollback:
                raise AuthoritativeRecoveryRequired(
                    "authoritative publication rollback failed; retained %s: %s"
                    % (stage_root, rollback)
                ) from original
        raise

    # The old tree is now only cleanup state.  Removing it after both parent
    # directories are durable cannot affect availability of the new snapshot.
    if os.path.lexists(staged):
        if os.path.isdir(staged) and not os.path.islink(staged):
            shutil.rmtree(staged)
        else:
            os.unlink(staged)
        _fsync_directory(staged_parent)


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
    staging_abs = os.path.join(repo, ".staging")
    out_abs = os.path.abspath(out)
    if not args.apply and os.path.commonpath([repo, out_abs]) == repo and not (
            out_abs == staging_abs or out_abs.startswith(staging_abs + os.sep)):
        # an unscanned dry-run must never write into the repository tree
        print("ERROR: a dry-run --out inside the repository must be under .staging/",
              file=sys.stderr)
        return 2

    try:
        _capture_lock_fd = _acquire_capture_lock(repo)
    except (BlockingIOError, OSError, SyncError) as exc:
        print("ERROR: another capture is active or the capture lock is unsafe: %s" % exc,
              file=sys.stderr)
        return 2
    try:
        _reset_default_dry_run_tree(repo, out, args.apply)
    except (OSError, SyncError) as exc:
        print("ERROR: cannot reset the locked dry-run tree: %s" % exc, file=sys.stderr)
        return 2

    with open(manifest_path, "rb") as fh:
        manifest_raw = fh.read()
    manifest = yaml.safe_load(manifest_raw)
    manifest_errors = validate_manifest(manifest)
    if manifest_errors:
        for error in manifest_errors:
            print("ERROR: %s" % error, file=sys.stderr)
        return 2
    placeholder = manifest.get("home_placeholder", "{{ HOME }}")
    entries = manifest["entries"]
    roots = manifest["roots"]
    global_exclude = manifest.get("global_exclude") or []

    try:
        _authoritative_source_lock_fds = _acquire_authoritative_source_locks(entries)
    except (BlockingIOError, OSError, SyncError) as exc:
        print(
            "ERROR: authoritative source restore/capture interlock refused: %s" % exc,
            file=sys.stderr,
        )
        return 2

    errors, warnings = [], []
    symlinks = []          # (home-rel link, target, disposition)
    claimed = set()        # home-relative paths already handled
    report = {
        "entries": {},
        "orphans": [],
        "private": [],
        "outputs": 0,
        "output_paths": [],
        "output_records": {},
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "applied": False,
    }
    report_path = os.path.join(repo, ".staging", "sync-report.json")
    incomplete = dict(report)
    incomplete["errors"] = ["capture did not reach its publication gate"]
    incomplete["warnings"] = []
    _write_json_atomic(report_path, incomplete)

    # Exact mirrors are a backup authority boundary.  Validate every literal
    # source path before ordinary entries can write into the repository.
    errors.extend(preflight_authoritative_entries(entries))
    errors.extend(preflight_authoritative_classification(entries))
    if errors:
        report["symlinks"] = 0
        report["warnings"] = warnings
        report["errors"] = errors
        _write_json_atomic(report_path, report)
        for error in errors:
            print("ERROR: %s" % error, file=sys.stderr)
        return 2

    # Privacy preconditions.  --apply publishes only with the private denylist
    # and an owner review of every public entry; a dry-run reports both gaps.
    # These errors do not stop the render, so every problem is reported; the
    # publication gates below refuse to publish while any error stands.
    denylist = load_denylist(denylist_path())
    if denylist is None:
        (errors if args.apply else warnings).append(
            "private denylist missing or empty at %s (run make init-private)"
            % denylist_path())
    try:
        unreviewed = unreviewed_items(repo, manifest)
    except SyncError as exc:
        errors.append(str(exc))
        unreviewed = []
    if unreviewed:
        (errors if args.apply else warnings).append(
            "manifest items not owner-reviewed (bin/review-manifest.py): %s"
            % ", ".join(unreviewed))
    for entry in entries:
        if entry.get("class") not in PUBLIC_CLASSES:
            continue
        for pattern in list(entry.get("match") or []) + list(entry.get("include") or []):
            if any(ch in pattern for ch in "*?["):
                continue
            rule = (forbidden_public_reason(pattern)
                    or forbidden_public_reason(pattern, is_dir=True))
            if rule:
                errors.append("forbidden in a public class (%s): %s in entry %s"
                              % (rule, pattern, entry["id"]))

    authoritative_stages = {}
    if args.apply:
        stage_parent = os.path.join(repo, ".staging")
        os.makedirs(stage_parent, exist_ok=True)
        for entry in entries:
            if entry.get("authoritative"):
                authoritative_stages[entry["id"]] = tempfile.mkdtemp(
                    prefix="authoritative-%s-" % entry["id"], dir=stage_parent)
    publish_root = out
    render_root = None
    if args.apply:
        # Ordinary entries render into a private stage too; nothing reaches the
        # repository until that whole tree has passed the leak scan.
        render_root = tempfile.mkdtemp(prefix="apply-", dir=stage_parent)
        atexit.register(shutil.rmtree, render_root, True)
        out = render_root

    # ---------------- orphans: top-level paths no entry matches are never captured
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
        warnings.append(
            "unclassified paths, excluded from capture until MANIFEST.yaml classifies them:\n    "
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
        entry_out = authoritative_stages.get(eid, out)

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
            if any(match_glob(rel_root, g) for g in exc) or (
                    cls in PUBLIC_CLASSES and excluded_globally(rel_root, global_exclude)):
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
                    errors.append(
                        "private-archive path NOT covered by secrets-manifest: %s"
                        % rel_home)
                if "emit-keys" in verbs and f.endswith(".json"):
                    keys_text = emit_keys(f)
                    if keys_text and entry.get("dest_dir"):
                        dest = os.path.join(
                            entry_out, entry["dest_dir"],
                            os.path.basename(f).lstrip(".") + ".keys")
                        if os.path.commonpath([entry_out, os.path.normpath(dest)]) != entry_out:
                            errors.append("output escapes its tree (%s): %s" % (eid, rel_home))
                            continue
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "w") as fh:
                            fh.write(keys_text)
                        # Stage backup accepts only 0600/0644/0700/0755 — force
                        # 0644 so umask 002 cannot leave 0664 producer records.
                        os.chmod(dest, 0o644)
                        report["output_paths"].append(
                            os.path.relpath(dest, entry_out).replace(os.sep, "/")
                        )
                        report["outputs"] += 1
                stats_e["captured"] += 1
                continue

            # ---- public classes
            if is_elf(f):
                errors.append("ELF binary in public class (%s): %s" % (eid, rel_home))
                continue
            rule = forbidden_public_reason(rel_root, f)
            if rule:
                errors.append("forbidden in a public class (%s): %s (%s)"
                              % (rule, rel_home, eid))
                continue
            reason = unscannable_reason(rel_root, os.lstat(f).st_size)
            if reason:
                errors.append("not scannable, so not publishable (%s): %s (%s)"
                              % (reason, rel_home, eid))
                continue
            if entry.get("dest"):
                dest = os.path.join(entry_out, entry["dest"])
            else:
                dest = os.path.join(entry_out, entry["dest_dir"], rel_root)
                if cls == "public-template" and entry.get("dest_dir") and (
                        "key-redact" in verbs):
                    dest += ".template" if not dest.endswith(".template") else ""
            if os.path.commonpath([entry_out, os.path.normpath(dest)]) != entry_out:
                errors.append("output escapes its tree (%s): %s" % (eid, rel_home))
                continue

            with open(f, "rb") as fh:
                raw = fh.read()
            if is_binary(raw):
                # the leak scan reads no binary: only images and fonts may pass,
                # copied as the bytes checked here
                if not rel_root.lower().endswith(BINARY_ASSET_SUFFIXES):
                    errors.append("binary file in a public class (only images and fonts "
                                  "may be): %s (%s)" % (rel_home, eid))
                    continue
                if denylist and any(e.encode("utf-8") in raw for e in denylist):
                    errors.append("private denylist entry in public output (%s): %s:binary"
                                  % (eid, rel_home))
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(raw)
                os.chmod(dest, 0o755 if os.access(f, os.X_OK) else 0o644)
                report["output_paths"].append(
                    os.path.relpath(dest, entry_out).replace(os.sep, "/")
                )
                stats_e["captured"] += 1
                report["outputs"] += 1
                continue
            text = raw.decode("utf-8", errors="surrogateescape")

            if "secret-env-split" in verbs:
                text = split_bashrc(text, errors)
                if text is None:
                    continue
            if "key-redact" in verbs:
                text = key_redact(text, os.path.splitext(f)[1],
                                  entry.get("keys", []))
            if "strip-projects" in verbs:
                text = strip_projects(text, os.path.splitext(f)[1])
                if text is None:
                    errors.append("strip-projects cannot parse a file that names home "
                                  "paths: %s (%s)" % (rel_home, eid))
                    continue
            # implicit home-substitute on ALL public text files
            text = home_substitute(text, placeholder)
            if HOME in text:
                errors.append("home path survived render: %s" % rel_home)
                continue
            if dest.endswith(".template"):
                text = redact_template_identities(text)
            hits = denylist_lines(text, denylist) if denylist else []
            if hits:
                errors.append("private denylist entry in public output (%s): %s:%s"
                              % (eid, rel_home, ",".join(str(n) for n in hits[:20])))
                continue
            if EXEMPT_MARKER in text and not entry.get("authoritative"):
                # the marker would switch the leak scan off for that line; only
                # owner-authored mirrors (authoritative entries) may carry it
                errors.append("scanner exemption marker in captured content (%s): %s"
                              % (eid, rel_home))
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", errors="surrogateescape") as fh:
                fh.write(text)
            os.chmod(dest, 0o755 if os.access(f, os.X_OK) else 0o644)
            report["output_paths"].append(
                os.path.relpath(dest, entry_out).replace(os.sep, "/")
            )
            stats_e["captured"] += 1
            report["outputs"] += 1

    # ---------------- symlink topology comparison
    default_manifest = os.path.abspath(os.path.join(repo, "MANIFEST.yaml"))
    if args.apply and os.path.abspath(manifest_path) == default_manifest:
        # rendered with the other outputs, so the leak scan covers it
        obs_path = os.path.join(render_root, ".staging-symlinks-observed.tsv")
    elif args.apply:
        # A scoped/custom apply must not replace the global topology report
        # with a partial view of the machine.
        obs_path = os.path.join(repo, ".staging", "symlinks-observed.tsv")
    else:
        obs_path = os.path.join(out, "symlinks-observed.tsv")
    os.makedirs(os.path.dirname(obs_path), exist_ok=True)
    with open(obs_path, "w") as fh:
        for link, target, disp in sorted(symlinks):
            fh.write("%s\t%s\t%s\n" % (
                link.replace(HOME, placeholder),
                target.replace(HOME, placeholder), disp))
    os.chmod(obs_path, 0o644)
    if args.apply and os.path.abspath(manifest_path) == default_manifest:
        report["output_paths"].append(".staging-symlinks-observed.tsv")
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

    # The rendered tree is what would be published: scan all of it.  A dry-run
    # reports the verdict that --apply would enforce.  --apply publishes only
    # bytes that match the digests taken before the scan.
    render_digests = None
    if render_root is not None:
        try:
            render_digests = _tree_digests(render_root)
        except (OSError, SyncError) as exc:
            errors.append("cannot record the rendered tree: %s" % exc)
    if not _leak_scan(repo, out, require_denylist=args.apply):
        errors.append("rendered public tree failed the leak scan (FINDING lines above)"
                      + ("; nothing was published" if args.apply else ""))
    if render_digests is not None and not errors:
        try:
            for rel in sorted(render_digests):
                _check_publish_destination(publish_root, rel)
        except (OSError, SyncError) as exc:
            errors.append("capture publication refused: %s" % exc)

    # No authoritative destination is touched until every render and safety
    # check has succeeded.  Each destination is then swapped as one tree; on a
    # publication error the previous tree is restored before returning.
    retain_stages = set()
    if not errors:
        for entry in entries:
            stage_root = authoritative_stages.get(entry.get("id"))
            if stage_root is None:
                continue
            try:
                validate_authoritative_snapshot(stage_root, entry, placeholder, global_exclude)
                _scan_authoritative_stage(repo, stage_root, entry)
                publish_authoritative_entry(repo, stage_root, entry)
            except AuthoritativeRecoveryRequired as exc:
                retain_stages.add(stage_root)
                errors.append(
                    "authoritative publish requires recovery for %s: %s"
                    % (entry.get("id", "<unknown>"), exc)
                )
            except (OSError, SyncError) as exc:
                errors.append(
                    "authoritative publish failed for %s: %s"
                    % (entry.get("id", "<unknown>"), exc))

    for stage_root in authoritative_stages.values():
        if stage_root in retain_stages:
            continue
        if os.path.isdir(stage_root):
            shutil.rmtree(stage_root)

    if render_root is not None:
        if not errors and render_digests is not None:
            try:
                _publish_rendered_tree(render_root, publish_root, render_digests)
            except (OSError, SyncError) as exc:
                errors.append("capture publication failed: %s" % exc)
        shutil.rmtree(render_root, ignore_errors=True)

    # ---------------- report
    report["output_paths"] = sorted(set(report["output_paths"]))
    report["outputs"] = len(report["output_paths"])
    if args.apply and not errors:
        try:
            report["output_records"] = {
                path: _output_record(os.path.join(repo, path))
                for path in report["output_paths"]
            }
            report["applied"] = True
        except (OSError, SyncError) as exc:
            errors.append("captured output changed before report publication: %s" % exc)
    report["symlinks"] = len(symlinks)
    report["warnings"] = warnings
    report["errors"] = errors
    _write_json_atomic(report_path, report)

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
