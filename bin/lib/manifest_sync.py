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
SECRET_NAME_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API|CHAT_ID)", re.I
)
PERSONAL_PREFIX_RE = re.compile(r"^(MOLTBOOK|MOLBOOK)_")
EXPORT_RE = re.compile(r'^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$')


class SyncError(Exception):
    pass


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
    for directory, dirnames, filenames in os.walk(path, topdown=False):
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


def _scan_authoritative_stage(repo, stage_root, entry):
    """Run the repository's artifact scanner before public-tree publication."""
    scanner = os.path.join(repo, "bin", "leak-scan.sh")
    if not os.path.isfile(scanner):
        return
    dest_rel = safe_relative_path(entry.get("dest_dir"))
    if dest_rel is None:
        raise SyncError("unsafe authoritative destination")
    result = subprocess.run(
        ["/bin/bash", scanner, os.path.join(stage_root, dest_rel)],
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise SyncError("authoritative staged output failed the leak scan")


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


def strip_projects(text, ext):
    """Drop per-machine project/location trust records that would otherwise leak
    local directory names. TOML: every [projects."..."] table. JSON: dict keys
    that are absolute home paths (the editor/agent "locations" trust ledger).
    Other formats, and files without such records, pass through unchanged so the
    verb is a safe no-op on the rest of a multi-file entry."""
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
            data = json.loads(text)
        except ValueError:
            return text
        removed = [False]

        def scrub(node):
            if isinstance(node, dict):
                for k in [k for k in node
                          if isinstance(k, str) and k.startswith(HOME)]:
                    del node[k]
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
        "# coding-system: personal/secret exports live in ~/.secrets.env "
        "(restored from the encrypted archive)\n",
        '[ -f ~/.secrets.env ] && . ~/.secrets.env\n',
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
    for dp, dns, fns in os.walk(path, followlinks=False):
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


def _authoritative_source_records(entry, placeholder):
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
        for directory, dirnames, filenames in os.walk(source, followlinks=False):
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
        if any(match_glob(rel, pattern) for pattern in excludes):
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
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
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


def validate_authoritative_snapshot(stage_root, entry, placeholder):
    """Require staged bytes to equal two consecutive stable source views."""
    first = _authoritative_source_records(entry, placeholder)
    second = _authoritative_source_records(entry, placeholder)
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
    placeholder = manifest.get("home_placeholder", "{{ HOME }}")
    entries = manifest["entries"]
    roots = manifest["roots"]

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
    if errors:
        report["symlinks"] = 0
        report["warnings"] = warnings
        report["errors"] = errors
        _write_json_atomic(report_path, report)
        for error in errors:
            print("ERROR: %s" % error, file=sys.stderr)
        return 2

    authoritative_stages = {}
    if args.apply:
        stage_parent = os.path.join(repo, ".staging")
        os.makedirs(stage_parent, exist_ok=True)
        for entry in entries:
            if entry.get("authoritative"):
                authoritative_stages[entry["id"]] = tempfile.mkdtemp(
                    prefix="authoritative-%s-" % entry["id"], dir=stage_parent)

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
                    errors.append(
                        "private-archive path NOT covered by secrets-manifest: %s"
                        % rel_home)
                if "emit-keys" in verbs and f.endswith(".json"):
                    keys_text = emit_keys(f)
                    if keys_text and entry.get("dest_dir"):
                        dest = os.path.join(
                            entry_out, entry["dest_dir"],
                            os.path.basename(f).lstrip(".") + ".keys")
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "w") as fh:
                            fh.write(keys_text)
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
            if entry.get("dest"):
                dest = os.path.join(entry_out, entry["dest"])
            else:
                dest = os.path.join(entry_out, entry["dest_dir"], rel_root)
                if cls == "public-template" and entry.get("dest_dir") and (
                        "key-redact" in verbs):
                    dest += ".template" if not dest.endswith(".template") else ""

            text = read_text(f)
            if text is None:
                # binary asset (image, db...) — copy raw, no substitution
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(f, dest)
                os.chmod(dest, 0o755 if os.access(f, os.X_OK) else 0o644)
                report["output_paths"].append(
                    os.path.relpath(dest, entry_out).replace(os.sep, "/")
                )
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
            if "strip-projects" in verbs:
                text = strip_projects(text, os.path.splitext(f)[1])
            # implicit home-substitute on ALL public text files
            text = home_substitute(text, placeholder)
            if HOME in text:
                errors.append("home path survived render: %s" % rel_home)
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
        obs_path = os.path.join(repo, ".staging-symlinks-observed.tsv")
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
                validate_authoritative_snapshot(stage_root, entry, placeholder)
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
