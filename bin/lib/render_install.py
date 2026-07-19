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
import ctypes
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

import yaml

# only {{ HOME }} is render-install's own placeholder; key-redact placeholders
# live exclusively in *.template files, and captured content (e.g. get-shit-done
# workflow templates) legitimately uses {{ VAR }} moustache syntax of its own
PLACEHOLDER_RE = re.compile(r"\{\{ *HOME *\}\}")
RELEASE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
GROK_PROXY_ENTRY_ID = "grokproxy-scripts"
GROK_RELEASE_SCHEMA_VERSION = 2
GROK_RELEASE_OUTPUT_LIMIT = 1024 * 1024
GROK_BOOTSTRAP_DIRECTORY = "/usr/local/libexec/grok-proxy/bootstrap"
GROK_BOOTSTRAP_BINARY = "grok-bootstrap"
GROK_BOOTSTRAP_SELECTOR = "selected-release"
GROK_BOOTSTRAP_UPDATE_LOCK = "update.lock"
GROK_BOOTSTRAP_RELEASE_ROOT = "/usr/local/libexec/grok-proxy/bootstrap-releases"


class GrokReleaseInstallError(RuntimeError):
    """The atomic grok-proxy release could not be installed or verified."""


class GrokSourceRestoreError(RuntimeError):
    """The editable Grok source cannot be restored without overwriting work."""


def _raise_grok_walk_error(error):
    raise GrokSourceRestoreError(
        f"cannot inspect Grok source tree: {error.filename}: {error.strerror}"
    ) from error


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


def install_file(src, dst, home, report, skip_if_exists=False,
                 overwrite_existing=False):
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
            if overwrite_existing:
                with open(dst, "wb") as fh:
                    fh.write(data)
                os.chmod(dst, stat.S_IMODE(mode))
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
            if overwrite_existing:
                with open(dst, "w", errors="surrogateescape") as fh:
                    fh.write(rendered)
                if not src.endswith(".template") and PLACEHOLDER_RE.search(rendered):
                    report["placeholders"].append(dst)
                if os.access(src, os.X_OK):
                    os.chmod(dst, os.stat(dst).st_mode | stat.S_IXUSR
                             | stat.S_IXGRP | stat.S_IXOTH)
                report["installed"] += 1
                return
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


def entry_excludes_path(entry, rel):
    """Return whether a canonical destination path is explicitly generated."""
    rel = rel.replace(os.sep, "/")
    for pattern in entry.get("exclude", []) or []:
        if fnmatch.fnmatch(rel, pattern):
            return True
        # Python's fnmatch requires a slash for a leading ``**/``.  Manifest
        # semantics also let that prefix match at the destination root.
        if pattern.startswith("**/") and fnmatch.fnmatch(rel, pattern[3:]):
            return True
        if pattern.endswith("/**"):
            base = pattern[:-3]
            if fnmatch.fnmatch(rel, base) or (
                pattern.startswith("**/") and fnmatch.fnmatch(rel, base[3:])
            ):
                return True
    return False


def _safe_relative(value):
    if not isinstance(value, str) or not value or os.path.isabs(value):
        return None
    normalized = os.path.normpath(value)
    if normalized in ("", ".", "..") or normalized.startswith(".." + os.sep):
        return None
    if any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return normalized


def _entry_matches_path(entry, rel):
    rel = rel.replace(os.sep, "/")
    for pattern in entry.get("match", []) or []:
        if rel == pattern or rel.startswith(pattern.rstrip("/") + "/"):
            return True
        if fnmatch.fnmatch(rel, pattern):
            return True
    return False


def validate_grok_source_classification(home, entries):
    """Require every existing Grok source path to have one closed class.

    Public entries may carry ``exclude`` patterns so generated descendants do
    not overlap their emitting closure.  Non-emitting private/generated/iOS
    entries remain in the manifest as explicit classification boundaries.
    """
    grouped = {}
    for entry in entries:
        root = _safe_relative(entry.get("root"))
        if root is None:
            raise GrokSourceRestoreError("Grok classification root is unsafe")
        grouped.setdefault(root, []).append(entry)

    for root, root_entries in grouped.items():
        source_root = os.path.join(home, root)
        if not os.path.lexists(source_root):
            continue
        info = os.lstat(source_root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise GrokSourceRestoreError(
                f"Grok classified root is not a real directory: {root}"
            )
        for directory, dirnames, filenames in os.walk(
            source_root, followlinks=False, onerror=_raise_grok_walk_error
        ):
            for name in dirnames + filenames:
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, source_root).replace(os.sep, "/")
                matches = [
                    entry.get("id", "<unknown>")
                    for entry in root_entries
                    if _entry_matches_path(entry, rel)
                    and not entry_excludes_path(entry, rel)
                ]
                if len(matches) != 1:
                    disposition = "unclassified" if not matches else "multiply classified"
                    raise GrokSourceRestoreError(
                        f"Grok source path is {disposition}: {root}/{rel}"
                    )


def _rendered_source_bytes(path, home):
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        return data
    text = data.decode("utf-8", errors="surrogateescape")
    return text.replace("{{ HOME }}", home).encode(
        "utf-8", errors="surrogateescape"
    )


def _grok_expected_tree(repo, home, entry):
    """Return exact allowlisted file/dir records from the public snapshot."""
    dest_dir = _safe_relative(entry.get("dest_dir"))
    if dest_dir is None:
        raise GrokSourceRestoreError("Grok manifest destination is unsafe")
    source_root = os.path.join(repo, dest_dir)
    try:
        source_info = os.lstat(source_root)
    except OSError as exc:
        raise GrokSourceRestoreError(
            f"Grok public backup is unavailable: {exc}"
        ) from exc
    if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISDIR(source_info.st_mode):
        raise GrokSourceRestoreError("Grok public backup is not a real directory")

    files = {}
    directories = set()
    for match in entry.get("match", []) or []:
        rel = _safe_relative(match)
        if rel is None or any(character in match for character in "*?["):
            raise GrokSourceRestoreError(
                f"Grok source restore requires literal manifest matches: {match!r}"
            )
        if not os.path.lexists(os.path.join(source_root, rel)):
            raise GrokSourceRestoreError(
                f"Grok public backup is missing allowlisted path: {rel}"
            )

    for dp, dns, fns in os.walk(
        source_root, followlinks=False, onerror=_raise_grok_walk_error
    ):
        rel_dir = os.path.relpath(dp, source_root)
        rel_dir = "" if rel_dir == "." else rel_dir
        kept_dirs = []
        for name in dns:
            path = os.path.join(dp, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if not _entry_matches_path(entry, rel) or entry_excludes_path(entry, rel):
                continue
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise GrokSourceRestoreError(
                    f"Grok public backup contains an unsafe directory: {rel}"
                )
            directories.add(rel)
            kept_dirs.append(name)
        dns[:] = kept_dirs
        for name in fns:
            path = os.path.join(dp, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if not _entry_matches_path(entry, rel) or entry_excludes_path(entry, rel):
                continue
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise GrokSourceRestoreError(
                    f"Grok public backup contains an unsafe file: {rel}"
                )
            files[rel] = (
                _rendered_source_bytes(path, home),
                bool(stat.S_IMODE(info.st_mode) & 0o111),
            )
    if not files:
        raise GrokSourceRestoreError("Grok public backup has no allowlisted files")
    return source_root, files, directories


def _grok_actual_tree(target_root, entry):
    """Inspect only managed public paths, ignoring private/generated siblings."""
    files = {}
    directories = set()
    unsafe = []
    if not os.path.lexists(target_root):
        return files, directories, unsafe
    root_info = os.lstat(target_root)
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        return files, directories, ["authoring root is not a real directory"]
    for dp, dns, fns in os.walk(
        target_root, followlinks=False, onerror=_raise_grok_walk_error
    ):
        rel_dir = os.path.relpath(dp, target_root)
        rel_dir = "" if rel_dir == "." else rel_dir
        kept_dirs = []
        for name in dns:
            path = os.path.join(dp, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if not _entry_matches_path(entry, rel) or entry_excludes_path(entry, rel):
                continue
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                unsafe.append(f"unsafe managed directory: {rel}")
                continue
            directories.add(rel)
            kept_dirs.append(name)
        dns[:] = kept_dirs
        for name in fns:
            path = os.path.join(dp, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if not _entry_matches_path(entry, rel) or entry_excludes_path(entry, rel):
                continue
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                unsafe.append(f"unsafe managed file: {rel}")
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            files[rel] = (data, bool(stat.S_IMODE(info.st_mode) & 0o111))
    return files, directories, unsafe


def _restore_identity(files, directories, matches):
    record = {
        "schema_version": 1,
        "files": [
            {
                "path": rel,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "executable": executable,
            }
            for rel, (data, executable) in sorted(files.items())
        ],
        "directories": sorted(directories),
        "matches": sorted(matches),
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _restore_marker_payload(identity):
    return (
        json.dumps(
            {"schema_version": 1, "restore_sha256": identity},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _read_restore_marker(root_fd, identity):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(".grok-source-restore.json", flags, dir_fd=root_fd)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise GrokSourceRestoreError("Grok source restore marker is unsafe")
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096 or raw != _restore_marker_payload(identity):
            raise GrokSourceRestoreError(
                "Grok source restore marker belongs to a different snapshot"
            )
    finally:
        os.close(descriptor)


def _rename_noreplace(source_fd, source, destination_fd, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise GrokSourceRestoreError("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(
        source_fd,
        os.fsencode(source),
        destination_fd,
        os.fsencode(destination),
        1,
    ):
        error = ctypes.get_errno()
        raise GrokSourceRestoreError(
            f"managed destination appeared during restore: {destination}: "
            f"{os.strerror(error)}"
        )


def _restore_dir_flags():
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_restore_directory(parent_fd, name):
    descriptor = os.open(name, _restore_dir_flags(), dir_fd=parent_fd)
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        os.close(descriptor)
        raise GrokSourceRestoreError(f"restore path is not a directory: {name}")
    return descriptor


def _read_restore_regular(parent_fd, name, expected_info):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino)
            != (expected_info.st_dev, expected_info.st_ino)
        ):
            raise GrokSourceRestoreError(
                f"managed destination changed during restore: {name}"
            )
        chunks = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), bool(stat.S_IMODE(info.st_mode) & 0o111)
    finally:
        os.close(descriptor)


def _merge_restore_tree(
    source_parent_fd,
    source_name,
    destination_parent_fd,
    destination_name,
    destination_rel,
    expected_files,
):
    """Publish through held directory FDs without replacing existing siblings."""
    source_info = os.lstat(source_name, dir_fd=source_parent_fd)
    try:
        destination_info = os.lstat(destination_name, dir_fd=destination_parent_fd)
    except FileNotFoundError:
        _rename_noreplace(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
        )
        os.fsync(source_parent_fd)
        if destination_parent_fd != source_parent_fd:
            os.fsync(destination_parent_fd)
        return sum(
            1
            for rel in expected_files
            if rel == destination_rel
            or rel.startswith(destination_rel.rstrip("/") + "/")
        )

    if stat.S_ISDIR(source_info.st_mode):
        if stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISDIR(
            destination_info.st_mode
        ):
            raise GrokSourceRestoreError(
                f"managed destination appeared during restore: {destination_rel}"
            )
        source_fd = _open_restore_directory(source_parent_fd, source_name)
        destination_fd = _open_restore_directory(
            destination_parent_fd, destination_name
        )
        try:
            published = 0
            for name in sorted(os.listdir(source_fd)):
                published += _merge_restore_tree(
                    source_fd,
                    name,
                    destination_fd,
                    name,
                    f"{destination_rel}/{name}",
                    expected_files,
                )
            os.fsync(destination_fd)
            os.fsync(source_fd)
        finally:
            os.close(destination_fd)
            os.close(source_fd)
        os.rmdir(source_name, dir_fd=source_parent_fd)
        os.fsync(source_parent_fd)
        return published

    if not stat.S_ISREG(source_info.st_mode) or not stat.S_ISREG(
        destination_info.st_mode
    ):
        raise GrokSourceRestoreError(
            f"managed destination appeared during restore: {destination_rel}"
        )
    expected = expected_files.get(destination_rel)
    current = _read_restore_regular(
        destination_parent_fd, destination_name, destination_info
    )
    if expected is None or current != expected:
        raise GrokSourceRestoreError(
            f"managed destination changed during restore: {destination_rel}"
        )
    os.unlink(source_name, dir_fd=source_parent_fd)
    os.fsync(source_parent_fd)
    return 0


def _write_restore_marker(root_fd, identity):
    """Publish a complete durable marker or leave no final marker at all."""
    payload = _restore_marker_payload(identity)
    temporary = ".grok-source-restore-marker-" + secrets.token_hex(12)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GrokSourceRestoreError("short write while creating restore marker")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.fsync(root_fd)
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    try:
        os.link(
            temporary,
            ".grok-source-restore.json",
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
            follow_symlinks=False,
        )
        linked = True
    except FileExistsError:
        _read_restore_marker(root_fd, identity)
        linked = False
    finally:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.fsync(root_fd)
    return linked


def _fsync_restore_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _populate_grok_source(target_root, files, directories, entry):
    """Resume-safe, no-replace publication of complete literal match roots."""
    root_created = False
    if not os.path.lexists(target_root):
        try:
            os.mkdir(target_root, 0o755)
            root_created = True
        except FileExistsError:
            pass
    try:
        root_info = os.lstat(target_root)
    except OSError as exc:
        raise GrokSourceRestoreError(f"cannot inspect Grok authoring root: {exc}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise GrokSourceRestoreError("Grok authoring root is not a real directory")
    if root_created:
        _fsync_restore_directory(os.path.dirname(target_root))
    root_fd = os.open(target_root, _restore_dir_flags())
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(
        ".grok-source-restore.lock", lock_flags, 0o600, dir_fd=root_fd
    )
    try:
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.geteuid()
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise GrokSourceRestoreError("Grok source restore lock is unsafe")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GrokSourceRestoreError(
                "another Grok source restore or capture is active"
            ) from exc
    except BaseException:
        os.close(lock_fd)
        os.close(root_fd)
        raise
    stage_name = ".grok-source-restore-" + secrets.token_hex(12)
    matches = []
    for value in entry.get("match", []) or []:
        rel = _safe_relative(value)
        if rel is None or any(character in value for character in "*?["):
            os.close(lock_fd)
            os.close(root_fd)
            raise GrokSourceRestoreError("Grok restore match is not a safe literal")
        if os.sep in rel:
            os.close(lock_fd)
            os.close(root_fd)
            raise GrokSourceRestoreError(
                "Grok restore match roots must be top-level literals"
            )
        matches.append(rel)
    identity = _restore_identity(files, directories, matches)
    marker_created = False
    try:
        try:
            _read_restore_marker(root_fd, identity)
        except FileNotFoundError:
            marker_created = _write_restore_marker(root_fd, identity)

        os.mkdir(stage_name, 0o700, dir_fd=root_fd)
        stage = f"/proc/self/fd/{root_fd}/{stage_name}"
        for rel in sorted(directories, key=lambda item: (item.count(os.sep), item)):
            os.makedirs(os.path.join(stage, rel), mode=0o755, exist_ok=True)
        for rel, (data, executable) in sorted(files.items()):
            destination = os.path.join(stage, rel)
            os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o755 if executable else 0o644,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise GrokSourceRestoreError(
                            f"short write while staging Grok source: {rel}"
                        )
                    view = view[written:]
                os.fchmod(descriptor, 0o755 if executable else 0o644)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for directory, _dirnames, _filenames in os.walk(
            stage, topdown=False, onerror=_raise_grok_walk_error
        ):
            _fsync_restore_directory(directory)

        anchored_root = f"/proc/self/fd/{root_fd}/."
        actual_files, actual_dirs, unsafe = _grok_actual_tree(anchored_root, entry)
        if unsafe or not set(actual_files).issubset(files) or not actual_dirs.issubset(
            directories
        ):
            raise GrokSourceRestoreError(
                "managed source changed while a restore transaction was active"
            )
        for rel, value in actual_files.items():
            if value != files[rel]:
                raise GrokSourceRestoreError(
                    f"managed source changed while restoring: {rel}"
                )

        published = 0
        for rel in matches:
            source_stage_fd = _open_restore_directory(root_fd, stage_name)
            try:
                published += _merge_restore_tree(
                    source_stage_fd,
                    rel,
                    root_fd,
                    rel,
                    rel,
                    files,
                )
            finally:
                os.close(source_stage_fd)
            os.fsync(root_fd)

        final_files, final_dirs, final_unsafe = _grok_actual_tree(anchored_root, entry)
        if final_unsafe or final_files != files or final_dirs != directories:
            raise GrokSourceRestoreError(
                "Grok source restore did not converge; its marker was retained for resume"
            )
        os.rmdir(stage_name, dir_fd=root_fd)
        os.fsync(root_fd)
        for name in os.listdir(anchored_root):
            if not name.startswith(".grok-source-restore-"):
                continue
            stale = os.path.join(anchored_root, name)
            info = os.lstat(stale)
            if (
                not stat.S_ISLNK(info.st_mode)
                and stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700
            ):
                shutil.rmtree(stale)
        os.unlink(".grok-source-restore.json", dir_fd=root_fd)
        os.fsync(root_fd)
        return published
    except BaseException:
        # Published match roots are deliberately retained.  They were installed
        # with NOREPLACE and the authenticated marker makes the next run resume
        # rather than treating a hard-crash prefix as user-authored drift.
        if marker_created:
            os.fsync(root_fd)
        raise
    finally:
        os.close(lock_fd)
        os.close(root_fd)


def reconcile_grok_authoring_source(repo, home, entry):
    """Create an absent authoring surface, no-op on equality, refuse drift."""
    _source_root, expected_files, expected_dirs = _grok_expected_tree(
        repo, home, entry
    )
    root = _safe_relative(entry.get("root"))
    if root is None:
        raise GrokSourceRestoreError("Grok authoring root is unsafe")
    target_root = os.path.join(home, root)
    actual_files, actual_dirs, unsafe = _grok_actual_tree(target_root, entry)
    expected_file_set = set(expected_files)
    actual_file_set = set(actual_files)
    unexpected_dirs = actual_dirs - expected_dirs
    marker = os.path.join(target_root, ".grok-source-restore.json")
    restore_in_progress = os.path.lexists(marker)
    managed_surface_present = bool(actual_files or unexpected_dirs or unsafe)

    if not managed_surface_present:
        return _populate_grok_source(
            target_root, expected_files, expected_dirs, entry
        )

    differences = list(unsafe)
    if actual_file_set != expected_file_set:
        missing = sorted(expected_file_set - actual_file_set)
        extra = sorted(actual_file_set - expected_file_set)
        if missing:
            differences.append("missing: " + ", ".join(missing[:5]))
        if extra:
            differences.append("extra: " + ", ".join(extra[:5]))
    if actual_dirs != expected_dirs:
        missing = sorted(expected_dirs - actual_dirs)
        extra = sorted(actual_dirs - expected_dirs)
        if missing:
            differences.append("missing directories: " + ", ".join(missing[:5]))
        if extra:
            differences.append("extra directories: " + ", ".join(extra[:5]))
    for rel in sorted(actual_file_set & expected_file_set):
        if actual_files[rel] != expected_files[rel]:
            differences.append(f"content or executable mode differs: {rel}")
            if len(differences) >= 10:
                break
    if not differences and restore_in_progress:
        return _populate_grok_source(
            target_root, expected_files, expected_dirs, entry
        )
    if differences and restore_in_progress:
        subset_safe = (
            not unsafe
            and actual_file_set.issubset(expected_file_set)
            and actual_dirs.issubset(expected_dirs)
            and all(
                actual_files[rel] == expected_files[rel]
                for rel in actual_file_set & expected_file_set
            )
        )
        if subset_safe:
            return _populate_grok_source(
                target_root, expected_files, expected_dirs, entry
            )
    if differences:
        raise GrokSourceRestoreError(
            "Grok authoring source differs from the public backup; "
            "preserved it without changes (" + "; ".join(differences) + ")"
        )
    return 0


def _capture_metadata(stream):
    """Return exact size/hash metadata without loading child output into memory."""
    stream.flush()
    size = os.fstat(stream.fileno()).st_size
    stream.seek(0)
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    stream.seek(0)
    return size, digest.hexdigest()


def _capture_diagnostic(stdout_stream, stderr_stream):
    stdout_size, stdout_sha256 = _capture_metadata(stdout_stream)
    stderr_size, stderr_sha256 = _capture_metadata(stderr_stream)
    return (
        f"stdout_bytes={stdout_size} stdout_sha256={stdout_sha256} "
        f"stderr_bytes={stderr_size} stderr_sha256={stderr_sha256}"
    )


def _trusted_snapshot(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_trusted_absolute_directory(path):
    """Open a fixed root-owned directory without following mutable ancestry."""
    if not os.path.isabs(path):
        raise GrokReleaseInstallError("bootstrap directory is not absolute")
    parts = tuple(part for part in path.split(os.sep) if part)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for part in (None, *parts):
            if part is not None:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_gid != 0
                or info.st_mode & 0o022
            ):
                raise GrokReleaseInstallError(
                    "bootstrap directory ancestry is not trusted"
                )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_trusted_selector(directory_fd, *, trusted_uid=0, trusted_gid=0):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        named = os.stat(
            GROK_BOOTSTRAP_SELECTOR,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        descriptor = os.open(
            GROK_BOOTSTRAP_SELECTOR,
            flags,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise GrokReleaseInstallError("trusted bootstrap selector is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != trusted_uid
            or opened.st_gid != trusted_gid
            or stat.S_IMODE(opened.st_mode) != 0o444
            or opened.st_nlink != 1
            or opened.st_size != 65
            or _trusted_snapshot(named) != _trusted_snapshot(opened)
        ):
            raise GrokReleaseInstallError("trusted bootstrap selector is unsafe")
        raw = b""
        while len(raw) <= 65:
            chunk = os.read(descriptor, 66 - len(raw))
            if not chunk:
                break
            raw += chunk
        current = os.stat(
            GROK_BOOTSTRAP_SELECTOR,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if _trusted_snapshot(opened) != _trusted_snapshot(current):
            raise GrokReleaseInstallError("trusted bootstrap selector changed")
    finally:
        os.close(descriptor)
    if re.fullmatch(rb"[0-9a-f]{64}\n", raw) is None:
        raise GrokReleaseInstallError("trusted bootstrap selector is invalid")
    return raw[:-1].decode("ascii")


def _verify_trusted_bootstrap_lock(directory_fd, *, trusted_uid=0, trusted_gid=0):
    try:
        information = os.stat(
            GROK_BOOTSTRAP_UPDATE_LOCK,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise GrokReleaseInstallError(
            "trusted bootstrap update lock is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != trusted_uid
        or information.st_gid != trusted_gid
        or stat.S_IMODE(information.st_mode) != 0o600
        or information.st_nlink != 1
        or information.st_size != 0
    ):
        raise GrokReleaseInstallError("trusted bootstrap update lock is unsafe")


def _verify_trusted_bootstrap_binary(directory_fd, *, trusted_uid=0, trusted_gid=0):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        named = os.stat(
            GROK_BOOTSTRAP_BINARY,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        descriptor = os.open(GROK_BOOTSTRAP_BINARY, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise GrokReleaseInstallError("trusted bootstrap executable is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.stat(
            GROK_BOOTSTRAP_BINARY,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != trusted_uid
            or opened.st_gid != trusted_gid
            or stat.S_IMODE(opened.st_mode) != 0o555
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or _trusted_snapshot(named) != _trusted_snapshot(opened)
            or _trusted_snapshot(opened) != _trusted_snapshot(current)
        ):
            raise GrokReleaseInstallError("trusted bootstrap executable is unsafe")
    finally:
        os.close(descriptor)


def _trusted_bootstrap_prefix():
    directory_fd = _open_trusted_absolute_directory(GROK_BOOTSTRAP_DIRECTORY)
    try:
        _verify_trusted_bootstrap_lock(directory_fd)
        release_id = _read_trusted_selector(directory_fd)
        _verify_trusted_bootstrap_binary(directory_fd)
    finally:
        os.close(directory_fd)
    executable = os.path.join(GROK_BOOTSTRAP_DIRECTORY, GROK_BOOTSTRAP_BINARY)
    release_dir = os.path.join(GROK_BOOTSTRAP_RELEASE_ROOT, release_id)
    return [
        "/usr/bin/sudo",
        "-n",
        "--",
        executable,
        "--release-dir",
        release_dir,
        "--",
    ]


def _run_release_command(command, label):
    with tempfile.TemporaryFile(mode="w+b") as stdout_stream, tempfile.TemporaryFile(
        mode="w+b"
    ) as stderr_stream:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_stream,
                stderr=stderr_stream,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            diagnostic = _capture_diagnostic(stdout_stream, stderr_stream)
            raise GrokReleaseInstallError(
                f"{label} timed out after 120 seconds; {diagnostic}"
            ) from exc
        except OSError as exc:
            errno = "unknown" if exc.errno is None else str(exc.errno)
            raise GrokReleaseInstallError(
                f"{label} could not run: {type(exc).__name__} errno={errno}"
            ) from exc
        if result.returncode != 0:
            diagnostic = _capture_diagnostic(stdout_stream, stderr_stream)
            raise GrokReleaseInstallError(
                f"{label} failed with exit {result.returncode}; {diagnostic}"
            )
        stdout_size = os.fstat(stdout_stream.fileno()).st_size
        if stdout_size > GROK_RELEASE_OUTPUT_LIMIT:
            diagnostic = _capture_diagnostic(stdout_stream, stderr_stream)
            raise GrokReleaseInstallError(
                f"{label} returned oversized JSON; {diagnostic}"
            )
        stdout_stream.seek(0)
        stdout = stdout_stream.read(GROK_RELEASE_OUTPUT_LIMIT + 1)
        try:
            record = json.loads(stdout)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            diagnostic = _capture_diagnostic(stdout_stream, stderr_stream)
            raise GrokReleaseInstallError(
                f"{label} returned invalid JSON; {diagnostic}"
            ) from exc
    if not isinstance(record, dict):
        raise GrokReleaseInstallError(f"{label} returned a non-object record")
    if record.get("schema_version") != GROK_RELEASE_SCHEMA_VERSION:
        raise GrokReleaseInstallError(f"{label} returned an unsupported schema")
    return record


def install_grok_proxy_release(repo, home):
    """Install and independently validate one coherent user/root release pair."""
    source = os.path.join(home, "grok-proxy")
    del repo
    if not os.path.isfile(os.path.join(source, "install-release.py")):
        raise GrokReleaseInstallError(
            f"missing canonical Grok authoring source: {source}"
        )
    prefix = _trusted_bootstrap_prefix()
    installed = _run_release_command(
        [*prefix, "install", "--apply"],
        "grok-proxy release install",
    )
    release_id = installed.get("release_id")
    if (
        installed.get("applied") is not True
        or installed.get("operation") != "install"
        or not isinstance(installed.get("changed"), bool)
        or not isinstance(release_id, str)
        or not RELEASE_ID_RE.fullmatch(release_id)
    ):
        raise GrokReleaseInstallError("grok-proxy release install returned an invalid result")

    installed_dispatcher = os.path.join(
        "/usr/local/libexec/grok-proxy/releases",
        release_id,
        "install-release.py",
    )
    status_prefix = [
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/bin/python3",
        "-I",
        "-B",
        installed_dispatcher,
    ]
    status = _run_release_command(
        [*status_prefix, "status"],
        "grok-proxy release status",
    )
    if (
        status.get("active_release_valid") is not True
        or status.get("rollback_denied") is not False
        or status.get("active_release_id") != release_id
        or status.get("active_user_release_id") != release_id
        or status.get("active_root_release_id") != release_id
        or status.get("release_access_policy_valid") is not True
        or status.get("rollback_eligibility_complete") is not True
        or not isinstance(status.get("rollback_eligible_releases"), list)
        or release_id not in status["rollback_eligible_releases"]
        or status.get("exposed_user_releases") != [release_id]
    ):
        raise GrokReleaseInstallError(
            "grok-proxy release status is not one coherent admitted release"
        )
    return release_id, installed["changed"]


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

    # Grok's public tree is an authoring source, not an ordinary overwriteable
    # install target.  Reconcile it before any other render: create only when
    # the managed surface is absent, accept exact equality, and otherwise fail
    # without writing previews, partial files, or invoking the release installer.
    grok_classification_entries = [
        entry for entry in manifest["entries"]
        if str(entry.get("id", "")).startswith("grokproxy-")
    ]
    try:
        validate_grok_source_classification(
            home, grok_classification_entries
        )
    except (OSError, GrokSourceRestoreError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    grok_entries = [
        entry for entry in manifest["entries"]
        if entry.get("id") == GROK_PROXY_ENTRY_ID
    ]
    if len(grok_entries) != 1:
        print("ERROR: manifest must define one grokproxy-scripts entry", file=sys.stderr)
        return 2
    try:
        report["installed"] += reconcile_grok_authoring_source(
            repo, home, grok_entries[0]
        )
    except (OSError, GrokSourceRestoreError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

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
        overwrite = dst_rel in (".bashrc", ".profile")
        install_file(src, dst, home, report, skip_if_exists=skip,
                     overwrite_existing=overwrite)

    # --- manifest-driven agent/system trees ---------------------------------
    handled_dests = set(shell_map)
    for entry in manifest["entries"]:
        root = entry.get("root", "")
        cls = entry["class"]
        if not cls.startswith("public"):
            continue
        # The dedicated preflight above already handled the allowlisted Grok
        # source.  Never let the generic whole-dest_dir walk copy repository-
        # local planning/learnings or produce per-file conflict previews there.
        if entry.get("id") == GROK_PROXY_ENTRY_ID:
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
                    if entry_excludes_path(entry, rel):
                        continue
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
            for line in open(tsv2):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                link, target = [p.replace("{{ HOME }}", home)
                                for p in line.split("\t")[:2]]
                subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/ln", "-sfn", target, link],
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
    if not args.render_only:
        try:
            release_id, changed = install_grok_proxy_release(repo, home)
        except GrokReleaseInstallError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        action = "selected new release" if changed else "already active"
        print(f"render-install: grok-proxy {release_id} ({action})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
