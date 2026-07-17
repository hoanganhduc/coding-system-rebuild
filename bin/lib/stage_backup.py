#!/usr/bin/env python3
"""Stage or commit only files produced by the public-backup transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import yaml


class StageError(RuntimeError):
    pass


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or os.path.isabs(value):
        raise StageError(f"unsafe backup output path: {value!r}")
    normalized = os.path.normpath(value).replace(os.sep, "/")
    if normalized in ("", ".", "..") or normalized.startswith("../"):
        raise StageError(f"unsafe backup output path: {value!r}")
    if any(part in ("", ".", "..", ".git") for part in value.split("/")):
        raise StageError(f"unsafe backup output path: {value!r}")
    return normalized


def _git(
    repo: Path,
    *arguments: str,
    input_data: bytes | None = None,
    environment: dict[str, str] | None = None,
):
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )


def _nul_paths(raw: bytes) -> set[str]:
    paths = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            paths.add(_safe_relative(os.fsdecode(item)))
        except UnicodeError as exc:
            raise StageError("Git returned a non-filesystem path") from exc
    return paths


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _load_nul_ledger(path: Path) -> set[str]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise StageError(f"refresh output ledger is unavailable: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise StageError("refresh output ledger is not a regular file")
    return _nul_paths(raw)


def _regular_record(path: Path) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StageError(f"backup output is not a regular file: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    linked = path.lstat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        stat.S_IMODE(value.st_mode),
    )
    if (
        path.is_symlink()
        or not stat.S_ISREG(linked.st_mode)
        or identity(before) != identity(after)
        or identity(after) != identity(linked)
    ):
        raise StageError(f"backup output changed during validation: {path}")
    data = b"".join(chunks)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": stat.S_IMODE(after.st_mode),
    }


def _validate_record(path: str, value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != {"sha256", "size", "mode"}
        or not isinstance(value.get("sha256"), str)
        or len(value["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in value["sha256"])
        or type(value.get("size")) is not int
        or value["size"] < 0
        or type(value.get("mode")) is not int
        or value["mode"] not in (0o600, 0o644, 0o700, 0o755)
    ):
        raise StageError(f"invalid producer record for {path}")
    return value


def _load_refresh_records(repo: Path) -> tuple[set[str], dict[str, dict[str, object]]]:
    ledger_path = repo / ".staging/refresh-output-paths.nul"
    try:
        ledger_info = ledger_path.lstat()
        ledger_raw = ledger_path.read_bytes()
    except OSError as exc:
        raise StageError(f"refresh output ledger is unavailable: {exc}") from exc
    if ledger_path.is_symlink() or not stat.S_ISREG(ledger_info.st_mode):
        raise StageError("refresh output ledger is not a regular file")
    paths = _nul_paths(ledger_raw)
    records_path = repo / ".staging/refresh-output-records.json"
    try:
        records_info = records_path.lstat()
        value = json.loads(records_path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise StageError(f"refresh output records are unavailable: {exc}") from exc
    if records_path.is_symlink() or not stat.S_ISREG(records_info.st_mode):
        raise StageError("refresh output records are not a regular file")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "ledger_sha256", "records"}
        or value.get("schema_version") != 1
        or value.get("ledger_sha256") != hashlib.sha256(ledger_raw).hexdigest()
        or not isinstance(value.get("records"), dict)
        or set(value["records"]) != paths
    ):
        raise StageError("refresh output records do not bind the current ledger")
    return paths, {
        path: _validate_record(path, record)
        for path, record in value["records"].items()
    }


def authorized_paths(
    repo: Path,
) -> tuple[list[str], dict[str, dict[str, object]], set[str]]:
    report_path = repo / ".staging/sync-report.json"
    try:
        report_info = report_path.lstat()
        report = json.loads(report_path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise StageError(f"successful sync report is unavailable: {exc}") from exc
    if report_path.is_symlink() or not stat.S_ISREG(report_info.st_mode):
        raise StageError("sync report is not a regular file")
    if (
        not isinstance(report, dict)
        or report.get("errors") != []
        or report.get("applied") is not True
        or type(report.get("outputs")) is not int
        or not isinstance(report.get("output_paths"), list)
        or not isinstance(report.get("output_records"), dict)
        or not isinstance(report.get("manifest_sha256"), str)
    ):
        raise StageError("sync report does not describe a successful capture")
    outputs = {_safe_relative(path) for path in report["output_paths"]}
    if (
        len(outputs) != report["outputs"]
        or set(report["output_records"]) != outputs
    ):
        raise StageError("sync report output count/path/record ledger disagree")
    records = {
        path: _validate_record(path, value)
        for path, value in report["output_records"].items()
    }

    manifest_path = repo / "MANIFEST.yaml"
    try:
        manifest_info = manifest_path.lstat()
        manifest_raw = manifest_path.read_bytes()
        manifest = yaml.safe_load(manifest_raw)
    except (OSError, ValueError, TypeError) as exc:
        raise StageError(f"manifest is unavailable: {exc}") from exc
    if manifest_path.is_symlink() or not stat.S_ISREG(manifest_info.st_mode):
        raise StageError("manifest is not a regular file")
    if report["manifest_sha256"] != hashlib.sha256(manifest_raw).hexdigest():
        raise StageError("manifest changed after the successful capture")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        raise StageError("manifest entries are invalid")

    authorized = set(outputs)
    expected_absent = set()
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or not entry.get("authoritative"):
            continue
        destination = _safe_relative(entry.get("dest_dir"))
        preserved = [
            destination + "/" + _safe_relative(path)
            for path in (entry.get("preserve_dest") or [])
        ]
        tracked = _git(repo, "ls-files", "-z", "--", destination)
        if tracked.returncode != 0:
            raise StageError("cannot enumerate authoritative tracked files")
        for path in _nul_paths(tracked.stdout):
            if not any(_under(path, prefix) for prefix in preserved):
                authorized.add(path)
                if path not in outputs:
                    expected_absent.add(path)

    refresh_paths, refresh_records = _load_refresh_records(repo)
    overlap = set(records) & set(refresh_records)
    if overlap:
        raise StageError(
            "capture and refresh producer ledgers overlap: "
            + ", ".join(sorted(overlap)[:5])
        )
    records.update(refresh_records)
    authorized.update(refresh_paths)

    for path, expected in records.items():
        candidate = repo / path
        try:
            actual = _regular_record(candidate)
        except OSError as exc:
            raise StageError(f"captured output disappeared before staging: {path}: {exc}") from exc
        if actual != expected:
            raise StageError(f"producer output changed before staging: {path}")
    for path in expected_absent:
        if os.path.lexists(repo / path):
            raise StageError(f"authoritative stale path reappeared before staging: {path}")
    return sorted(authorized), records, expected_absent


def _verify_index(
    repo: Path,
    records: dict[str, dict[str, object]],
    expected_absent: set[str],
    *,
    environment: dict[str, str] | None = None,
) -> None:
    for path, expected in records.items():
        blob = _git(repo, "show", f":{path}", environment=environment)
        if blob.returncode != 0:
            raise StageError(f"staged producer output is missing: {path}")
        if (
            hashlib.sha256(blob.stdout).hexdigest() != expected["sha256"]
            or len(blob.stdout) != expected["size"]
        ):
            raise StageError(f"staged producer output does not match its ledger: {path}")
        index = _git(
            repo, "ls-files", "--stage", "-z", "--", path,
            environment=environment,
        )
        rows = [row for row in index.stdout.split(b"\0") if row]
        if index.returncode != 0 or len(rows) != 1 or b"\t" not in rows[0]:
            raise StageError(f"staged producer mode is unavailable: {path}")
        git_mode = rows[0].split(b" ", 1)[0]
        expected_mode = b"100755" if int(expected["mode"]) & 0o111 else b"100644"
        if git_mode != expected_mode:
            raise StageError(f"staged producer mode does not match its ledger: {path}")
    for path in expected_absent:
        present = _git(
            repo, "ls-files", "--error-unmatch", "--", path,
            environment=environment,
        )
        if present.returncode == 0:
            raise StageError(f"staged authoritative deletion was not preserved: {path}")


def _reset_owned_index(repo: Path, ledger: bytes) -> None:
    result = _git(
        repo,
        "reset",
        "-q",
        "HEAD",
        "--pathspec-from-file=-",
        "--pathspec-file-nul",
        input_data=ledger,
    )
    if result.returncode != 0:
        raise StageError("cannot restore the caller's Git index after staging failure")


def _add_to_index(
    repo: Path,
    ledger: bytes,
    *,
    environment: dict[str, str] | None = None,
) -> None:
    staged = _git(
        repo,
        "add",
        "-A",
        "--pathspec-from-file=-",
        "--pathspec-file-nul",
        input_data=ledger,
        environment=environment,
    )
    if staged.returncode != 0:
        detail = staged.stderr.decode("utf-8", errors="replace").strip()
        raise StageError(f"exact backup staging failed: {detail}")


def stage_or_commit(repo: Path, commit_message: str | None) -> int:
    paths, records, expected_absent = authorized_paths(repo)
    ledger = b"".join(os.fsencode(path) + b"\0" for path in paths)
    before = _git(repo, "diff", "--cached", "--name-only", "-z", "--no-renames")
    if before.returncode != 0:
        raise StageError("cannot inspect the existing Git index")
    overlap = _nul_paths(before.stdout) & set(paths)
    if overlap:
        raise StageError(
            "backup-owned paths already have staged changes: "
            + ", ".join(sorted(overlap)[:5])
        )

    if commit_message is None:
        try:
            _add_to_index(repo, ledger)
            _verify_index(repo, records, expected_absent)
            after = _git(
                repo, "diff", "--cached", "--name-only", "-z", "--no-renames"
            )
            if after.returncode != 0:
                raise StageError("cannot verify the staged backup paths")
            newly_staged = _nul_paths(after.stdout) - _nul_paths(before.stdout)
            unexpected = newly_staged - set(paths)
            if unexpected:
                raise StageError(
                    "Git staged paths outside the producer ledger: "
                    + ", ".join(sorted(unexpected)[:5])
                )
        except BaseException:
            _reset_owned_index(repo, ledger)
            raise
        changed = _git(repo, "diff", "--cached", "--quiet", "--", *paths)
        if changed.returncode == 0:
            print("backup: no generated changes to stage")
            return 0
        if changed.returncode != 1:
            raise StageError("cannot inspect staged generated changes")
        print(f"backup: staged {len(newly_staged)} generated path(s)")
        return 0

    staging = repo / ".staging"
    staging.mkdir(exist_ok=True)
    descriptor, temporary_index = tempfile.mkstemp(prefix="backup-index-", dir=staging)
    os.close(descriptor)
    os.unlink(temporary_index)
    environment = dict(os.environ)
    environment["GIT_INDEX_FILE"] = temporary_index
    try:
        head = _git(repo, "rev-parse", "HEAD")
        if head.returncode != 0:
            raise StageError("backup commit requires an existing HEAD")
        old_head = head.stdout.strip()
        read_tree = _git(repo, "read-tree", "HEAD", environment=environment)
        if read_tree.returncode != 0:
            raise StageError("cannot initialize the isolated backup index")
        _add_to_index(repo, ledger, environment=environment)
        _verify_index(
            repo, records, expected_absent, environment=environment
        )
        changed = _git(repo, "diff", "--cached", "--quiet", environment=environment)
        if changed.returncode == 0:
            print("backup: no generated changes to commit")
            return 0
        if changed.returncode != 1:
            raise StageError("cannot inspect the isolated backup index")
        tree = _git(repo, "write-tree", environment=environment)
        if tree.returncode != 0:
            raise StageError("cannot write the isolated backup tree")
        committed = _git(
            repo,
            "commit-tree",
            tree.stdout.strip().decode("ascii"),
            "-p",
            old_head.decode("ascii"),
            "-F",
            "-",
            input_data=(commit_message + "\n").encode("utf-8"),
            environment=environment,
        )
        if committed.returncode != 0:
            detail = committed.stderr.decode("utf-8", errors="replace").strip()
            raise StageError(f"exact backup commit failed: {detail}")
        new_head = committed.stdout.strip()
        updated = _git(
            repo,
            "update-ref",
            "HEAD",
            new_head.decode("ascii"),
            old_head.decode("ascii"),
        )
        if updated.returncode != 0:
            raise StageError("HEAD changed while the exact backup commit was prepared")
        _reset_owned_index(repo, ledger)
        show = _git(repo, "show", "--stat", "--oneline", "-s", new_head.decode("ascii"))
        sys.stdout.buffer.write(b"committed:\n" + show.stdout)
        return 0
    finally:
        try:
            os.unlink(temporary_index)
        except FileNotFoundError:
            pass
        try:
            os.unlink(temporary_index + ".lock")
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit-message", default=None)
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    try:
        return stage_or_commit(repo, args.commit_message)
    except StageError as exc:
        print(f"backup staging: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
