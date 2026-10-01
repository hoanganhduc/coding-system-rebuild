#!/usr/bin/env python3
"""Install pinned third-party skills that ai-agents-skills does not ship.

Each source in ``system/software/vendor-skills.lock.json`` names one public
repository commit and the skill directories taken from it.  A skill is copied
into an agent's skills directory only where it is missing; a copy that differs
from the pin is reported and left alone, so local edits are never overwritten.
Targets whose agent home is absent are skipped.  Every destination is checked
before anything is written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = REPO / "system/software/vendor-skills.lock.json"
COMMIT = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}


class VendorSkillError(RuntimeError):
    """A redaction-safe vendor skill installation failure."""


def _git(directory: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
         "-c", "credential.helper=", "-C", os.fspath(directory), *arguments],
        env=GIT_ENV,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if completed.returncode != 0:
        raise VendorSkillError(f"git {arguments[0]} failed for a vendor skill source")
    return completed.stdout


def _relative(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise VendorSkillError(f"vendor skill lock {label} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise VendorSkillError(f"vendor skill lock {label} is not a safe relative path")
    return path


def _load_lock(path: Path) -> list[dict]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(lock, dict) or lock.get("schema_version") != 1 or not isinstance(lock.get("sources"), list):
        raise VendorSkillError("vendor skill lock schema is invalid")
    for source in lock["sources"]:
        if not isinstance(source, dict) or not NAME.fullmatch(str(source.get("id", ""))):
            raise VendorSkillError("vendor skill source id is invalid")
        if not str(source.get("repository", "")).startswith("https://"):
            raise VendorSkillError("vendor skill repository must be an HTTPS URL")
        if not COMMIT.fullmatch(str(source.get("commit", ""))):
            raise VendorSkillError("vendor skill source must pin one full commit")
        if not str(source.get("license", "")):
            raise VendorSkillError("vendor skill source must record its license")
        _relative(source.get("source_dir"), "source_dir")
        skills = source.get("skills")
        if not isinstance(skills, list) or not skills or not all(NAME.fullmatch(str(s)) for s in skills):
            raise VendorSkillError("vendor skill names are invalid")
        targets = source.get("targets")
        if not isinstance(targets, list) or not targets:
            raise VendorSkillError("vendor skill targets are invalid")
        for target in targets:
            _relative(target, "target")
    return lock["sources"]


def _fetch(source: dict, scratch: Path) -> Path:
    checkout = scratch / source["id"]
    checkout.mkdir(mode=0o700)
    _git(checkout, "init", "-q")
    _git(checkout, "remote", "add", "origin", source["repository"])
    _git(checkout, "fetch", "-q", "--depth", "1", "origin", source["commit"])
    _git(checkout, "checkout", "-q", "--detach", "FETCH_HEAD")
    return checkout


def _pinned_files(checkout: Path, source: dict, skill: str) -> dict[str, tuple[bool, str]]:
    """Relative file path -> (executable, git blob id) for one pinned skill."""
    prefix = f"{source['source_dir']}/{skill}/"
    files: dict[str, tuple[bool, str]] = {}
    for line in _git(checkout, "ls-tree", "-r", source["commit"], "--", prefix).splitlines():
        meta, path = line.split("\t", 1)
        mode, kind, oid = meta.split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise VendorSkillError(f"pinned skill {skill} contains a non-regular file")
        files[path[len(prefix):]] = (mode == "100755", oid)
    if not files:
        raise VendorSkillError(f"pinned commit does not contain skill {skill}")
    return files


def _blob_id(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _state(destination: Path, pinned: dict[str, tuple[bool, str]]) -> str:
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise VendorSkillError(f"vendor skill destination is unsafe: {destination.name}")
    if not destination.exists():
        return "missing"
    observed: dict[str, tuple[bool, str]] = {}
    for root, directories, names in os.walk(destination):
        for name in directories + names:
            path = Path(root, name)
            if path.is_symlink():
                return "modified"
        for name in names:
            path = Path(root, name)
            relative = path.relative_to(destination).as_posix()
            if relative.split("/")[0] == "__pycache__" or "/__pycache__/" in f"/{relative}":
                continue
            observed[relative] = (bool(path.stat().st_mode & stat.S_IXUSR), _blob_id(path))
    return "current" if observed == pinned else "modified"


def _install(checkout: Path, source: dict, skill: str, pinned: dict, destination: Path) -> None:
    stage = Path(tempfile.mkdtemp(prefix=f".{skill}.", dir=destination.parent))
    try:
        for relative, (executable, _oid) in pinned.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(checkout / source["source_dir"] / skill / relative, target)
            target.chmod(0o755 if executable else 0o644)
        stage.chmod(0o755)
        os.rename(stage, destination)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def run(lock_path: Path, home: Path, check: bool, source_checkout: Path | None) -> tuple[dict, bool]:
    report: dict[str, dict] = {}
    complete = True
    with tempfile.TemporaryDirectory(prefix="vendor-skills-") as scratch:
        for source in _load_lock(lock_path):
            checkout = source_checkout or _fetch(source, Path(scratch))
            if _git(checkout, "rev-parse", "HEAD").strip() != source["commit"]:
                raise VendorSkillError("vendor skill source is not the pinned commit")
            pinned = {skill: _pinned_files(checkout, source, skill) for skill in source["skills"]}
            plan: list[tuple[str, str, Path, str]] = []
            targets: dict[str, object] = {}
            for target in source["targets"]:
                directory = home / target
                agent_home = directory.parent
                if agent_home.is_symlink() or directory.is_symlink():
                    raise VendorSkillError(f"vendor skill target is unsafe: {target}")
                if not agent_home.is_dir():
                    targets[target] = "agent-absent"
                    continue
                states = {}
                for skill in source["skills"]:
                    states[skill] = _state(directory / skill, pinned[skill])
                    plan.append((target, skill, directory / skill, states[skill]))
                targets[target] = states
            for target, skill, destination, state in plan:
                if state == "missing" and not check:
                    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    _install(checkout, source, skill, pinned[skill], destination)
                    targets[target][skill] = "installed"
                elif state != "current":
                    complete = False
            report[source["id"]] = targets
    return report, complete


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--check", action="store_true", help="report only; exit 1 unless every skill is current")
    parser.add_argument("--source-checkout", type=Path, help="use an existing checkout instead of fetching")
    args = parser.parse_args()
    try:
        report, complete = run(args.lock, args.home.expanduser().absolute(), args.check, args.source_checkout)
    except (VendorSkillError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"install-vendor-skills: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if args.check and not complete else 0


if __name__ == "__main__":
    raise SystemExit(main())
