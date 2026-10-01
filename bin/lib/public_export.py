#!/usr/bin/env python3
"""History-free public export builder and verifier."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

try:
    import yaml
except ImportError:  # pragma: no cover - repository tooling depends on PyYAML.
    yaml = None


DENY_DIR_NAMES = {
    ".git",
    ".learnings",
    ".planning",
    ".staging",
    ".pytest_cache",
    "__pycache__",
    "external",
    "node_modules",
    "secrets",
    "secrets-out",
}
DENY_EXACT = {
    ".staging-symlinks-observed.tsv",
}
DENY_PREFIXES = (
    "system/packages/observed/",
)
DENY_SUFFIXES = (
    ".log",
    ".tmp",
    ".pyc",
    ".zip",
    ".tar",
    ".tgz",
    ".gz",
    ".7z",
)
DENY_BASENAMES = {
    ".secrets.env",
    "auth.json",
    "config.json",
    "credentials.json",
    "leak-denylist.txt",
    "secrets.json",
    "settings.local.json",
}
SENSITIVE_PATH_WORD = re.compile(r"(auth|credential|secret|token)", re.IGNORECASE)
PUBLIC_TEMPLATE_SUFFIXES = (
    ".example",
    ".example.json",
    ".schema.json",
    ".template",
    ".template.json",
)

ALLOW_EXACT = {
    ".gitignore",
    "Makefile",
    "README.md",
    "bin/lib/public_export.py",
    "bin/public-export.sh",
    "components.lock",
    "docs/PUBLIC-EXPORT.md",
    "public-export-exceptions.yaml",
}
ALLOW_PREFIXES: tuple[str, ...] = ()

KNOWN_CLASSES = {
    "account_id",
    "email",
    "home_path",
    "id_field",
    "long_numeric_id",
    "private_key_block",
    "secret_json_field",
    "token_shape",
    "uuid",
}

TOKEN_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"gsk_[A-Za-z0-9]{16,}"),
    re.compile(r"pplx-[A-Za-z0-9]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[bpas]-[A-Za-z0-9-]{10,}"),
    re.compile(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\b[rs]t_[A-Za-z0-9_-]{20,}\b"),
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
HOME_RE = re.compile(r"/home/[A-Za-z0-9._-]+")
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
LONG_NUMERIC_RE = re.compile(r"(?<![A-Za-z0-9])\d{8,}(?![A-Za-z0-9])")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
ID_FIELD_RE = re.compile(
    r"\b(account|app|application|chat|client|course|document|owner|tenant|user|workspace)"
    r"[_-]?id\b[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9][A-Za-z0-9_.:+/-]{7,}",
    re.IGNORECASE,
)
SECRET_JSON_RE = re.compile(
    r'"(key|apikey|api_key|token|accountid|clientsecret|client_secret|access|refresh|'
    r'bearer|secret|password|credential|sessionid|session_id|ownerid|owner_id|'
    r'clientid|client_id|cookie|auth|serviceaccount|service_account|serviceaccountfile)"'
    r'\s*:\s*"[A-Za-z0-9][A-Za-z0-9_.+/-]{19,}"',
    re.IGNORECASE,
)


class PublicExportError(Exception):
    """A public export policy or verification failure."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    klass: str
    message: str

    def format(self) -> str:
        location = self.path if self.line <= 0 else f"{self.path}:{self.line}"
        return f"{location}: {self.klass}: {self.message}"


@dataclass(frozen=True)
class ExceptionRule:
    path: str
    klass: str
    line: int
    reason: str
    proof: str


def normalize_relative(path: str | Path) -> str:
    value = Path(path).as_posix().strip("/")
    if not value or value == "." or value.startswith("../") or "/../" in value:
        raise PublicExportError(f"unsafe relative path: {path}")
    return value


def is_public_template(rel: str) -> bool:
    lower = rel.lower()
    return lower.endswith(PUBLIC_TEMPLATE_SUFFIXES) or ".example." in lower


def is_denied(rel: str) -> bool:
    parts = tuple(Path(rel).parts)
    base = parts[-1] if parts else rel
    if any(part in DENY_DIR_NAMES for part in parts):
        return True
    if rel in DENY_EXACT:
        return True
    if any(rel.startswith(prefix) for prefix in DENY_PREFIXES):
        return True
    if base in DENY_BASENAMES or base.endswith(".keys"):
        return True
    if rel.endswith(DENY_SUFFIXES):
        return True
    if SENSITIVE_PATH_WORD.search(rel) and not is_public_template(rel):
        return True
    return False


def is_allowed_candidate(rel: str) -> bool:
    return rel in ALLOW_EXACT or any(rel.startswith(prefix) for prefix in ALLOW_PREFIXES)


def should_export(rel: str) -> bool:
    return is_allowed_candidate(rel) and not is_denied(rel)


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=os.fspath(cwd) if cwd is not None else None,
        text=True,
        stdout=stdout,
        stderr=stderr,
        check=False,
    )


def require_clean_head(repo: Path, ref: str) -> None:
    if ref != "HEAD":
        return
    status = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo)
    if status.returncode != 0:
        raise PublicExportError(status.stderr.strip() or "cannot inspect git status")
    if status.stdout.strip():
        raise PublicExportError("ref HEAD requires a clean source tree")


def require_safe_output(repo: Path, output: Path) -> None:
    if not output.is_absolute():
        raise PublicExportError("export output must be an absolute path")
    repo_real = repo.resolve()
    output_real = output.resolve(strict=False)
    try:
        output_real.relative_to(repo_real)
    except ValueError:
        pass
    else:
        raise PublicExportError("export output must not be inside the source repository")
    if output.exists() and output.is_symlink():
        raise PublicExportError("export output must not be a symlink")
    if output.exists() and any(output.iterdir()):
        raise PublicExportError("export output directory already exists and is not empty")
    if not output.parent.exists():
        raise PublicExportError("export output parent does not exist")


def archive_ref(repo: Path, ref: str, target: Path) -> None:
    process = subprocess.Popen(
        ["git", "archive", "--format=tar", ref],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            archive.extractall(target)
    except (tarfile.TarError, OSError) as exc:
        process.kill()
        raise PublicExportError(f"cannot extract git archive: {exc}") from exc
    _stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise PublicExportError(stderr.decode("utf-8", "replace").strip())


def copy_public_files(staged: Path, output: Path) -> list[str]:
    copied: list[str] = []
    output.mkdir(parents=True, exist_ok=True)
    for path in sorted(staged.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(staged).as_posix()
        if not should_export(rel):
            continue
        if path.is_symlink():
            raise PublicExportError(f"refusing symlink in public export: {rel}")
        destination = output / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        copied.append(rel)
    if not copied:
        raise PublicExportError("public export policy selected no files")
    return copied


def load_exceptions(path: Path) -> list[ExceptionRule]:
    if not path.exists():
        return []
    if yaml is None:
        raise PublicExportError("PyYAML is required to read public-export exceptions")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = raw.get("exceptions", [])
    if not isinstance(entries, list):
        raise PublicExportError("public-export exceptions must be a list")
    rules: list[ExceptionRule] = []
    for index, item in enumerate(entries, 1):
        if not isinstance(item, dict):
            raise PublicExportError(f"exception #{index} is not a mapping")
        rel = normalize_relative(str(item.get("path", "")))
        klass = str(item.get("class", ""))
        try:
            line = int(item.get("line"))
        except (TypeError, ValueError) as exc:
            raise PublicExportError(f"exception #{index} requires integer line") from exc
        reason = str(item.get("reason", "")).strip()
        proof = str(item.get("proof", "")).strip()
        if klass not in KNOWN_CLASSES:
            raise PublicExportError(f"exception #{index} has unknown class: {klass}")
        if line < 1:
            raise PublicExportError(f"exception #{index} requires line >= 1")
        if not reason or not proof:
            raise PublicExportError(f"exception #{index} requires reason and proof")
        rules.append(ExceptionRule(rel, klass, line, reason, proof))
    return rules


def exception_applies(finding: Finding, rules: list[ExceptionRule]) -> bool:
    return any(
        rule.path == finding.path
        and rule.klass == finding.klass
        and rule.line == finding.line
        for rule in rules
    )


def is_textish(path: Path, data: bytes) -> bool:
    if b"\0" in data[:4096]:
        return False
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf"}:
        return False
    return True


def is_reserved_email(domain: str) -> bool:
    domain = domain.lower()
    return (
        domain.endswith(".invalid")
        or domain in {"example.com", "example.org", "example.net"}
        or domain.endswith(".example")
    )


def is_yyyymmdd(value: str) -> bool:
    if len(value) != 8:
        return False
    year = int(value[:4])
    month = int(value[4:6])
    day = int(value[6:8])
    return 1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_text(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    uuid_spans = [match.span() for match in UUID_RE.finditer(text)]

    def add_matches(pattern: re.Pattern[str], klass: str, message: str) -> None:
        for match in pattern.finditer(text):
            findings.append(Finding(rel, line_number(text, match.start()), klass, message))

    for pattern in TOKEN_PATTERNS:
        add_matches(pattern, "token_shape", "token-shaped string")
    add_matches(HOME_RE, "home_path", "local home path")
    add_matches(UUID_RE, "uuid", "uuid-like identifier")
    add_matches(PRIVATE_KEY_RE, "private_key_block", "private key block marker")
    add_matches(ID_FIELD_RE, "id_field", "identifier field with literal value")
    add_matches(SECRET_JSON_RE, "secret_json_field", "secret-shaped JSON field value")

    for match in EMAIL_RE.finditer(text):
        domain = match.group(1)
        if not is_reserved_email(domain):
            findings.append(
                Finding(rel, line_number(text, match.start()), "email", "real-looking email")
            )
    for match in LONG_NUMERIC_RE.finditer(text):
        value = match.group(0)
        if any(start <= match.start() and match.end() <= end for start, end in uuid_spans):
            continue
        if not is_yyyymmdd(value):
            findings.append(
                Finding(
                    rel,
                    line_number(text, match.start()),
                    "long_numeric_id",
                    "long numeric identifier",
                )
            )
    return findings


def scan_export_tree(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(target).as_posix()
        if is_denied(rel):
            findings.append(Finding(rel, 0, "account_id", "denied private path present"))
        data = path.read_bytes()
        if is_textish(path, data):
            findings.extend(scan_text(rel, data.decode("utf-8", "replace")))
    return findings


def run_leak_scan(repo: Path, target: Path) -> list[Finding]:
    scanner = repo / "bin/leak-scan.sh"
    if not scanner.exists():
        return [Finding("<export>", 0, "token_shape", "source leak scanner missing")]
    result = run(["bash", os.fspath(scanner), os.fspath(target)])
    if result.returncode == 0:
        return []
    message = "\n".join((result.stdout + result.stderr).splitlines()[:20])
    return [Finding("<export>", 0, "token_shape", "leak-scan failed:\n" + message)]


def verify_export(repo: Path, target: Path, exceptions_path: Path, *, leak_scan: bool = True) -> list[Finding]:
    if not target.is_dir():
        raise PublicExportError("export target is not a directory")
    rules = load_exceptions(exceptions_path)
    findings: list[Finding] = []
    if (target / ".git").exists():
        findings.append(Finding(".git", 0, "account_id", "git history is present"))
    findings.extend(scan_export_tree(target))
    if leak_scan:
        findings.extend(run_leak_scan(repo, target))
    filtered = [finding for finding in findings if not exception_applies(finding, rules)]
    known_identities = {(finding.path, finding.klass, finding.line) for finding in findings}
    for rule in rules:
        if (rule.path, rule.klass, rule.line) not in known_identities:
            filtered.append(
                Finding(rule.path, rule.line, rule.klass, "unused public-export exception")
            )
    return filtered


def export_public(repo: Path, output: Path, ref: str) -> None:
    require_clean_head(repo, ref)
    require_safe_output(repo, output)
    with tempfile.TemporaryDirectory(prefix="csr-public-export.") as temporary:
        staged = Path(temporary) / "archive"
        candidate = Path(temporary) / "candidate"
        staged.mkdir()
        archive_ref(repo, ref, staged)
        copied = copy_public_files(staged, candidate)
        exceptions = repo / "public-export-exceptions.yaml"
        findings = verify_export(repo, candidate, exceptions)
        if findings:
            raise PublicExportError(format_findings(findings))
        output.mkdir(parents=True, exist_ok=True)
        if any(output.iterdir()):
            raise PublicExportError("export output directory became non-empty before publish")
        for child in candidate.iterdir():
            shutil.move(os.fspath(child), os.fspath(output / child.name))
    print(f"public-export: wrote {len(copied)} files to {output}")


def format_findings(findings: list[Finding]) -> str:
    lines = ["public export verification failed:"]
    for finding in findings[:80]:
        lines.append("  " + finding.format())
    if len(findings) > 80:
        lines.append(f"  ... {len(findings) - 80} more finding(s)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("--repo", required=True, type=Path)
    export_parser.add_argument("--output", required=True, type=Path)
    export_parser.add_argument("--ref", default="HEAD")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo", required=True, type=Path)
    verify_parser.add_argument("--target", required=True, type=Path)
    verify_parser.add_argument("--exceptions", type=Path)
    verify_parser.add_argument("--skip-leak-scan", action="store_true")

    args = parser.parse_args(argv)
    try:
        repo = args.repo.resolve()
        if args.command == "export":
            export_public(repo, args.output, args.ref)
        else:
            exceptions = args.exceptions or (repo / "public-export-exceptions.yaml")
            findings = verify_export(
                repo,
                args.target,
                exceptions,
                leak_scan=not args.skip_leak_scan,
            )
            if findings:
                raise PublicExportError(format_findings(findings))
            print(f"public-export verify: clean ({args.target})")
    except PublicExportError as exc:
        print(f"public-export: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
