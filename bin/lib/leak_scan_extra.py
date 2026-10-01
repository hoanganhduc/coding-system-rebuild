#!/usr/bin/env python3
"""Layer 4 of bin/leak-scan.sh: identity-bearing classes that grep misses.

Reads NUL-separated file paths on stdin (the scanner's own file list, zip
archives included) and reports:
  - the public-export classes of bin/lib/public_export.py: real-looking email,
    home path, uuid, long numeric identifier, identifier field; plus home
    paths under /Users and C:\\Users;
  - tailnet host names and Tailscale CGNAT addresses (100.64.0.0/10);
  - phone numbers, .onion addresses and public tunnel host names;
  - in UTF-16 text and in zip members, which grep cannot read, also private
    denylist entries.
Text is read as UTF-8, or as UTF-16 when it carries a byte-order mark or
alternating NUL bytes; zip members are read the same way.  Lines containing
LEAKSCAN-EXEMPT, and the reviewed path/class/line exceptions listed in
leak-scan-exceptions.yaml (the public-export format), are skipped.  Output is "FINDING [<class>]:" followed by "  <path>:<line>"
lines; the matched value is never printed.  Exit status 2 on any finding.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_export  # noqa: E402

EXEMPT = "LEAKSCAN-EXEMPT"
MAX_BYTES = 20 * 1024 * 1024
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".webp", ".woff", ".woff2", ".gz", ".xz"}
PUBLIC_EXPORT_CLASSES = {
    "email": "email",
    "home_path": "home path",
    "uuid": "uuid",
    "long_numeric_id": "long numeric identifier",
    "id_field": "identifier field",
}
EXTRA_PATTERNS = [
    ("home path", re.compile(r"/Users/[A-Za-z0-9._-]+|[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+")),
    ("tailnet host name", re.compile(r"\b[a-z0-9-]+\.[a-z0-9-]+\.ts\.net\b", re.IGNORECASE)),
    ("tailscale cgnat address", re.compile(r"\b100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}\b")),
    ("phone number", re.compile(r"(?<![\w+])\+[1-9]\d{0,2}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\d)"
                                r"|(?<!\d)0[35789]\d[\s.-]\d{3}[\s.-]\d{4}(?!\d)")),
    ("onion address", re.compile(r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b")),
    ("tunnel host name", re.compile(r"\b[a-z0-9-]+\.(?:trycloudflare\.com|cfargotunnel\.com|ngrok(?:-free)?\.(?:app|io|dev)"
                                    r"|loca\.lt|serveo\.net|localhost\.run)\b", re.IGNORECASE)),
]
# Test and fixture files are full of synthetic ids, paths and addresses; there
# only these classes are relaxed.  Denylist entries, tailnet names, emails,
# phone numbers and live tailnet addresses are still reported everywhere.
FIXTURE_PATH = re.compile(r"(^|/)(tests?|fixtures?|__tests__)/|(^|/)test_[^/]*$|_test\.[^/]+$")
FIXTURE_TOLERANT = {"home path", "uuid", "long numeric identifier", "identifier field", "tailscale cgnat address"}
CGNAT_CONSTANTS = {"100.64.0.0", "100.100.100.100", "100.127.255.255"}  # range bounds and MagicDNS
GENERIC_HOME_NAMES = {"runner", "runneradmin", "user", "username", "vscode", "codespace", "root", "nobody",
                      "alice", "bob", "example", "you", "yourname", "me", "iphone", "ipad", "android"}
# user@1001.service is a systemd unit instance, not an address; .test and .localhost are reserved TLDs
NON_EMAIL_SUFFIXES = (".service", ".socket", ".target", ".timer", ".mount", ".slice", ".scope", ".path",
                      ".device", ".test", ".localhost")
# a long number right after a size or time word is a quantity, not an identifier
QUANTITY_WORD = re.compile(r"(?i)(max|min|size|bytes|limit|timeout|deadline|memory|_ns|_ms|seconds|length|count)[A-Za-z_]*[\s\"'`:=({$<>!-]*$")
# powers of two (and 2**n - 1, the integer maxima) and powers of ten are limits, never identifiers
WELL_KNOWN_NUMBERS = {str(2 ** n) for n in range(24, 65)} | {str(2 ** n - 1) for n in range(24, 65)} \
    | {str(10 ** n) for n in range(8, 20)}
HOME_NAME = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]+)")
UUID_ANY = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
SCHEMA_BOUND = re.compile(r'"(?:maximum|minimum|exclusiveMaximum|exclusiveMinimum|maxLength|minLength|'
                          r'maxItems|minItems|multipleOf)"\s*:\s*-?\d{8,}')


def decode(data: bytes) -> tuple[str | None, str]:
    """Return (text, encoding label), or (None, "") for binary data."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace"), "utf-16"
    head = data[:4096]
    if b"\0" in head:
        if len(head) >= 4 and head[1::2].count(0) >= len(head[1::2]) * 0.9:
            return data.decode("utf-16-le", "replace"), "utf-16"
        return None, ""
    return data.decode("utf-8", "replace"), ""


def load_exceptions(repo: Path) -> set[tuple[str, str, int]]:
    """(path, class, line) triples from leak-scan-exceptions.yaml, read with
    public_export's validating loader so both scanners share one reviewed format."""
    rules = public_export.load_exceptions(repo / "leak-scan-exceptions.yaml")
    return {(rule.path, PUBLIC_EXPORT_CLASSES.get(rule.klass, rule.klass), rule.line)
            for rule in rules}


def live_tailnet_addresses() -> set[str]:
    """Current tailnet addresses of this host and its peers, if Tailscale is available."""
    try:
        result = subprocess.run(["tailscale", "status", "--json"], capture_output=True, timeout=5)
        status = json.loads(result.stdout) if result.returncode == 0 else {}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return set()
    nodes = [status.get("Self") or {}] + list((status.get("Peer") or {}).values())
    return {ip for node in nodes for ip in node.get("TailscaleIPs") or [] if ip}


def relaxed(klass: str, line: str) -> bool:
    """True when every match of the class on this line is a known non-identity value."""
    if klass == "home path":
        names = HOME_NAME.findall(line)
        return bool(names) and all(n.startswith(".") or n.lower() in GENERIC_HOME_NAMES for n in names)
    if klass == "uuid":
        values = UUID_ANY.findall(line)
        return bool(values) and all(len(set(v.replace("-", ""))) <= 1 for v in values)
    if klass == "long numeric identifier":
        if SCHEMA_BOUND.search(line):
            return True
        numbers = list(re.finditer(r"(?<![A-Za-z0-9])\d{8,}(?![A-Za-z0-9])", line))
        return bool(numbers) and all(m.group(0) in WELL_KNOWN_NUMBERS or QUANTITY_WORD.search(line[:m.start()])
                                     for m in numbers)
    if klass == "identifier field":
        # a value read through a call (config.get(...)) is code, not a literal id
        matches = list(public_export.ID_FIELD_RE.finditer(line))
        return bool(matches) and all(line[m.end():m.end() + 1] == "(" for m in matches)
    if klass == "tailscale cgnat address":
        values = EXTRA_PATTERNS[2][1].findall(line)
        return bool(values) and all(v in CGNAT_CONSTANTS for v in values)
    return False


def scan_text(label: str, text: str, denylist: list[str], widened: bool,
              live: set[str] = frozenset()) -> list[tuple[str, int]]:
    lines = text.splitlines()
    exempt = {i + 1 for i, line in enumerate(lines) if EXEMPT in line}
    fixture = bool(FIXTURE_PATH.search(label))
    found: list[tuple[str, int]] = []

    def keep(klass: str, number: int) -> bool:
        if number in exempt or (fixture and klass in FIXTURE_TOLERANT):
            return False
        return not relaxed(klass, lines[number - 1] if 0 < number <= len(lines) else "")

    for finding in public_export.scan_text(label, text):
        klass = PUBLIC_EXPORT_CLASSES.get(finding.klass)
        if klass and keep(klass, finding.line):
            if klass == "email" and finding_is_noreply(lines, finding.line):
                continue
            found.append((klass, finding.line))
    for number, line in enumerate(lines, 1):
        if number in exempt:
            continue
        for klass, pattern in EXTRA_PATTERNS:
            if pattern.search(line) and keep(klass, number):
                found.append((klass, number))
        if live and any(re.search(r"(?<![\w.:])" + re.escape(ip) + r"(?![\w:])", line) for ip in live):
            found.append(("live tailnet address", number))
        if widened and any(entry in line for entry in denylist):
            found.append(("private denylist match", number))
    return found


def finding_is_noreply(lines: list[str], number: int) -> bool:
    line = lines[number - 1] if 0 < number <= len(lines) else ""
    emails = re.findall(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", line)
    return bool(emails) and all(d.lower().endswith(("users.noreply.github.com", "noreply.github.com") + NON_EMAIL_SUFFIXES)
                                or d.lower() in {"github.com", "anthropic.com"} and "noreply@" in line.lower()
                                or public_export.is_reserved_email(d) for d in emails)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--denylist", type=Path)
    args = parser.parse_args()
    if os.environ.get("LEAKSCAN_EXTRA_FAULT") == "1":  # selftest hook: the caller must fail closed
        raise SystemExit(3)
    denylist = []
    if args.denylist and args.denylist.is_file():
        denylist = [l.strip() for l in args.denylist.read_text().splitlines()
                    if l.strip() and not l.lstrip().startswith("#")]
    exceptions = load_exceptions(args.repo)
    live = live_tailnet_addresses()
    results: dict[str, list[str]] = defaultdict(list)
    for raw in sys.stdin.buffer.read().split(b"\0"):
        if not raw:
            continue
        path = Path(raw.decode(errors="replace"))
        try:
            rel = path.relative_to(args.target).as_posix()
        except ValueError:
            rel = path.as_posix()
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            continue
        members: list[tuple[str, bytes, str]] = []
        if path.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if not info.is_dir() and info.file_size <= MAX_BYTES:
                            members.append((f"{rel}!{info.filename}", archive.read(info), "zip member"))
            except zipfile.BadZipFile:
                continue
        elif path.suffix.lower() not in BINARY_SUFFIXES:
            members.append((rel, path.read_bytes(), ""))
        for label, data, container in members:
            text, encoding = decode(data)
            if text is None:
                continue
            widened = bool(encoding or container)
            for klass, line in scan_text(label, text, denylist, widened, live):
                if (rel, klass, line) in exceptions:
                    continue
                if klass == "home path" and path.name == "REBUILD-MANIFEST.json":
                    continue  # that manifest lists the home path as a forbidden pattern
                note = ", ".join(x for x in (encoding, container) if x)
                results[klass].append(f"{label}:{line}" + (f" ({note})" if note else ""))
    for klass in sorted(results):
        locations = sorted(set(results[klass]))
        print(f"FINDING [{klass}]: {len(locations)}")
        for location in locations[:50]:
            print(f"  {location}")
        if len(locations) > 50:
            print(f"  ... and {len(locations) - 50} more")
    return 2 if results else 0


if __name__ == "__main__":
    sys.exit(main())
