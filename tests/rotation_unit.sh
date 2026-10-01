#!/usr/bin/env bash
# Adversarial tests for the fail-closed secret-rotation compatibility boundary.
# No network, real credentials, prompts, restarts, backups, or provider calls.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="$REPO/bin/lib/rotate_secrets.py"
WRAPPER="$REPO/bin/rotate-keys.sh"

python3 - "$ENG" "$WRAPPER" <<'PYEOF'
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ENGINE = sys.argv[1]
WRAPPER = sys.argv[2]
ROOT = Path(tempfile.mkdtemp(prefix="rotation-fail-closed-"))
FAKE_HOME = ROOT / "home"
FAKE_BIN = ROOT / "bin"
FAKE_HOME.mkdir()
FAKE_BIN.mkdir()

SECRET_VALUES = {
    "old_google": "old-google-sentinel",
    "new_google": "new-google-sentinel",
    "old_zotero": "old-zotero-sentinel",
    "new_zotero": "new-zotero-sentinel",
    "old_deepseek": "old-deepseek-sentinel",
    "new_deepseek": "new-deepseek-sentinel",
}


def write(rel, content, mode=0o600):
    path = FAKE_HOME / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, dict):
        content = json.dumps(content, sort_keys=True) + "\n"
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return path


# Migration-era targets that the retired implementation used to edit.
legacy_google = write(
    ".secrets.env",
    f'export GOOGLE_API_KEY="{SECRET_VALUES["old_google"]}"\n',
)
legacy_zotero = write(
    ".claude/secrets.json",
    {"ZOTERO_API_KEY": SECRET_VALUES["old_zotero"], "KEEP": "untouched"},
)
legacy_openclaw = write(
    ".openclaw/secrets.json",
    {"ZOTERO_API_KEY": SECRET_VALUES["old_zotero"]},
)
legacy_deepseek = write(
    ".deepseek/config.toml",
    f'api_key = "{SECRET_VALUES["old_deepseek"]}"\n',
)

# Canonical AAS authorities.  These are deliberately different files so the
# test catches a legacy-only mutation reported as a successful rotation.
canonical_shared = write(
    ".config/ai-agents-skills/secrets.json",
    {"ZOTERO_API_KEY": SECRET_VALUES["old_zotero"]},
)
canonical_providers = write(
    ".config/ai-agents-skills/providers.env",
    "\n".join(
        (
            f'GOOGLE_API_KEY="{SECRET_VALUES["old_google"]}"',
            f'DEEPSEEK_API_KEY="{SECRET_VALUES["old_deepseek"]}"',
            "",
        )
    ),
)

# Make one historical target unwritable.  A correct fail-closed implementation
# rejects before discovering or attempting any target, regardless of mode.
legacy_zotero.chmod(0o400)

tracked = (
    legacy_google,
    legacy_zotero,
    legacy_openclaw,
    legacy_deepseek,
    canonical_shared,
    canonical_providers,
)


def snapshot():
    return {
        str(path.relative_to(FAKE_HOME)): (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
        )
        for path in tracked
    }


baseline = snapshot()
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def run_engine(command, identifier, value):
    result = subprocess.run(
        [sys.executable, ENGINE, command, identifier],
        env={**os.environ, "HOME": str(FAKE_HOME), "NEWSECRET_VALUE": value},
        capture_output=True,
        text=True,
        timeout=10,
    )
    combined = result.stdout + result.stderr
    check(result.returncode != 0, f"{command} {identifier} unexpectedly succeeded")
    check(value not in combined, f"{command} {identifier} leaked the supplied value")
    check(snapshot() == baseline, f"{command} {identifier} changed a legacy or canonical authority")
    return result


# Uppercase dynamic names must not rediscover and mutate legacy mirrors.
run_engine("apply", "GOOGLE_API_KEY", SECRET_VALUES["new_google"])
run_engine("apply", "ZOTERO_API_KEY", SECRET_VALUES["new_zotero"])

# Declared field targets, missing targets, write failures, and no-change inputs
# must all be nonzero rather than producing a false success.
run_engine("apply", "DEEPSEEK_API_KEY", SECRET_VALUES["new_deepseek"])
run_engine("apply", "MISSING_API_KEY", "missing-target-sentinel")
run_engine("apply", "ZOTERO_API_KEY", SECRET_VALUES["old_zotero"])

for identifier in ("GOOGLE_API_KEY", "ZOTERO_API_KEY", "DEEPSEEK_API_KEY"):
    result = run_engine("kind", identifier, "kind-value-sentinel")
    check(result.stdout.strip() == "unsupported", f"kind {identifier} was not explicitly unsupported")

listing = subprocess.run(
    [sys.executable, ENGINE, "list"],
    env={**os.environ, "HOME": str(FAKE_HOME)},
    capture_output=True,
    text=True,
    timeout=10,
)
check(listing.returncode == 0, "informational list command failed")
check("disabled" in listing.stdout.lower(), "list did not explain disabled rotation")
for identifier in ("GOOGLE_API_KEY", "ZOTERO_API_KEY", "DEEPSEEK_API_KEY"):
    check(identifier not in listing.stdout, f"list exposed {identifier} as rotatable")

# Marker commands demonstrate that the shell wrapper exits before the old
# restart and recovery-set post-actions. Output also proves that neither prompt
# was offered.
restart_marker = ROOT / "systemctl-called"
backup_marker = ROOT / "secrets-pack-called"
systemctl = FAKE_BIN / "systemctl"
systemctl.write_text(
    "#!/bin/sh\n: > \"$ROTATION_TEST_MARKER\"\nexit 99\n",
    encoding="utf-8",
)
systemctl.chmod(0o755)
fake_bash = FAKE_BIN / "bash"
fake_bash.write_text(
    "#!/bin/sh\n: > \"$ROTATION_BACKUP_MARKER\"\nexit 99\n",
    encoding="utf-8",
)
fake_bash.chmod(0o755)
wrapper_result = subprocess.run(
    ["/usr/bin/bash", WRAPPER, "SECRET=ZOTERO_API_KEY"],
    env={
        **os.environ,
        "HOME": str(FAKE_HOME),
        "PATH": f"{FAKE_BIN}:/usr/bin:/bin",
        "ROTATION_TEST_MARKER": str(restart_marker),
        "ROTATION_BACKUP_MARKER": str(backup_marker),
    },
    input=f'{SECRET_VALUES["new_zotero"]}\ny\ny\n',
    capture_output=True,
    text=True,
    timeout=10,
)
wrapper_output = wrapper_result.stdout + wrapper_result.stderr
check(wrapper_result.returncode != 0, "wrapper unexpectedly succeeded")
check(not restart_marker.exists(), "wrapper reached the restart post-action")
check(not backup_marker.exists(), "wrapper reached the recovery-set post-action")
check("Restart the OpenClaw gateway" not in wrapper_output, "wrapper offered a restart prompt")
check("Create a signed recovery set" not in wrapper_output, "wrapper offered a recovery-set prompt")
check(SECRET_VALUES["new_zotero"] not in wrapper_output, "wrapper leaked stdin secret input")
check(snapshot() == baseline, "wrapper changed a legacy or canonical authority")
check(not list(FAKE_HOME.rglob("*.bak-prerotate-*")), "failed rotation left pre-rotation backups")

shutil.rmtree(ROOT)
if failures:
    print("rotation unit tests: FAIL")
    for failure in failures:
        print(f"  - {failure}")
    raise SystemExit(1)

print(
    "rotation unit tests: PASS "
    "(legacy/canonical files unchanged, all mutation paths nonzero, no leaks or post-actions)"
)
PYEOF
