#!/usr/bin/env python3
"""Offline tests for the Ubuntu Stage-0 and immutable software/image locks."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import zlib


ROOT = Path(__file__).resolve().parents[1]


def _pinned_openclaw_bot() -> Path:
    """The pinned openclaw-bot checkout: the installed component, else external/.

    bin/components.sh installs it under ~/.local/share/coding-system/components;
    a development layout may provide it as external/openclaw-bot instead.
    """
    spec = importlib.util.spec_from_file_location(
        "component_paths_for_tests", ROOT / "bin/lib/component_paths.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.resolve_component_path(
            ROOT, Path.home(), "openclaw-bot", source_fallback=True
        )
    except module.ComponentPathError:
        return ROOT / "external/openclaw-bot"


OPENCLAW_BOT = _pinned_openclaw_bot()
LOCKCTL_PATH = ROOT / "system/software/lockctl.py"
PULL_IMAGES = ROOT / "system/software/pull-locked-images.py"
BOOTSTRAP = ROOT / "restore-ubuntu.sh"
NPM_CLOSURE = ROOT / "system/software/npm-closure"
NPM_CLOSURECTL = NPM_CLOSURE / "closurectl.py"


def load_lockctl():
    spec = importlib.util.spec_from_file_location("csr_lockctl", LOCKCTL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SoftwareLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lockctl = load_lockctl()

    def test_both_platform_locks_are_internally_consistent(self) -> None:
        for arch in ("arm64", "amd64"):
            with self.subTest(arch=arch):
                self.assertEqual(self.lockctl.validate_profile(arch), [])
                profile = self.lockctl.load_profile(arch)
                self.assertEqual(profile["host"]["platform"], f"linux/{arch}")
                identifiers = {item["id"] for item in profile["artifacts"]}
                self.assertTrue(
                    {"node", "rustup-init", "bun", "elan", "kimi", "grok", "antigravity-agy"}.issubset(identifiers)
                )
                for artifact in profile["artifacts"]:
                    self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
                    self.assertTrue(artifact["url"].startswith("https://"))

    def test_bare_host_packages_and_gateway_use_exact_openclaw_launcher(self) -> None:
        apt_packages = {
            re.split(r">=|=|@", line, maxsplit=1)[0]
            for line in (ROOT / "system/packages/apt.lock.txt").read_text().splitlines()
            if line and not line.startswith("#")
        }
        self.assertTrue({"cron", "rclone"}.issubset(apt_packages))
        gateway_unit = OPENCLAW_BOT / "systemd/user/openclaw-gateway.service"
        if not gateway_unit.exists():
            self.skipTest("the openclaw-bot component is not fetched in this job")
        gateway = gateway_unit.read_text()
        self.assertIn(
            "{{ OPENCLAW_LIBEXEC }}/host_exec.py --generation "
            "{{ OPENCLAW_LIBEXEC }} --artifact openclaw_host_cli.py -- gateway",
            gateway,
        )
        self.assertNotIn("{{ HOME }}/.local/bin/openclaw", gateway)
        self.assertNotIn("{{ HOME }}/.npm-global/bin/node", gateway)
        self.assertNotIn("exec /usr/bin/node", gateway)

    def test_apt_lock_uses_minimums_and_a_locked_ppa_source(self) -> None:
        entries = [
            line
            for line in (ROOT / "system/packages/apt.lock.txt").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertTrue(entries)
        for entry in entries:
            self.assertRegex(entry, r"^[a-z0-9][a-z0-9+.-]*(>=[0-9][^\s]*|@xtradeb)$")
        self.assertEqual(
            {entry.split("@", 1)[0] for entry in entries if "@" in entry},
            {"chromium", "chromium-driver", "calibre"},
        )
        source = "system/packages/apt-sources/xtradeb-ubuntu-apps-noble.sources"
        text = (ROOT / source).read_text(encoding="utf-8")
        self.assertIn("URIs: https://ppa.launchpadcontent.net/xtradeb/apps/ubuntu/", text)
        self.assertIn("Signed-By: -----BEGIN PGP PUBLIC KEY BLOCK-----", text)
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                manifests = {item["path"] for item in self.lockctl.load_profile(architecture)["manifests"]}
                self.assertIn(source, manifests)
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        self.assertNotIn("add-apt-repository", prepare)
        self.assertNotIn("--allow-downgrades", prepare)
        self.assertIn("Acquire::Retries=5", prepare)
        self.assertIn("require_locked_versions", prepare)

    def test_caddy_installs_from_its_locked_cloudsmith_source(self) -> None:
        lock = (ROOT / "system/packages/apt.lock.txt").read_text(encoding="utf-8")
        self.assertRegex(lock, r"(?m)^caddy>=[0-9]")
        sources = ("system/packages/apt-sources/caddy-stable.list",
                   "system/packages/apt-sources/caddy-stable-archive-keyring.gpg")
        self.assertIn("https://dl.cloudsmith.io/public/caddy/stable/deb/debian",
                      (ROOT / sources[0]).read_text(encoding="utf-8"))
        for architecture in ("amd64", "arm64"):
            manifests = {item["path"] for item in self.lockctl.load_profile(architecture)["manifests"]}
            self.assertTrue(set(sources) <= manifests)
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        caddy = prepare[prepare.index('step "Caddy web server'):]
        caddy = caddy[: caddy.index("\nfi\n")]
        self.assertIn("skip SKIP_CADDY", caddy)
        self.assertIn('"$PKG/apt-sources/caddy-stable.list"', caddy)
        self.assertIn("require_locked_versions caddy", caddy)

    def test_ollama_gnu_prolog_and_veracrypt_install_from_locked_artifacts(self) -> None:
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        for step, flag, artifact in (
            ("Ollama", "SKIP_OLLAMA", "ollama"),
            ("GNU Prolog", "SKIP_GPROLOG", "gprolog"),
            ("VeraCrypt", "SKIP_VERACRYPT", "veracrypt-console"),
        ):
            with self.subTest(step=step):
                section = prepare[prepare.index(f'step "{step}'):]
                section = section[: section.index("\nfi\n")]
                self.assertIn(f"skip {flag}", section)
                self.assertIn(f"fetch_locked {artifact}", section)
        for architecture in ("amd64", "arm64"):
            profile = self.lockctl.load_profile(architecture)
            artifacts = {item["id"]: item for item in profile["artifacts"]}
            for identifier, artifact_format, cli in (
                ("ollama", "tar.zst", "ollama"),
                ("gprolog", "tar.gz", "gprolog"),
                ("veracrypt-console", "deb", "veracrypt"),
            ):
                with self.subTest(architecture=architecture, artifact=identifier):
                    self.assertEqual(artifacts[identifier]["format"], artifact_format)
                    self.assertEqual(profile["cli_versions"][cli], artifacts[identifier]["version"])
                    self.assertEqual(self.lockctl.CLI_ARTIFACTS[cli], identifier)

    def test_previous_docker_source_is_set_aside_before_the_locked_one(self) -> None:
        # apt refuses one repository configured with two different keyrings.
        prepare = (ROOT / "bin/prepare.sh").read_text(encoding="utf-8")
        docker = prepare[prepare.index('step "Docker engine"'):]
        moved = docker.index("/var/backups/coding-system/docker.list")
        self.assertIn("download.docker.com/linux/ubuntu", docker[:moved])
        self.assertLess(moved, docker.index("/etc/apt/sources.list.d/docker.sources"))

    def test_tailscale_version_and_signed_repository_are_cross_lock_consistent(self) -> None:
        apt_versions = {
            package: version
            for line in (ROOT / "system/packages/apt.lock.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#") and "@" not in line
            for package, version in (line.split(">=", 1),)
        }
        self.assertEqual(apt_versions["tailscale"], "1.102.3")
        expected_artifacts = {
            "tailscale-keyring": {
                "url": "https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg",
                "sha256": "3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39",
            },
            "tailscale-source": {
                "url": "https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list",
                "sha256": "e95b581a3d0d34614731b867339b48e312c0db16e4b788b736d759f95669e7d9",
            },
        }
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                profile = self.lockctl.load_profile(architecture)
                self.assertEqual(
                    profile["cli_versions"]["tailscale"],
                    ">=" + apt_versions["tailscale"],
                )
                artifacts = {item["id"]: item for item in profile["artifacts"]}
                for identifier, expected in expected_artifacts.items():
                    self.assertEqual(
                        {
                            "url": artifacts[identifier]["url"],
                            "sha256": artifacts[identifier]["sha256"],
                        },
                        expected,
                    )

    def test_release_gate_rejects_pending_hosts_and_unverified_grok(self) -> None:
        for arch in ("arm64", "amd64"):
            errors = self.lockctl.validate_profile(arch, require_complete=True)
            self.assertTrue(any("clean-host release gate" in error for error in errors))
            self.assertTrue(any("grok-artifact" in error for error in errors))
            unresolved = self.lockctl.load_profile(arch)["unresolved"]
            self.assertEqual({item["status"] for item in unresolved}, {"unverified-artifact", "not-applicable"})

    def test_release_gate_reports_pending_release_inputs_as_unavailable_artifacts(self) -> None:
        completed = subprocess.run(
            [
                "python3",
                str(LOCKCTL_PATH),
                "--arch",
                "arm64",
                "validate",
                "--require-complete",
            ],
            env={key: value for key, value in os.environ.items() if key != "SKIP_GROK"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("ARTIFACT_UNAVAILABLE: platform", completed.stderr)
        self.assertIn("ARTIFACT_UNAVAILABLE: unresolved required artifact", completed.stderr)

    def test_skip_grok_makes_only_the_grok_artifact_optional(self) -> None:
        for arch in ("arm64", "amd64"):
            errors = self.lockctl.validate_profile(
                arch, require_complete=True, skipped=frozenset({"SKIP_GROK"})
            )
            self.assertTrue(any("clean-host release gate" in error for error in errors))
            self.assertFalse(any("grok-artifact" in error for error in errors))
        environment = {key: value for key, value in os.environ.items() if key != "SKIP_GROK"}
        for value, skipped in (("1", True), ("0", False), ("yes", False)):
            with self.subTest(SKIP_GROK=value):
                completed = subprocess.run(
                    ["python3", str(LOCKCTL_PATH), "--arch", "arm64", "validate", "--require-complete"],
                    env={**environment, "SKIP_GROK": value},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("ARTIFACT_UNAVAILABLE: platform", completed.stderr)
                self.assertEqual("grok-artifact" in completed.stderr, not skipped)

    def test_manifest_digest_tampering_fails_validation(self) -> None:
        original = self.lockctl.sha256_file

        def tampered(path: Path) -> str:
            if path.name == "npm-globals.txt":
                return "0" * 64
            return original(path)

        with mock.patch.object(self.lockctl, "sha256_file", side_effect=tampered):
            errors = self.lockctl.validate_profile("arm64")
        self.assertTrue(any("manifest digest mismatch" in error for error in errors))

    def test_npm_versions_and_integrities_are_one_to_one(self) -> None:
        requested = {
            line.strip()
            for line in (ROOT / "system/packages/npm-globals.txt").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
        npm_lock = json.loads((ROOT / "system/software/npm-globals.lock.json").read_text())
        locked = {f"{item['name']}@{item['version']}" for item in npm_lock["packages"]}
        self.assertEqual(requested, locked)
        self.assertTrue(all(item["integrity"].startswith("sha512-") for item in npm_lock["packages"]))

    def test_npm_closure_locks_every_direct_and_transitive_package(self) -> None:
        requested = {
            line.rsplit("@", 1)[0]: line.rsplit("@", 1)[1]
            for line in (ROOT / "system/packages/npm-globals.txt").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
        package = json.loads((NPM_CLOSURE / "package.json").read_text())
        lock = json.loads((NPM_CLOSURE / "package-lock.json").read_text())
        self.assertTrue(package["private"])
        self.assertEqual(package["dependencies"], requested)
        self.assertEqual(lock["lockfileVersion"], 3)
        self.assertEqual(lock["packages"][""]["dependencies"], requested)
        self.assertGreater(len(lock["packages"]), len(requested))
        for path, record in lock["packages"].items():
            if not path:
                continue
            self.assertTrue(record["resolved"].startswith("https://registry.npmjs.org/"), path)
            self.assertTrue(record["integrity"].startswith("sha512-"), path)

        result = subprocess.run(
            ["python3", str(NPM_CLOSURECTL), "validate"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        self.assertIn("397 total packages", result.stdout)

    def test_prepare_uses_npm_ci_without_lifecycle_or_global_installs(self) -> None:
        source = (ROOT / "bin/prepare.sh").read_text()
        npm_section = source.split(
            'step "transitively locked npm agent CLI closure"', 1
        )[1].split('step "pipx tools"', 1)[0]
        # The closure is installed by the builder (as the user, never root),
        # not by npm in the prepare step; prepare only binds the published root.
        builder = (ROOT / "bin/lib/openclaw_closure.py").read_text()
        self.assertIn(
            '"ci", "--ignore-scripts", "--include=optional", '
            '"--install-strategy=hoisted", "--no-audit", "--no-fund",',
            " ".join(builder.split()),
        )
        self.assertIn('f"sha256-{arch}-{source_hash}-{tree_hash}"', builder)
        self.assertIn("sha256-${LOCK_ARCH}-${source_hash}-", npm_section)
        self.assertIn("closurectl.py", source)
        for forbidden in ("npm ci", "npm install -g", "npm view"):
            self.assertNotIn(forbidden, npm_section)
            self.assertNotIn(forbidden, builder)

    def test_codewhale_native_release_assets_are_exactly_locked_per_arch(self) -> None:
        # Since v0.9.5 CodeWhale ships one binary per platform under three asset
        # names; the official codewhale-artifacts-sha256.txt lists one digest.
        digests = {
            "arm64": ("linux-arm64", "f3e2d82257cac33ef033f033a9638cb00189a3334deb58fbff7b89aed218273a"),
            "amd64": ("linux-x64", "c443c2c32c743dd80ff56397b1e7bbfe55b1ca6306ff55065b977bc655d50ed1"),
        }
        assets = {"codewhale-codew": "codew", "codewhale-cli": "codewhale", "codewhale-tui": "codewhale-tui"}
        base_url = "https://github.com/Hmbown/CodeWhale/releases/download/v0.10.0/"
        wrapper = json.loads(
            (ROOT / "system/software/npm-closure/package-lock.json").read_text(encoding="utf-8")
        )["packages"]["node_modules/codewhale"]["version"]
        for arch, (platform_suffix, digest) in digests.items():
            artifacts = {
                item["id"]: item for item in self.lockctl.load_profile(arch)["artifacts"]
            }
            with self.subTest(arch=arch):
                for identifier, asset in assets.items():
                    artifact = artifacts[identifier]
                    self.assertEqual(artifact["version"], "0.10.0")
                    self.assertEqual(artifact["version"], wrapper)
                    self.assertEqual(artifact["url"], f"{base_url}{asset}-{platform_suffix}")
                    self.assertEqual(artifact["sha256"], digest)
                    self.assertEqual(artifact["format"], "binary")
                    self.assertTrue(
                        artifact["evidence"].startswith(
                            "CodeWhale v0.10.0 official codewhale-artifacts-sha256.txt"
                        )
                    )

    def test_codewhale_native_assets_are_injected_before_tree_digest(self) -> None:
        prepare = (ROOT / "bin/prepare.sh").read_text()
        npm_section = prepare.split(
            'step "transitively locked npm agent CLI closure"', 1
        )[1].split('step "pipx tools"', 1)[0]
        self.assertIn(
            "for artifact_id in codewhale-codew codewhale-cli codewhale-tui; do",
            npm_section,
        )
        self.assertIn(
            'fetch_locked "$artifact_id" "$TMP_ROOT/$artifact_id"', npm_section
        )

        # The builder re-reads the platform lock, injects the three
        # locked native assets into the staged closure, and only then takes the
        # tree digest that names the published generation.
        builder = (ROOT / "bin/lib/openclaw_closure.py").read_text()
        self.assertIn(
            'ARTIFACT_IDS = ("codewhale-codew", "codewhale-cli", "codewhale-tui")',
            builder,
        )
        self.assertIn(
            'ARTIFACT_TARGETS = ("codew", "codewhale", "codewhale-tui")', builder
        )
        self.assertIn(
            'native_versions = {artifacts[identifier]["version"] for identifier in ARTIFACT_IDS}',
            builder,
        )
        self.assertIn('manifest.get("version") != codewhale_version', builder)
        self.assertIn('codewhale_version.encode("ascii")', builder)
        self.assertLess(
            builder.index("_write_owned_file(downloads / target_name"),
            builder.index('"tree-digest"'),
        )
        self.assertNotIn("scripts/install.js", npm_section)
        self.assertNotIn("scripts/install.js", builder)

        verification = (ROOT / "bin/verify.sh").read_text()
        self.assertIn("CodeWhale locked native asset", verification)
        self.assertIn('artifact "$artifact_id" sha256', verification)
        self.assertIn('cmp -s -- "$marker"', verification)


class ImageLockTests(unittest.TestCase):
    def test_all_image_references_are_digest_only(self) -> None:
        digest_reference = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
        lock = json.loads((ROOT / "system/software/images.lock.json").read_text())
        for image in lock["images"]:
            self.assertRegex(image["reference"], digest_reference)
            self.assertNotIn(":latest", image["reference"])
            self.assertEqual(image["reference"].rsplit("@", 1)[1], image["index_digest"])
            for digest in image["platforms"].values():
                self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")

        for line in (ROOT / "system/packages/docker-images.txt").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            reference, arch = line.split("|", 1)
            self.assertRegex(reference, digest_reference)
            self.assertIn(arch, {"any", "amd64", "arm64"})

    def test_dry_run_selects_every_locked_image_once_per_platform(self) -> None:
        lock = json.loads((ROOT / "system/software/images.lock.json").read_text())
        for arch in ("arm64", "amd64"):
            expected = [
                image
                for image in lock["images"]
                if f"linux/{arch}" in image["platforms"]
            ]
            result = subprocess.run(
                ["python3", str(PULL_IMAGES), "--arch", arch, "--dry-run"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            commands = result.stdout.splitlines()
            self.assertEqual(len(commands), len(expected))
            self.assertEqual(
                {command.rsplit(" ", 1)[1] for command in commands},
                {image["reference"] for image in expected},
            )
            self.assertTrue(all(f"--platform linux/{arch}" in command for command in commands))
            self.assertTrue(all("@sha256:" in command for command in commands))
            self.assertTrue(all(":latest" not in command for command in commands))


class BootstrapTests(unittest.TestCase):
    GENERATION_ROOT = Path(
        "/usr/local/libexec/coding-system/repository-generations"
    )
    GENERATION_NAME = re.compile(r"^[0-9a-f]{40,64}-[0-9a-f]{40,64}$")

    def install_generation_helper(self, repository: Path) -> None:
        """Stage-0 materializes the checkout through this authenticated helper."""
        (repository / "bin/lib").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            ROOT / "bin/lib/repository_generation.py",
            repository / "bin/lib/repository_generation.py",
        )

    def guard_published_generations(self) -> None:
        """Discard the root-owned generations a fixture Stage-0 run publishes."""
        before = set(self.GENERATION_ROOT.glob("*"))

        def discard() -> None:
            for path in sorted(set(self.GENERATION_ROOT.glob("*")) - before):
                # The publisher also keeps a persistent lock beside the
                # generations; only identity-named trees are fixture residue.
                if self.GENERATION_NAME.fullmatch(path.name) is None:
                    continue
                subprocess.run(
                    ["/usr/bin/sudo", "-n", "--", "/usr/bin/rm", "-rf", "--", str(path)],
                    check=True,
                )

        self.addCleanup(discard)

    def remove_group_world_write(self, path: Path) -> None:
        path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o022)
        for member in path.rglob("*"):
            try:
                if not member.is_symlink():
                    member.chmod(stat.S_IMODE(member.stat().st_mode) & ~0o022)
            except FileNotFoundError:
                # Git's background maintenance removes its lock files mid-walk.
                continue

    def write_recovery_set(self, directory: Path, commit: str = "a" * 40) -> None:
        directory.mkdir(parents=True)
        manifest = directory / "recovery-set.json"
        manifest.write_text(
            json.dumps({"components": {"coding-system-rebuild": {"commit": commit}}}) + "\n",
            encoding="utf-8",
        )
        (directory / "recovery-signing-public-key.pub").write_bytes(
            (ROOT / "system/recovery/recovery-signing-public-key.pub").read_bytes()
        )
        # never a production signature over test data; callers stop before the
        # signature gate (write_complete_recovery_set signs with a test-only key)
        (directory / "recovery-set.json.sig").write_text("unsigned fixture\n", encoding="utf-8")

    def write_complete_recovery_set(
        self,
        directory: Path,
        *,
        commit: str = "a" * 40,
        skip_package_convergence: bool = False,
        owner_payload: bytes | None = None,
    ) -> Path:
        """Build a complete, genuinely signed Stage-0 fixture."""
        fixture_root = directory.parents[1]
        fixture_root.mkdir(parents=True, exist_ok=True)
        signing_key = fixture_root / "stage0-signing-key"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(signing_key),
            ],
            check=True,
        )
        public_key = signing_key.with_suffix(".pub").read_bytes()
        key_digest = hashlib.sha256(public_key).hexdigest()
        bootstrap_source = BOOTSTRAP.read_text(encoding="utf-8")
        bootstrap_source, replacements = re.subn(
            r'^SIGNING_KEY_SHA256="[0-9a-f]{64}"$',
            f'SIGNING_KEY_SHA256="{key_digest}"',
            bootstrap_source,
            count=1,
            flags=re.MULTILINE,
        )
        self.assertEqual(replacements, 1)
        if skip_package_convergence:
            package_block = """if (( ! BOOTSTRAPPED )); then
  note "converging the signed Ubuntu bootstrap substrate"
  sudo -v
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${BOOTSTRAP_PACKAGES[@]}"
fi
"""
            self.assertIn(package_block, bootstrap_source)
            bootstrap_source = bootstrap_source.replace(
                package_block,
                'note "fixture: package convergence already satisfied"\n',
                1,
            )
        executable = fixture_root / "restore-ubuntu-fixture.sh"
        executable.write_text(bootstrap_source, encoding="utf-8")
        executable.chmod(0o700)
        bootstrap_raw = executable.read_bytes()

        directory.mkdir(parents=True)
        (directory / "recovery-signing-public-key.pub").write_bytes(public_key)
        (directory / "restore-ubuntu.sh").write_bytes(bootstrap_raw)
        artifacts = {}
        for label, filename in {
            "keys": "keys.json.gpg",
            "secrets": "secrets.tar.gpg",
            "private_state": "private-state.tar.gpg",
        }.items():
            payload = f"encrypted-{label}-fixture\n".encode()
            (directory / filename).write_bytes(payload)
            artifacts[label] = {
                "file": filename,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }

        generation_id = "escrow-stage0-fixture"
        share_records = []
        share_payloads = []
        for index in range(1, 5):
            payload = f"shamir-v1:{index}:fixture-{index}\n".encode("ascii")
            share_payloads.append(payload)
            share_records.append(
                {
                    "index": index,
                    "file": f"share-{index:02d}.txt",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        escrow = {
            "schema": "coding-system.escrow-generation.v1",
            "generation_id": generation_id,
            "created_at": "2026-08-04T00:00:00Z",
            "threshold": 2,
            "shares": 4,
            "master_key_sha256": "0" * 64,
            "share_records": share_records,
        }
        escrow_raw = (json.dumps(escrow, indent=2, sort_keys=True) + "\n").encode()
        (directory / "escrow-generation.json").write_bytes(escrow_raw)
        owner_data = None
        if owner_payload is not None:
            owner_name = "openclaw-private-20260805T010203Z.tar.gz.gpg"
            (directory / owner_name).write_bytes(owner_payload)
            owner_data = {
                "file": owner_name,
                "sha256": hashlib.sha256(owner_payload).hexdigest(),
                "size": len(owner_payload),
                "openclaw_version": "2026.7.1-2",
                "requirement": "agent-private-capability",
                "created_at": "2026-08-05T01:02:03Z",
                "source_state_hmac_sha256": "1" * 64,
                "capture_policy": "fresh-native-snapshot",
            }
        manifest = {
            "schema": "coding-system.recovery-set.v2",
            "set_id": "stage0-fixture",
            "created_at": "2026-08-04T00:00:00Z",
            "components": {"coding-system-rebuild": {"commit": commit}},
            "escrow_generation": {
                "generation_id": generation_id,
                "file": "escrow-generation.json",
                "manifest_sha256": hashlib.sha256(escrow_raw).hexdigest(),
            },
            "secrets_manifest": {
                "schema": "coding-system.secrets-manifest.v2",
                "sha256": "0" * 64,
            },
            "bootstrap": {
                "file": "restore-ubuntu.sh",
                "sha256": hashlib.sha256(bootstrap_raw).hexdigest(),
                "size": len(bootstrap_raw),
            },
            "artifacts": artifacts,
            "owner_data": owner_data,
        }
        manifest_path = directory / "recovery-set.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(signing_key),
                "-n",
                "coding-system-recovery-set-v1",
                str(manifest_path),
            ],
            check=True,
        )

        share_root = directory.parent / "escrow" / generation_id
        share_root.mkdir(parents=True)
        directory.parent.chmod(0o700)
        share_root.parent.chmod(0o700)
        share_root.chmod(0o700)
        for record, payload in zip(share_records[:2], share_payloads[:2], strict=True):
            share = share_root / record["file"]
            share.write_bytes(payload)
            share.chmod(0o600)
        return executable

    def test_check_only_resolves_one_recovery_set_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            inbox = home / "secrets-restore-inbox"
            bootstrap = self.write_complete_recovery_set(inbox / "generation-one")
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "CSR_RESTORE_INBOX": str(inbox)})
            result = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env=environment,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertIn("Stage-0 structural check complete", result.stdout)
            self.assertIn("decryption was not attempted", result.stdout)
            self.assertFalse((home / "coding-system-rebuild").exists())

    def test_check_only_accepts_exact_signed_v2_owner_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            inbox = home / "secrets-restore-inbox"
            payload = b"encrypted owner-data fixture\n"
            bootstrap = self.write_complete_recovery_set(
                inbox / "generation-one", owner_payload=payload
            )
            result = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env={
                    **os.environ,
                    "HOME": str(home),
                    "CSR_RESTORE_INBOX": str(inbox),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Stage-0 structural check complete", result.stdout)

    def test_check_only_rejects_owner_swap_missing_extra_duplicate_and_v1(self) -> None:
        for case in ("swap", "missing", "extra", "duplicate", "v1"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                inbox = home / "secrets-restore-inbox"
                recovery_set = inbox / "generation-one"
                bootstrap = self.write_complete_recovery_set(
                    recovery_set, owner_payload=b"encrypted owner-data fixture\n"
                )
                owner = (
                    recovery_set
                    / "openclaw-private-20260805T010203Z.tar.gz.gpg"
                )
                if case == "swap":
                    owner.write_bytes(b"swapped owner-data fixture\n")
                elif case == "missing":
                    owner.unlink()
                elif case == "extra":
                    (
                        recovery_set
                        / "openclaw-private-20260805T010204Z.tar.gz.gpg"
                    ).write_bytes(b"extra owner-data fixture\n")
                elif case == "duplicate":
                    manifest = recovery_set / "recovery-set.json"
                    raw = manifest.read_bytes()
                    manifest.write_bytes(
                        raw.replace(
                            b'  "owner_data":',
                            b'  "owner_data": null,\n  "owner_data":',
                            1,
                        )
                    )
                else:
                    manifest = recovery_set / "recovery-set.json"
                    value = json.loads(manifest.read_text(encoding="utf-8"))
                    value["schema"] = "coding-system.recovery-set.v1"
                    value.pop("owner_data")
                    manifest.write_text(
                        json.dumps(value, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    signature = recovery_set / "recovery-set.json.sig"
                    signature.unlink()
                    subprocess.run(
                        [
                            "/usr/bin/ssh-keygen",
                            "-Y",
                            "sign",
                            "-q",
                            "-f",
                            str(home / "stage0-signing-key"),
                            "-n",
                            "coding-system-recovery-set-v1",
                            str(manifest),
                        ],
                        check=True,
                    )
                completed = subprocess.run(
                    ["/usr/bin/bash", str(bootstrap), "--check-only"],
                    env={
                        **os.environ,
                        "HOME": str(home),
                        "CSR_RESTORE_INBOX": str(inbox),
                    },
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("structural check complete", completed.stdout)

    def test_check_only_rejects_ambiguous_and_invalid_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            inbox = home / "secrets-restore-inbox"
            self.write_recovery_set(inbox / "one")
            self.write_recovery_set(inbox / "two")
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "CSR_RESTORE_INBOX": str(inbox)})
            ambiguous = subprocess.run(
                ["bash", str(BOOTSTRAP), "--check-only"],
                env=environment,
                text=True,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(ambiguous.returncode, 0)
            self.assertIn("exactly one", ambiguous.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            inbox = home / "secrets-restore-inbox"
            bootstrap = self.write_complete_recovery_set(inbox / "one")
            (inbox / "one/recovery-set.json.sig").write_text(
                "tampered\n", encoding="utf-8"
            )
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "CSR_RESTORE_INBOX": str(inbox)})
            invalid = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env=environment,
                text=True,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("signature is invalid", invalid.stderr)

    def test_check_only_uses_authenticated_snapshot_after_source_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            home = Path(temporary) / "home"
            inbox = home / "secrets-restore-inbox"
            recovery_set = inbox / "generation-one"
            bootstrap = self.write_complete_recovery_set(recovery_set)
            marker = Path(temporary) / "stage0-snapshot-pause"
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CSR_RESTORE_INBOX": str(inbox),
                    "CSR_STAGE0_TEST_PAUSE_AFTER_SNAPSHOT": str(marker),
                }
            )
            process = subprocess.Popen(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            ready = Path(f"{marker}.ready")
            deadline = time.monotonic() + 10
            while not ready.is_file() and process.poll() is None:
                if time.monotonic() >= deadline:
                    process.kill()
                    self.fail("Stage-0 did not publish the snapshot synchronization marker")
                time.sleep(0.02)
            self.assertIsNone(process.poll())
            (recovery_set / "recovery-set.json").write_text(
                '{"components":{"coding-system-rebuild":{"commit":"'
                + "b" * 40
                + '"}}}\n',
                encoding="utf-8",
            )
            Path(f"{marker}.continue").touch(mode=0o600)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("Stage-0 structural check complete", stdout)
            self.assertIn("b" * 40, (recovery_set / "recovery-set.json").read_text())

    def test_check_only_does_not_trust_inherited_path_for_signature_gate(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            home = Path(temporary) / "home"
            inbox = home / "secrets-restore-inbox"
            recovery_set = inbox / "generation-one"
            bootstrap = self.write_complete_recovery_set(recovery_set)
            (recovery_set / "recovery-set.json.sig").write_text(
                "bogus-signature\n", encoding="utf-8"
            )
            hostile_bin = Path(temporary) / "hostile-bin"
            hostile_bin.mkdir()
            marker = Path(temporary) / "path-tool-ran"
            for name in ("ssh-keygen", "sha256sum"):
                tool = hostile_bin / name
                tool.write_text(
                    f'#!/usr/bin/env bash\n: > "{marker}"\nexit 0\n', encoding="utf-8"
                )
                tool.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CSR_RESTORE_INBOX": str(inbox),
                    "PATH": f"{hostile_bin}:{environment['PATH']}",
                }
            )
            completed = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("signature is invalid", completed.stderr)
            self.assertFalse(marker.exists())

    def test_explicit_bash_invocation_ignores_exported_functions_before_stage0(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            home = Path(temporary) / "home"
            inbox = home / "secrets-restore-inbox"
            bootstrap = self.write_complete_recovery_set(inbox / "generation-one")
            marker = Path(temporary) / "exported-function-ran"
            environment = {
                **os.environ,
                "HOME": str(home),
                "CSR_RESTORE_INBOX": str(inbox),
                "BASH_FUNC_uname%%": (
                    f"() {{ : > {marker}; /usr/bin/uname \"$@\"; }}"
                ),
                "BASH_FUNC_sha256sum%%": (
                    f"() {{ : > {marker}; /usr/bin/sha256sum \"$@\"; }}"
                ),
            }

            completed = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Stage-0 structural check complete", completed.stdout)
            self.assertFalse(marker.exists())

    def test_check_only_requires_exactly_two_matching_shares(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            home = Path(temporary) / "home"
            inbox = home / "secrets-restore-inbox"
            recovery_set = inbox / "generation-one"
            bootstrap = self.write_complete_recovery_set(recovery_set)
            share_root = inbox / "escrow/escrow-stage0-fixture"
            next(share_root.glob("share-*.txt")).unlink()
            completed = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env={**os.environ, "HOME": str(home), "CSR_RESTORE_INBOX": str(inbox)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("escrow shares are incomplete or unsafe", completed.stderr)
            self.assertNotIn("structural check complete", completed.stdout)

    def test_check_only_rejects_insecure_escrow_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            home = Path(temporary) / "home"
            inbox = home / "secrets-restore-inbox"
            bootstrap = self.write_complete_recovery_set(inbox / "generation-one")
            (inbox / "escrow").chmod(0o755)
            completed = subprocess.run(
                ["/usr/bin/bash", str(bootstrap), "--check-only"],
                env={**os.environ, "HOME": str(home), "CSR_RESTORE_INBOX": str(inbox)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("escrow shares are incomplete or unsafe", completed.stderr)
            self.assertNotIn("structural check complete", completed.stdout)

    def test_stage0_cleans_snapshot_when_make_handoff_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "bin").mkdir(parents=True)
            (repository / "Makefile").write_text(
                ".PHONY: restore\nrestore:\n\t@exit 73\n", encoding="utf-8"
            )
            shutil.copy2(
                ROOT / "bin/verify-exact-checkout.py",
                repository / "bin/verify-exact-checkout.py",
            )
            self.install_generation_helper(repository)
            doctor = repository / "bin/doctor.sh"
            doctor.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            doctor.chmod(0o700)
            restore = repository / "bin/restore.sh"
            restore.write_text("#!/usr/bin/env bash\nexit 73\n", encoding="utf-8")
            restore.chmod(0o755)
            subprocess.run(["/usr/bin/git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["/usr/bin/git", "add", "."], cwd=repository, check=True)
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "user.name=Stage0 Test",
                    "-c",
                    "user.email=stage0@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=repository,
                check=True,
            )
            self.remove_group_world_write(repository)
            commit = subprocess.run(
                ["/usr/bin/git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            home = root / "home"
            inbox = home / "secrets-restore-inbox"
            bootstrap = self.write_complete_recovery_set(
                inbox / "generation-one",
                commit=commit,
                skip_package_convergence=True,
            )
            snapshot_tag = secrets.token_hex(16)
            snapshot_pattern = (
                f"csr-recovery-snapshot.{os.geteuid()}.{snapshot_tag}.*"
            )
            before = set(Path("/tmp").glob(snapshot_pattern))
            self.guard_published_generations()
            completed = subprocess.run(
                ["/usr/bin/bash", str(bootstrap)],
                env={
                    **os.environ,
                    "HOME": str(home),
                    "CSR_RESTORE_INBOX": str(inbox),
                    "CSR_REPOSITORY_DIR": str(repository),
                    "CSR_STAGE0_TEST_SNAPSHOT_TAG": snapshot_tag,
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("repository restore target failed", completed.stderr)
            after = set(Path("/tmp").glob(snapshot_pattern))
            self.assertEqual(after, before)

            verifier_object = subprocess.run(
                [
                    "/usr/bin/git",
                    "rev-parse",
                    f"{commit}:bin/verify-exact-checkout.py",
                ],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            malicious_marker = root / "forged-object-verifier-ran"
            malicious = (
                "from pathlib import Path\n"
                f"Path({str(malicious_marker)!r}).touch()\n"
            ).encode("utf-8")
            forged_object = (
                repository
                / ".git/objects"
                / verifier_object[:2]
                / verifier_object[2:]
            )
            forged_object.chmod(0o600)
            forged_object.write_bytes(
                zlib.compress(
                    b"blob " + str(len(malicious)).encode("ascii") + b"\0" + malicious
                )
            )
            forged = subprocess.run(
                ["/usr/bin/bash", str(bootstrap)],
                env={
                    **os.environ,
                    "HOME": str(home),
                    "CSR_RESTORE_INBOX": str(inbox),
                    "CSR_REPOSITORY_DIR": str(repository),
                    "CSR_STAGE0_TEST_SNAPSHOT_TAG": snapshot_tag,
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(forged.returncode, 0)
            self.assertIn("exact protected commit tree", forged.stderr)
            self.assertFalse(malicious_marker.exists())
            final = set(Path("/tmp").glob(snapshot_pattern))
            self.assertEqual(final, before)

    def test_stage0_handoff_ignores_entrypoint_replaced_after_checkout_verification(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "bin").mkdir(parents=True)
            (repository / "Makefile").write_text("restore:\n\t@true\n", encoding="utf-8")
            shutil.copy2(
                ROOT / "bin/verify-exact-checkout.py",
                repository / "bin/verify-exact-checkout.py",
            )
            self.install_generation_helper(repository)
            doctor = repository / "bin/doctor.sh"
            doctor.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            doctor.chmod(0o755)
            authentic_marker = root / "authenticated-entrypoint-ran"
            restore = repository / "bin/restore.sh"
            restore.write_text(
                f"#!/usr/bin/env bash\n: > {authentic_marker}\nexit 0\n",
                encoding="utf-8",
            )
            restore.chmod(0o755)
            subprocess.run(["/usr/bin/git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["/usr/bin/git", "add", "."], cwd=repository, check=True)
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "user.name=Stage0 Race Test",
                    "-c",
                    "user.email=stage0-race@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=repository,
                check=True,
            )
            self.remove_group_world_write(repository)
            commit = subprocess.run(
                ["/usr/bin/git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            home = root / "home"
            inbox = home / "secrets-restore-inbox"
            bootstrap = self.write_complete_recovery_set(
                inbox / "generation-one",
                commit=commit,
                skip_package_convergence=True,
            )
            pause = root / "handoff-pause"
            malicious_marker = root / "replacement-ran"
            self.guard_published_generations()
            process = subprocess.Popen(
                ["/usr/bin/bash", str(bootstrap)],
                env={
                    **os.environ,
                    "HOME": str(home),
                    "CSR_RESTORE_INBOX": str(inbox),
                    "CSR_REPOSITORY_DIR": str(repository),
                    "CSR_STAGE0_TEST_PAUSE_BEFORE_HANDOFF": str(pause),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            ready = Path(f"{pause}.ready")
            deadline = time.monotonic() + 10
            while not ready.is_file() and process.poll() is None:
                if time.monotonic() >= deadline:
                    process.kill()
                    self.fail("Stage-0 did not publish the handoff synchronization marker")
                time.sleep(0.02)
            self.assertIsNone(process.poll())
            restore.write_text(
                f"#!/usr/bin/env bash\n: > {malicious_marker}\nexit 0\n",
                encoding="utf-8",
            )
            restore.chmod(0o755)
            Path(f"{pause}.continue").touch(mode=0o600)
            _stdout, stderr = process.communicate(timeout=60)

            # The handoff never reads the mutable checkout: Stage-0 rebuilds the
            # entry point from the authenticated Git objects into a root-owned
            # immutable generation, so the replacement is simply never executed.
            self.assertEqual(process.returncode, 0, stderr)
            self.assertTrue(authentic_marker.exists())
            self.assertFalse(malicious_marker.exists())

    def test_scripts_never_execute_remote_shell_pipelines(self) -> None:
        source = BOOTSTRAP.read_text() + (ROOT / "bin/prepare.sh").read_text()
        self.assertNotRegex(source, r"curl[^\n|]*\|\s*(?:ba)?sh")
        self.assertNotRegex(source, r"wget[^\n|]*\|\s*(?:ba)?sh")
        self.assertIn("os.memfd_create", source)
        self.assertIn("F_ADD_SEALS", source)
        self.assertNotIn('make -C "$REPO_DIR" restore', source)


if __name__ == "__main__":
    unittest.main()
