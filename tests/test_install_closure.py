#!/usr/bin/env python3
"""Regression checks for fail-closed closure phases in bin/install.sh."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
# The compatibility checkout sits beside the repository on the reference host
# and in $HOME on a fresh one (bin/components.sh).
AAS_CHECKOUT = next(
    (path for path in (ROOT.parent / "ai-agents-skills", Path.home() / "ai-agents-skills") if path.is_dir()),
    ROOT.parent / "ai-agents-skills",
)


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
MIGRATION_SCRIPT = ROOT / "bin/migrate-openclaw-config.py"
MIGRATION_SPEC = importlib.util.spec_from_file_location(
    "migrate_openclaw_config", MIGRATION_SCRIPT
)
assert MIGRATION_SPEC and MIGRATION_SPEC.loader
MIGRATION = importlib.util.module_from_spec(MIGRATION_SPEC)
MIGRATION_SPEC.loader.exec_module(MIGRATION)
OPENCLAW_RUNTIME_SCRIPT = ROOT / "bin/verify-openclaw-runtime.py"
OPENCLAW_RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "verify_openclaw_runtime", OPENCLAW_RUNTIME_SCRIPT
)
assert OPENCLAW_RUNTIME_SPEC and OPENCLAW_RUNTIME_SPEC.loader
OPENCLAW_RUNTIME = importlib.util.module_from_spec(OPENCLAW_RUNTIME_SPEC)
OPENCLAW_RUNTIME_SPEC.loader.exec_module(OPENCLAW_RUNTIME)


class InstallClosureTests(unittest.TestCase):
    def test_claude_managed_skills_use_only_the_fixed_shared_runtime(self) -> None:
        runner = ROOT / "agents/claude/skills/_run.sh"
        source = runner.read_text(encoding="utf-8")
        self.assertIn("unset OPENCLAW_SECRETS_FILE AAS_SECRETS_FILE", source)
        self.assertNotIn("export OPENCLAW_SECRETS_FILE", source)
        self.assertNotIn("export AAS_SECRETS_FILE", source)
        self.assertIn('$HOME/.local/share/ai-agents-skills/runtime', source)
        for skill in (
            "skills/zotero/*",
            "skills/calibre/*",
            "skills/vnthuquan/*",
            "skills/modal-research-compute/*",
        ):
            self.assertIn(skill, source)

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            shared = home / ".local/share/ai-agents-skills/runtime"
            shared.mkdir(parents=True)
            fake = shared / "run_skill.sh"
            fake.write_text(
                "#!/bin/bash\n"
                "set -eu\n"
                "test -z \"${AAS_SECRETS_FILE+x}\"\n"
                "test -z \"${OPENCLAW_SECRETS_FILE+x}\"\n"
                "printf 'runtime=%s\\n' \"$AAS_RUNTIME_ROOT\"\n"
                "printf 'arg=%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            environment = {
                "HOME": str(home),
                "PATH": "/usr/bin:/bin",
                "AAS_RUNTIME_ROOT": "/attacker/runtime",
                "AAS_SECRETS_FILE": "/attacker/broad.json",
                "OPENCLAW_SECRETS_FILE": "/attacker/openclaw.json",
            }
            completed = subprocess.run(
                [str(runner), "skills/zotero/run_zot.sh", "doctor"],
                env=environment,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(f"runtime={shared}", completed.stdout)
            self.assertIn("arg=skills/zotero/run_zot.sh", completed.stdout)
            self.assertIn("arg=doctor", completed.stdout)

    def test_claude_managed_skill_never_falls_back_to_local_runtime(self) -> None:
        runner = ROOT / "agents/claude/skills/_run.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            local = home / ".claude/skills/zotero/run_zot.sh"
            marker = home / "local-runtime-executed"
            local.parent.mkdir(parents=True)
            local.write_text(
                f"#!/bin/bash\nprintf local > {marker}\n",
                encoding="utf-8",
            )
            local.chmod(0o755)

            completed = subprocess.run(
                [str(runner), "skills/zotero/run_zot.sh", "doctor"],
                env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("shared ai-agents-skills runtime is unavailable", completed.stderr)
            self.assertFalse(marker.exists())

    def test_pinned_aas_runtime_converges_before_any_service_activation(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_eight = source.index("# 8 ─ skills via ai-agents-skills")
        retirement = source.index("--retire-claude-runtime-only", phase_eight)
        install = source.index('case_id":"install.phase8.aas-install', retirement)
        digest_gate = source.index("AAS_RUNTIME_DIGEST_PAIRS", install)
        clobber_gate = source.index('gate "_run.sh intact"', digest_gate)
        services = source.index("# 11 ─", clobber_gate)
        self.assertLess(phase_eight, retirement)
        self.assertLess(retirement, install)
        self.assertLess(install, digest_gate)
        self.assertLess(digest_gate, clobber_gate)
        self.assertLess(clobber_gate, services)
        self.assertIn(
            "$AAS_IMMUTABLE/canonical/runtime/runners/run_skill.sh",
            source[digest_gate:clobber_gate],
        )
        self.assertIn(
            "installed shared runtime differs from pinned ai-agents-skills source",
            source[digest_gate:clobber_gate],
        )
        pre_runtime = source[:digest_gate]
        for activation in (
            "systemctl --user start",
            "systemctl --user restart",
            "openclaw gateway start",
            "openclaw agent start",
        ):
            self.assertNotIn(activation, pre_runtime)

    def test_aas_target_credentials_have_an_explicit_recovery_classification(self) -> None:
        lock_lines = (ROOT / "components.lock").read_text(encoding="utf-8").splitlines()
        pins = [
            line.rsplit("@", 1)[1]
            for line in lock_lines
            if line.startswith("ai-agents-skills=")
        ]
        self.assertEqual(len(pins), 1)
        self.assertRegex(pins[0], r"^[0-9a-f]{40}$")
        aas_root = AAS_CHECKOUT
        self.assertTrue(aas_root.is_dir())
        completed = subprocess.run(
            ["git", "show", f"{pins[0]}:manifest/target-state.yaml"],
            cwd=aas_root,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        target_state = json.loads(completed.stdout)
        recovery = yaml.safe_load(
            (ROOT / "secrets/secrets-manifest.yaml").read_text(encoding="utf-8")
        )
        classified = {
            str(entry["path"]).rstrip("/")
            for entry in recovery["entries"]
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        exceptions = set()
        environment_projections = set()
        for target_name, target in target_state["targets"].items():
            for surface in target.get("surfaces", [target]):
                for authority in surface["credential_authorities"]:
                    record = (
                        target_name,
                        authority["kind"],
                        authority["path"].rstrip("/"),
                        authority["restore_policy"],
                    )
                    if authority["kind"] == "environment":
                        environment_projections.add(record)
                        continue
                    if (
                        authority["kind"] == "native-store"
                        and authority["restore_policy"] == "reauth-if-nonportable"
                    ):
                        exceptions.add(record)
                        continue
                    self.assertIn(record[2], classified, record)
        self.assertEqual(
            exceptions,
            {("copilot", "native-store", ".copilot", "reauth-if-nonportable")},
        )
        # The pinned target state carries no environment-kind authority: Copilot's
        # former COPILOT_GITHUB_TOKEN/GITHUB_TOKEN/GH_TOKEN projections were replaced
        # by the strict-env-file authority asserted below. A non-empty set here means
        # a target reintroduced an ambient environment credential that no manifest
        # entry can classify, so it must be triaged rather than absorbed.
        self.assertEqual(environment_projections, set())
        copilot_authorities = [
            entry
            for entry in recovery["entries"]
            if entry.get("id") == "aas-copilot-provider-authority"
        ]
        self.assertEqual(len(copilot_authorities), 1)
        copilot_authority = copilot_authorities[0]
        defaults = recovery["entry_defaults"]
        self.assertEqual(
            copilot_authority.get("classification", defaults["classification"]),
            "authority",
        )
        self.assertTrue(copilot_authority.get("backup", defaults["backup"]))
        self.assertEqual(
            copilot_authority["path"],
            ".config/ai-agents-skills/providers/copilot.env",
        )

    def test_openclaw_auth_report_rejects_unexpected_fields_before_serialization(self) -> None:
        report = {
            "schema": "openclaw.agent-auth-closure/v2",
            "status": "PASS",
            "runtimeVersion": "2026.7.1-2",
            "verificationMode": "offline-structural-only",
            "openclawExecuted": False,
            "networkEnabled": False,
            "agents": [
                {
                    "agentId": "main",
                    "status": "PASS",
                    "canonicalStore": {
                        "exists": True,
                        "integrity": True,
                        "schemaVersion": 1,
                        "appVersion": None,
                        "authStoreRows": 1,
                        "profileCount": 1,
                        "configured": True,
                        "authorityJsonValid": True,
                        "executableSecretRefFree": True,
                        "credentialSourceKinds": [],
                        "redactionSentinelFree": True,
                        "device": 1,
                        "inode": 2,
                        "size": 3,
                        "mtimeNs": 4,
                        "ctimeNs": 5,
                    },
                    "reasons": [],
                }
            ],
            "failureCount": 0,
            "failures": [],
        }
        sanitized = OPENCLAW_RUNTIME.sanitize_agent_auth_report(report)
        self.assertEqual(sanitized, report)
        canary = "credential-canary-never-serialize"
        report["agents"][0]["canonicalStore"]["unexpected"] = canary
        with self.assertRaisesRegex(ValueError, "metadata is invalid") as raised:
            OPENCLAW_RUNTIME.sanitize_agent_auth_report(report)
        self.assertNotIn(canary, str(raised.exception))

    def test_classroom50_private_reader_accumulates_short_descriptor_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / ".secrets.env"
            authority.write_text(
                'CLASSROOM50_ORG_ALLOWLIST=fixture-org,foundation50\n',
                encoding="utf-8",
            )
            authority.chmod(0o600)
            real_read = os.read
            read_lengths: list[int] = []

            def short_read(descriptor: int, count: int) -> bytes:
                block = real_read(descriptor, min(count, 3))
                read_lengths.append(len(block))
                return block

            with mock.patch.object(MIGRATION.os, "read", side_effect=short_read):
                observed = MIGRATION.read_classroom50_allowlist(authority)

            self.assertEqual(observed, "fixture-org,foundation50")
            self.assertGreater(len(read_lengths), 2)
            self.assertEqual(read_lengths[-1], 0)

    def test_openclaw_runtime_user_tracks_nondefault_host_account(self) -> None:
        with (
            mock.patch.object(MIGRATION.os, "getuid", return_value=1000),
            mock.patch.object(MIGRATION.os, "getgid", return_value=1000),
        ):
            self.assertEqual(MIGRATION.host_runtime_user(), "1000:1000")

    def test_component_cannot_downgrade_openclaw_and_plugins_use_lockfiles(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn(
            'export PATH="$PATH:/usr/local/sbin:/usr/local/bin:$HOME/.npm-global/bin:$HOME/.local/bin"',
            source,
        )
        self.assertIn(
            'gate "OpenClaw npm selector and descriptor target are owner-safe"',
            source,
        )
        self.assertIn("--skip-openclaw-install", source)
        self.assertIn("--convergent", source)
        component_call = source.split(
            'bash "$OPENCLAW_COMPONENT/install.sh"', 1
        )[1].split("# the \"don't clobber restored secrets\" gate", 1)[0]
        self.assertNotIn("--skip-config", component_call)
        self.assertIn("npm ci --ignore-scripts --omit=dev", source)
        self.assertIn('openclaw_exact plugins install --pin --force "$plugin_spec"', source)
        self.assertNotIn("npm install --silent || echo", source)
        self.assertIn("openclaw_exact exec-policy set --host sandbox", source)
        self.assertIn("systemctl --user restart openclaw-gateway", source)
        self.assertIn("openclaw_exact sandbox recreate --all --force", source)
        owner_restore = source.index("restore-openclaw-owner-data.sh")
        restore_source = (ROOT / "bin/secrets-restore.sh").read_text(encoding="utf-8")
        self.assertLess(
            restore_source.index("validate-set"),
            restore_source.index("secret-restore-quiescence.sh"),
        )
        self.assertLess(
            restore_source.index("secret-restore-quiescence.sh"),
            restore_source.index('ARGS=(restore'),
        )
        quiescence = (ROOT / "bin/secret-restore-quiescence.sh").read_text(
            encoding="utf-8"
        )
        for owner in (
            "claude",
            "codex",
            "copilot",
            "gcloud",
            "gh",
            "grok",
            "lean-explore",
            "opencode",
            "rclone",
            "wrangler",
        ):
            self.assertIn(f'"{owner}"', quiescence)
        self.assertIn("grok-tailscaled", quiescence)
        self.assertIn("openclaw-gateway.service", quiescence)
        for worker in (
            "send-queue-worker.service",
            "openclaw-sage-worker.service",
            "openclaw-manim-worker.service",
            "openclaw-email-worker.service",
        ):
            self.assertIn(worker, quiescence)
        self.assertIn("job_queue_worker", quiescence)
        phase_seven = source.split('# 7 ─ OpenClaw slice', 1)[1].split(
            '# 8 ─ skills via ai-agents-skills', 1
        )[0]
        self.assertLess(
            phase_seven.index("quiesce_openclaw_writers"),
            phase_seven.index("restore-openclaw-owner-data.sh"),
        )
        component_converge = source.index("--convergent", owner_restore)
        config_migration = source.index("migrate-openclaw-config.py", component_converge)
        plugin_install = source.index("openclaw_exact plugins install", component_converge)
        self.assertLess(owner_restore, component_converge)
        self.assertLess(config_migration, plugin_install)

    def test_required_python_environments_are_not_suppressed(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_nine = source.split("# 9 ─", 1)[1].split("# 10 ─", 1)[0]
        self.assertNotIn("|| true", phase_nine)

    def test_backup_and_full_verify_bind_configured_credential_capabilities(self) -> None:
        pack = (ROOT / "bin/secrets-pack.sh").read_text(encoding="utf-8")
        legacy_import = (ROOT / "bin/secrets-import-legacy-zip.sh").read_text(
            encoding="utf-8"
        )
        verify = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        manifest = (ROOT / "secrets/secrets-manifest.yaml").read_text(
            encoding="utf-8"
        )
        contract = "skill-credential-source-contract.json"
        self.assertIn(f"--output \"$SOURCE_CAPABILITY_CONTRACT\"", pack)
        self.assertIn("--expect-source-capabilities", verify)
        self.assertIn(contract, verify)
        self.assertIn(contract, manifest)
        self.assertIn("required: true", manifest.split(contract, 1)[1].split("}", 1)[0])
        self.assertIn("materialize-secret-projections.py", legacy_import)
        self.assertIn("verify-skill-credentials.py", legacy_import)
        self.assertIn("secrets_tool.py\" fixperms", legacy_import)
        self.assertIn("stage-legacy-signing-authority", legacy_import)
        self.assertIn("CSR_RECOVERY_SIGNING_KEY_FILE", legacy_import)
        self.assertIn("recovery-signing-public-key.pub", legacy_import)
        self.assertLess(
            legacy_import.index("manifest-check"),
            legacy_import.index("verify-legacy-zip"),
        )
        self.assertIn(contract, legacy_import)
        self.assertLess(
            legacy_import.index("stage-legacy-signing-authority"),
            legacy_import.index("fixperms"),
        )
        self.assertLess(
            legacy_import.index("fixperms"),
            legacy_import.index("materialize-secret-projections.py"),
        )
        self.assertLess(
            legacy_import.index("verify-skill-credentials.py"),
            legacy_import.index("create-set"),
        )
        self.assertIn("migrate-owner-settings.py", pack)
        self.assertLess(
            pack.index("migrate-owner-settings.py"),
            pack.index("materialize-secret-projections.py"),
        )

    def test_recovery_pack_embeds_one_fresh_or_explicitly_reviewed_owner_archive(self) -> None:
        pack = (ROOT / "bin/secrets-pack.sh").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("inspect-owner-source", pack)
        self.assertIn("--owner-data-archive", pack)
        self.assertIn("--expected-owner-source-state-hmac", pack)
        self.assertIn("--owner-data-capture-policy", pack)
        self.assertIn("fresh-native-snapshot", pack)
        self.assertIn("reviewed-prebuilt-override", pack)
        self.assertIn("USE_REVIEWED_PREBUILT_OWNER_ARCHIVE", pack)
        self.assertIn("owner_archive.py\" decrypt", pack)
        self.assertIn("owner_archive.py\" verify", pack)
        self.assertIn("inspect-owner-extracted-source", pack)
        self.assertIn("verify-extract", pack)
        self.assertIn("OWNER_ARCHIVE_SOURCE_HMAC", pack)
        self.assertIn(
            "verified OpenClaw owner archive does not match the live source capability state",
            pack,
        )
        self.assertIn("--expected-runtime-version", pack)
        self.assertIn("--verify", pack)
        self.assertTrue(pack.startswith("#!/usr/bin/bash -p\n"))
        self.assertIn('secure_temp.py" create --prefix csr-owner-review-', pack)
        self.assertNotIn("/tmp/csr-owner-review", pack)
        self.assertIn('/usr/bin/bash -p "$OPENCLAW_COMPONENT/backup.sh"', pack)
        self.assertIn('/usr/bin/bash -p "$REPO/bin/sign-recovery-set.sh"', pack)
        self.assertIn("@/usr/bin/bash -p bin/secrets-pack.sh", makefile)
        self.assertNotIn("ls -1t", pack)
        self.assertIn("materialize-legacy", pack)
        self.assertLess(
            pack.index("materialize-legacy"), pack.index("inspect-owner-source")
        )
        self.assertLess(pack.index("inspect-owner-source"), pack.index("create-set"))
        self.assertLess(pack.index("backup.sh"), pack.index("create-set"))
        self.assertGreaterEqual(pack.count("owner_source_state)"), 2)

    def test_signed_v2_owner_digest_is_the_only_automatic_authority_activation(self) -> None:
        wrapper = (ROOT / "bin/restore-openclaw-owner-data.sh").read_text(
            encoding="utf-8"
        )
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn("CSR_SIGNED_OWNER_DATA_SHA256", install)
        self.assertIn("inspect-set-owner", install)
        self.assertIn("CSR_SIGNED_OWNER_DATA_SHA256", wrapper)
        self.assertIn("verify-recovery-signature.sh", wrapper)
        self.assertIn("inspect-set-owner", wrapper)
        self.assertIn("--signed-recovery-set-v2-owner-sha256", wrapper)
        self.assertNotIn("ACTIVATE_REVIEWED_ARCHIVE_AUTHORITY", wrapper)
        self.assertTrue(wrapper.startswith("#!/usr/bin/bash -p\n"))
        self.assertIn('/usr/bin/bash -p "$RESTORE"', wrapper)
        self.assertIn(
            '/usr/bin/bash -p "$REPO/bin/restore-openclaw-owner-data.sh"',
            install,
        )

    def test_shell_startup_keeps_service_and_opengauss_credentials_bounded(self) -> None:
        bashrc = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        profile = (ROOT / "system/shell/profile.block.sh").read_text(encoding="utf-8")
        for source in (bashrc, profile):
            self.assertNotIn(".openclaw/moltbook.env", source)
            self.assertNotIn("MOLTBOOK_API_KEY", source)
            self.assertNotIn("$GAUSS_HOME/.env", source)
            self.assertNotIn("${GAUSS_HOME}/.env", source)
            self.assertNotIn(".gauss/.env", source)
            self.assertNotIn("_gauss_shell_autoenv", source)
        self.assertIn("export GAUSS_HOME=", bashrc)
        self.assertIn("export GAUSS_HOME=", profile)

    def test_backup_refresh_observes_drift_without_rewriting_release_locks(self) -> None:
        source = (ROOT / "bin/refresh-state.sh").read_text(encoding="utf-8")
        self.assertIn('OBS="$PKG/observed"', source)
        self.assertIn('> "$OBS/npm-globals.txt"', source)
        self.assertIn('> "$OBS/requirements/workspace-local.txt"', source)
        self.assertNotIn('> "$PKG/npm-globals.txt"', source)
        self.assertNotIn('> "$PKG/requirements/workspace-local.txt"', source)
        self.assertIn("check-closure-drift.py", source)
        self.assertNotIn("git ls-remote", source)

        drift_source = (ROOT / "bin/check-closure-drift.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("installed_component_path(", drift_source)
        self.assertNotIn('"external"', drift_source)

    def test_local_coder_and_exit_forensics_restore_with_their_helpers(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_six = install[install.index("# 6 ─ render public configs"):install.index("# 7 ─ OpenClaw slice")]
        self.assertIn('"$REPO/system/libexec"', phase_six)
        self.assertIn('"$HOME/.local/libexec/$relative"', phase_six)
        phase_eleven = install[install.index("# 11 ─ generated state"):install.index("# 12 ─ verification")]
        # a restored host has the locked node under ~/.npm-global, not /usr/bin/node
        self.assertIn('NODE_FOR_UNITS="$HOME/.npm-global/bin/node"', phase_eleven)
        self.assertIn('-e "s|/usr/bin/node |$NODE_FOR_UNITS |g"', phase_eleven)
        self.assertIn('install -d -m 0755 "$HOME/Research"', phase_eleven)
        self.assertIn('install -d -m 0700 "$HOME/.local/state/chatgpt-local-coder"', phase_eleven)
        units = ("chatgpt-local-coder.service", "chatgpt-local-coder-tunnel.service",
                 "chatgpt-local-coder-tunnel-health.service", "chatgpt-local-coder-tunnel-health.timer",
                 "exit-forensics.service")
        state = (ROOT / "system/systemd/units.state").read_text(encoding="utf-8")
        refresh = (ROOT / "bin/refresh-state.sh").read_text(encoding="utf-8")
        for unit in units:
            with self.subTest(unit=unit):
                self.assertTrue((ROOT / "system/systemd/user" / unit).is_file())
                self.assertIn(f"\n{unit}\t", "\n" + state)
                self.assertIn(unit, refresh)
        self.assertTrue((ROOT / "system/libexec/chatgpt-local-coder/tunnel-health.sh").is_file())
        self.assertTrue((ROOT / "system/bin/exit-forensics.sh").is_file())

    def test_chatgpt_local_coder_is_a_pinned_component_built_once(self) -> None:
        lock = (ROOT / "components.lock").read_text(encoding="utf-8")
        self.assertRegex(
            lock,
            r"(?m)^chatgpt-local-coder=https://github\.com/hoanganhduc/chatgpt-local-coder\.git@[0-9a-f]{40}$",
        )
        components = (ROOT / "bin/components.sh").read_text(encoding="utf-8")
        branch = components[components.index('if [[ "$name" == "chatgpt-local-coder"'):]
        branch = branch[: branch.index("    continue\n  fi\n")]
        # an existing development checkout is never touched
        self.assertLess(branch.index("existing checkout preserved"), branch.index("clone -q"))
        self.assertIn("unset NODE_ENV", branch)
        self.assertIn("ci --include=dev --ignore-scripts", branch)
        self.assertIn("run build", branch)

    def test_chatgpt_local_coder_cli_is_linked_like_npm_link(self) -> None:
        components = (ROOT / "bin/components.sh").read_text(encoding="utf-8")
        start = components.index("link_local_coder_cli() {")
        function = components[start: components.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".npm-global/lib/node_modules").mkdir(parents=True)
            (home / ".npm-global/bin").mkdir()
            checkout = home / "chatgpt-local-coder"
            (checkout / "dist/cli").mkdir(parents=True)
            (checkout / "package.json").write_text(json.dumps({"bin": {
                "chatgpt-local-coder": "dist/cli/main.js", "clc": "dist/cli/main.js",
                "codex-mcp-server": "dist/index.js"}}), encoding="utf-8")
            for name in ("dist/cli/main.js", "dist/index.js"):
                (checkout / name).write_text("#!/usr/bin/env node\n", encoding="utf-8")
                (checkout / name).chmod(0o644)
            run = lambda: subprocess.run(
                ["/usr/bin/bash", "-c", function + f'\nlink_local_coder_cli "{checkout}"'],
                env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                text=True, capture_output=True, check=False,
            )
            for attempt in (1, 2):  # a rerun converges to the same links
                completed = run()
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                os.readlink(home / ".npm-global/lib/node_modules/chatgpt-local-coder"),
                "../../../chatgpt-local-coder",
            )
            for name, target in (("chatgpt-local-coder", "dist/cli/main.js"),
                                 ("clc", "dist/cli/main.js"),
                                 ("codex-mcp-server", "dist/index.js")):
                link = home / ".npm-global/bin" / name
                self.assertEqual(os.readlink(link),
                                 f"../lib/node_modules/chatgpt-local-coder/{target}")
                self.assertEqual(link.resolve(), (checkout / target).resolve())
                self.assertTrue(os.access(checkout / target, os.X_OK))
            # A real file where a link belongs is left alone and reported.
            (home / ".npm-global/bin/clc").unlink()
            (home / ".npm-global/bin/clc").write_text("owner file\n", encoding="utf-8")
            completed = run()
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual((home / ".npm-global/bin/clc").read_text(encoding="utf-8"), "owner file\n")

    def test_compatibility_is_gated_before_services(self) -> None:
        source = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        compatibility = source.index("verify-openclaw-compat.py")
        services = source.index("# 11 ─")
        self.assertLess(compatibility, services)
        self.assertIn('verify-openclaw-compat.py" --static-only', source)
        self.assertIn("a full restore cannot skip the locked OpenClaw sandbox image", source)
        gate = source.split(
            'gate "OpenClaw compatibility tuple before service startup"', 1
        )[1].split("# 11 ─", 1)[0]
        self.assertLess(
            gate.index("[[ $DEGRADED_MODE -eq 1 ]]"),
            gate.index("skip_enabled SKIP_DOCKER"),
        )

    def test_verifier_requires_an_explicit_profile_and_effective_runtime_gate(self) -> None:
        source = (ROOT / "bin/verify.sh").read_text(encoding="utf-8")
        self.assertIn('PROFILE="full"', source)
        self.assertNotIn("have_user_systemd || DEGRADED=1", source)
        self.assertIn("verify-openclaw-runtime.py", source)
        self.assertIn(
            '$HOME/.local/state/coding-system/restore/openclaw-runtime-verification.json',
            source,
        )
        self.assertIn('--openclaw-runtime-report "$OPENCLAW_RUNTIME_REPORT"', source)
        runtime = (ROOT / "bin/verify-openclaw-runtime.py").read_text(encoding="utf-8")
        self.assertIn("os.fchmod(descriptor, 0o600)", runtime)
        for command in (
            '"skills", "check", "--json"',
            '"channels", "status", "--probe"',
            '"plugins", "doctor"',
            '"security", "audit", "--deep", "--json"',
            '"docker", "run", "--rm", "--read-only"',
        ):
            self.assertIn(command, runtime)

    def test_split_queue_workers_use_the_reviewed_generational_host_runtime(self) -> None:
        queue_kinds = {
            "send-queue-worker.service": "send",
            "openclaw-sage-worker.service": "sage",
            "openclaw-manim-worker.service": "manim",
            "openclaw-email-worker.service": "email",
        }
        for unit, queue_kind in queue_kinds.items():
            with self.subTest(unit=unit):
                service = (OPENCLAW_BOT / "systemd/user" / unit).read_text(
                    encoding="utf-8"
                )
                self.assertIn("{{ OPENCLAW_LIBEXEC }}/host_exec.py", service)
                self.assertIn("--artifact owner_state_lock.py", service)
                self.assertIn("--artifact job_queue_worker.sh", service)
                self.assertIn(f"OPENCLAW_QUEUE_KIND={queue_kind}", service)
                self.assertNotIn("/skills/zotero/job_queue_worker.sh", service)
                self.assertNotIn("ExecStart={{ OPENCLAW_WORKSPACE }}", service)

    def test_component_units_are_exact_and_phase_eleven_installs_them_transactionally(self) -> None:
        component_root = OPENCLAW_BOT / "systemd/user"
        managed = sorted(
            path.relative_to(component_root)
            for path in component_root.rglob("*")
            if path.is_file()
        )
        # The component owns these units (D13): phase 11 installs them through its
        # transaction, and the repository loop below skips every one of them.
        self.assertEqual(len(managed), 14)

        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_eleven = install.split("# 11 ─", 1)[1].split("# 12 ─", 1)[0]
        transaction = phase_eleven.index("--services-only")
        confirmation = phase_eleven.index(
            "--install-reviewed-services INSTALL_REVIEWED_USER_SERVICES"
        )
        registration = phase_eleven.index(
            "reconcile-systemd-user-units.sh\" --registration-only"
        )
        self.assertLess(transaction, confirmation)
        self.assertLess(confirmation, registration)
        for relative in managed:
            self.assertIn(relative.as_posix(), phase_eleven)

    def test_config_migration_removes_open_access_and_bounds_sandboxes(self) -> None:
        lock = ROOT / "system/openclaw/compatibility.lock.json"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "openclaw.json"
            allowlist = Path(temporary) / ".secrets.env"
            allowlist.write_text(
                'CLASSROOM50_ORG_ALLOWLIST=fixture-org,foundation50\n',
                encoding="utf-8",
            )
            allowlist.chmod(0o600)
            config.write_text(
                json.dumps(
                    {
                        "agents": {
                            "defaults": {
                                "model": {"fallbacks": ["strong", "groq/openai/gpt-oss-120b"]},
                                "sandbox": {
                                    "docker": {
                                        "env": {
                                            "AAS_SECRETS_FILE": "/workspace/stale-shared.json",
                                            "GETSCIPAPERS_CACHE_DIR": "/workspace/cache/getscipapers",
                                            "GETSCIPAPERS_CONFIG_DIR": "/workspace/secrets/getscipapers",
                                            "GETSCIPAPERS_SKILL_CONFIG": "/workspace/stale-skill.json",
                                            "GH_CONFIG_DIR": "/workspace/stale-gh",
                                            "OPENCLAW_SECRETS_FILE": "/workspace/stale-secrets.json",
                                            "OPENCLAW_WORKSPACE": "/workspace",
                                            "XDG_CACHE_HOME": "/workspace/.cache",
                                            "XDG_DATA_HOME": "/workspace/stale-data",
                                        },
                                        "image": "old",
                                    }
                                },
                                "workspace": str(root / "workspace"),
                            },
                            "list": [
                                {
                                    "id": "main",
                                    "sandbox": {
                                        "docker": {
                                            "env": {
                                            "REMOTE_BRIDGE_SECRETS_FILE": (
                                                "/workspace/secrets/remote-bridge/secrets.json"
                                            ),
                                            "OPENCLAW_SECRETS_FILE": (
                                                "/workspace/.secrets.json"
                                            ),
                                            "AAS_SKILL_SECRETS_FILE": (
                                                "/workspace/stale-skill.env"
                                            ),
                                            "AAS_ZOTERO_SKILL_SECRETS_FILE": (
                                                "/workspace/stale-zotero.json"
                                            ),
                                            }
                                        }
                                    },
                                    "skills": ["main-skill"],
                                    "workspace": str(root / "workspace"),
                                },
                                {
                                    "id": "worker",
                                    "sandbox": {
                                        "docker": {
                                            "env": {
                                                "CANVAS_CONFIG_PATH": "/workspace/stale-canvas.json",
                                                "CLASSROOM50_ORG_ALLOWLIST": "stale-org",
                                                "GETSCIPAPERS_CONFIG_DIR": (
                                                    "/workspace/secrets/getscipapers"
                                                ),
                                                "GH_CONFIG_DIR": "/workspace/stale-gh",
                                                "MOLTBOOK_AUTH": "/workspace/moltbook-auth.json",
                                            },
                                            "image": "latest",
                                            "dangerouslyAllowExternalBindSources": True,
                                            "binds": ["/outside:/outside:rw"],
                                        }
                                    },
                                    "skills": ["send-email", "course-canvas"],
                                },
                                {"id": "review", "sandbox": {"mode": "all"}},
                            ],
                        },
                        "channels": {
                            "googlechat": {
                                "enabled": True,
                                "groupPolicy": "open",
                                "groupAllowFrom": ["owner", "*"],
                            }
                        },
                        "tools": {
                            "elevated": {"enabled": True},
                            "exec": {"security": "full", "ask": "off"},
                        },
                    }
                )
            )
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "bin/migrate-openclaw-config.py"),
                    "--config",
                    str(config),
                    "--lock",
                    str(lock),
                    "--classroom50-allowlist-file",
                    str(allowlist),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            migrated = json.loads(config.read_text())
            channel = migrated["channels"]["googlechat"]
            self.assertEqual(channel["groupPolicy"], "allowlist")
            self.assertEqual(channel["groupAllowFrom"], ["owner"])
            self.assertFalse(migrated["tools"]["elevated"]["enabled"])
            self.assertEqual(migrated["tools"]["exec"]["host"], "sandbox")
            self.assertEqual(migrated["tools"]["exec"]["security"], "allowlist")
            self.assertEqual(migrated["tools"]["exec"]["ask"], "on-miss")
            for agent in (
                migrated["agents"]["defaults"],
                migrated["agents"]["list"][0],
                migrated["agents"]["list"][1],
            ):
                docker = agent["sandbox"]["docker"]
                self.assertEqual(docker["pidsLimit"], 512)
                self.assertEqual(docker["memory"], "4g")
                self.assertEqual(docker["memorySwap"], "4g")
                self.assertEqual(docker["cpus"], 2)
                self.assertEqual(docker["user"], f"{os.getuid()}:{os.getgid()}")
                self.assertTrue(docker["readOnlyRoot"])
            worker_docker = migrated["agents"]["list"][1]["sandbox"]["docker"]
            self.assertNotIn("dangerouslyAllowExternalBindSources", worker_docker)
            self.assertEqual(worker_docker["binds"], [])
            self.assertEqual(migrated["agents"]["defaults"]["model"]["fallbacks"], ["strong"])
            default_environment = migrated["agents"]["defaults"]["sandbox"]["docker"]["env"]
            self.assertEqual(default_environment["XDG_DATA_HOME"], "/workspace/.local-data")
            managed_selectors = {
                "AAS_SECRETS_FILE",
                "OPENCLAW_SECRETS_FILE",
                "AAS_COMPUTE_SECRETS_FILE",
                "AAS_SKILL_SECRETS_FILE",
                "AAS_PROVIDER_SECRETS_FILE",
                "AAS_AXLE_SECRETS_FILE",
                "AAS_LEANEXPLORE_SECRETS_FILE",
                "AAS_RESEARCH_DIGEST_SECRETS_FILE",
                "AAS_SUBMISSION_VENUE_SECRETS_FILE",
                "AAS_ZOTERO_SKILL_SECRETS_FILE",
                "AAS_FILE_DELIVERY_SECRETS_FILE",
                "REMOTE_BRIDGE_SECRETS_FILE",
                "SEND_EMAIL_SECRETS_FILE",
                "GOOGLE_CLASSROOM_CREDENTIALS",
                "GOOGLE_CLASSROOM_TOKEN",
                "CANVAS_CONFIG_PATH",
                "GETSCIPAPERS_CONFIG_DIR",
                "GETSCIPAPERS_SKILL_CONFIG",
                "GH_CONFIG_DIR",
                "CLASSROOM50_ORG_ALLOWLIST",
            }
            self.assertTrue(managed_selectors.isdisjoint(default_environment))
            self.assertEqual(
                default_environment["GETSCIPAPERS_CACHE_DIR"],
                "/workspace/cache/getscipapers",
            )
            self.assertEqual(default_environment["OPENCLAW_WORKSPACE"], "/workspace")
            self.assertEqual(default_environment["XDG_CACHE_HOME"], "/workspace/.cache")
            main_environment = migrated["agents"]["list"][0]["sandbox"]["docker"]["env"]
            self.assertEqual(main_environment["GH_CONFIG_DIR"], "/workspace/.config/gh")
            self.assertTrue(
                {
                    "AAS_SECRETS_FILE",
                    "OPENCLAW_SECRETS_FILE",
                    "AAS_SKILL_SECRETS_FILE",
                    "AAS_AXLE_SECRETS_FILE",
                    "AAS_LEANEXPLORE_SECRETS_FILE",
                    "AAS_RESEARCH_DIGEST_SECRETS_FILE",
                    "AAS_SUBMISSION_VENUE_SECRETS_FILE",
                    "AAS_ZOTERO_SKILL_SECRETS_FILE",
                    "AAS_FILE_DELIVERY_SECRETS_FILE",
                    "REMOTE_BRIDGE_SECRETS_FILE",
                }.isdisjoint(main_environment)
            )
            self.assertEqual(
                main_environment["GETSCIPAPERS_CONFIG_DIR"],
                "/workspace/.config/getscipapers",
            )
            self.assertEqual(
                main_environment["GETSCIPAPERS_SKILL_CONFIG"],
                "/workspace/data/research/getscipapers_bot/state/config.json",
            )
            self.assertEqual(
                main_environment["CANVAS_CONFIG_PATH"],
                "/workspace/.config/course/canvas/config.json",
            )
            self.assertEqual(
                main_environment["CLASSROOM50_ORG_ALLOWLIST"],
                "fixture-org,foundation50",
            )
            self.assertTrue(managed_selectors.isdisjoint(worker_docker["env"]))
            self.assertEqual(
                worker_docker["env"]["MOLTBOOK_AUTH"],
                "/workspace/moltbook-auth.json",
            )
            self.assertEqual(migrated["agents"]["list"][0]["skills"], ["main-skill"])
            self.assertEqual(migrated["agents"]["list"][1]["skills"], [])
            self.assertEqual(migrated["agents"]["list"][2]["skills"], [])
            backups = set(root.glob("openclaw.json.bak.compat-*"))
            repeated = subprocess.run(
                [
                    "python3",
                    str(ROOT / "bin/migrate-openclaw-config.py"),
                    "--config",
                    str(config),
                    "--lock",
                    str(lock),
                    "--classroom50-allowlist-file",
                    str(allowlist),
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertIn("policy: current", repeated.stdout)
            self.assertEqual(set(root.glob("openclaw.json.bak.compat-*")), backups)

    def test_config_migration_fails_without_one_usable_main_agent(self) -> None:
        lock = ROOT / "system/openclaw/compatibility.lock.json"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_main = {"id": "main", "workspace": str(root / "workspace")}
            cases = (
                [{"id": "worker", "workspace": str(root / "workspace-worker")}],
                [base_main, dict(base_main)],
                [{"id": "main", "workspace": ""}],
            )
            for index, listed in enumerate(cases):
                with self.subTest(index=index):
                    config = root / f"openclaw-{index}.json"
                    config.write_text(
                        json.dumps(
                            {
                                "agents": {
                                    "defaults": {
                                        "sandbox": {"docker": {"image": "old"}},
                                        "workspace": str(root / "workspace"),
                                    },
                                    "list": listed,
                                }
                            }
                        ),
                        encoding="utf-8",
                    )
                    original = config.read_bytes()
                    completed = subprocess.run(
                        [
                            "python3",
                            str(ROOT / "bin/migrate-openclaw-config.py"),
                            "--config",
                            str(config),
                            "--lock",
                            str(lock),
                        ],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(config.read_bytes(), original)
                    self.assertEqual(list(root.glob(f"{config.name}.bak.compat-*")), [])

    def test_degraded_migration_removes_placeholders_and_disables_channels(self) -> None:
        lock = ROOT / "system/openclaw/compatibility.lock.json"
        template = OPENCLAW_BOT / "config/openclaw.json.template"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            config = home / ".openclaw/openclaw.json"
            config.parent.mkdir(parents=True)
            rendered = (
                template.read_text(encoding="utf-8")
                .replace("{{ OPENCLAW_HOME }}", str(home / ".openclaw"))
                .replace("{{ OPENCLAW_WORKSPACE }}", str(home / ".openclaw/workspace"))
                .replace("{{ USER_HOME }}", str(home))
                .replace(
                    "{{ WRITING_STYLE_FILE }}",
                    str(home / ".openclaw/workspace/data/writing-style.md"),
                )
                .replace(
                    "{{ PRIVATE_DATA_DIR }}", str(home / ".openclaw/workspace/data")
                )
            )
            config.write_text(rendered, encoding="utf-8")

            subprocess.run(
                [
                    "python3",
                    str(ROOT / "bin/migrate-openclaw-config.py"),
                    "--config",
                    str(config),
                    "--lock",
                    str(lock),
                    "--degraded",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            migrated = json.loads(config.read_text(encoding="utf-8"))
            self.assertNotIn("{{", json.dumps(migrated))
            self.assertEqual(migrated["gateway"]["auth"]["mode"], "none")
            self.assertFalse(migrated["browser"]["ssrfPolicy"]["dangerouslyAllowPrivateNetwork"])
            self.assertTrue(
                all(not channel["enabled"] for channel in migrated["channels"].values())
            )
            self.assertEqual(
                migrated["agents"]["defaults"]["model"]["primary"],
                "openrouter/auto",
            )
            default_environment = migrated["agents"]["defaults"]["sandbox"]["docker"]["env"]
            for selector in (
                "OPENCLAW_SECRETS_FILE",
                "GETSCIPAPERS_CONFIG_DIR",
                "GETSCIPAPERS_SKILL_CONFIG",
            ):
                self.assertNotIn(selector, default_environment)
            self.assertEqual(
                default_environment["GETSCIPAPERS_CACHE_DIR"],
                "/workspace/cache/getscipapers",
            )
            self.assertEqual(default_environment["OPENCLAW_WORKSPACE"], "/workspace")
            self.assertEqual(default_environment["XDG_CACHE_HOME"], "/workspace/.cache")
            main_environment = migrated["agents"]["list"][0]["sandbox"]["docker"]["env"]
            self.assertNotIn("OPENCLAW_SECRETS_FILE", main_environment)
            self.assertEqual(
                main_environment["GETSCIPAPERS_CONFIG_DIR"],
                "/workspace/.config/getscipapers",
            )
            self.assertEqual(
                main_environment["GETSCIPAPERS_SKILL_CONFIG"],
                "/workspace/data/research/getscipapers_bot/state/config.json",
            )
            self.assertTrue(
                all(agent.get("skills") == [] for agent in migrated["agents"]["list"][1:])
            )


if __name__ == "__main__":
    unittest.main()
