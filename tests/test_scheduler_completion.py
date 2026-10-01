#!/usr/bin/env python3
"""Fixture-only tests for completion and host scheduler closure."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COMPLETION = ROOT / "bin/materialize-openclaw-completion.sh"
SCHEDULES = ROOT / "bin/reconcile-host-schedules.py"
SYSTEMD = ROOT / "bin/reconcile-systemd-user-units.sh"
CANARY = ROOT / "bin/scheduler-canary.py"
VERIFY_SCHEDULERS = ROOT / "bin/verify-schedulers.sh"
DECLARATION = ROOT / "system/schedules/host.v1.json"


def load_schedule_module():
    spec = importlib.util.spec_from_file_location("host_schedules", SCHEDULES)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CompletionTests(unittest.TestCase):
    def make_fake_openclaw(self, root: Path) -> Path:
        executable = root / "fake-openclaw"
        executable.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "[[ \"$*\" == 'completion --shell bash' ]]\n"
            "[[ -n \"${OPENCLAW_STATE_DIR:-}\" ]]\n"
            "[[ -n \"${OPENCLAW_CONFIG_PATH:-}\" ]]\n"
            "[[ \"$OPENCLAW_CONFIG_PATH\" == \"$OPENCLAW_STATE_DIR/openclaw.json\" ]]\n"
            "[[ \"$OPENCLAW_STATE_DIR\" != \"$HOME/.openclaw\" ]]\n"
            "[[ -d \"$OPENCLAW_STATE_DIR\" ]]\n"
            "[[ -f \"$OPENCLAW_CONFIG_PATH\" ]]\n"
            "grep -Eq '\"enabled\"[[:space:]]*:[[:space:]]*false' \"$OPENCLAW_CONFIG_PATH\"\n"
            "printf '%s\\n' '# generated fixture completion' "
            "'complete -W \"status health\" openclaw'\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable

    def run_helper(self, home: Path, executable: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                str(COMPLETION),
                "--home",
                str(home),
                "--openclaw-bin",
                str(executable),
                *extra,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_materializer_is_private_atomic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            executable = self.make_fake_openclaw(root)

            first = self.run_helper(home, executable)
            destination = home / ".openclaw/completions/openclaw.bash"
            self.assertEqual(first.returncode, 0, first.stdout)
            self.assertTrue(destination.is_file())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
            self.assertNotIn(str(destination.read_text()), first.stdout)

            os.utime(destination, (1, 1))
            second = self.run_helper(home, executable)
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertIn("current", second.stdout)
            self.assertEqual(destination.stat().st_mtime_ns, 1_000_000_000)
            verified = self.run_helper(home, executable, "--verify")
            self.assertEqual(verified.returncode, 0, verified.stdout)

            destination.write_text("# stale\n", encoding="utf-8")
            stale = self.run_helper(home, executable, "--verify")
            self.assertEqual(stale.returncode, 1, stale.stdout)

    def test_dry_run_and_symlink_guard_do_not_write_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            executable = self.make_fake_openclaw(root)

            dry = self.run_helper(home, executable, "--dry-run")
            self.assertEqual(dry.returncode, 0, dry.stdout)
            self.assertFalse((home / ".openclaw").exists())

            state = home / ".openclaw"
            state.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (state / "completions").symlink_to(outside, target_is_directory=True)
            guarded = self.run_helper(home, executable)
            self.assertEqual(guarded.returncode, 2, guarded.stdout)
            self.assertFalse((outside / "openclaw.bash").exists())

    def test_invalid_generated_completion_does_not_replace_current_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            destination = home / ".openclaw/completions/openclaw.bash"
            destination.parent.mkdir(parents=True)
            destination.write_text("# known-good\n", encoding="utf-8")
            executable = root / "bad-openclaw"
            executable.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' 'if ('\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            result = self.run_helper(home, executable)

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(destination.read_text(encoding="utf-8"), "# known-good\n")

    def test_bashrc_sources_completion_only_when_readable(self) -> None:
        source = (ROOT / "system/shell/bashrc.block.sh").read_text(encoding="utf-8")
        self.assertIn('[[ -r "$HOME/.openclaw/completions/openclaw.bash" ]]', source)
        self.assertNotIn('source "{{ HOME }}/.openclaw/completions/openclaw.bash"', source)


class OwnerScheduleSettingTests(unittest.TestCase):
    """Personal schedule values come from owner settings, never from the repository."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_schedule_module()

    def declaration(self, directory: Path, schedule: str, timezone: str) -> Path:
        path = directory / "host.v1.json"
        path.write_text(json.dumps({
            "schema": "coding-system.schedules/v1",
            "jobs": [{
                "id": "host.rss-news-digest-bot", "backend": "systemd",
                "timerUnit": "rss_news_digest_bot.timer", "schedule": schedule,
                "timezone": timezone, "missedRunPolicy": "catch-up-once",
            }],
        }), encoding="utf-8")
        return path

    def test_owner_placeholders_expand_from_the_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self.declaration(Path(temporary), "${CSR_RSS_DIGEST_ONCALENDAR}", "${CSR_OWNER_TIMEZONE}")
            values = {"CSR_RSS_DIGEST_ONCALENDAR": "*-*-* 05:00:00 Etc/UTC", "CSR_OWNER_TIMEZONE": "Etc/UTC",
                      "HOME": temporary}
            with mock.patch.dict(os.environ, values):
                job = self.module.load_declaration(path)["jobs"][0]
            self.assertEqual((job["schedule"], job["timezone"]), ("*-*-* 05:00:00 Etc/UTC", "Etc/UTC"))

    def test_owner_settings_file_supplies_values_outside_a_login_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            settings = home / ".secrets.env"
            settings.write_text("CSR_OWNER_TIMEZONE=Etc/UTC\n"
                                "CSR_RSS_DIGEST_ONCALENDAR=*-*-* 04:30:00 Etc/UTC\n", encoding="utf-8")
            settings.chmod(0o600)
            path = self.declaration(Path(temporary), "${CSR_RSS_DIGEST_ONCALENDAR}", "${CSR_OWNER_TIMEZONE}")
            environment = {k: v for k, v in os.environ.items()
                           if k not in {"CSR_RSS_DIGEST_ONCALENDAR", "CSR_OWNER_TIMEZONE"}}
            environment["HOME"] = str(home)
            with mock.patch.dict(os.environ, environment, clear=True):
                job = self.module.load_declaration(path)["jobs"][0]
            self.assertEqual((job["schedule"], job["timezone"]), ("*-*-* 04:30:00 Etc/UTC", "Etc/UTC"))

    def test_missing_unknown_or_invalid_owner_values_fail_closed(self) -> None:
        cases = (
            ("${CSR_RSS_DIGEST_ONCALENDAR}", "${CSR_OWNER_TIMEZONE}", {}, "CSR_OWNER_TIMEZONE"),
            ("${CSR_OTHER_SETTING}", "Etc/UTC", {}, "CSR_OTHER_SETTING"),
            ("*-*-* 05:00:00 Etc/UTC", "${CSR_OWNER_TIMEZONE}", {"CSR_OWNER_TIMEZONE": "Not/AZone"}, "timezone"),
            ("*-*-* 05:00:00 Etc/UTC", "${CSR_OWNER_TIMEZONE}", {"CSR_OWNER_TIMEZONE": "../x"}, "timezone"),
            ("*-*-* 05:00:00 Etc/UTC", "/etc/localtime", {}, "timezone"),
        )
        for schedule, timezone, values, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                path = self.declaration(Path(temporary), schedule, timezone)
                environment = {k: v for k, v in os.environ.items()
                               if k not in {"CSR_RSS_DIGEST_ONCALENDAR", "CSR_OWNER_TIMEZONE"}}
                environment.update(values)
                environment["HOME"] = temporary
                with mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(self.module.ScheduleError, message):
                        self.module.load_declaration(path)


class HostScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_schedule_module()
        # synthetic owner settings, so no test reads the real ~/.secrets.env
        cls.owner_settings = mock.patch.dict(os.environ, {
            "CSR_OWNER_TIMEZONE": "Etc/UTC",
            # deliberately not the component's own timer schedule
            "CSR_RSS_DIGEST_ONCALENDAR": "*-*-* 05:30:00 UTC",
        })
        cls.owner_settings.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.owner_settings.stop()

    def test_declaration_has_stable_identity_timezone_and_missed_run_policy(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        jobs = declaration["jobs"]
        self.assertEqual(len({job["id"] for job in jobs}), len(jobs))
        self.assertTrue(all(job["timezone"] == "Etc/UTC" for job in jobs))
        self.assertTrue(all(job["missedRunPolicy"] in {"skip", "catch-up-once"} for job in jobs))

        timers = {job["timerUnit"]: job for job in jobs if job["backend"] == "systemd"}
        unit_states = {}
        for raw in (ROOT / "system/systemd/units.state").read_text(
            encoding="utf-8"
        ).splitlines():
            if not raw or raw.startswith("#"):
                continue
            unit, enabled, activity = raw.split("\t")
            unit_states[unit] = (enabled, activity)
        for unit, job in timers.items():
            # The component rewrites timer units, so the declared schedule lives
            # in a drop-in that first clears every trigger the unit declares.
            lines = self.module.render_timer_dropin(job).splitlines()
            declared = lines.index(f"OnCalendar={job['schedule']}")
            for reset in ("OnCalendar=", "OnBootSec=", "OnUnitActiveSec="):
                self.assertLess(lines.index(reset), declared)
            self.assertEqual(
                [line for line in lines if line.startswith("OnCalendar=") and line != "OnCalendar="],
                [f"OnCalendar={job['schedule']}"],
            )
            persistent = "true" if job["missedRunPolicy"] == "catch-up-once" else "false"
            self.assertIn(f"Persistent={persistent}", lines)
            self.assertEqual(
                unit_states.get(unit),
                ("enabled", "active"),
                f"declared timer {unit} must be enabled and active",
            )

        self.module.validate_repository_commands(
            declaration, Path("/fixture/home"), ROOT
        )

    def test_timer_dropin_rejects_values_systemd_would_reinterpret(self) -> None:
        job = {
            "id": "fixture.timer",
            "backend": "systemd",
            "timerUnit": "fixture.timer",
            "schedule": "*-*-* 05:30:00 UTC",
            "timezone": "Etc/UTC",
            "missedRunPolicy": "skip",
            "legacyCronLines": [],
        }
        self.assertIn("Persistent=false", self.module.render_timer_dropin(job))
        for schedule in ("*-*-* 05:30:%H UTC", "*-*-* 05:30:00 UTC\\"):
            with self.subTest(schedule=schedule):
                with self.assertRaises(self.module.ScheduleError):
                    self.module.render_timer_dropin({**job, "schedule": schedule})

    def make_fake_timer_tools(self, root: Path) -> tuple[Path, Path, Path, Path]:
        """A systemctl that answers `show` from a JSON state file and logs reloads,
        and a systemd-analyze whose normalized form is its input."""
        state = root / "timers.json"
        log = root / "systemctl.log"
        systemctl = root / "fake-systemctl"
        systemctl.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "arguments = sys.argv[1:]\n"
            "with open(os.environ['FAKE_SYSTEMCTL_LOG'], 'a') as log:\n"
            "    log.write(' '.join(arguments) + '\\n')\n"
            "if 'show' in arguments:\n"
            "    unit = json.load(open(os.environ['FAKE_TIMER_STATE']))[arguments[-1]]\n"
            "    for calendar in unit['calendars']:\n"
            "        print(f'TimersCalendar={{ OnCalendar={calendar} ; next_elapse=n/a }}')\n"
            "    if unit['monotonic']:\n"
            "        print('TimersMonotonic={ OnUnitActiveUSec=4h ; next_elapse=n/a }')\n"
            "    print('DropInPaths=' + ' '.join(unit['dropins']))\n",
            encoding="utf-8",
        )
        analyze = root / "fake-systemd-analyze"
        analyze.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "print('Normalized form: ' + sys.argv[-1])\n",
            encoding="utf-8",
        )
        for executable in (systemctl, analyze):
            executable.chmod(0o755)
        return systemctl, analyze, state, log

    def test_timer_dropins_apply_once_survive_unit_rewrites_and_verify_live_state(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        timers = {job["timerUnit"]: job for job in declaration["jobs"] if job["backend"] == "systemd"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            units = home / ".config/systemd/user"
            units.mkdir(parents=True)
            systemctl, analyze, state, log = self.make_fake_timer_tools(root)
            environment = {**os.environ, "FAKE_SYSTEMCTL_LOG": str(log), "FAKE_TIMER_STATE": str(state)}
            command = [
                "python3", str(SCHEDULES), "--scope", "systemd", "--home", str(home),
                "--systemctl-bin", str(systemctl), "--systemd-analyze-bin", str(analyze),
            ]

            def run(*extra: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [*command, *extra], check=False, text=True, capture_output=True, env=environment
                )

            def dropin(unit: str) -> Path:
                return units / f"{unit}.d" / self.module.DROPIN_NAME

            def live(**override: object) -> None:
                state.write_text(
                    json.dumps(
                        {
                            unit: {
                                "calendars": [job["schedule"]],
                                "monotonic": False,
                                "dropins": [str(dropin(unit))],
                                **override,
                            }
                            for unit, job in timers.items()
                        }
                    ),
                    encoding="utf-8",
                )

            first = run()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertIn("reconciled", first.stdout)
            for unit, job in timers.items():
                self.assertEqual(dropin(unit).read_text(encoding="utf-8"), self.module.render_timer_dropin(job))
                self.assertEqual(stat.S_IMODE(dropin(unit).stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(dropin(unit).parent.stat().st_mode), 0o700)
            self.assertEqual(log.read_text(encoding="utf-8").count("daemon-reload"), 1)

            # The component installer rewrites the timer unit; the drop-in stays.
            (units / "rss_news_digest_bot.timer").write_text(
                "[Timer]\nOnCalendar=*-*-* 00/4:00:00 UTC\nPersistent=true\n", encoding="utf-8"
            )
            second = run()
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("current", second.stdout)
            self.assertEqual(log.read_text(encoding="utf-8").count("daemon-reload"), 1)

            live()
            self.assertEqual(run("--verify").returncode, 0)
            live(calendars=["*-*-* 00/4:00:00 UTC"])
            self.assertEqual(run("--verify").returncode, 1)
            live(monotonic=True)
            self.assertEqual(run("--verify").returncode, 1)
            live(dropins=[])
            self.assertEqual(run("--verify").returncode, 1)
            live()
            dropin("rss_news_digest_bot.timer").write_text("[Timer]\n", encoding="utf-8")
            drifted = run("--verify")
            self.assertEqual(drifted.returncode, 1)
            self.assertIn("host.rss-news-digest-bot", drifted.stdout)
            self.assertNotIn(timers["rss_news_digest_bot.timer"]["schedule"], drifted.stdout + drifted.stderr)

    def test_install_writes_timer_dropins_before_any_timer_is_enabled(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        dropins = install.index('reconcile-host-schedules.py" --scope systemd')
        self.assertLess(install.index('done < <(find "$REPO/system/systemd/user"'), dropins)
        self.assertLess(dropins, install.index("reconcile-systemd-user-units.sh\" --registration-only"))

    def test_scheduled_command_from_the_mutable_checkout_is_rejected(self) -> None:
        declaration = {
            "schema": self.module.SCHEMA,
            "jobs": [
                {
                    "id": "fixture.command",
                    "backend": "cron",
                    "schedule": "* * * * *",
                    "timezone": "Etc/UTC",
                    "missedRunPolicy": "skip",
                    "legacyCronLines": [],
                    "command": "{{ HOME }}/coding-system-rebuild/bin/scheduler-canary.py",
                }
            ],
        }
        with self.assertRaisesRegex(self.module.ScheduleError, "checkout"):
            self.module.validate_repository_commands(declaration, Path("/fixture/home"), ROOT)

    def test_scheduled_entrypoints_run_code_through_the_repository_selector(self) -> None:
        selector = ".local/share/coding-system/repository/bin/"
        sources = {
            "bashrc block": ROOT / "system/shell/bashrc.block.sh",
            "capture loader": ROOT / "bin/lib/manifest_sync.py",
            "canary unit": ROOT / "system/systemd/user/coding-system-scheduler-canary.service",
            "host schedules": DECLARATION,
            "OpenClaw canary": ROOT / "system/schedules/openclaw-cron.v2.json",
            "OpenClaw canary helper": ROOT / "bin/openclaw-cron-v2.py",
        }
        jobs = json.loads(DECLARATION.read_text(encoding="utf-8"))["jobs"]
        for label, path in sources.items():
            with self.subTest(source=label):
                text = path.read_text(encoding="utf-8")
                self.assertIn(selector, text)
                if path != DECLARATION:
                    self.assertNotIn("coding-system-rebuild/bin/", text)
        for job in jobs:
            self.assertNotIn("coding-system-rebuild/", job.get("command", ""))
        canary = next(job for job in jobs if job["id"] == "host.scheduler-canary-cron")
        self.assertIn(selector + "scheduler-canary.py", canary["command"])
        # the live crontab's checkout line is claimed and replaced wherever it is
        self.assertTrue(
            any("{{ HOME }}/coding-system-rebuild/bin/scheduler-canary.py" in line
                for line in canary["legacyCronLines"])
        )

    def test_install_selects_the_repository_before_rendering_entrypoints(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        phase_six = install.index("# 6 ─ render public configs")
        selection = install.index("  select_repository\n", phase_six)
        self.assertLess(selection, install.index('bash "$REPO/bin/render-install.sh"', phase_six))
        self.assertIn('selector="$HOME/.local/share/coding-system/repository"', install)

    def test_hetzner_reaper_is_declared_and_its_hand_added_line_is_claimed(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        reaper = next(job for job in declaration["jobs"] if job["id"] == "host.hetzner-reaper")
        self.assertEqual(reaper["backend"], "cron")
        self.assertEqual(reaper["schedule"], "*/2 * * * *")
        self.assertIn("hetzner-research-compute", reaper["command"])
        self.assertIn("reap", reaper["command"])
        home = Path("/tmp/fixture-home")
        legacy = self.module.substitute_home(reaper["legacyCronLines"][0], home)
        current = "7 7 * * * unrelated\n" + legacy + "\n"
        desired = self.module.reconcile_text(current, declaration, home)
        outside, inside = desired.split(self.module.BEGIN, 1)
        self.assertNotIn("hetzner-reaper", outside)
        self.assertIn(f"*/2 * * * * {self.module.substitute_home(reaper['command'], home)}", inside)
        self.assertTrue(outside.startswith("7 7 * * * unrelated\n"))

    def test_hand_added_lines_move_into_a_private_block_that_restores(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        home = Path("/tmp/fixture-home")
        private = "CRON_TZ=Asia/Ho_Chi_Minh\n30 6 * * * cd {{ HOME }}/Courses && ./sync scheduled\n"
        hand_added = "CRON_TZ=Asia/Ho_Chi_Minh\n30 6 * * * cd /tmp/fixture-home/Courses && ./sync scheduled\n"
        # adoption collects every unmanaged line, home-relative, without the managed ones
        adopted = self.module.adopt_unmanaged(hand_added, "", declaration, home)
        self.assertEqual(adopted, private)
        self.assertEqual(self.module.adopt_unmanaged(hand_added, adopted, declaration, home), private)
        # the private block claims the same lines and is rendered after the public block
        desired = self.module.reconcile_text(hand_added, declaration, home, private=private)
        outside, rest = desired.split(self.module.BEGIN, 1)
        self.assertEqual(outside, "")
        public, private_block = rest.split(self.module.PRIVATE_BEGIN, 1)
        self.assertIn("cd /tmp/fixture-home/Courses && ./sync scheduled", private_block)
        self.assertTrue(private_block.rstrip().endswith(self.module.PRIVATE_END))
        # a restored host with an empty crontab gets the same text back
        self.assertEqual(self.module.reconcile_text("", declaration, home, private=private), desired)
        # and nothing private reaches the public crontab template
        refresh = (ROOT / "bin/refresh-state.sh").read_text(encoding="utf-8")
        self.assertIn("--public-block", refresh)
        self.assertIn("--adopt-unmanaged", refresh)

    def test_repository_command_verifier_rejects_non_executable_and_symlink(self) -> None:
        declaration = {
            "schema": self.module.SCHEMA,
            "jobs": [
                {
                    "id": "fixture.command",
                    "backend": "cron",
                    "schedule": "* * * * *",
                    "timezone": "Etc/UTC",
                    "missedRunPolicy": "skip",
                    "legacyCronLines": [],
                    "command": "{{ HOME }}/.local/share/coding-system/repository/bin/fixture.sh",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "coding-system-rebuild"
            target = repository / "bin/fixture.sh"
            target.parent.mkdir(parents=True)
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o644)
            with self.assertRaisesRegex(self.module.ScheduleError, "executable"):
                self.module.validate_repository_commands(
                    declaration, Path("/fixture/home"), repository
                )
            target.chmod(0o755)
            self.module.validate_repository_commands(
                declaration, Path("/fixture/home"), repository
            )
            target.unlink()
            outside = Path(temporary) / "outside"
            outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            outside.chmod(0o755)
            target.symlink_to(outside)
            with self.assertRaisesRegex(self.module.ScheduleError, "executable"):
                self.module.validate_repository_commands(
                    declaration, Path("/fixture/home"), repository
                )

    def test_reconcile_deduplicates_legacy_jobs_and_preserves_unrelated_bytes(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        home = Path("/tmp/fixture-home")
        keep_alive = next(job for job in declaration["jobs"] if job["id"] == "host.keep-alive")
        legacy_keep_alive = self.module.substitute_home(keep_alive["legacyCronLines"][0], home)
        canary = next(
            job
            for job in declaration["jobs"]
            if job["id"] == "host.scheduler-canary-cron"
        )
        old_canary = (
            f"{canary['schedule']} "
            f"{self.module.substitute_home(canary['command'], home)}"
        )
        current = (
            "MAILTO=operator@example.invalid\n"
            "13 7 * * * /opt/unrelated --flag='a b'\n"
            f"{legacy_keep_alive}\n"
            f"{old_canary}\n"
            "# >>> coding-system >>>\n"
            "0 0 * * * stale-managed-command\n"
            "# <<< coding-system <<<\n"
        )

        desired = self.module.reconcile_text(current, declaration, home)

        self.assertIn("MAILTO=operator@example.invalid\n", desired)
        self.assertIn("13 7 * * * /opt/unrelated --flag='a b'\n", desired)
        self.assertNotIn(legacy_keep_alive, desired)
        self.assertEqual(desired.count(old_canary), 1)
        self.assertNotIn("stale-managed-command", desired)
        self.assertEqual(desired.count(self.module.BEGIN), 1)
        self.assertEqual(self.module.reconcile_text(desired, declaration, home), desired)

    def test_reconcile_claims_live_duplicate_predecessors_exactly_once(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        home = Path("/tmp/fixture-home")
        canonical_cron = [
            f"{job['schedule']} {self.module.substitute_home(job['command'], home)}"
            for job in declaration["jobs"]
            if job["backend"] == "cron"
        ]
        keep_alive = next(
            job for job in declaration["jobs"] if job["id"] == "host.keep-alive"
        )
        keep_alive_legacy = self.module.substitute_home(keep_alive["legacyCronLines"][0], home)
        current = (
            "11 11 * * * /opt/operator-owned\n"
            + "\n".join((*canonical_cron, keep_alive_legacy))
            + "\n# >>> coding-system >>>\n"
            + "\n".join(canonical_cron)
            + "\n# <<< coding-system <<<\n"
        )

        desired = self.module.reconcile_text(current, declaration, home)

        self.assertIn("11 11 * * * /opt/operator-owned\n", desired)
        for line in canonical_cron:
            self.assertEqual(desired.count(line), 1)
        self.assertNotIn(keep_alive_legacy, desired)
        self.assertEqual(self.module.reconcile_text(desired, declaration, home), desired)

    def test_reconcile_rejects_conflicting_managed_command_near_match(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        home = Path("/tmp/fixture-home")
        canary = next(
            job
            for job in declaration["jobs"]
            if job["id"] == "host.scheduler-canary-cron"
        )
        command = self.module.substitute_home(canary["command"], home)
        for conflict in (
            f"27 5 * * 1 {command}",
            f"{canary['schedule']} {command} --alternate",
        ):
            with self.subTest(conflict=conflict), self.assertRaisesRegex(
                self.module.ScheduleError, "managed cron"
            ):
                self.module.reconcile_text(conflict + "\n", declaration, home)

    def test_unterminated_managed_block_fails_closed(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        with self.assertRaisesRegex(self.module.ScheduleError, "unterminated"):
            self.module.reconcile_text(
                "keep-me\n# >>> coding-system schedules v1 >>>\nstale\n",
                declaration,
                Path("/tmp/fixture-home"),
            )

    def test_mismatched_managed_markers_fail_closed(self) -> None:
        declaration = self.module.load_declaration(DECLARATION)
        with self.assertRaisesRegex(self.module.ScheduleError, "mismatched"):
            self.module.reconcile_text(
                "# >>> coding-system >>>\nstale\n# <<< coding-system schedules v1 <<<\n",
                declaration,
                Path("/tmp/fixture-home"),
            )

    def make_fake_crontab(self, root: Path) -> tuple[Path, Path]:
        state = root / "crontab.txt"
        executable = root / "fake-crontab"
        executable.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"${1:-}\" == '-l' ]]; then\n"
            "  [[ -f \"$FAKE_CRONTAB_STATE\" ]] || { echo 'no crontab for fixture' >&2; exit 1; }\n"
            "  exec /bin/cat \"$FAKE_CRONTAB_STATE\"\n"
            "fi\n"
            "[[ $# -eq 1 ]]\n"
            "/bin/cp \"$1\" \"$FAKE_CRONTAB_STATE\"\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable, state

    def test_cli_reconciles_only_fake_crontab_and_second_run_is_current(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            executable, state = self.make_fake_crontab(root)
            state.write_text("7 7 * * * unrelated\n", encoding="utf-8")
            environment = os.environ.copy()
            environment["FAKE_CRONTAB_STATE"] = str(state)
            command = [
                "python3",
                str(SCHEDULES),
                "--home",
                str(home),
                "--crontab-bin",
                str(executable),
            ]

            first = subprocess.run(command, check=False, text=True, capture_output=True, env=environment)
            first_bytes = state.read_bytes()
            second = subprocess.run(command, check=False, text=True, capture_output=True, env=environment)

            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("current", second.stdout)
            self.assertEqual(state.read_bytes(), first_bytes)
            self.assertTrue(state.read_text(encoding="utf-8").startswith("7 7 * * * unrelated\n"))

    def test_verify_reports_drift_without_writing_fake_crontab(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            executable, state = self.make_fake_crontab(root)
            state.write_text("7 7 * * * unrelated\n", encoding="utf-8")
            original = state.read_bytes()
            environment = os.environ.copy()
            environment["FAKE_CRONTAB_STATE"] = str(state)

            result = subprocess.run(
                [
                    "python3",
                    str(SCHEDULES),
                    "--home",
                    str(home),
                    "--crontab-bin",
                    str(executable),
                    "--verify",
                ],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
            )

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(state.read_bytes(), original)
            self.assertIn("verification only", result.stdout)


class SystemdStateTests(unittest.TestCase):
    def make_fake_systemctl(self, root: Path) -> tuple[Path, Path]:
        log = root / "systemctl.log"
        executable = root / "fake-systemctl"
        executable.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_SYSTEMCTL_LOG\"\n"
            "if [[ \"$*\" == *'is-enabled'* ]]; then printf '%s\\n' static; fi\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable, log

    def test_enable_now_disable_now_and_static_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, log = self.make_fake_systemctl(root)
            state = root / "units.state"
            state.write_text(
                "active.timer\tenabled\n"
                "off.service\tdisabled\n"
                "helper.service\tstatic\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["FAKE_SYSTEMCTL_LOG"] = str(log)
            result = subprocess.run(
                [
                    "bash",
                    str(SYSTEMD),
                    "--state",
                    str(state),
                    "--systemctl-bin",
                    str(executable),
                ],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
            )
            calls = log.read_text(encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("--user daemon-reload", calls)
            self.assertIn("--user enable --now active.timer", calls)
            self.assertIn("--user disable --now off.service", calls)
            self.assertIn("--user is-enabled helper.service", calls)

    def test_dry_run_never_invokes_systemctl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, log = self.make_fake_systemctl(root)
            state = root / "units.state"
            state.write_text("active.timer\tenabled\n", encoding="utf-8")
            environment = os.environ.copy()
            environment["FAKE_SYSTEMCTL_LOG"] = str(log)
            result = subprocess.run(
                [
                    "bash",
                    str(SYSTEMD),
                    "--state",
                    str(state),
                    "--systemctl-bin",
                    str(executable),
                    "--dry-run",
                ],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(log.exists())
            self.assertIn("would enable --now", result.stdout)

    def test_verify_is_read_only_and_checks_enabled_timer_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "verify-systemctl.log"
            executable = root / "verify-systemctl"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_SYSTEMCTL_LOG\"\n"
                "case \"$*\" in\n"
                "  *'is-enabled active.timer') echo enabled ;;\n"
                "  *'is-active active.timer') echo \"${FAKE_TIMER_ACTIVE:-active}\" ;;\n"
                "  *'is-enabled off.service') echo disabled; exit 1 ;;\n"
                "  *'is-active off.service') echo inactive; exit 3 ;;\n"
                "  *'is-enabled helper.service') echo static; exit 1 ;;\n"
                "  *) exit 64 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            state = root / "units.state"
            state.write_text(
                "active.timer\tenabled\n"
                "off.service\tdisabled\n"
                "helper.service\tstatic\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["FAKE_SYSTEMCTL_LOG"] = str(log)
            command = [
                "bash",
                str(SYSTEMD),
                "--state",
                str(state),
                "--systemctl-bin",
                str(executable),
                "--verify",
            ]

            current = subprocess.run(
                command, check=False, text=True, capture_output=True, env=environment
            )
            environment["FAKE_TIMER_ACTIVE"] = "inactive"
            drift = subprocess.run(
                command, check=False, text=True, capture_output=True, env=environment
            )

            self.assertEqual(current.returncode, 0, current.stdout + current.stderr)
            self.assertEqual(drift.returncode, 1, drift.stdout + drift.stderr)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(all("daemon-reload" not in call for call in calls))
            self.assertTrue(all(" --now " not in f" {call} " for call in calls))

    def test_checked_in_canary_units_are_provider_free_and_recorded(self) -> None:
        service = (
            ROOT / "system/systemd/user/coding-system-scheduler-canary.service"
        ).read_text(encoding="utf-8")
        timer = (
            ROOT / "system/systemd/user/coding-system-scheduler-canary.timer"
        ).read_text(encoding="utf-8")
        states = (ROOT / "system/systemd/units.state").read_text(encoding="utf-8")
        self.assertIn("scheduler-canary.py record --scheduler systemd", service)
        self.assertIn("StateDirectory=coding-system/scheduler-canaries", service)
        self.assertNotRegex(service.lower(), r"--model|api[_-]?key|openai|anthropic")
        self.assertIn("OnCalendar=*-*-* *:*:00 UTC", timer)
        self.assertIn("coding-system-scheduler-canary.service\tstatic", states)
        self.assertIn("coding-system-scheduler-canary.timer\tenabled", states)
        for worker in (
            "send-queue-worker.service",
            "openclaw-sage-worker.service",
            "openclaw-manim-worker.service",
            "openclaw-email-worker.service",
        ):
            self.assertIn(f"{worker}\tenabled\tactive", states)

    def test_verify_returns_error_when_user_manager_state_is_unreadable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "unavailable-systemctl"
            executable.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            executable.chmod(0o755)
            state = root / "units.state"
            state.write_text("active.timer\tenabled\n", encoding="utf-8")

            result = subprocess.run(
                [
                    "bash",
                    str(SYSTEMD),
                    "--state",
                    str(state),
                    "--systemctl-bin",
                    str(executable),
                    "--verify",
                ],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("could not read enable state", result.stderr)

    def run_refresh_state(self, root: Path, systemctl_body: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        repo = root / "repo"
        (repo / "bin").mkdir(parents=True)
        (repo / "bin/refresh-state.sh").write_bytes(
            (ROOT / "bin/refresh-state.sh").read_bytes()
        )
        units = repo / "system/systemd/units.state"
        units.parent.mkdir(parents=True)
        units.write_text("openclaw-gateway.service\tenabled\tactive\n", encoding="utf-8")
        shims = root / "shims"
        shims.mkdir()
        # Later refresh steps must never reach the real npm, crontab or Docker.
        for name, body in (
            ("systemctl", systemctl_body),
            ("npm", "echo '{}'\n"),
            ("crontab", "exit 0\n"),
            ("docker", "exit 1\n"),
        ):
            shim = shims / name
            shim.write_text("#!/bin/sh\n" + body, encoding="utf-8")
            shim.chmod(0o755)
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"}
        }
        environment.update(HOME=str(root / "home"), PATH=f"{shims}:/usr/bin:/bin")
        result = subprocess.run(
            ["bash", str(repo / "bin/refresh-state.sh")],
            env=environment,
            check=False,
            text=True,
            capture_output=True,
        )
        return result, repo

    def assert_units_state_kept(self, result: subprocess.CompletedProcess[str], repo: Path) -> None:
        units = repo / "system/systemd/units.state"
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("units.state is unchanged", result.stderr)
        self.assertEqual(
            units.read_text(encoding="utf-8"),
            "openclaw-gateway.service\tenabled\tactive\n",
        )
        self.assertEqual(list(units.parent.glob(".units.state.*")), [])
        self.assertFalse((repo / ".staging/refresh-output-records.json").exists())

    def test_refresh_state_keeps_units_state_when_the_user_manager_is_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, repo = self.run_refresh_state(
                Path(temporary),
                "echo 'Failed to connect to bus: No medium found' >&2\nexit 1\n",
            )
            self.assert_units_state_kept(result, repo)

    def test_refresh_state_refuses_an_enable_state_the_reconciler_cannot_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, repo = self.run_refresh_state(
                Path(temporary),
                'case "$*" in\n'
                "  *is-enabled*) echo indirect ;;\n"
                "  *is-active*) echo inactive ;;\n"
                "  *) echo success ;;\n"
                "esac\n",
            )
            self.assert_units_state_kept(result, repo)
            self.assertIn("indirect", result.stderr)


class SchedulerDeclarationVerifierTests(unittest.TestCase):
    def make_path_shims(self, root: Path) -> tuple[Path, Path]:
        fake_bin = root / "bin"
        fake_bin.mkdir()
        marker = root / "path-shim-ran"
        python = fake_bin / "python3"
        python.write_text(
            f"#!/bin/sh\nprintf shim > {marker}\nexit 99\n",
            encoding="utf-8",
        )
        python.chmod(0o755)
        bash = fake_bin / "bash"
        bash.write_text(
            f"#!/bin/sh\nprintf shim > {marker}\nexit 99\n",
            encoding="utf-8",
        )
        bash.chmod(0o755)
        return fake_bin, marker

    def make_verifier_fixture(self, root: Path, host_status: int) -> Path:
        repo = root / "repo"
        bin_dir = repo / "bin"
        schedule_dir = repo / "system/schedules"
        bin_dir.mkdir(parents=True)
        schedule_dir.mkdir(parents=True)
        verifier = bin_dir / "verify-schedulers.sh"
        verifier.write_text(VERIFY_SCHEDULERS.read_text(encoding="utf-8"), encoding="utf-8")
        verifier.chmod(0o755)
        (bin_dir / "reconcile-host-schedules.py").write_text(
            f"raise SystemExit({host_status})\n", encoding="utf-8"
        )
        systemd = bin_dir / "reconcile-systemd-user-units.sh"
        systemd.write_text("#!/usr/bin/bash -p\nexit 0\n", encoding="utf-8")
        systemd.chmod(0o755)
        (bin_dir / "openclaw-cron-v2.py").write_text(
            "def load_snapshot(path):\n    return {}\n", encoding="utf-8"
        )
        (schedule_dir / "openclaw-cron.v2.json").write_text("{}\n", encoding="utf-8")
        return verifier

    def test_ci_ignores_path_shims_and_reports_a_consistent_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin, marker = self.make_path_shims(Path(temporary))
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            }
            result = subprocess.run(
                ["/usr/bin/bash", "-p", str(VERIFY_SCHEDULERS), "--profile", "ci"],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
            )
            self.assertFalse(marker.exists(), result.stdout)
            expected = {
                0: "scheduler verification: PASS",
                1: "scheduler verification: DRIFT",
                2: "scheduler verification: TECHNICAL_FAIL",
            }
            self.assertIn(result.returncode, expected, result.stdout)
            self.assertIn(expected[result.returncode], result.stdout)

    def test_ci_preserves_pass_drift_and_technical_failure_classification(self) -> None:
        cases = (
            (0, 0, "scheduler verification: PASS"),
            (1, 1, "scheduler verification: DRIFT"),
            (7, 2, "scheduler verification: TECHNICAL_FAIL"),
        )
        for child_status, expected_status, expected_text in cases:
            with self.subTest(child_status=child_status), tempfile.TemporaryDirectory() as temporary:
                verifier = self.make_verifier_fixture(Path(temporary), child_status)
                result = subprocess.run(
                    ["/usr/bin/bash", "-p", str(verifier), "--profile", "ci"],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, "PATH": "/nonexistent"},
                )
                self.assertEqual(result.returncode, expected_status, result.stdout)
                self.assertIn(expected_text, result.stdout)

    def test_ci_checks_host_declarations_without_private_owner_settings(self) -> None:
        # A degraded install has no owner settings; the ci profile still checks
        # the public declaration instead of failing on the private values.
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            crontab = Path(temporary) / "crontab"
            crontab.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            crontab.chmod(0o755)
            environment = {
                key: value
                for key, value in os.environ.items()
                if key not in {"CSR_OWNER_TIMEZONE", "CSR_RSS_DIGEST_ONCALENDAR"}
            }
            environment.update({"HOME": str(home), "CRONTAB_BIN": str(crontab)})
            result = subprocess.run(
                ["/usr/bin/bash", "-p", str(VERIFY_SCHEDULERS), "--profile", "ci"],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
            )
            self.assertIn("PASS  host schedule declarations", result.stdout)

    def test_full_install_checks_owner_schedule_settings_before_activation(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        secrets_phase = install.split("# 3 ─ secrets", 1)[1].split("# 4 ─", 1)[0]
        full_branch = secrets_phase.split("else", 1)[0]
        self.assertIn("preflight_host_schedules", full_branch)
        activation = install.split("# 11 ─", 1)[1]
        self.assertLess(
            activation.index("preflight_host_schedules"),
            activation.index('"$OPENCLAW_COMPONENT/install.sh"'),
        )
        self.assertIn('--dry-run', install.split("preflight_host_schedules()", 1)[1].split("}", 1)[0])

    def test_synthetic_owner_values_stay_inside_the_ci_profile(self) -> None:
        source = VERIFY_SCHEDULERS.read_text(encoding="utf-8")
        ci_block = source.split('if [[ "$PROFILE" == "ci" ]]; then', 1)[1].split("\nfi\n", 1)[0]
        outside = source.replace(ci_block, "")
        for synthetic in ("CSR_OWNER_TIMEZONE=", "CSR_RSS_DIGEST_ONCALENDAR="):
            self.assertIn(synthetic, ci_block)
            self.assertNotIn(synthetic, outside)

    def test_absent_private_cron_declarations_are_an_error_not_a_skip(self) -> None:
        source = VERIFY_SCHEDULERS.read_text(encoding="utf-8")
        # A home that bin/secrets-pack.sh exports declarations for must not
        # verify as PASS once those declarations go missing.
        self.assertNotIn(
            '[[ -f "$PRIVATE_SNAPSHOT" && ! -L "$PRIVATE_SNAPSHOT" ]]', source
        )
        self.assertIn('elif [[ -f "$HOME/.openclaw/openclaw.json" ]]; then', source)
        self.assertIn(
            "ERROR OpenClaw scheduler: private cron declarations are absent", source
        )
        self.assertIn(
            "ERROR OpenClaw scheduler: private cron declarations are not a regular file",
            source,
        )
        # bin/secrets-pack.sh gates its export on the same file, so the two
        # sides of the contract stay in step.
        pack = (ROOT / "bin/secrets-pack.sh").read_text(encoding="utf-8")
        self.assertIn('-f "$HOME/.openclaw/openclaw.json"', pack)


class SchedulerCanaryTests(unittest.TestCase):
    def run_canary(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CANARY), *arguments],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_record_verify_stale_and_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dry_state = root / "dry"
            dry = self.run_canary(
                "record",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(dry_state),
                "--dry-run",
                "--test-now",
                "1000",
            )
            self.assertEqual(dry.returncode, 0, dry.stdout)
            self.assertFalse(dry_state.exists())

            state = root / "state"
            record = self.run_canary(
                "record",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--test-now",
                "1000",
                "--test-run-id",
                "fixture-run",
            )
            evidence = state / "openclaw.json"
            self.assertEqual(record.returncode, 0, record.stdout)
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)

            fresh = self.run_canary(
                "verify",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--max-age-seconds",
                "60",
                "--test-now",
                "1050",
            )
            stale = self.run_canary(
                "verify",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--max-age-seconds",
                "60",
                "--test-now",
                "1100",
            )
            before_activation = self.run_canary(
                "verify",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--max-age-seconds",
                "600",
                "--not-before-unix",
                "1001",
                "--test-now",
                "1050",
            )
            at_activation_boundary = self.run_canary(
                "verify",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--max-age-seconds",
                "600",
                "--not-before-unix",
                "1000",
                "--test-now",
                "1050",
            )
            invalid_boundary = self.run_canary(
                "verify",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--not-before-unix",
                "-1",
                "--test-now",
                "1050",
            )
            self.assertEqual(fresh.returncode, 0, fresh.stdout)
            self.assertEqual(stale.returncode, 1, stale.stdout)
            self.assertEqual(before_activation.returncode, 1, before_activation.stdout)
            self.assertIn("pre-boundary", before_activation.stdout)
            self.assertEqual(
                at_activation_boundary.returncode, 0, at_activation_boundary.stdout
            )
            self.assertEqual(invalid_boundary.returncode, 2, invalid_boundary.stdout)

            systemd_record = self.run_canary(
                "record",
                "--scheduler",
                "systemd",
                "--state-dir",
                str(state),
                "--test-now",
                "1050",
                "--test-run-id",
                "fixture-systemd-run",
            )
            self.assertEqual(systemd_record.returncode, 0, systemd_record.stdout)
            self.assertTrue((state / "systemd.json").is_file())

            cron_record = self.run_canary(
                "record",
                "--scheduler",
                "cron",
                "--state-dir",
                str(state),
                "--test-now",
                "1050",
                "--test-run-id",
                "fixture-cron-run",
            )
            self.assertEqual(cron_record.returncode, 0, cron_record.stdout)
            self.assertTrue((state / "cron.json").is_file())

            future_record = self.run_canary(
                "record",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--test-now",
                "1100",
                "--test-run-id",
                "fixture-future-run",
            )
            run_bound_future = self.run_canary(
                "verify",
                "--scheduler",
                "openclaw",
                "--state-dir",
                str(state),
                "--max-age-seconds",
                "600",
                "--not-before-unix",
                "1050",
                "--test-now",
                "1050",
            )
            self.assertEqual(future_record.returncode, 0, future_record.stdout)
            self.assertEqual(run_bound_future.returncode, 2, run_bound_future.stdout)
            self.assertIn("timestamp is in the future", run_bound_future.stdout)

    def test_waiter_requires_and_propagates_activation_boundary(self) -> None:
        source = (ROOT / "bin/wait-scheduler-canaries.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('[[ -n "$NOT_BEFORE_UNIX" ]]', source)
        self.assertIn('--not-before-unix "$NOT_BEFORE_UNIX"', source)

        missing = subprocess.run(
            ["bash", str(ROOT / "bin/wait-scheduler-canaries.sh"), "--timeout", "1"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(missing.returncode, 2, missing.stdout)
        self.assertIn("--not-before-unix", missing.stdout)


if __name__ == "__main__":
    unittest.main()
