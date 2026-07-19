#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))

from grok_ms.config import (
    CommandKind,
    ConfigurationError,
    build_contract,
    classify,
    gate_enabled,
    parse_hosts,
    resolve_model,
)
from grok_ms.contract import RouteMode
from grok_ms.ios_registry import IosDevice, IosRegistry, write_registry
from grok_ms.grok_exec import (  # noqa: E402
    GrokExecutableError,
    VerifiedGrokExecutable,
    grok_release_id,
)


class ConfigTests(unittest.TestCase):
    def test_gate_is_exact(self) -> None:
        self.assertTrue(gate_enabled("1"))
        for value in (None, "", "0", "true", "01", " 1"):
            self.assertFalse(gate_enabled(value))

    def test_classifier_preserves_bypass_and_prefix_boundary(self) -> None:
        self.assertEqual(classify(["inspect"]).kind, CommandKind.BARE)
        self.assertEqual(classify(["help"]).kind, CommandKind.USAGE)
        self.assertEqual(classify(["recover"]).kind, CommandKind.RECOVERY)
        with self.assertRaises(ConfigurationError):
            classify(["recover", "extra"])
        self.assertEqual(classify(["--vpn", "-p", "hello"]).grok_argv, ("-p", "hello"))
        # A wrapper-looking option after the first Grok token belongs to Grok.
        self.assertEqual(
            classify(["-p", "hello", "--vpn"]).grok_argv,
            ("-p", "hello", "--vpn"),
        )
        with self.assertRaises(ConfigurationError):
            classify(["--host"])
        with self.assertRaises(ConfigurationError):
            classify(["--host", "pc", "--iphone"])
        direct = classify(["--direct", "-m", "grok-4.5"])
        self.assertEqual(direct.route_mode, RouteMode.DIRECT)
        with self.assertRaises(ConfigurationError):
            classify(["--direct", "--vpn"])
        with self.assertRaisesRegex(ConfigurationError, "contradictory"):
            classify(["--direct", "--no-direct", "-m", "grok-4.5"])
        family = classify(["--iphone", "-m", "grok-4.5"])
        self.assertEqual(family.route_mode, RouteMode.IOS)
        self.assertIsNone(family.forced_ios_key)
        exact = classify(["--ios", "ipad-pro", "-m", "grok-4.5"])
        self.assertEqual(exact.route_mode, RouteMode.IOS)
        self.assertEqual(exact.forced_ios_key, "ipad-pro")
        with self.assertRaises(ConfigurationError):
            classify(["--ios", "Bad/Key"])
        self.assertEqual(classify(["iphone-list"]).kind, CommandKind.CONTROL)
        for command in ("iphone-setup", "iphone-remove", "iphone-reorder"):
            self.assertEqual(classify([command]).kind, CommandKind.MAINTENANCE)

    def test_two_device_contracts_preserve_family_order_and_exact_selection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            release = root / "release"
            release.mkdir()
            for name in (
                "grok-remote",
                "egress.sh",
                "socks-netns.py",
                "vpngate-connect.sh",
            ):
                (release / name).write_text(name)
            phone = root / "iphone"
            phone.mkdir(mode=0o700)
            write_registry(
                phone / "devices.json",
                IosRegistry(
                    (
                        IosDevice("iphone-xr", "n-phone"),
                        IosDevice("ipad-pro", "n-tablet"),
                    )
                ),
            )
            environment = {
                "GROK_TESTING": "1",
                "GROK_TEST_IPHONE_STATE_DIR": str(phone),
            }
            with mock.patch("grok_ms.config._grok_release", return_value="grok-test"):
                family = build_contract(
                    classify(["--iphone", "-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env=environment,
                )
                exact = build_contract(
                    classify(["--ios", "ipad-pro", "-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env=environment,
                )
            self.assertEqual(
                family.ladder,
                ("ios:iphone-xr", "ios:ipad-pro"),
            )
            self.assertEqual(exact.ladder, ("ios:ipad-pro",))
            self.assertEqual(exact.forced_ios_key, "ipad-pro")
            self.assertEqual(
                tuple(
                    (endpoint.key, endpoint.stable_node_id)
                    for endpoint in exact.ios_endpoints
                ),
                (("ipad-pro", "n-tablet"),),
            )

    def test_gated_classifier_reserves_leader_controls(self) -> None:
        self.assertEqual(classify(["leader", "list"]).kind, CommandKind.BARE)
        self.assertEqual(
            classify(["--vpn", "leader", "list"]).kind,
            CommandKind.BARE,
        )
        for argv in (
            ("--leader",),
            ("--no-leader",),
            ("--leader-socket", "/tmp/user.sock"),
            ("--leader-socket=/tmp/user.sock",),
            ("-p", "prompt", "--no-leader"),
            ("--", "--leader"),
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(
                    ConfigurationError,
                    "leader controls are reserved",
                ):
                    classify(argv)

    def test_grok_identity_hashes_exact_bytes_and_fd_survives_symlink_retarget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = root / "first-grok"
            second = root / "second-grok"
            first.write_text(
                "#!/usr/bin/env python3\n# build one\nprint('same-version')\n",
                encoding="ascii",
            )
            second.write_text(
                "#!/usr/bin/env python3\n# build two\nprint('same-version')\n",
                encoding="ascii",
            )
            first.chmod(0o700)
            second.chmod(0o700)
            self.assertNotEqual(grok_release_id(first), grok_release_id(second))

            selected = root / "grok"
            selected.symlink_to(first)
            with VerifiedGrokExecutable.open(selected) as executable:
                selected.unlink()
                selected.symlink_to(second)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "grok_ms/fd_exec.py"),
                        str(executable.descriptor),
                        str(executable.path),
                    ],
                    pass_fds=(executable.descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "same-version")
                duplicate = os.dup(executable.descriptor)
                with VerifiedGrokExecutable.adopt(
                    duplicate, executable.release_id
                ) as adopted:
                    self.assertEqual(adopted.path, first.resolve())
                first.write_text(first.read_text() + "# changed\n", encoding="ascii")
                with self.assertRaisesRegex(GrokExecutableError, "changed"):
                    executable.verify()

    def test_explicit_owner_set_survives_privilege_boundary_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            grok = Path(td) / "grok"
            grok.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="ascii")
            grok.chmod(0o700)
            target_uid = grok.stat().st_uid
            if target_uid == 0:
                self.skipTest("split root/user owner simulation requires a non-root fixture")

            with mock.patch("grok_ms.grok_exec.os.getuid", return_value=0):
                with self.assertRaisesRegex(
                    GrokExecutableError,
                    "unexpected owner",
                ):
                    VerifiedGrokExecutable.open(grok)
                with VerifiedGrokExecutable.open(
                    grok,
                    allowed_owner_uids=frozenset((0, target_uid)),
                ) as executable:
                    self.assertEqual(
                        executable.allowed_owner_uids,
                        frozenset((0, target_uid)),
                    )
                    executable.verify()

    def test_exact_env_shell_fixtures_use_fixed_interpreters_in_both_fd_paths(self) -> None:
        bootstrap = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from grok_ms.grok_exec import VerifiedGrokExecutable
path = Path(sys.argv[2])
with VerifiedGrokExecutable.open(path) as executable:
    executable.exec([str(path), "hello"], {"PATH": "/untrusted"})
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, shebang in (
                ("env-bash", "#!/usr/bin/env bash"),
                ("env-sh", "#!/usr/bin/env sh"),
            ):
                script = root / name
                script.write_text(
                    f"{shebang}\nprintf 'fixed:%s\\n' \"$1\"\n",
                    encoding="ascii",
                )
                script.chmod(0o700)
                direct = subprocess.run(
                    [sys.executable, "-I", "-c", bootstrap, str(ROOT), str(script)],
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(direct.returncode, 0, direct.stderr)
                self.assertEqual(direct.stdout, "fixed:hello\n")

                with VerifiedGrokExecutable.open(script) as executable:
                    helper = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            str(ROOT / "grok_ms/fd_exec.py"),
                            str(executable.descriptor),
                            str(script),
                            "hello",
                        ],
                        pass_fds=(executable.descriptor,),
                        text=True,
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                self.assertEqual(helper.returncode, 0, helper.stderr)
                self.assertEqual(helper.stdout, "fixed:hello\n")

    def test_fd_exec_python_fixture_preserves_script_semantics_without_fd_leak(self) -> None:
        source = r'''#!/usr/bin/env python3
import json
import os
import sys

expected = (int(sys.argv[3]), int(sys.argv[4]))
matching = []
for item in os.listdir("/proc/self/fd"):
    try:
        descriptor = int(item)
        info = os.fstat(descriptor)
    except (OSError, ValueError):
        continue
    if (info.st_dev, info.st_ino) == expected:
        matching.append(descriptor)
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(
        {"file": __file__, "argv": sys.argv, "source_descriptors": matching},
        output,
        sort_keys=True,
    )
'''
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script = root / "python-fixture"
            output = root / "result.json"
            script.write_text(source, encoding="ascii")
            script.chmod(0o700)
            with VerifiedGrokExecutable.open(script) as executable:
                identity = os.fstat(executable.descriptor)
                display_path = str(executable.path)
                script.unlink()
                script.write_text(
                    "#!/usr/bin/env python3\nraise SystemExit(99)\n",
                    encoding="ascii",
                )
                script.chmod(0o700)
                os.lseek(executable.descriptor, identity.st_size, os.SEEK_SET)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "grok_ms/fd_exec.py"),
                        str(executable.descriptor),
                        display_path,
                        str(output),
                        "payload",
                        str(identity.st_dev),
                        str(identity.st_ino),
                    ],
                    pass_fds=(executable.descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["file"], display_path)
            self.assertEqual(
                payload["argv"],
                [
                    display_path,
                    str(output),
                    "payload",
                    str(identity.st_dev),
                    str(identity.st_ino),
                ],
            )
            self.assertEqual(payload["source_descriptors"], [])

            direct_script = root / "python-direct-fixture"
            direct_output = root / "direct-result.json"
            direct_script.write_text(source, encoding="ascii")
            direct_script.chmod(0o700)
            direct_bootstrap = r'''
import os
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from grok_ms.grok_exec import VerifiedGrokExecutable

path = Path(sys.argv[2])
output = sys.argv[3]
with VerifiedGrokExecutable.open(path) as executable:
    identity = os.fstat(executable.descriptor)
    display = str(executable.path)
    path.unlink()
    path.write_text("#!/usr/bin/env python3\nraise SystemExit(99)\n", encoding="ascii")
    path.chmod(0o700)
    executable.exec(
        [display, output, "direct", str(identity.st_dev), str(identity.st_ino)],
        {"PATH": "/usr/bin:/bin"},
    )
'''
            direct = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    direct_bootstrap,
                    str(ROOT),
                    str(direct_script),
                    str(direct_output),
                ],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(direct.returncode, 0, direct.stderr)
            direct_payload = json.loads(direct_output.read_text(encoding="utf-8"))
            direct_identity = direct_payload["argv"][3:]
            self.assertEqual(direct_payload["file"], str(direct_script))
            self.assertEqual(
                direct_payload["argv"],
                [str(direct_script), str(direct_output), "direct", *direct_identity],
            )
            self.assertEqual(direct_payload["source_descriptors"], [])

    def test_caller_owned_canary_file_cannot_authorize_source_execution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            auth = Path(td) / "canary-auth"
            auth.write_bytes(b"")
            auth.chmod(0o600)
            descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
            try:
                base = dict(os.environ)
                base.update(
                    {
                        "GROK_RELEASE_CANARY_MODE": "1",
                        "GROK_RELEASE_CANARY_FD": str(descriptor),
                        "GROK_RELEASE_CANARY_RELEASE_ID": "a" * 64,
                        "GROK_TESTING": "1",
                    }
                )
                local_version = subprocess.run(
                    [str(ROOT / "grok-remote"), "--version"],
                    env=base,
                    pass_fds=(descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                local_help = subprocess.run(
                    [str(ROOT / "grok-remote"), "--help"],
                    env=base,
                    pass_fds=(descriptor,),
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(local_version.returncode, 78)
                self.assertIn("unauthorized release canary", local_version.stderr)
                self.assertEqual(local_help.returncode, 78)
                self.assertIn("unauthorized release canary", local_help.stderr)

                rung = {
                    **base,
                    "GROK_RELEASE_RUNG_CANARY": "1",
                    "GROK_RELEASE_CANARY_RUNG": "direct",
                    "GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct",
                    "GROK_RELEASE_CANARY_CONTRACT": "b" * 64,
                    "GROK_RELEASE_CANARY_GROK_RELEASE": "grok-build-v1",
                    "GROK_RELEASE_CANARY_KIND": "rung",
                    "GROK_RELEASE_CANARY_MODEL": "grok-model",
                    "GROK_RELEASE_CANARY_NONCE": "c" * 64,
                }
                for argv in (
                    ("--help",),
                    ("inspect",),
                    ("stop",),
                    ("--direct", "completions"),
                ):
                    rejected = subprocess.run(
                        [str(ROOT / "grok-remote"), *argv],
                        env=rung,
                        pass_fds=(descriptor,),
                        text=True,
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(rejected.returncode, 78, rejected.stderr)
                    self.assertIn("unauthorized release canary", rejected.stderr)

                partial = dict(os.environ)
                partial["GROK_RELEASE_CANARY_ROUTE_PROFILE"] = "direct"
                rejected = subprocess.run(
                    [str(ROOT / "grok-remote"), "status"],
                    env=partial,
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(rejected.returncode, 78, rejected.stderr)
                self.assertIn("incomplete release canary authorization", rejected.stderr)
            finally:
                os.close(descriptor)

    def test_model_resolution_is_concrete_and_unambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            choice, config = root / "choice", root / "config.toml"
            config.write_text('[models]\ndefault = "grok-default"\n')
            self.assertEqual(
                resolve_model([], choice_path=choice, config_path=config),
                ("grok-default", False),
            )
            config.write_text('default = "grok-legacy-default"\n')
            self.assertEqual(
                resolve_model([], choice_path=choice, config_path=config),
                ("grok-legacy-default", False),
            )
            choice.write_text("grok-choice\n")
            self.assertEqual(
                resolve_model([], choice_path=choice, config_path=config),
                ("grok-choice", False),
            )
            self.assertEqual(
                resolve_model(["--model=grok-explicit"], choice_path=choice, config_path=config),
                ("grok-explicit", True),
            )
            with self.assertRaises(ConfigurationError):
                resolve_model(["-m", "one", "--model=two"], choice_path=choice, config_path=config)

    def test_hosts_are_strict_and_ordered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "hosts.conf"
            path.write_text("arch 100.64.0.1 alice 22\nwin host.example bob 2200 # ok\n")
            self.assertEqual(parse_hosts(path)[1], ("win", "host.example", "bob", 2200))
            path.write_text("arch host user 22\narch other user 22\n")
            with self.assertRaises(ConfigurationError):
                parse_hosts(path)
            path.write_text("lab/phone host user 22\n")
            with self.assertRaisesRegex(ConfigurationError, "unsupported characters"):
                parse_hosts(path)
            with self.assertRaisesRegex(ConfigurationError, "unsupported characters"):
                classify(["--host", "lab/phone", "-m", "xai/grok-4.5"])

    def test_contract_snapshot_join_and_difference(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            release = Path(td)
            for name in ("grok-remote", "egress.sh", "socks-netns.py", "vpngate-connect.sh"):
                (release / name).write_text(name)
            (release / "hosts.conf").write_text("arch 100.64.0.1 alice 22\n")
            classification = classify(["--host", "arch", "-m", "grok-4.5"])
            with mock.patch("grok_ms.config._grok_release", return_value="grok-test"):
                first = build_contract(
                    classification,
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env={},
                )
                second = build_contract(
                    classification,
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env={},
                )
                changed = build_contract(
                    classify(["--host", "arch", "--no-direct", "-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env={},
                )
            self.assertEqual(first.digest(), second.digest())
            self.assertEqual(first.route_mode, RouteMode.HOME)
            self.assertEqual(
                [item.to_dict() for item in first.home_endpoints],
                [{"host": "100.64.0.1", "label": "arch", "port": 22, "user": "alice"}],
            )
            self.assertIn("allow_direct", first.semantic_differences(changed))

    def test_direct_contract_has_only_the_committed_direct_rung(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            release = Path(td)
            for name in ("grok-remote", "egress.sh", "socks-netns.py", "vpngate-connect.sh"):
                (release / name).write_text(name)
            with mock.patch("grok_ms.config._grok_release", return_value="grok-test"):
                wanted = build_contract(
                    classify(["--direct", "-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env={},
                )
            self.assertEqual(wanted.route_mode, RouteMode.DIRECT)
            self.assertEqual(wanted.ladder, ("direct",))

    def test_vpn_attempt_bound_matches_fixed_broker_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            release = Path(td)
            for name in ("grok-remote", "egress.sh", "socks-netns.py", "vpngate-connect.sh"):
                (release / name).write_text(name)
            with mock.patch("grok_ms.config._grok_release", return_value="grok-test"):
                accepted = build_contract(
                    classify(["--direct", "-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env={"GROK_VPN_MAX_TRIES": "8"},
                )
                self.assertEqual(accepted.vpn_policy.max_tries, 8)
                with self.assertRaises(ConfigurationError):
                    build_contract(
                        classify(["--direct", "-m", "grok-4.5"]),
                        "grok-4.5",
                        release_dir=release,
                        grok_bin=Path("/bin/false"),
                        env={"GROK_VPN_MAX_TRIES": "9"},
                    )

    def test_auto_contract_freezes_ordered_home_and_ios_identities(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            release = Path(td) / "release"
            release.mkdir()
            for name in ("grok-remote", "egress.sh", "socks-netns.py", "vpngate-connect.sh"):
                (release / name).write_text(name)
            hosts = release / "hosts.conf"
            hosts.write_text(
                "arch 100.64.0.1 alice 22\nwin pc.example bob 2200\n"
            )
            phone = Path(td) / "iphone"
            phone.mkdir()
            os.chmod(phone, 0o700)
            (phone / "exit-node").write_text("n-stable-iphone\n")
            (phone / "ready").write_text("n-stable-iphone\n")
            os.chmod(phone / "exit-node", 0o600)
            os.chmod(phone / "ready", 0o600)
            environment = {
                "GROK_TESTING": "1",
                "GROK_TEST_IPHONE_STATE_DIR": str(phone),
            }
            with mock.patch("grok_ms.config._grok_release", return_value="grok-test"):
                frozen = build_contract(
                    classify(["-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env=environment,
                )
                hosts.write_text("changed 100.64.0.9 mallory 2022\n")
                changed = build_contract(
                    classify(["-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env=environment,
                )

            self.assertEqual(
                tuple(item.label for item in frozen.home_endpoints),
                ("arch", "win"),
            )
            self.assertEqual(
                tuple((item.key, item.stable_node_id) for item in frozen.ios_endpoints),
                (("iphone", "n-stable-iphone"),),
            )
            self.assertEqual(
                frozen.ladder,
                ("home:arch", "home:win", "ios:iphone", "vpn", "direct"),
            )
            self.assertEqual(frozen.home_endpoint("win").port, 2200)
            self.assertEqual(tuple(item.label for item in changed.home_endpoints), ("changed",))
            self.assertIn("home_endpoints", frozen.semantic_differences(changed))

    def test_phone_state_is_fixed_to_passwd_home_outside_test_seam(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            account_home = root / "account"
            release = root / "release"
            release.mkdir()
            for name in ("grok-remote", "egress.sh", "socks-netns.py", "vpngate-connect.sh"):
                (release / name).write_text(name)
            alternate = root / "caller-state"
            alternate.mkdir()
            os.chmod(alternate, 0o700)
            (alternate / "exit-node").write_text("n-wrong-source\n")
            (alternate / "ready").write_text("n-wrong-source\n")
            os.chmod(alternate / "exit-node", 0o600)
            os.chmod(alternate / "ready", 0o600)

            patches = (
                mock.patch("grok_ms.config._account_home", return_value=account_home),
                mock.patch("grok_ms.config._grok_release", return_value="grok-test"),
            )
            with patches[0], patches[1]:
                with self.assertRaisesRegex(ConfigurationError, "fixed"):
                    build_contract(
                        classify(["-m", "grok-4.5"]),
                        "grok-4.5",
                        release_dir=release,
                        grok_bin=Path("/bin/false"),
                        env={
                            "HOME": str(root / "spoofed-home"),
                            "GROK_IPHONE_STATE_DIR": str(alternate),
                        },
                    )
                with self.assertRaisesRegex(ConfigurationError, "requires GROK_TESTING"):
                    build_contract(
                        classify(["-m", "grok-4.5"]),
                        "grok-4.5",
                        release_dir=release,
                        grok_bin=Path("/bin/false"),
                        env={"GROK_TEST_IPHONE_STATE_DIR": str(alternate)},
                    )
                tested = build_contract(
                    classify(["-m", "grok-4.5"]),
                    "grok-4.5",
                    release_dir=release,
                    grok_bin=Path("/bin/false"),
                    env={
                        "GROK_TESTING": "1",
                        "GROK_TEST_IPHONE_STATE_DIR": str(alternate),
                    },
                )
            self.assertEqual(
                tuple((item.key, item.stable_node_id) for item in tested.ios_endpoints),
                (("iphone", "n-wrong-source"),),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
