#!/usr/bin/env python3
"""Focused client ownership, timeout, and bounded-log regressions."""

from __future__ import annotations

import errno
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from grok_ms import client  # noqa: E402
from grok_ms.grok_exec import VerifiedGrokExecutable  # noqa: E402
from grok_ms.ipc import SeqPacketConnection, bind_seqpacket_listener  # noqa: E402


class ClientTests(unittest.TestCase):
    _PTY_CHILD = r'''#!/usr/bin/env python3
import json, os, signal, sys
mode = sys.argv[-1]
print(json.dumps({
    "argv": sys.argv[1:],
    "stdin_tty": os.isatty(0),
    "stdout_tty": os.isatty(1),
    "stderr_tty": os.isatty(2),
    "pid": os.getpid(),
    "ppid": os.getppid(),
    "sid": os.getsid(0),
    "pgrp": os.getpgrp(),
    "foreground_pgrp": os.tcgetpgrp(0),
    "direct_qualification_marker": os.environ.get("GROK_INTERNAL_DIRECT_QUALIFICATION"),
}), flush=True)
print("ERR-MARKER", file=sys.stderr, flush=True)
if mode == "exit7":
    raise SystemExit(7)
if mode == "term":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(43))
elif mode == "interrupt":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(42))
elif mode == "quit":
    signal.signal(signal.SIGQUIT, lambda *_: sys.exit(44))
elif mode == "eof":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("READY-" + mode, flush=True)
while True:
    signal.pause()
'''

    @dataclass(frozen=True)
    class _Home:
        label: str

    @dataclass(frozen=True)
    class _Contract:
        release_id: str
        grok_release_id: str
        ladder: tuple[str, ...]
        home_endpoints: tuple[object, ...]

        def digest(self) -> str:
            return "a" * 64

    @staticmethod
    def _canary_environment(descriptor: int, kind: str = "rung") -> dict[str, str]:
        environment = {
            "GROK_TESTING": "1",
            "HOME": "/tmp",
            "GROK_RELEASE_CANARY_MODE": "1",
            "GROK_RELEASE_CANARY_FD": str(descriptor),
            "GROK_RELEASE_CANARY_RELEASE_ID": "f" * 64,
            "GROK_RELEASE_RUNG_CANARY": "1",
            "GROK_RELEASE_CANARY_RUNG": "direct",
            "GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct",
            "GROK_RELEASE_CANARY_GROK_RELEASE": "grok-build-v1",
            "GROK_RELEASE_CANARY_KIND": kind,
            "GROK_RELEASE_CANARY_MODEL": "grok-model",
            "GROK_RELEASE_CANARY_NONCE": "e" * 64,
        }
        if kind == "rung":
            environment["GROK_RELEASE_CANARY_CONTRACT"] = "a" * 64
        return environment

    @staticmethod
    def _canary_authorization_fixture(
        descriptor: int,
        kind: str = "rung",
    ) -> tuple[dict[str, object], str, str | None, str, str, str, int, str]:
        return (
            {},
            "direct",
            "a" * 64 if kind == "rung" else None,
            "grok-build-v1",
            "grok-model",
            kind,
            descriptor,
            "direct",
        )

    def assertDescriptorClosed(self, descriptor: int) -> None:
        with self.assertRaises(OSError) as caught:
            os.fstat(descriptor)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_schema_v4_canary_accepts_namespaced_model_not_namespaced_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth = root / "canary-auth.lock"
            auth.write_bytes(b"")
            os.chmod(auth, 0o600)
            release_id = "a" * 64
            nonce = "b" * 64
            contract_digest = "c" * 64
            model_id = "xai/grok-4.5"
            record = {
                "schema_version": 4,
                "release_id": release_id,
                "host_id": client._host_id(),
                "canary_kind": "rung",
                "rung": "home:lab-phone",
                "route_profile": "home:lab-phone",
                "contract_sha256": contract_digest,
                "grok_release_id": "grok-cli@1.2.3",
                "model_id": model_id,
                "canary_nonce": nonce,
                "created_unix_ns": time.time_ns(),
            }
            canary = root / "rung-canary.json"
            canary.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            os.chmod(canary, 0o444)
            descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
            env = {
                "GROK_TESTING": "1",
                "GROK_TEST_ROOT_RELEASE_CONTROL": str(root),
                "GROK_RELEASE_RUNG_CANARY": "1",
                "GROK_RELEASE_CANARY_MODE": "1",
                "GROK_RELEASE_CANARY_FD": str(descriptor),
                "GROK_RELEASE_CANARY_RELEASE_ID": release_id,
                "GROK_RELEASE_CANARY_KIND": "rung",
                "GROK_RELEASE_CANARY_RUNG": "home:lab-phone",
                "GROK_RELEASE_CANARY_ROUTE_PROFILE": "home:lab-phone",
                "GROK_RELEASE_CANARY_CONTRACT": contract_digest,
                "GROK_RELEASE_CANARY_GROK_RELEASE": "grok-cli@1.2.3",
                "GROK_RELEASE_CANARY_MODEL": model_id,
                "GROK_RELEASE_CANARY_NONCE": nonce,
            }
            try:
                authorization = client._canary_authorization(release_id, env)
                invalid = dict(env)
                invalid["GROK_RELEASE_CANARY_GROK_RELEASE"] = "vendor/grok-cli"
                with self.assertRaisesRegex(
                    client.ClientError, "authorization record is not exact"
                ):
                    client._canary_authorization(release_id, invalid)
                invalid_home = dict(env)
                invalid_home["GROK_RELEASE_CANARY_RUNG"] = "home:lab/phone"
                invalid_home["GROK_RELEASE_CANARY_ROUTE_PROFILE"] = "home:lab/phone"
                with self.assertRaisesRegex(
                    client.ClientError, "authorization record is not exact"
                ):
                    client._canary_authorization(release_id, invalid_home)
            finally:
                os.close(descriptor)
            self.assertIsNotNone(authorization)
            self.assertEqual(authorization[4], model_id)

    def test_partial_canary_context_fails_before_every_command_class(self) -> None:
        commands = (
            ("usage", ("--help",)),
            ("bare", ("inspect",)),
            ("maintenance", ("stop",)),
            ("control", ("status",)),
            ("recovery", ("recover",)),
            ("gated", ("--direct", "-m", "grok-model", "prompt")),
        )
        with mock.patch.object(client, "_release_id", return_value="f" * 64):
            for label, argv in commands:
                with self.subTest(command_class=label), self.assertRaisesRegex(
                    client.ClientError, "incomplete rung canary authorization"
                ):
                    client._prepare_canary_dispatch(
                        client.classify(argv),
                        ROOT,
                        {"GROK_RELEASE_CANARY_ROUTE_PROFILE": "direct"},
                    )

    def test_explicit_model_choice_is_atomic_and_canary_never_persists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / "grok-proxy"
            choice = parent / ".model.choice"
            client._remember_explicit_model(
                choice,
                "grok-build",
                canary_active=False,
            )
            self.assertEqual(choice.read_text(encoding="ascii"), "grok-build\n")
            self.assertEqual(stat.S_IMODE(choice.stat().st_mode), 0o600)
            self.assertEqual(list(parent.glob("..model.choice.tmp-*")), [])

            client._remember_explicit_model(
                choice,
                "grok-canary-only",
                canary_active=True,
            )
            self.assertEqual(choice.read_text(encoding="ascii"), "grok-build\n")

    def test_authenticated_canary_rejects_bypass_classes_and_never_dispatches(self) -> None:
        commands = (
            (("--help",), "_bare_exec"),
            (("inspect",), "_bare_exec"),
            (("stop",), "_maintenance"),
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            for kind in ("release", "rung"):
                for argv, forbidden_handler in commands:
                    descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
                    environment = self._canary_environment(descriptor, kind)
                    authorization = self._canary_authorization_fixture(descriptor, kind)
                    with (
                        self.subTest(kind=kind, argv=argv),
                        mock.patch.object(client, "_release_id", return_value="f" * 64),
                        mock.patch.object(
                            client, "_canary_authorization", return_value=authorization
                        ),
                        mock.patch.object(
                            client,
                            "_close_canary_authorization",
                            wraps=client._close_canary_authorization,
                        ) as close_authorization,
                        mock.patch.object(client, forbidden_handler) as handler,
                        self.assertRaisesRegex(client.ClientError, "command class is forbidden"),
                    ):
                        client.run(argv, ROOT, environment)
                    handler.assert_not_called()
                    self.assertDescriptorClosed(descriptor)
                    scrubbed = close_authorization.call_args.args[1]
                    self.assertFalse(set(scrubbed).intersection(client._CANARY_BINDINGS))

    def test_canary_status_and_recover_revalidate_then_drop_capability(self) -> None:
        commands = (
            (("status",), "_control"),
            (("recover",), "_recover"),
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            for kind in ("release", "rung"):
                for argv, handler_name in commands:
                    descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
                    environment = self._canary_environment(descriptor, kind)
                    authorization = self._canary_authorization_fixture(descriptor, kind)

                    def dispatched(
                        *arguments: object,
                        **keyword_arguments: object,
                    ) -> int:
                        visible = arguments[-1]
                        assert isinstance(visible, dict)
                        if handler_name == "_recover":
                            self.assertEqual(
                                keyword_arguments, {"strict_direct": False}
                            )
                        else:
                            self.assertEqual(keyword_arguments, {})
                        self.assertDescriptorClosed(descriptor)
                        self.assertFalse(
                            set(visible).intersection(client._CANARY_BINDINGS)
                        )
                        return 0

                    with (
                        self.subTest(kind=kind, argv=argv),
                        mock.patch.object(client, "_release_id", return_value="f" * 64),
                        mock.patch.object(
                            client, "_canary_authorization", return_value=authorization
                        ),
                        mock.patch.object(client, "_release_gate") as release_gate,
                        mock.patch.object(
                            client, handler_name, side_effect=dispatched
                        ) as handler,
                    ):
                        self.assertEqual(client.run(argv, ROOT, environment), 0)
                    release_gate.assert_called_once()
                    handler.assert_called_once()

    def test_direct_qualification_recovery_flag_requires_authentication(self) -> None:
        classification = client.classify(("recover",))
        with mock.patch.object(client, "_canary_authorization") as authorization:
            with self.assertRaisesRegex(
                client.ClientError, "lacks canary authorization"
            ):
                client._prepare_canary_dispatch(
                    classification,
                    ROOT,
                    {"GROK_QUALIFICATION_DIRECT_RECOVERY": "1"},
                )
        authorization.assert_not_called()

        with self.assertRaisesRegex(client.ClientError, "literal value 1"):
            client._prepare_canary_dispatch(
                classification,
                ROOT,
                {"GROK_QUALIFICATION_DIRECT_RECOVERY": "true"},
            )

    def test_internal_direct_qualification_marker_rejects_ambient_spoof(self) -> None:
        environment = {"GROK_INTERNAL_DIRECT_QUALIFICATION": "1"}
        with (
            mock.patch.object(client, "_release_id") as release_id,
            mock.patch.object(client, "_canary_authorization") as authorization,
            self.assertRaisesRegex(
                client.ClientError, "reserved for authenticated dispatch"
            ),
        ):
            client._prepare_canary_dispatch(
                client.classify(("--direct", "-m", "grok-model", "prompt")),
                ROOT,
                environment,
            )
        release_id.assert_not_called()
        authorization.assert_not_called()

    def test_authenticated_release_direct_recovery_routes_strictly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
            environment = self._canary_environment(descriptor, "release")
            environment["GROK_QUALIFICATION_DIRECT_RECOVERY"] = "1"
            authorization = self._canary_authorization_fixture(
                descriptor, "release"
            )

            def recovered(
                release_dir: Path,
                visible: dict[str, str],
                *,
                strict_direct: bool = False,
            ) -> int:
                self.assertEqual(release_dir, ROOT)
                self.assertTrue(strict_direct)
                self.assertDescriptorClosed(descriptor)
                self.assertNotIn("GROK_QUALIFICATION_DIRECT_RECOVERY", visible)
                self.assertFalse(set(visible).intersection(client._CANARY_BINDINGS))
                return 0

            with (
                mock.patch.object(client, "_release_id", return_value="f" * 64),
                mock.patch.object(
                    client, "_canary_authorization", return_value=authorization
                ),
                mock.patch.object(client, "_release_gate") as release_gate,
                mock.patch.object(
                    client, "_recover", side_effect=recovered
                ) as recover,
            ):
                self.assertEqual(client.run(("recover",), ROOT, environment), 0)
            release_gate.assert_called_once()
            recover.assert_called_once()
            self.assertTrue(recover.call_args.kwargs["strict_direct"])

    def test_direct_recovery_rejects_authenticated_nonrelease_canary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
            environment = self._canary_environment(descriptor, "rung")
            environment["GROK_QUALIFICATION_DIRECT_RECOVERY"] = "1"
            authorization = self._canary_authorization_fixture(descriptor, "rung")
            with (
                mock.patch.object(client, "_release_id", return_value="f" * 64),
                mock.patch.object(
                    client, "_canary_authorization", return_value=authorization
                ),
                mock.patch.object(client, "_recover") as recover,
                self.assertRaisesRegex(
                    client.ClientError, "recovery authorization is mismatched"
                ),
            ):
                client.run(("recover",), ROOT, environment)
            recover.assert_not_called()
            self.assertDescriptorClosed(descriptor)

    def test_gated_canary_contract_consumes_capability_before_grok(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            for kind in ("release", "rung"):
                descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
                environment = self._canary_environment(descriptor, kind)
                authorization = self._canary_authorization_fixture(descriptor, kind)
                contract = SimpleNamespace(
                    release_id="f" * 64,
                    grok_release_id="grok-build-v1",
                    model_id="grok-model",
                    ladder=("direct",),
                    digest=lambda: "a" * 64,
                    limits=SimpleNamespace(max_control_connections=8),
                )
                close_authorization = client._close_canary_authorization

                def close_after_authentication(
                    selected: tuple[
                        dict[str, object],
                        str,
                        str | None,
                        str,
                        str,
                        str,
                        int,
                        str,
                    ],
                    visible: dict[str, str],
                ) -> None:
                    self.assertNotIn(
                        "GROK_INTERNAL_DIRECT_QUALIFICATION", visible
                    )
                    close_authorization(selected, visible)

                with (
                    self.subTest(kind=kind),
                    mock.patch.object(
                        client, "_canary_authorization", return_value=authorization
                    ),
                    mock.patch.object(
                        client, "qualification_route_profile_matches", return_value=True
                    ),
                    mock.patch.object(
                        client,
                        "_close_canary_authorization",
                        side_effect=close_after_authentication,
                    ) as close,
                ):
                    self.assertEqual(
                        client._canary_rung(contract, environment),
                        ("direct", None),
                    )
                close.assert_called_once()
                self.assertDescriptorClosed(descriptor)
                self.assertFalse(set(environment).intersection(client._CANARY_BINDINGS))
                if kind == "release":
                    self.assertEqual(
                        environment.get("GROK_INTERNAL_DIRECT_QUALIFICATION"),
                        "1",
                    )
                    argv = client._supervisor_argv(
                        ROOT,
                        Path("/isolated/control"),
                        contract,
                        environment,
                    )
                    self.assertNotIn("--warm-legacy-handoff", argv)
                    self.assertNotIn(
                        "GROK_INTERNAL_DIRECT_QUALIFICATION",
                        client._supervisor_env(environment, ROOT),
                    )
                else:
                    self.assertNotIn(
                        "GROK_INTERNAL_DIRECT_QUALIFICATION", environment
                    )

    def test_non_direct_canary_transfers_only_explicit_provider_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
            environment = self._canary_environment(descriptor, "rung")
            environment["GROK_RELEASE_CANARY_RUNG"] = "home:windows"
            environment["GROK_RELEASE_CANARY_ROUTE_PROFILE"] = "home:windows"
            authorization = (
                {"canary_nonce": "e" * 64},
                "home:windows",
                "a" * 64,
                "grok-build-v1",
                "grok-model",
                "rung",
                descriptor,
                "home:windows",
            )
            contract = SimpleNamespace(
                release_id="f" * 64,
                grok_release_id="grok-build-v1",
                model_id="grok-model",
                ladder=("home:windows", "vpn"),
                digest=lambda: "a" * 64,
                limits=SimpleNamespace(max_control_connections=8),
            )
            with (
                mock.patch.object(
                    client, "_canary_authorization", return_value=authorization
                ),
                mock.patch.object(
                    client,
                    "qualification_route_profile_matches",
                    return_value=True,
                ),
            ):
                rung, capability = client._canary_rung(contract, environment)
            self.assertEqual(rung, "home:windows")
            self.assertIsNotNone(capability)
            assert capability is not None
            self.assertEqual(capability.descriptor, descriptor)
            self.assertEqual(capability.nonce, "e" * 64)
            os.fstat(descriptor)
            self.assertFalse(os.get_inheritable(descriptor))
            self.assertFalse(set(environment).intersection(client._CANARY_BINDINGS))
            launched = client._supervisor_env(
                {
                    **environment,
                    "GROK_RELEASE_CANARY_FD": str(descriptor),
                    "GROK_RELEASE_CANARY_NONCE": "e" * 64,
                },
                ROOT,
            )
            self.assertFalse(set(launched).intersection(client._CANARY_BINDINGS))
            argv = client._supervisor_argv(
                ROOT,
                Path("/isolated/control"),
                contract,
                environment,
                capability,
            )
            self.assertEqual(
                argv[-2:],
                ["--provider-canary-fd", str(descriptor)],
            )
            os.close(descriptor)

    def test_non_direct_canary_mismatch_closes_and_scrubs_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth"
            auth.write_bytes(b"")
            descriptor = os.open(auth, os.O_RDONLY | os.O_CLOEXEC)
            environment = self._canary_environment(descriptor, "rung")
            authorization = (
                {"canary_nonce": "e" * 64},
                "home:windows",
                "a" * 64,
                "wrong-grok",
                "grok-model",
                "rung",
                descriptor,
                "home:windows",
            )
            contract = SimpleNamespace(
                release_id="f" * 64,
                grok_release_id="grok-build-v1",
                model_id="grok-model",
                ladder=("home:windows",),
                digest=lambda: "a" * 64,
            )
            with (
                mock.patch.object(
                    client, "_canary_authorization", return_value=authorization
                ),
                mock.patch.object(
                    client,
                    "qualification_route_profile_matches",
                    return_value=True,
                ),
                self.assertRaisesRegex(client.ClientError, "not bound"),
            ):
                client._canary_rung(contract, environment)
            self.assertDescriptorClosed(descriptor)
            self.assertFalse(set(environment).intersection(client._CANARY_BINDINGS))

    def test_runtime_filters_unqualified_exact_rungs_and_rejects_empty(self) -> None:
        contract = self._Contract(
            release_id="b" * 64,
            grok_release_id="grok-v1",
            ladder=("home:pc", "iphone", "vpn", "direct"),
            home_endpoints=(self._Home("pc"),),
        )
        selection = {
            "qualified_rungs": [
                {
                    "contract_sha256": "a" * 64,
                    "evidence_sha256": "c" * 64,
                    "grok_release_id": "grok-v1",
                    "rung": "vpn",
                },
                {
                    "contract_sha256": "a" * 64,
                    "evidence_sha256": "d" * 64,
                    "grok_release_id": "grok-v1",
                    "rung": "direct",
                },
            ]
        }
        filtered, provider_canary = client._qualified_contract(
            contract, selection, {}
        )
        self.assertIsNone(provider_canary)
        self.assertEqual(filtered.ladder, ("vpn", "direct"))
        self.assertEqual(filtered.home_endpoints, (self._Home("pc"),))
        with self.assertRaisesRegex(client.ClientError, "no rung"):
            client._qualified_contract(contract, {"qualified_rungs": []}, {})

    def _pty_owned_child(self, mode: str, action: str | None) -> tuple[int, bytes]:
        with tempfile.TemporaryDirectory() as directory:
            grok = Path(directory) / "fake-grok"
            grok.write_text(self._PTY_CHILD, encoding="ascii")
            os.chmod(grok, 0o700)
            owned, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            wrapper, master = pty.fork()
            if wrapper == 0:
                peer.close()
                connection = SeqPacketConnection(owned)

                def accepted(_connection, payload, *, fds=()):
                    return {"ok": True, "type": payload["type"]}

                client._request = accepted
                registration = {
                    "lease_id": "lease",
                    "owner_epoch": "epoch",
                    "leader_path": "/tmp/test-pty-leader.sock",
                    "public_endpoint": {"host": "127.0.0.1", "port": 1080},
                }
                try:
                    with VerifiedGrokExecutable.open(grok) as executable:
                        result = client.run_owned_child(
                            connection,
                            registration,
                            executable,
                            (mode,),
                            "grok-build",
                            True,
                            {
                                "PATH": os.environ.get("PATH", ""),
                                "GROK_INTERNAL_DIRECT_QUALIFICATION": "1",
                            },
                        )
                except client.ClientError:
                    result = 2
                finally:
                    connection.close()
                os._exit(result)

            owned.close()
            output = bytearray()

            def read_until(marker: bytes | None, timeout: float) -> bool:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if marker is not None and marker in output:
                        return True
                    readable, _, _ = select.select([master], [], [], 0.1)
                    if not readable:
                        continue
                    try:
                        chunk = os.read(master, 4_096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            return marker is None or marker in output
                        raise
                    if not chunk:
                        return marker is None or marker in output
                    output.extend(chunk)
                return marker is None or marker in output

            try:
                if action is not None:
                    marker = f"READY-{mode}".encode("ascii")
                    self.assertTrue(read_until(marker, 5), bytes(output))
                    if action == "term":
                        os.kill(wrapper, signal.SIGTERM)
                    elif action == "interrupt":
                        os.write(master, b"\x03")
                    elif action == "quit":
                        os.write(master, b"\x1c")
                    elif action == "eof":
                        peer.close()
                    else:
                        self.fail(f"unknown PTY action: {action}")
                read_until(None, 5)
                waited, status = os.waitpid(wrapper, 0)
                self.assertEqual(waited, wrapper)
                if os.WIFEXITED(status):
                    result = os.WEXITSTATUS(status)
                else:
                    result = 128 + os.WTERMSIG(status)
                return result, bytes(output)
            finally:
                peer.close()
                os.close(master)
                try:
                    os.kill(wrapper, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(wrapper, os.WNOHANG)
                except ChildProcessError:
                    pass

    def _qualification_held_child(
        self, *, release: bool
    ) -> tuple[int, bytes, bytes, int]:
        with tempfile.TemporaryDirectory() as directory:
            grok = Path(directory) / "fake-grok"
            grok.write_text(self._PTY_CHILD, encoding="ascii")
            os.chmod(grok, 0o700)
            owned, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            hold_reader, hold_writer = os.pipe2(os.O_CLOEXEC)
            wrapper, master = pty.fork()
            if wrapper == 0:
                peer.close()
                os.close(hold_writer)
                connection = SeqPacketConnection(owned)

                def accepted(_connection, payload, *, fds=()):
                    if payload["type"] == "attach-child":
                        print(f"ATTACHED:{payload['child']['pid']}", flush=True)
                    return {"ok": True, "type": payload["type"]}

                client._request = accepted
                registration = {
                    "lease_id": "lease",
                    "owner_epoch": "epoch",
                    "leader_path": "/tmp/test-qualification-leader.sock",
                    "public_endpoint": {"host": "127.0.0.1", "port": 1080},
                }
                try:
                    with VerifiedGrokExecutable.open(grok) as executable:
                        result = client.run_owned_child(
                            connection,
                            registration,
                            executable,
                            ("exit7",),
                            "grok-build",
                            True,
                            {
                                "PATH": os.environ.get("PATH", ""),
                                "GROK_QUALIFICATION_CHILD_HOLD_FD": str(
                                    hold_reader
                                ),
                            },
                        )
                except client.ClientError as exc:
                    print(f"WRAPPER-ERROR:{exc}", flush=True)
                    result = 2
                finally:
                    connection.close()
                os._exit(result)

            owned.close()
            os.close(hold_reader)
            output = bytearray()
            reaped = False
            writer_open = True

            def pump(duration: float) -> None:
                deadline = time.monotonic() + duration
                while time.monotonic() < deadline:
                    readable, _, _ = select.select(
                        [master], [], [], min(0.05, deadline - time.monotonic())
                    )
                    if not readable:
                        continue
                    try:
                        chunk = os.read(master, 4_096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            return
                        raise
                    if not chunk:
                        return
                    output.extend(chunk)

            try:
                attach_deadline = time.monotonic() + 5
                while b"ATTACHED:" not in output and time.monotonic() < attach_deadline:
                    pump(0.05)
                self.assertIn(b"ATTACHED:", output, bytes(output))
                attached_line = next(
                    line
                    for line in output.replace(b"\r", b"").splitlines()
                    if line.startswith(b"ATTACHED:")
                )
                child_pid = int(attached_line.split(b":", 1)[1])

                pump(0.25)
                before_release = bytes(output)
                self.assertNotIn(b"ERR-MARKER", before_release)
                self.assertNotIn(b"READY-exit7", before_release)
                self.assertFalse(
                    any(
                        line.startswith(b"{")
                        for line in before_release.replace(b"\r", b"").splitlines()
                    )
                )

                if release:
                    os.write(hold_writer, b"1")
                os.close(hold_writer)
                writer_open = False

                status: int | None = None
                exit_deadline = time.monotonic() + 5
                while time.monotonic() < exit_deadline:
                    waited, candidate = os.waitpid(wrapper, os.WNOHANG)
                    if waited == wrapper:
                        status = candidate
                        reaped = True
                        break
                    pump(0.05)
                self.assertIsNotNone(status, bytes(output))
                pump(0.2)
                assert status is not None
                if os.WIFEXITED(status):
                    result = os.WEXITSTATUS(status)
                else:
                    result = 128 + os.WTERMSIG(status)
                return result, before_release, bytes(output), child_pid
            finally:
                if writer_open:
                    os.close(hold_writer)
                peer.close()
                os.close(master)
                if not reaped:
                    try:
                        os.kill(wrapper, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(wrapper, 0)
                    except ChildProcessError:
                        pass

    def test_connect_timeout_does_not_leak_into_long_registration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            path = root / "control.sock"
            listener = bind_seqpacket_listener(path)
            accepted: list[socket.socket] = []

            def accept() -> None:
                peer, _ = listener.accept()
                accepted.append(peer)

            thread = threading.Thread(target=accept)
            thread.start()
            connection = client._connect(path, timeout=0.2)
            thread.join(2)
            try:
                self.assertIsNone(connection.socket.gettimeout())
                self.assertEqual(len(accepted), 1)
            finally:
                connection.close()
                for peer in accepted:
                    peer.close()
                listener.close()
                path.unlink(missing_ok=True)

    def test_zombie_readiness_owner_is_not_treated_as_attachable(self) -> None:
        barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            os.close(barrier_write)
            os.read(barrier_read, 1)
            os.close(barrier_read)
            os._exit(0)
        os.close(barrier_read)
        identity = client.ProcessIdentity(
            child,
            client.read_pid_start_ticks(child),
            client.read_boot_id(),
        )
        os.write(barrier_write, b"1")
        os.close(barrier_write)
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                stat_record = Path(f"/proc/{child}/stat").read_text(
                    encoding="ascii"
                )
                closing = stat_record.rfind(")")
                fields = stat_record[closing + 2 :].split()
                if fields and fields[0] == "Z":
                    break
                time.sleep(0.005)
            else:
                self.fail("readiness owner did not enter zombie state")
            ready = {
                "schema_version": 1,
                "protocol_version": 1,
                "release_id": "test-release",
                "owner_epoch": "test-owner",
                "pid": identity.pid,
                "pid_start_ticks": identity.start_ticks,
                "boot_id": identity.boot_id,
                "socket": "/tmp/test-supervisor.sock",
            }
            self.assertTrue(client.process_matches(identity))
            with self.assertRaisesRegex(client.ClientError, "not live"):
                client._validate_ready(
                    ready,
                    release_id="test-release",
                    socket_path=Path("/tmp/test-supervisor.sock"),
                )
        finally:
                os.waitpid(child, 0)

    def test_provider_canary_readiness_requires_the_exact_nonce(self) -> None:
        ready = {
            "schema_version": 1,
            "protocol_version": 1,
            "release_id": "a" * 64,
            "owner_epoch": "owner",
            "pid": os.getpid(),
            "pid_start_ticks": client.read_pid_start_ticks(os.getpid()),
            "boot_id": client.read_boot_id(),
            "socket": "/tmp/supervisor.sock",
            "provider_canary_nonce": "b" * 64,
        }
        identity = client._validate_ready(
            ready,
            release_id="a" * 64,
            socket_path=Path("/tmp/supervisor.sock"),
            provider_canary_nonce="b" * 64,
        )
        self.assertEqual(identity.pid, os.getpid())
        with self.assertRaisesRegex(client.ClientError, "another provider canary"):
            client._validate_ready(
                ready,
                release_id="a" * 64,
                socket_path=Path("/tmp/supervisor.sock"),
                provider_canary_nonce="c" * 64,
            )
        with self.assertRaisesRegex(client.ClientError, "unexpected shape"):
            client._validate_ready(
                ready,
                release_id="a" * 64,
                socket_path=Path("/tmp/supervisor.sock"),
            )

    def test_fresh_provider_canary_bootstrap_accepts_only_its_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            root = state / "grok-proxy" / "control"
            root.mkdir(parents=True, mode=0o700)
            environment = {
                "GROK_TESTING": "1",
                "XDG_STATE_HOME": str(state),
            }
            identity = client.current_process_identity()
            ready = {
                "schema_version": 1,
                "protocol_version": 1,
                "release_id": "a" * 64,
                "owner_epoch": "owner",
                "pid": identity.pid,
                "pid_start_ticks": identity.start_ticks,
                "boot_id": identity.boot_id,
                "socket": str(root / "supervisor.sock"),
                "provider_canary_nonce": "b" * 64,
            }
            contract = SimpleNamespace(
                release_id="a" * 64,
                timeout_policy=SimpleNamespace(stop_ms=1_000),
            )
            authorization = root / "provider-canary"
            authorization.write_bytes(b"")
            descriptor = os.open(authorization, os.O_RDONLY | os.O_CLOEXEC)
            capability = client._ProviderCanary(descriptor, "b" * 64)
            connection = mock.Mock()
            launch = mock.Mock()
            launch.process.poll.return_value = None
            launch.record.child = identity
            try:
                with (
                    mock.patch.object(
                        client,
                        "_connect",
                        side_effect=[FileNotFoundError(), connection],
                    ),
                    mock.patch.object(client, "_read_json", return_value=ready),
                    mock.patch.object(
                        client,
                        "_spawn_scoped_supervisor",
                        return_value=launch,
                    ) as spawn,
                ):
                    result = client.ensure_supervisor(
                        ROOT,
                        contract,
                        environment,
                        start_timeout=0.5,
                        process_scopes=mock.Mock(),
                        detached_store=client.DetachedScopeStore(root),
                        provider_canary=capability,
                    )
                self.assertIs(result, connection)
                self.assertIs(spawn.call_args.kwargs["provider_canary"], capability)
                launch.transfer.assert_called_once_with("owner")
                launch.cleanup.assert_not_called()
            finally:
                os.close(descriptor)

    def test_existing_provider_canary_supervisor_reuse_is_nonce_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            root = state / "grok-proxy" / "control"
            root.mkdir(parents=True, mode=0o700)
            socket_path = root / "supervisor.sock"
            ready_path = root / "supervisor.ready"
            socket_path.write_bytes(b"socket-sentinel")
            ready_path.write_bytes(b"ready-sentinel")
            before = (socket_path.read_bytes(), ready_path.read_bytes())
            environment = {
                "GROK_TESTING": "1",
                "XDG_STATE_HOME": str(state),
            }
            identity = client.current_process_identity()
            ready = {
                "schema_version": 1,
                "protocol_version": 1,
                "release_id": "a" * 64,
                "owner_epoch": "owner",
                "pid": identity.pid,
                "pid_start_ticks": identity.start_ticks,
                "boot_id": identity.boot_id,
                "socket": str(socket_path),
                "provider_canary_nonce": "b" * 64,
            }
            contract = SimpleNamespace(
                release_id="a" * 64,
                timeout_policy=SimpleNamespace(stop_ms=1_000),
            )
            authorization = root / "provider-canary"
            authorization.write_bytes(b"")
            descriptor = os.open(authorization, os.O_RDONLY | os.O_CLOEXEC)
            try:
                connection = mock.Mock()
                with (
                    mock.patch.object(client, "_connect", return_value=connection),
                    mock.patch.object(client, "_read_json", return_value=ready),
                    mock.patch.object(
                        client,
                        "_validate_owned_supervisor_scope",
                        return_value=mock.sentinel.scope,
                    ) as validate_scope,
                    mock.patch.object(client, "_spawn_scoped_supervisor") as spawn,
                ):
                    result = client.ensure_supervisor(
                        ROOT,
                        contract,
                        environment,
                        process_scopes=mock.Mock(),
                        detached_store=mock.Mock(),
                        provider_canary=client._ProviderCanary(
                            descriptor,
                            "b" * 64,
                        ),
                    )
                self.assertIs(result, connection)
                validate_scope.assert_called_once()
                spawn.assert_not_called()
                connection.close.assert_not_called()

                for nonce in ("c" * 64, None):
                    with self.subTest(nonce=nonce):
                        rejected = mock.Mock()
                        capability = (
                            None
                            if nonce is None
                            else client._ProviderCanary(descriptor, nonce)
                        )
                        with (
                            mock.patch.object(
                                client,
                                "_connect",
                                return_value=rejected,
                            ),
                            mock.patch.object(
                                client,
                                "_read_json",
                                return_value=ready,
                            ),
                            mock.patch.object(
                                client,
                                "_validate_owned_supervisor_scope",
                            ) as rejected_scope,
                            mock.patch.object(
                                client,
                                "_spawn_scoped_supervisor",
                            ) as rejected_spawn,
                            self.assertRaises(client.ClientError),
                        ):
                            client.ensure_supervisor(
                                ROOT,
                                contract,
                                environment,
                                process_scopes=mock.Mock(),
                                detached_store=mock.Mock(),
                                provider_canary=capability,
                            )
                        rejected.close.assert_called_once_with()
                        rejected_scope.assert_not_called()
                        rejected_spawn.assert_not_called()
                        self.assertEqual(
                            (socket_path.read_bytes(), ready_path.read_bytes()),
                            before,
                        )
            finally:
                os.close(descriptor)

    def test_bounded_log_truncates_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "supervisor.log"
            path.write_bytes(b"x" * 200)
            descriptor = client._open_bounded_log(path, maximum=32)
            os.close(descriptor)
            self.assertLess(path.stat().st_size, 200)
            self.assertIn(b"exceeded its bound", path.read_bytes())

            path.unlink()
            target = root / "target"
            target.write_bytes(b"")
            path.symlink_to(target)
            with self.assertRaises(OSError):
                client._open_bounded_log(path, maximum=32)

    def test_home_override_controls_stable_state_defaults(self) -> None:
        env = {"HOME": "/tmp/example-home", "GROK_TESTING": "1"}
        self.assertEqual(client._home(env), Path("/tmp/example-home"))
        self.assertEqual(
            client._state_home(env),
            Path("/tmp/example-home/.local/state"),
        )

    def test_production_control_root_uses_passwd_home_not_environment(self) -> None:
        record = type("Passwd", (), {"pw_dir": "/canonical/home"})()
        with mock.patch.object(client.pwd, "getpwuid", return_value=record):
            self.assertEqual(
                client.control_root(
                    {"HOME": "/spoofed", "XDG_STATE_HOME": "/split/state"}
                ),
                Path("/canonical/home/.local/state/grok-proxy/control"),
            )

    def test_production_execution_home_is_passwd_fixed_and_grok_bin_is_absolute(self) -> None:
        record = type("Passwd", (), {"pw_dir": "/canonical/home"})()
        with mock.patch.object(client.pwd, "getpwuid", return_value=record):
            environment = client._execution_env(
                {
                    "HOME": "/spoofed",
                    "GROK_HOME": "/spoofed/grok",
                    "XDG_STATE_HOME": "/spoofed/state",
                }
            )
            self.assertEqual(environment["HOME"], "/canonical/home")
            self.assertEqual(environment["GROK_HOME"], "/canonical/home/.grok")
            self.assertEqual(environment["XDG_STATE_HOME"], "/canonical/home/.local/state")
            self.assertEqual(client._grok_bin(environment), Path("/canonical/home/.local/bin/grok"))
            with self.assertRaisesRegex(client.ClientError, "absolute"):
                client._grok_bin({**environment, "GROK_BIN": "relative-grok"})

    def test_secure_json_requires_exact_mode_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = root / "record.json"
            record.write_text('{"ok":true}\n', encoding="ascii")
            os.chmod(record, 0o600)
            self.assertEqual(client._read_json(record), {"ok": True})
            os.chmod(record, 0o644)
            with self.assertRaisesRegex(client.ClientError, "owner/type/mode"):
                client._read_json(record)
            os.chmod(record, 0o444)
            self.assertEqual(client._read_json(record, expected_mode=0o444), {"ok": True})
            link = root / "link.json"
            link.symlink_to(record)
            with self.assertRaises(client.ClientError):
                client._read_json(link, expected_mode=0o444)

    def test_bootstrap_deadline_bounds_lock_acquisition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            root = state / "grok-proxy/control"
            root.mkdir(parents=True, mode=0o700)
            lock = os.open(root / "bootstrap.lock", os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            environment = {"GROK_TESTING": "1", "XDG_STATE_HOME": str(state)}
            contract = SimpleNamespace(timeout_policy=SimpleNamespace(stop_ms=1))
            started = time.monotonic()
            try:
                with mock.patch.object(client, "_bootstrap_timeout", return_value=0.15), mock.patch.object(
                    client.subprocess, "Popen"
                ) as popen:
                    with self.assertRaisesRegex(client.ClientError, "bootstrap lock"):
                        client.ensure_supervisor(ROOT, contract, environment)
                popen.assert_not_called()
                self.assertLess(time.monotonic() - started, 0.75)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)

    def test_warm_bootstrap_timeout_includes_stop_budget_and_is_capped(self) -> None:
        contract = SimpleNamespace(
            timeout_policy=SimpleNamespace(stop_ms=8_000)
        )
        self.assertEqual(client._bootstrap_timeout(contract, 15), 33.0)
        very_slow = SimpleNamespace(
            timeout_policy=SimpleNamespace(stop_ms=300_000)
        )
        self.assertEqual(client._bootstrap_timeout(very_slow, 15), 60.0)

    def test_status_reports_recovery_required_when_socket_is_absent_but_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            root = state / "grok-proxy" / "control"
            root.mkdir(parents=True, mode=0o700)
            fence = root / "recovery.fence"
            fence.write_text("{}\n", encoding="ascii")
            os.chmod(fence, 0o600)
            environment = {
                "GROK_TESTING": "1",
                "XDG_STATE_HOME": str(state),
            }
            with mock.patch("sys.stderr") as stderr:
                self.assertEqual(client._control("status", environment), 2)
            self.assertIn("recovery required", str(stderr.write.call_args_list))

    def test_recover_passes_complete_exact_epoch_expectation_atomically(self) -> None:
        environment = {
            "GROK_TESTING": "1",
            "XDG_STATE_HOME": "/tmp/grok-client-recovery-state",
            "GROK_TEST_SKIP_WARM_HANDOFF": "1",
            "GROK_RECOVERY_EXPECT_RELEASE_ID": "a" * 64,
            "GROK_RECOVERY_EXPECT_OWNER_EPOCH": "epoch-a",
            "GROK_RECOVERY_EXPECT_PID": "123",
            "GROK_RECOVERY_EXPECT_PID_START_TICKS": "456",
            "GROK_RECOVERY_EXPECT_BOOT_ID": "11111111-2222-3333-4444-555555555555",
        }
        outcome = SimpleNamespace(to_dict=lambda: {"recovered": True})
        with mock.patch(
            "grok_ms.supervisor.recover_offline", return_value=outcome
        ) as recover, mock.patch("builtins.print"):
            self.assertEqual(client._recover(ROOT, environment), 0)
        expected = recover.call_args.kwargs["expected_fence"]
        self.assertEqual(expected[:2], ("a" * 64, "epoch-a"))
        self.assertEqual(
            (expected[2].pid, expected[2].start_ticks, expected[2].boot_id),
            (123, 456, "11111111-2222-3333-4444-555555555555"),
        )
        self.assertFalse(recover.call_args.kwargs["require_fence_absent"])

    def test_strict_direct_client_recovery_forbids_compatibility_handoff(self) -> None:
        environment = {
            "GROK_TESTING": "1",
            "XDG_STATE_HOME": "/tmp/grok-client-strict-recovery-state",
        }
        outcome = SimpleNamespace(to_dict=lambda: {"recovered": True})
        with mock.patch(
            "grok_ms.supervisor.recover_offline", return_value=outcome
        ) as recover, mock.patch("builtins.print"):
            self.assertEqual(
                client._recover(ROOT, environment, strict_direct=True),
                0,
            )
        self.assertFalse(recover.call_args.kwargs["recover_compatibility"])
        self.assertTrue(recover.call_args.kwargs["forbid_compatibility_handoff"])

    def test_recover_rejects_incomplete_or_conflicting_expectations_before_mutation(self) -> None:
        incomplete = {
            "GROK_TESTING": "1",
            "GROK_RECOVERY_EXPECT_RELEASE_ID": "a" * 64,
        }
        with mock.patch("grok_ms.supervisor.recover_offline") as recover:
            with self.assertRaisesRegex(client.ClientError, "incomplete"):
                client._recover(ROOT, incomplete)
            recover.assert_not_called()
        conflicting = {
            "GROK_TESTING": "1",
            "GROK_RECOVERY_EXPECT_ABSENT": "1",
            "GROK_RECOVERY_EXPECT_RELEASE_ID": "a" * 64,
        }
        with mock.patch("grok_ms.supervisor.recover_offline") as recover:
            with self.assertRaisesRegex(client.ClientError, "owner and an absent"):
                client._recover(ROOT, conflicting)
            recover.assert_not_called()

    def test_installed_client_always_requests_warm_legacy_handoff(self) -> None:
        contract = mock.Mock()
        contract.digest.return_value = "a" * 64
        argv = client._supervisor_argv(
            Path("/installed/release"),
            Path("/canonical/home/.local/state/grok-proxy/control"),
            contract,
        )
        self.assertIn("--warm-legacy-handoff", argv)
        self.assertEqual(argv[argv.index("--control-root") + 1], "/canonical/home/.local/state/grok-proxy/control")

        live_override = client._supervisor_argv(
            Path("/installed/release"),
            Path("/canonical/home/.local/state/grok-proxy/control"),
            contract,
            {"GROK_TEST_SKIP_WARM_HANDOFF": "1"},
        )
        self.assertIn("--warm-legacy-handoff", live_override)

        test_skip = client._supervisor_argv(
            Path("/installed/release"),
            Path("/isolated/control"),
            contract,
            {
                "GROK_TESTING": "1",
                "GROK_TEST_SKIP_WARM_HANDOFF": "1",
            },
        )
        self.assertNotIn("--warm-legacy-handoff", test_skip)
        non_exact = client._supervisor_argv(
            Path("/installed/release"),
            Path("/isolated/control"),
            contract,
            {
                "GROK_TESTING": "1",
                "GROK_TEST_SKIP_WARM_HANDOFF": "true",
            },
        )
        self.assertIn("--warm-legacy-handoff", non_exact)

    def test_supervisor_launch_is_pinned_to_release_cwd_and_ignores_pythonpath_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            shadow = base / "caller-cwd"
            (shadow / "grok_ms").mkdir(parents=True)
            (shadow / "grok_ms" / "supervisor.py").write_text(
                "raise SystemExit(91)\n",
                encoding="ascii",
            )
            environment = {
                "GROK_TESTING": "1",
                "XDG_STATE_HOME": str(base / "state"),
                "PYTHONPATH": str(shadow),
                "PATH": os.environ.get("PATH", ""),
            }
            contract = mock.Mock()
            contract.digest.return_value = "a" * 64
            contract.timeout_policy.stop_ms = 1_000
            launch = mock.Mock()
            launch.process.poll.return_value = None
            previous = Path.cwd()
            try:
                os.chdir(shadow)
                with mock.patch.object(
                    client,
                    "_bootstrap_timeout",
                    return_value=0.06,
                ), mock.patch.object(
                    client,
                    "_connect",
                    side_effect=FileNotFoundError,
                ), mock.patch.object(
                    client,
                    "_spawn_scoped_supervisor",
                    return_value=launch,
                ) as spawn:
                    with self.assertRaisesRegex(
                        client.ClientError,
                        "supervisor did not become ready",
                    ):
                        client.ensure_supervisor(ROOT, contract, environment)
            finally:
                os.chdir(previous)
            spawn.assert_called_once()
            argv = client._supervisor_argv(
                ROOT,
                client.control_root(environment),
                contract,
                environment,
            )
            self.assertEqual(
                argv[:5],
                [
                    "/usr/bin/python3",
                    "-E",
                    "-s",
                    "-m",
                    "grok_ms.supervisor",
                ],
            )
            self.assertIn("--scoped-bootstrap", argv)
            self.assertEqual(spawn.call_args.args[0], ROOT)
            launched_environment = client._supervisor_env(environment, ROOT)
            self.assertNotIn("PYTHONPATH", launched_environment)
            self.assertEqual(
                launched_environment["PATH"],
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            launch.cleanup.assert_called_once()

    def test_scoped_supervisor_isolated_from_wrapper_process_group(self) -> None:
        contract = mock.Mock()
        contract.digest.return_value = "a" * 64
        contract.limits.max_control_connections = 3
        backend = mock.Mock()
        backend.plan.return_value = mock.sentinel.scope
        store = mock.Mock()
        with mock.patch.object(
            client.subprocess,
            "Popen",
            side_effect=OSError("injected before process creation"),
        ) as popen:
            with self.assertRaisesRegex(
                client.ClientError,
                "cannot establish scoped supervisor bootstrap",
            ):
                client._spawn_scoped_supervisor(
                    ROOT,
                    Path("/tmp/grok-client-session-isolation"),
                    contract,
                    {"GROK_TESTING": "1"},
                    2,
                    backend=backend,
                    store=store,
                    cleanup_seconds=1.0,
                )
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_scoped_supervisor_client_crash_matrix_reconciles_exact_epoch(self) -> None:
        contract = SimpleNamespace(
            release_id="a" * 64,
            digest=lambda: "b" * 64,
            limits=SimpleNamespace(max_control_connections=8),
        )
        for boundary, expected_phase in (
            ("prepared", "PREPARED"),
            ("created-effect", "PREPARED"),
            ("scope-created", "SCOPE_CREATED"),
            ("attach-effect", "SCOPE_CREATED"),
            ("attached", "ATTACHED"),
        ):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as td:
                root = Path(td) / "control"
                store = client.DetachedScopeStore(root)
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                child = os.fork()
                if child == 0:
                    os.close(read_fd)
                    backend = client.LinuxCgroupV2Scope()
                    child_store = client.DetachedScopeStore(root)
                    log_fd = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)

                    def checkpoint() -> None:
                        os.write(write_fd, b"1")
                        while True:
                            signal.pause()

                    original_put = client.DetachedScopeStore.put
                    original_replace = client.DetachedScopeStore.replace
                    original_create = client.LinuxCgroupV2Scope.create
                    original_attach = client.LinuxCgroupV2Scope.attach

                    def put(instance, record):
                        result = original_put(instance, record)
                        if boundary == "prepared":
                            checkpoint()
                        return result

                    def create(instance, planned):
                        result = original_create(instance, planned)
                        if boundary == "created-effect":
                            checkpoint()
                        return result

                    def replace(instance, expected, updated):
                        result = original_replace(instance, expected, updated)
                        if (
                            boundary == "scope-created"
                            and updated.phase == "SCOPE_CREATED"
                        ) or (
                            boundary == "attached"
                            and updated.phase == "ATTACHED"
                        ):
                            checkpoint()
                        return result

                    def attach(instance, handle, identity):
                        result = original_attach(instance, handle, identity)
                        if boundary == "attach-effect":
                            checkpoint()
                        return result

                    try:
                        with (
                            mock.patch.object(
                                client.DetachedScopeStore, "put", put
                            ),
                            mock.patch.object(
                                client.DetachedScopeStore, "replace", replace
                            ),
                            mock.patch.object(
                                client.LinuxCgroupV2Scope, "create", create
                            ),
                            mock.patch.object(
                                client.LinuxCgroupV2Scope, "attach", attach
                            ),
                        ):
                            client._spawn_scoped_supervisor(
                                ROOT,
                                root,
                                contract,
                                {
                                    "GROK_TESTING": "1",
                                    "GROK_TEST_SKIP_WARM_HANDOFF": "1",
                                    "PATH": os.environ.get("PATH", ""),
                                },
                                log_fd,
                                backend=backend,
                                store=child_store,
                                cleanup_seconds=5.0,
                            )
                    except BaseException:
                        os._exit(91)
                    os._exit(92)
                os.close(write_fd)
                record = None
                try:
                    readable, _, _ = select.select([read_fd], [], [], 10)
                    self.assertEqual(readable, [read_fd])
                    self.assertEqual(os.read(read_fd, 1), b"1")
                    record = store.load("supervisor-epoch")
                    self.assertIsNotNone(record)
                    assert record is not None
                    self.assertEqual(record.phase, expected_phase)
                    if boundary in {
                        "created-effect",
                        "scope-created",
                        "attach-effect",
                        "attached",
                    }:
                        self.assertTrue(Path(record.scope.scope_path).exists())
                    os.kill(child, signal.SIGKILL)
                    waited, status = os.waitpid(child, 0)
                    self.assertEqual(waited, child)
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

                    client._reconcile_stale_supervisor_scope(
                        store,
                        client.LinuxCgroupV2Scope(),
                        5.0,
                    )
                    self.assertIsNone(store.load("supervisor-epoch"))
                    self.assertFalse(Path(record.scope.scope_path).exists())
                    self.assertFalse(
                        client.process_can_still_execute(record.child)
                    )
                finally:
                    os.close(read_fd)
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child, os.WNOHANG)
                    except ChildProcessError:
                        pass
                    remaining = store.load("supervisor-epoch")
                    if remaining is not None:
                        try:
                            client._reconcile_stale_supervisor_scope(
                                store,
                                client.LinuxCgroupV2Scope(),
                                5.0,
                            )
                        except Exception:
                            pass

    def test_failed_child_attach_kills_and_reaps_blocked_child(self) -> None:
        registration = {
            "lease_id": "lease",
            "owner_epoch": "epoch",
            "leader_path": "/tmp/unused-leader.sock",
            "public_endpoint": {"host": "127.0.0.1", "port": 1080},
        }
        with mock.patch.object(
            client,
            "_request",
            side_effect=client.ClientError("injected attach failure"),
        ):
            with VerifiedGrokExecutable.open(Path("/bin/false")) as executable:
                with self.assertRaisesRegex(client.ClientError, "injected attach"):
                    client.run_owned_child(
                        object(),
                        registration,
                        executable,
                        (),
                        "grok-build",
                        False,
                        {"PATH": os.environ.get("PATH", "")},
                    )
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_qualification_child_hold_blocks_exec_until_explicit_release(self) -> None:
        result, before_release, output, child_pid = self._qualification_held_child(
            release=True
        )
        self.assertEqual(result, 7, output)
        self.assertIn(b"ATTACHED:", before_release)
        self.assertNotIn(b"ERR-MARKER", before_release)
        self.assertIn(b"ERR-MARKER", output)
        self.assertTrue(
            any(
                line.startswith(b"{")
                for line in output.replace(b"\r", b"").splitlines()
            )
        )
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_qualification_child_hold_eof_aborts_before_exec_and_reaps_child(self) -> None:
        result, before_release, output, child_pid = self._qualification_held_child(
            release=False
        )
        self.assertEqual(result, 2, output)
        self.assertIn(b"ATTACHED:", before_release)
        self.assertIn(
            b"WRAPPER-ERROR:qualification child hold was not released", output
        )
        self.assertNotIn(b"ERR-MARKER", output)
        self.assertNotIn(b"READY-exit7", output)
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_owned_child_preserves_pty_process_group_output_and_exit(self) -> None:
        result, output = self._pty_owned_child("exit7", None)
        self.assertEqual(result, 7, output)
        self.assertIn(b"ERR-MARKER", output)
        records = []
        for line in output.replace(b"\r", b"").splitlines():
            if line.startswith(b"{"):
                records.append(json.loads(line))
        self.assertEqual(len(records), 1, output)
        record = records[0]
        self.assertTrue(record["stdin_tty"])
        self.assertTrue(record["stdout_tty"])
        self.assertTrue(record["stderr_tty"])
        self.assertEqual(record["pgrp"], record["foreground_pgrp"])
        self.assertEqual(record["sid"], record["ppid"])
        self.assertIsNone(record["direct_qualification_marker"])
        self.assertEqual(
            record["argv"],
            [
                "--no-leader",
                "--leader-socket",
                "/tmp/test-pty-leader.sock",
                "exit7",
            ],
        )

    def test_owned_child_forwards_wrapper_term_and_terminal_interrupt(self) -> None:
        term_result, term_output = self._pty_owned_child("term", "term")
        self.assertEqual(term_result, 43, term_output)
        int_result, int_output = self._pty_owned_child("interrupt", "interrupt")
        self.assertEqual(int_result, 42, int_output)

    def test_terminal_quit_reaches_child_while_wrapper_reaps_and_survives(self) -> None:
        result, output = self._pty_owned_child("quit", "quit")
        self.assertEqual(result, 44, output)
        records = [
            json.loads(line)
            for line in output.replace(b"\r", b"").splitlines()
            if line.startswith(b"{")
        ]
        self.assertEqual(len(records), 1, output)
        with self.assertRaises(ProcessLookupError):
            os.kill(records[0]["pid"], 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_supervisor_eof_kills_direct_child_and_exits_fail_closed(self) -> None:
        result, output = self._pty_owned_child("eof", "eof")
        self.assertEqual(result, 2, output)

    def test_registered_client_releases_self_opened_selection_lock_before_child(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            release_dir = base / "release"
            release_dir.mkdir()
            root_control = base / "root-control"
            root_control.mkdir()
            lock_path = root_control / "install.lock"
            lock_path.write_bytes(b"")
            lock_path.chmod(0o644)
            attacker_descriptor = os.open(lock_path, os.O_RDONLY)
            initial_frontend_descriptor = os.open(lock_path, os.O_RDONLY)
            frontend_descriptor = fcntl.fcntl(
                initial_frontend_descriptor,
                fcntl.F_DUPFD_CLOEXEC,
                200,
            )
            os.close(initial_frontend_descriptor)
            os.set_inheritable(frontend_descriptor, True)
            environment = {
                "GROK_TESTING": "1",
                "GROK_TEST_ROOT_RELEASE_CONTROL": str(root_control),
                "GROK_RELEASE_LOCK_FD": str(attacker_descriptor),
                "GROK_FRONTEND_RELEASE_LOCK_FD": str(frontend_descriptor),
                "HOME": str(base),
                "GROK_BIN": "/bin/true",
            }
            connection = SimpleNamespace(close=mock.Mock())
            registration = {
                "lease_id": "lease",
                "owner_epoch": "epoch",
                "leader_path": "/tmp/leader",
                "public_endpoint": {"host": "127.0.0.1", "port": 1080},
            }
            acquired: list[int] = []
            original_acquire = client._release_lock_fd

            def acquire_selection_lock(env: dict[str, str]) -> int:
                descriptor = original_acquire(env)
                acquired.append(descriptor)
                return descriptor

            def child_after_registration(*_args: object, **_kwargs: object) -> int:
                self.assertEqual(len(acquired), 1)
                with self.assertRaises(OSError):
                    os.fstat(acquired[0])
                with self.assertRaises(OSError):
                    os.fstat(frontend_descriptor)
                os.fstat(attacker_descriptor)
                child_environment = _args[6]
                self.assertIsInstance(child_environment, dict)
                self.assertNotIn(
                    "GROK_FRONTEND_RELEASE_LOCK_FD",
                    child_environment,
                )
                self.assertNotIn("GROK_RELEASE_LOCK_FD", child_environment)
                return 23

            with (
                mock.patch.object(client, "_release_gate", return_value={}),
                mock.patch.object(
                    client, "_release_lock_fd", side_effect=acquire_selection_lock
                ),
                mock.patch.object(
                    client,
                    "_qualified_contract",
                    side_effect=lambda contract, _selection, _env: (
                        contract,
                        None,
                    ),
                ),
                mock.patch.object(client, "resolve_model", return_value=("grok-build", True)),
                mock.patch.object(
                    client,
                    "build_contract",
                    return_value=SimpleNamespace(to_dict=lambda: {}),
                ),
                mock.patch.object(client, "ensure_supervisor", return_value=connection),
                mock.patch.object(client, "_request", return_value=registration),
                mock.patch.object(
                    client, "run_owned_child", side_effect=child_after_registration
                ),
            ):
                result = client.run(
                    ("--direct", "-m", "grok-build", "prompt"),
                    release_dir,
                    environment,
                )
            self.assertEqual(result, 23)
            connection.close.assert_called_once_with()
            choice = base / "grok-proxy/.model.choice"
            self.assertEqual(choice.read_text(encoding="ascii"), "grok-build\n")
            self.assertEqual(stat.S_IMODE(choice.stat().st_mode), 0o600)
            os.close(attacker_descriptor)

    def test_root_release_control_override_is_test_only_and_absolute(self) -> None:
        production = client._root_release_control(
            {"GROK_TEST_ROOT_RELEASE_CONTROL": "/tmp/untrusted"}
        )
        self.assertEqual(production, Path("/var/lib/grok-proxy/release-control"))
        self.assertEqual(
            client._root_release_control(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_ROOT_RELEASE_CONTROL": "/tmp/isolated-control",
                }
            ),
            Path("/tmp/isolated-control"),
        )
        with self.assertRaisesRegex(client.ClientError, "must be absolute"):
            client._root_release_control(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_ROOT_RELEASE_CONTROL": "relative/control",
                }
            )

    def test_inactive_residue_includes_intents_and_leaders_with_safe_modes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "control"
            root.mkdir(mode=0o700)
            for name, expected in (("intents", "effect intent"), ("leaders", "leader")):
                with self.subTest(name=name):
                    directory = root / name
                    directory.mkdir(mode=0o700)
                    residue = directory / "residue"
                    residue.write_bytes(b"fixture\n")
                    self.assertIn(expected, client._inactive_residue(root) or "")
                    residue.unlink()
                    directory.chmod(0o755)
                    self.assertIn("unsafe", client._inactive_residue(root) or "")
                    directory.rmdir()
            recovery = root / "recovery"
            recovery.mkdir(mode=0o700)
            scopes = recovery / "provider-scopes"
            scopes.mkdir(mode=0o700)
            residue = scopes / "fixture.provider.json"
            residue.write_bytes(b"fixture\n")
            self.assertIn(
                "provider command scope record",
                client._inactive_residue(root) or "",
            )
            residue.unlink()
            scopes.chmod(0o755)
            self.assertIn("unsafe", client._inactive_residue(root) or "")
            scopes.rmdir()
            recovery.rmdir()


if __name__ == "__main__":
    unittest.main(verbosity=2)
