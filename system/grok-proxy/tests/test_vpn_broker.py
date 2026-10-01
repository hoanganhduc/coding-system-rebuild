#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader("vpn_broker", str(ROOT / "vpn-broker"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
loader.exec_module(module)


def scope_record(serial: int = 1) -> dict[str, object]:
    name = f"grok-vpn-{serial:024x}"
    parent = Path("/sys/fs/cgroup/grok-vpn-broker-test")
    return {
        "backend": "cgroup-v2-v1",
        "parent_path": str(parent),
        "parent_device": 1,
        "parent_inode": 2,
        "scope_path": str(parent / name),
        "scope_device": 1,
        "scope_inode": serial + 2,
    }


class Result:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self) -> None:
        self.namespace = False
        self.tun = False
        self.host_tun = False
        self.calls: list[tuple[str, ...]] = []
        self.call_options: list[dict[str, object]] = []
        self.environments: list[dict[str, str]] = []
        self.vpn_serial = 100

    def __call__(self, argv, **_kwargs):
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        self.call_options.append(dict(_kwargs))
        if "env" in _kwargs:
            self.environments.append(dict(_kwargs["env"]))
        if command == ("ip", "netns", "list"):
            return Result(0, "grokvpn\n" if self.namespace else "")
        if command == (
            "ip", "netns", "exec", "grokvpn", "ip", "-json", "link", "show"
        ):
            if not self.namespace:
                return Result(1, "", "namespace absent")
            links = [{"ifname": "lo"}]
            if self.tun:
                links.append({"ifname": "tun-grok"})
            return Result(0, json.dumps(links))
        if command == ("ip", "-json", "link", "show"):
            links = [{"ifname": "lo"}]
            if self.host_tun:
                links.append({"ifname": "tun-grok"})
            return Result(0, json.dumps(links))
        if command and command[0] == "ss":
            return Result(0, "")
        operation = command[-1]
        if operation in {"up", "next"}:
            self.namespace = self.tun = True
            self.vpn_serial += 1
        elif operation == "down":
            self.namespace = self.tun = False
        return Result(0)


class FakeBroker(module.Broker):
    def __init__(self, *args, runtime: Path, **kwargs):
        super().__init__(*args, **kwargs)
        self.runtime = runtime
        self.relay_running = False
        self.relay_pid = 4242
        self.stop_failure = False
        self.spawned_helper: Path | None = None
        self.current_vpn: dict[str, object] | None = None
        self.invoked_guards: list[Path] = []

    def _relay_pidfile(self, request):
        del request
        self.runtime.mkdir(mode=0o700, exist_ok=True)
        return self.runtime / "backend.pid"

    def _vpn_identity(self, scope=None):
        if scope is None:
            scope = scope_record(self.runner.vpn_serial)
        record = {
            "pid": self.runner.vpn_serial,
            "start_ticks": self.runner.vpn_serial + 1000,
            "boot_id": self._boot_id(),
            "uid": self.expected_root_uid,
            "pidfile": str(self.layout.vpn_pid),
            "scope": scope,
        }
        self.current_vpn = record
        return record

    def _vpn_process_matches(self, record):
        return bool(self.runner.tun and record is not None and record == self.current_vpn)

    def _spawn_relay(self, request, relay):
        self.spawned_helper = relay
        self.relay_running = True
        path = self._relay_pidfile(request)
        path.write_text(f"{self.relay_pid}\n", encoding="ascii")
        path.chmod(0o600)
        return {
            "pid": self.relay_pid,
            "start_ticks": 777,
            "boot_id": self._boot_id(),
            "uid": request.caller_uid,
            "pidfile": str(path),
            "listen_port": request.listen_port,
            "helper": str(relay),
        }

    def _relay_process_matches(self, record, request, relay):
        return bool(
            self.relay_running
            and record
            and record["pid"] == self.relay_pid
            and record["uid"] == request.caller_uid
            and record["listen_port"] == request.listen_port
            and record["helper"] == str(relay)
        )

    def _relay_alive(self, record, request, relay):
        return self._relay_process_matches(record, request, relay)

    def _listener_owner(self, port):
        del port
        return self.relay_pid if self.relay_running else None

    def _stop_relay(self, record, request, relay):
        del record, relay
        if self.stop_failure:
            raise module.BrokerError("injected relay stop failure")
        self.relay_running = False
        self._relay_pidfile(request).unlink(missing_ok=True)

    def _invoke(
        self,
        helper,
        broker_guard,
        operation,
        request,
        *,
        phase,
        vpn,
        relay,
    ):
        self.invoked_guards.append(Path(broker_guard))
        del phase, relay
        result = self.runner(
            [str(helper), operation],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
            close_fds=True,
            cwd="/",
            env=self._helper_environment(request),
            check=False,
        )
        if result.returncode:
            raise module.BrokerError(f"VPN helper {operation} failed")
        if operation in {"up", "next", "reset"}:
            return self._vpn_identity()
        return vpn


class BrokerTests(unittest.TestCase):
    def test_helper_failure_detail_hashes_untrusted_output(self) -> None:
        payload = b"hostile\n\x1b[31mTOKEN\x1b[0m"
        detail = module._bounded_failure_detail(payload, 42)
        self.assertIn("exit=42", detail)
        self.assertIn(f"output_bytes={len(payload)}", detail)
        self.assertIn(hashlib.sha256(payload).hexdigest(), detail)
        self.assertNotIn("TOKEN", detail)
        self.assertNotIn("\x1b", detail)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.base = base
        self.uid = os.getuid()
        self.release_id = "a" * 64
        self.release = base / "releases" / self.release_id
        self.release.mkdir(parents=True)
        self.root_files = {
            "broker": "vpn-broker",
            "relay": "socks-netns.py",
            "sanitizer": "sanitize.awk",
            "vpngate": "vpngate-connect.sh",
        }
        entries = []
        for role, name in self.root_files.items():
            helper = self.release / name
            helper.write_text(f"{role}\n", encoding="ascii")
            helper.chmod(0o444 if role == "sanitizer" else 0o555)
            data = helper.read_bytes()
            entries.append({
                "role": role,
                "path": name,
                "mode": "0444" if role == "sanitizer" else "0555",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        installer = self.release / "install-release.py"
        installer.write_text("# immutable installer runtime\n", encoding="ascii")
        installer.chmod(0o444)
        installer_data = installer.read_bytes()
        entries.append({
            "path": installer.name,
            "mode": "0444",
            "size": len(installer_data),
            "sha256": hashlib.sha256(installer_data).hexdigest(),
        })
        manifest = {
            "schema_version": 2,
            "kind": "root",
            "release_id": self.release_id,
            "files": entries,
        }
        (self.release / "release.json").write_text(json.dumps(manifest), encoding="utf-8")
        (self.release / "release.json").chmod(0o444)
        self.release.chmod(0o555)
        selection = base / "control/selected-release.json"
        selection.parent.mkdir()
        selection.write_text(json.dumps({
            "schema_version": 1,
            "release_schema_version": 2,
            "release_id": self.release_id,
            "root_release_id": self.release_id,
            "user_release_id": self.release_id,
            "root_files": self.root_files,
            "operation": "install",
            "selection_phase": "READY",
            "evidence_sha256": "1" * 64,
            "target_uid": self.uid,
            "target_gid": os.getgid(),
            "user_root": str(base / "home/.local/lib/grok-proxy"),
            "root_root": str(base),
            "root_control": str(selection.parent),
        }), encoding="utf-8")
        selection.chmod(0o444)
        (selection.parent / "install.lock").write_bytes(b"")
        (selection.parent / "install.lock").chmod(0o644)
        self.layout = module.Layout(
            releases=base / "releases",
            selection=selection,
            deny=base / "control/rollback-deny.json",
            state=base / "broker",
            vpn_pid=base / "vpngate/openvpn.pid",
            vpn_start=base / "vpngate/openvpn.start",
            vpn_boot=base / "vpngate/openvpn.boot",
            vpn_work=base / "vpngate",
            netns_dir=base / "netns/grokvpn",
        )
        self.layout.state.mkdir(mode=0o700)
        self.layout.state.chmod(0o700)
        self.layout.lock.write_bytes(b"")
        self.layout.lock.chmod(0o600)
        self.runner = FakeRunner()
        self.broker = FakeBroker(
            self.layout,
            expected_root_uid=self.uid,
            runner=self.runner,
            runtime=base / "runtime",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def request(self, operation: str, *, port: int = 18080, **policy):
        return module.Request(
            operation,
            "compatibility",
            self.uid,
            self.release_id,
            f"compat-{self.uid}",
            0,
            port,
            **policy,
        )

    def test_bootstrap_recovery_authority_retains_every_exact_lock(self) -> None:
        target_release_id = "b" * 64
        target = self.layout.releases / target_release_id
        target.mkdir()
        entries: list[dict[str, object]] = []
        for role, name in self.root_files.items():
            destination = target / name
            source = ROOT / "vpn-broker" if role == "broker" else self.release / name
            shutil.copyfile(source, destination)
            destination.chmod(0o444 if role == "sanitizer" else 0o555)
            payload = destination.read_bytes()
            entries.append(
                {
                    "role": role,
                    "path": name,
                    "mode": "0444" if role == "sanitizer" else "0555",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        manifest = target / "release.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "kind": "root",
                    "release_id": target_release_id,
                    "files": entries,
                }
            ),
            encoding="ascii",
        )
        manifest.chmod(0o444)
        target.chmod(0o555)

        home = self.base / "home"
        control = home / ".local/state/grok-proxy/control"
        legacy_parent = home / "grok-proxy"
        control.mkdir(parents=True, mode=0o700)
        legacy_parent.mkdir(mode=0o700)
        authorities = {
            "GROK_RELEASE_CANARY_FD": self.layout.selection.parent
            / "canary-auth.lock",
            "GROK_BOOTSTRAP_RECOVERY_OPERATION_FD": self.layout.selection.parent
            / "operation.lock",
            "GROK_BOOTSTRAP_RECOVERY_BOOTSTRAP_LOCK_FD": control
            / "bootstrap.lock",
            "GROK_BOOTSTRAP_RECOVERY_COMPATIBILITY_LOCK_FD": control
            / "compatibility.lock",
            "GROK_BOOTSTRAP_RECOVERY_LEGACY_LOCK_FD": legacy_parent
            / ".grok-remote.lock",
        }
        for path in authorities.values():
            path.write_bytes(b"")
            path.chmod(0o600)

        parent_fds: list[int] = []
        inherited_fds: list[int] = []
        environment = {
            "GROK_BOOTSTRAP_RECOVERY": "1",
            "GROK_BOOTSTRAP_RECOVERY_TARGET_RELEASE_ID": target_release_id,
            "GROK_TESTING": "1",
        }
        try:
            for name, path in authorities.items():
                parent_fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
                if name != "GROK_RELEASE_CANARY_FD":
                    fcntl.flock(parent_fd, fcntl.LOCK_EX)
                inherited_fd = os.dup(parent_fd)
                parent_fds.append(parent_fd)
                inherited_fds.append(inherited_fd)
                environment[name] = str(inherited_fd)

            with mock.patch.object(module, "__file__", str(target / "vpn-broker")):
                guard, retained = module._authorize_bootstrap_recovery(
                    self.layout,
                    self.handoff_request("recover"),
                    environment,
                    expected_root_uid=self.uid,
                    expected_root_gid=os.getgid(),
                )
            self.assertEqual(guard, target / "vpn-broker")
            self.assertEqual(set(retained), set(inherited_fds))

            for descriptor in parent_fds:
                os.close(descriptor)
            parent_fds.clear()
            for name, path in authorities.items():
                if name == "GROK_RELEASE_CANARY_FD":
                    continue
                probe = os.open(path, os.O_RDWR | os.O_CLOEXEC)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe)

            for descriptor in retained:
                os.close(descriptor)
            inherited_fds.clear()
            for name, path in authorities.items():
                if name == "GROK_RELEASE_CANARY_FD":
                    continue
                probe = os.open(path, os.O_RDWR | os.O_CLOEXEC)
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(probe, fcntl.LOCK_UN)
                finally:
                    os.close(probe)
        finally:
            for descriptor in (*parent_fds, *inherited_fds):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_bootstrap_recovery_separates_authority_pid_from_ledger_uid(self) -> None:
        authority = module.Request(
            operation="recover",
            mode="compatibility-handoff",
            caller_uid=self.uid + 1,
            release_id=self.release_id,
            owner_epoch="dead-supervisor-owner",
            generation=1,
            listen_port=1080,
            caller_pid=os.getpid(),
            caller_start_ticks=self.broker._proc_start_ticks(os.getpid()),
            caller_boot_id=self.broker._boot_id(),
            deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
            caller_process_uid=self.uid,
        )
        authority.validate()
        self.assertTrue(self.broker._caller_matches(authority))
        without_override = module.replace(authority, caller_process_uid=None)
        self.assertFalse(self.broker._caller_matches(without_override))
        ledger = {
            "caller_uid": self.uid + 1,
            "release_id": self.release_id,
            "owner_epoch": f"compat-{self.uid + 1}",
            "generation": 0,
            "listen_port": 1080,
            "contract_digest": "0" * 64,
            "vpn_policy": {
                "max_tries": 1,
                "ranking_version": "vpngate-score-uptime-v1",
                "countries": [],
                "prefer_countries": [],
                "blocked_countries": [],
            },
        }
        cleanup = self.broker._request_from_ledger(
            ledger, "recover", authority
        )
        self.assertEqual(cleanup.caller_uid, self.uid + 1)
        self.assertEqual(cleanup.caller_process_uid, self.uid)
        self.assertTrue(self.broker._caller_matches(cleanup))

    def test_roleless_root_runtime_is_verified_without_becoming_a_helper(self) -> None:
        helpers = self.broker._helpers(self.release_id, self.root_files)
        self.assertEqual(set(helpers), module._ROOT_ROLES)
        self.assertNotIn("install-release.py", {path.name for path in helpers.values()})

        installer = self.release / "install-release.py"
        installer.chmod(0o644)
        installer.write_text("# tampered installer runtime\n", encoding="ascii")
        installer.chmod(0o444)
        with self.assertRaisesRegex(
            module.BrokerError,
            "root helper does not match its manifest",
        ):
            self.broker._helpers(self.release_id, self.root_files)

    def canary_supervisor_request(
        self,
        operation: str,
        *,
        contract_digest: str = "c" * 64,
        port: int = 18080,
    ):
        return module.Request(
            operation=operation,
            mode="supervisor",
            caller_uid=self.uid,
            release_id=self.release_id,
            owner_epoch="supervisor-epoch",
            generation=1,
            listen_port=port,
            contract_digest=contract_digest,
        )

    def write_vpn_rung_canary(self, **updates) -> None:
        deny = {
            "schema_version": 1,
            "operation": "canary",
            "from_release": self.release_id,
            "to_release": self.release_id,
        }
        record = {
            "schema_version": 6,
            "release_id": self.release_id,
            "host_id": module.Broker._host_id(),
            "rung": "vpn",
            "route_profile": "vpn",
            "contract_sha256": "c" * 64,
            "grok_release_id": "sha256:" + "d" * 64,
            "model_id": "grok-4.5",
            "canary_kind": "rung",
            "canary_nonce": "e" * 64,
            "created_unix_ns": 1,
            "profile_sha256": None,
        }
        record.update(updates)
        if self.layout.deny.exists():
            self.layout.deny.chmod(0o600)
        if self.layout.rung_canary.exists():
            self.layout.rung_canary.chmod(0o600)
        self.layout.deny.write_text(json.dumps(deny), encoding="ascii")
        self.layout.deny.chmod(0o444)
        self.layout.rung_canary.write_text(json.dumps(record), encoding="ascii")
        self.layout.rung_canary.chmod(0o444)

    def set_selection_phase(self, phase: str) -> None:
        self.layout.selection.chmod(0o600)
        value = json.loads(self.layout.selection.read_text(encoding="utf-8"))
        value["selection_phase"] = phase
        value["evidence_sha256"] = "0" * 64 if phase == "CANARY" else "1" * 64
        self.layout.selection.write_text(json.dumps(value), encoding="utf-8")
        self.layout.selection.chmod(0o444)

    def execute_first_install_bootstrap_migration(self):
        self.set_selection_phase("CANARY")
        if self.layout.deny.exists():
            self.layout.deny.chmod(0o600)
        self.layout.deny.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "install",
                    "from_release": None,
                    "to_release": self.release_id,
                }
            ),
            encoding="ascii",
        )
        self.layout.deny.chmod(0o444)
        return self.broker.release_bootstrap_migration(self.release_id)

    def make_prior_passing_release(
        self, release_id: str, *, evidence_schema: int = 3
    ) -> None:
        release = self.layout.releases / release_id
        release.mkdir()
        entries = []
        for role, name in self.root_files.items():
            helper = release / name
            helper.write_text(f"prior-{role}\n", encoding="ascii")
            helper.chmod(0o444 if role == "sanitizer" else 0o555)
            data = helper.read_bytes()
            entries.append(
                {
                    "role": role,
                    "path": name,
                    "mode": "0444" if role == "sanitizer" else "0555",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        manifest = {
            "schema_version": 2,
            "kind": "root",
            "release_id": release_id,
            "files": entries,
        }
        manifest_path = release / "release.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_path.chmod(0o444)
        release.chmod(0o555)
        if evidence_schema == 2:
            criteria_ids = (
                "release-pair",
                "target-root-map",
                "compatibility-matrix",
                "broker-status-helper-map",
                "multi-root-inventory-empty",
            )
        elif evidence_schema == 3:
            criteria_ids = (
                "release-pair",
                "target-root-map",
                "legacy-root-migration",
                "compatibility-matrix",
                "broker-status-helper-map",
                "multi-root-inventory-empty",
            )
        else:
            raise AssertionError("unsupported prior evidence test schema")
        evidence = {
            "schema_version": evidence_schema,
            "release_id": release_id,
            "operation": "install",
            "host_id": module.Broker._host_id(),
            "created_unix_ns": 1,
            "user_manifest_sha256": "d" * 64,
            "root_manifest_sha256": hashlib.sha256(
                manifest_path.read_bytes()
            ).hexdigest(),
            "root_files": self.root_files,
            "criteria": [
                {
                    "id": criterion_id,
                    "passed": True,
                    "result_sha256": "e" * 64,
                    "duration_ms": 0,
                }
                for criterion_id in criteria_ids
            ],
            "overall_pass": True,
        }
        evidence_path = (
            self.layout.selection.parent / "evidence" / f"{release_id}.json"
        )
        evidence_path.parent.mkdir(exist_ok=True)
        evidence_path.write_text(json.dumps(evidence), encoding="ascii")
        evidence_path.chmod(0o444)

    def test_status_missing_stable_lock_fails_without_creating_state(self) -> None:
        self.layout.lock.unlink()
        state_before = self.layout.state.stat()
        before = tuple(sorted(path.relative_to(self.base) for path in self.base.rglob("*")))
        with self.assertRaisesRegex(module.BrokerError, "stable broker lock"):
            self.broker.execute(self.request("status"))
        after = tuple(sorted(path.relative_to(self.base) for path in self.base.rglob("*")))
        state_after = self.layout.state.stat()
        self.assertEqual(after, before)
        self.assertEqual(
            (
                state_after.st_dev,
                state_after.st_ino,
                state_after.st_mtime_ns,
                stat.S_IMODE(state_after.st_mode),
            ),
            (
                state_before.st_dev,
                state_before.st_ino,
                state_before.st_mtime_ns,
                stat.S_IMODE(state_before.st_mode),
            ),
        )
        self.assertFalse(self.layout.lock.exists())

    def test_status_unsafe_state_mode_fails_without_chmod_or_creation(self) -> None:
        self.layout.state.chmod(0o755)
        lock_before = self.layout.lock.stat()
        with self.assertRaisesRegex(module.BrokerError, "unsafe stable broker state"):
            self.broker.execute(self.request("status"))
        state_after = self.layout.state.stat()
        lock_after = self.layout.lock.stat()
        self.assertEqual(stat.S_IMODE(state_after.st_mode), 0o755)
        self.assertEqual(
            (lock_after.st_dev, lock_after.st_ino, stat.S_IMODE(lock_after.st_mode)),
            (lock_before.st_dev, lock_before.st_ino, stat.S_IMODE(lock_before.st_mode)),
        )

    def test_status_unsafe_lock_mode_fails_without_repairing_it(self) -> None:
        self.layout.lock.chmod(0o644)
        before = self.layout.lock.stat()
        with self.assertRaisesRegex(module.BrokerError, "unsafe broker lock"):
            self.broker.execute(self.request("status"))
        after = self.layout.lock.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode)),
            (before.st_dev, before.st_ino, 0o644),
        )

    def test_unowned_host_tun_is_reported_and_blocks_activation_without_deletion(self) -> None:
        self.runner.host_tun = True
        status = self.broker.execute(self.request("status"))
        self.assertTrue(status["host_tun_alive"])
        self.assertFalse(status["active"])
        before = tuple(self.runner.calls)
        with self.assertRaisesRegex(module.BrokerError, "unowned VPN/relay residue"):
            self.broker.execute(self.request("up"))
        self.assertTrue(self.runner.host_tun)
        self.assertFalse(
            any(call[:3] == ("ip", "link", "del") for call in self.runner.calls[len(before):])
        )

    def test_expired_deadline_and_dead_exact_caller_fail_before_root_inspection(self) -> None:
        identity = {
            "caller_pid": os.getpid(),
            "caller_start_ticks": self.broker._proc_start_ticks(os.getpid()),
            "caller_boot_id": self.broker._boot_id(),
        }
        expired = self.request(
            "status",
            **identity,
            deadline_monotonic_ns=time.monotonic_ns() - 1,
        )
        with self.assertRaisesRegex(module.BrokerError, "deadline expired"):
            self.broker.execute(expired)
        self.assertEqual(self.runner.calls, [])

        dead = self.request(
            "status",
            caller_pid=2**31 - 1,
            caller_start_ticks=1,
            caller_boot_id=self.broker._boot_id(),
            deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
        )
        with self.assertRaisesRegex(module.BrokerError, "caller identity"):
            self.broker.execute(dead)
        self.assertEqual(self.runner.calls, [])

    def test_operation_result_poll_is_capped_by_provider_absolute_deadline(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            request = self.request(
                "up",
                caller_pid=os.getpid(),
                caller_start_ticks=self.broker._proc_start_ticks(os.getpid()),
                caller_boot_id=self.broker._boot_id(),
                deadline_monotonic_ns=time.monotonic_ns() + 30_000_000,
            )
            started = time.monotonic()
            with self.assertRaisesRegex(module.BrokerError, "deadline expired"):
                self.broker._read_operation_result(read_fd, 360.0, request)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_release_root_inventory_is_deny_safe_closed_and_noncreating(self) -> None:
        self.layout.lock.unlink()
        self.layout.state.rmdir()
        self.layout.deny.write_text("{}\n", encoding="ascii")
        self.layout.deny.chmod(0o600)
        before = tuple(sorted(path.relative_to(self.base) for path in self.base.rglob("*")))
        inventory = self.broker.release_root_inventory(self.release_id)
        after = tuple(sorted(path.relative_to(self.base) for path in self.base.rglob("*")))
        self.assertEqual(before, after)
        self.assertEqual(
            set(inventory),
            {
                "ok", "active", "namespace_alive", "tun_alive",
                "host_tun_alive", "vpn_alive", "relay_alive",
                "root_artifact_residue", "ledger", "release_id", "root_files",
            },
        )
        self.assertTrue(inventory["ok"])
        self.assertFalse(any(
            inventory[name]
            for name in (
                "active", "namespace_alive", "tun_alive", "host_tun_alive",
                "vpn_alive", "relay_alive", "root_artifact_residue",
            )
        ))
        self.assertIsNone(inventory["ledger"])
        self.assertEqual(inventory["release_id"], self.release_id)
        self.assertEqual(inventory["root_files"], self.root_files)
        self.assertFalse(self.layout.state.exists())

    def test_release_root_inventory_fd_authority_is_exact_and_unforgeable(self) -> None:
        auth = self.layout.selection.parent / "canary-auth.lock"
        auth.write_bytes(b"")
        auth.chmod(0o600)
        exact_fd = os.open(auth, os.O_RDONLY)
        with mock.patch.dict(
            os.environ,
            {
                "GROK_RELEASE_INVENTORY_FD": str(exact_fd),
                "GROK_RELEASE_INVENTORY_RELEASE_ID": self.release_id,
            },
            clear=False,
        ):
            self.assertEqual(
                module._authorize_release_inventory(self.layout, self.uid),
                self.release_id,
            )
        with self.assertRaises(OSError):
            os.fstat(exact_fd)

        forged = self.base / "forged-canary"
        forged.write_bytes(b"")
        forged.chmod(0o600)
        forged_fd = os.open(forged, os.O_RDONLY)
        with mock.patch.dict(
            os.environ,
            {
                "GROK_RELEASE_INVENTORY_FD": str(forged_fd),
                "GROK_RELEASE_INVENTORY_RELEASE_ID": self.release_id,
            },
            clear=False,
        ), self.assertRaisesRegex(module.BrokerError, "not exact"):
            module._authorize_release_inventory(self.layout, self.uid)
        with self.assertRaises(OSError):
            os.fstat(forged_fd)

    def handoff_request(self, operation: str = "migrate-legacy"):
        return module.Request(
            operation=operation,
            mode="compatibility-handoff",
            caller_uid=self.uid,
            release_id=self.release_id,
            owner_epoch="handoff-test-epoch",
            generation=1,
            listen_port=1080,
        )

    def supervisor_request(
        self,
        operation: str,
        *,
        owner: str = "supervisor-owner-a",
        port: int = 18080,
    ):
        return module.Request(
            operation=operation,
            mode="supervisor",
            caller_uid=self.uid,
            release_id=self.release_id,
            owner_epoch=owner,
            generation=1,
            listen_port=port,
        )

    def fence_record(self, owner: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "owner_epoch": owner,
            "release_id": self.release_id,
            "pid": os.getpid(),
            "pid_start_ticks": self.broker._proc_start_ticks(os.getpid()),
            "boot_id": self.broker._boot_id(),
            "phase": "BOOTSTRAPPING",
        }

    def write_fence(self, home: Path, owner: str) -> Path:
        fence = home / ".local/state/grok-proxy/control/recovery.fence"
        fence.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fence.write_text(json.dumps(self.fence_record(owner)), encoding="ascii")
        fence.chmod(0o600)
        return fence

    def write_dead_recovering_fence(self, home: Path, owner: str) -> Path:
        fence = self.write_fence(home, owner)
        record = self.fence_record(owner)
        record.update(
            {
                "boot_id": "00000000-0000-0000-0000-000000000000",
                "phase": "RECOVERING",
            }
        )
        fence.write_text(json.dumps(record), encoding="ascii")
        fence.chmod(0o600)
        return fence

    def execute_handoff(self, operation: str = "migrate-legacy"):
        home = self.base / "handoff-home"
        self.write_fence(home, "handoff-test-epoch")
        with mock.patch.object(self.broker, "_home", return_value=home):
            return self.broker.execute(self.handoff_request(operation))

    def make_inert_legacy_workdir(self, *, historical_private: bool = False) -> Path:
        work = self.layout.vpn_work
        work.mkdir(mode=0o700)
        fixtures = {
            "list.csv": (0o600 if historical_private else 0o644, b"csv\n"),
            "parsed.tsv": (0o600 if historical_private else 0o644, b"tsv\n"),
            "vpngate.ovpn": (0o600 if historical_private else 0o644, b"client\n"),
            "up.sh": (0o700 if historical_private else 0o755, b"#!/bin/sh\n"),
            "openvpn.log": (0o600, b""),
        }
        for name, (mode, content) in fixtures.items():
            path = work / name
            path.write_bytes(content)
            path.chmod(mode)
        return work

    def test_public_legacy_handoff_is_nonmutating_and_requires_absence(self) -> None:
        before = mock.Mock(
            st_dev=1, st_ino=2, st_uid=self.uid, st_mode=stat.S_IFDIR | 0o700,
            st_size=4096, st_nlink=2,
        )
        after = mock.Mock(
            st_dev=1, st_ino=2, st_uid=self.uid, st_mode=stat.S_IFDIR | 0o700,
            st_size=0, st_nlink=1,
        )
        self.assertTrue(self.broker._same_directory_identity(before, after))
        after.st_ino = 3
        self.assertFalse(self.broker._same_directory_identity(before, after))

        result = self.execute_handoff()
        self.assertFalse(result["migrated"])
        self.assertFalse(self.layout.ledger.exists())

        for historical_private in (False, True):
            with self.subTest(historical_private=historical_private):
                work = self.make_inert_legacy_workdir(
                    historical_private=historical_private
                )
                with self.assertRaisesRegex(
                    module.BrokerError,
                    "compatibility handoff requires absent legacy root artifacts",
                ):
                    self.execute_handoff()
                self.assertTrue(work.exists())
                shutil.rmtree(work)

    def test_public_handoff_recover_cannot_retire_compatibility_owner(self) -> None:
        with mock.patch.object(
            self.broker, "_home", return_value=self.base / "compat-start-home"
        ):
            self.broker.execute(self.request("up", port=1080))
        home = self.base / "handoff-recovery-home"
        fence = self.write_dead_recovering_fence(
            home, "handoff-test-epoch"
        )

        with mock.patch.object(self.broker, "_home", return_value=home):
            with self.assertRaisesRegex(
                module.BrokerError, "requires signed bootstrap authority"
            ):
                self.broker.execute(self.handoff_request("recover"))

        self.assertTrue(self.layout.ledger.exists())
        self.assertTrue(self.runner.tun)
        self.assertTrue(self.broker.relay_running)
        self.assertTrue(fence.exists())

    def test_bootstrap_handoff_cleanup_executes_only_candidate_broker_guard(
        self,
    ) -> None:
        with mock.patch.object(
            self.broker, "_home", return_value=self.base / "bootstrap-start-home"
        ):
            self.broker.execute(self.request("up", port=1080))
        self.broker.invoked_guards.clear()
        home = self.base / "bootstrap-recovery-home"
        self.write_dead_recovering_fence(home, "handoff-test-epoch")
        with mock.patch.object(self.broker, "_home", return_value=home):
            result = self.broker.execute(
                self.handoff_request("recover"),
                recovery_broker_guard=ROOT / "vpn-broker",
            )
        self.assertTrue(result["recovered"])
        self.assertEqual(self.broker.invoked_guards, [ROOT / "vpn-broker"])
        self.assertNotEqual(
            self.broker.invoked_guards[0], self.release / self.root_files["broker"]
        )

    def test_handoff_recover_requires_dead_recovering_fence(self) -> None:
        with mock.patch.object(
            self.broker, "_home", return_value=self.base / "compat-live-start-home"
        ):
            self.broker.execute(self.request("up", port=1080))
        home = self.base / "handoff-live-fence-home"
        fence = self.write_fence(home, "handoff-test-epoch")
        request = self.handoff_request("recover")
        with mock.patch.object(self.broker, "_home", return_value=home):
            with self.assertRaisesRegex(module.BrokerError, "RECOVERING"):
                self.broker.execute(request)
            record = self.fence_record("handoff-test-epoch")
            record["phase"] = "RECOVERING"
            fence.write_text(json.dumps(record), encoding="ascii")
            fence.chmod(0o600)
            with self.assertRaisesRegex(module.BrokerError, "still live"):
                self.broker.execute(request)
        self.assertTrue(self.layout.ledger.exists())
        self.assertTrue(self.runner.tun)

    def test_handoff_recover_rejects_noncompatibility_ledger(self) -> None:
        home = self.base / "handoff-wrong-ledger-home"
        supervisor = self.supervisor_request("up", port=1080)
        self.write_fence(home, supervisor.owner_epoch)
        with mock.patch.object(self.broker, "_home", return_value=home):
            self.broker.execute(supervisor)
        self.write_dead_recovering_fence(home, "handoff-test-epoch")
        with mock.patch.object(self.broker, "_home", return_value=home):
            with self.assertRaisesRegex(module.BrokerError, "exact legacy owner"):
                self.broker.execute(self.handoff_request("recover"))
        ledger = json.loads(self.layout.ledger.read_text(encoding="ascii"))
        self.assertEqual(ledger["owner_epoch"], supervisor.owner_epoch)
        self.assertEqual(ledger["phase"], "ACTIVE")

    def test_handoff_recover_failure_retains_failed_ledger_and_fence(self) -> None:
        with mock.patch.object(
            self.broker, "_home", return_value=self.base / "compat-fail-start-home"
        ):
            self.broker.execute(self.request("up", port=1080))
        home = self.base / "handoff-failed-recovery-home"
        fence = self.write_dead_recovering_fence(
            home, "handoff-test-epoch"
        )
        self.broker.stop_failure = True
        with mock.patch.object(self.broker, "_home", return_value=home):
            with self.assertRaises(module.BrokerError):
                self.broker.execute(
                    self.handoff_request("recover"),
                    recovery_broker_guard=ROOT / "vpn-broker",
                )
        ledger = json.loads(self.layout.ledger.read_text(encoding="ascii"))
        self.assertEqual(ledger["owner_epoch"], f"compat-{self.uid}")
        self.assertEqual(ledger["phase"], "FAILED")
        self.assertTrue(fence.exists())

    def test_handoff_recover_retry_durably_syncs_an_absent_ledger(self) -> None:
        with mock.patch.object(
            self.broker, "_home", return_value=self.base / "compat-fsync-start-home"
        ):
            self.broker.execute(self.request("up", port=1080))
        home = self.base / "handoff-fsync-recovery-home"
        fence = self.write_dead_recovering_fence(
            home, "handoff-test-epoch"
        )
        request = self.handoff_request("recover")
        real_fsync = module._fsync_directory
        failed = False

        def fail_first_absence(path: Path) -> None:
            nonlocal failed
            if (
                not failed
                and path == self.layout.ledger.parent
                and not self.layout.ledger.exists()
            ):
                failed = True
                raise OSError("injected ledger-parent fsync failure")
            real_fsync(path)

        with (
            mock.patch.object(self.broker, "_home", return_value=home),
            mock.patch.object(
                module, "_fsync_directory", side_effect=fail_first_absence
            ),
            self.assertRaisesRegex(OSError, "injected ledger-parent"),
        ):
            self.broker.execute(
                request,
                recovery_broker_guard=ROOT / "vpn-broker",
            )

        self.assertTrue(failed)
        self.assertFalse(self.layout.ledger.exists())
        absent_syncs = 0

        def record_absence(path: Path) -> None:
            nonlocal absent_syncs
            if (
                path == self.layout.ledger.parent
                and not self.layout.ledger.exists()
            ):
                absent_syncs += 1
            real_fsync(path)

        with (
            mock.patch.object(self.broker, "_home", return_value=home),
            mock.patch.object(
                module, "_fsync_directory", side_effect=record_absence
            ),
        ):
            result = self.broker.execute(
                request,
                recovery_broker_guard=ROOT / "vpn-broker",
            )
        self.assertFalse(result["recovered"])
        self.assertEqual(absent_syncs, 1)
        self.assertTrue(fence.exists())

    def test_installer_bootstrap_migration_is_install_bound_and_idempotent(self) -> None:
        source_release = "b" * 64
        self.set_selection_phase("CANARY")
        self.make_prior_passing_release(source_release)
        self.layout.deny.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "install",
                    "from_release": source_release,
                    "to_release": self.release_id,
                }
            ),
            encoding="ascii",
        )
        self.layout.deny.chmod(0o444)
        work = self.make_inert_legacy_workdir(historical_private=True)
        result = self.broker.release_bootstrap_migration(self.release_id)
        self.assertTrue(result["migrated"])
        self.assertTrue(result["pre_root_artifact_residue"])
        self.assertFalse(result["post_root_artifact_residue"])
        self.assertFalse(work.exists())
        repeated = self.broker.release_bootstrap_migration(self.release_id)
        self.assertFalse(repeated["migrated"])

        self.layout.deny.chmod(0o600)
        deny = json.loads(self.layout.deny.read_text(encoding="ascii"))
        deny["from_release"] = None
        self.layout.deny.write_text(json.dumps(deny), encoding="ascii")
        self.layout.deny.chmod(0o444)
        work = self.make_inert_legacy_workdir()
        first_install = self.broker.release_bootstrap_migration(self.release_id)
        self.assertTrue(first_install["migrated"])
        self.assertFalse(work.exists())

        for operation, source in (
            ("rollback", source_release),
            ("canary", self.release_id),
            ("install", self.release_id),
            ("install", "f" * 64),
        ):
            with self.subTest(operation=operation, source=source):
                self.layout.deny.chmod(0o600)
                self.layout.deny.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "operation": operation,
                            "from_release": source,
                            "to_release": self.release_id,
                        }
                    ),
                    encoding="ascii",
                )
                self.layout.deny.chmod(0o444)
                work = self.make_inert_legacy_workdir()
                with self.assertRaises(module.BrokerError):
                    self.broker.release_bootstrap_migration(self.release_id)
                self.assertTrue(work.exists())
                shutil.rmtree(work)

        self.layout.deny.chmod(0o600)
        self.layout.deny.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "install",
                    "from_release": None,
                    "to_release": self.release_id,
                }
            ),
            encoding="ascii",
        )
        self.layout.deny.chmod(0o444)
        self.set_selection_phase("READY")
        work = self.make_inert_legacy_workdir()
        with self.assertRaisesRegex(module.BrokerError, "exact CANARY"):
            self.broker.release_bootstrap_migration(self.release_id)
        self.assertTrue(work.exists())

    def test_installer_bootstrap_accepts_host_bound_passing_schema2_prior_release(self) -> None:
        source_release = "b" * 64
        self.set_selection_phase("CANARY")
        self.make_prior_passing_release(source_release, evidence_schema=2)
        self.layout.deny.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "install",
                    "from_release": source_release,
                    "to_release": self.release_id,
                }
            ),
            encoding="ascii",
        )
        self.layout.deny.chmod(0o444)
        work = self.make_inert_legacy_workdir(historical_private=True)

        result = self.broker.release_bootstrap_migration(self.release_id)

        self.assertTrue(result["migrated"])
        self.assertFalse(work.exists())

    def test_canary_deny_allows_only_absent_compatibility_handoff(self) -> None:
        self.layout.deny.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "canary",
                    "from_release": self.release_id,
                    "to_release": self.release_id,
                }
            ),
            encoding="ascii",
        )
        self.layout.deny.chmod(0o444)
        result = self.execute_handoff()
        self.assertFalse(result["migrated"])

        work = self.make_inert_legacy_workdir()
        with self.assertRaisesRegex(
            module.BrokerError, "compatibility handoff requires absent legacy root artifacts"
        ):
            self.execute_handoff()
        self.assertTrue(work.exists())

    def test_exact_vpn_rung_canary_admits_only_supervisor_up_and_next(self) -> None:
        self.write_vpn_rung_canary()
        home = self.base / "vpn-canary-home"
        self.write_fence(home, "supervisor-epoch")
        with mock.patch.object(self.broker, "_home", return_value=home):
            started = self.broker.execute(self.canary_supervisor_request("up"))
            self.assertTrue(started["active"])
            advanced = self.broker.execute(self.canary_supervisor_request("next"))
            self.assertTrue(advanced["active"])
            stopped = self.broker.execute(self.canary_supervisor_request("down"))
            self.assertFalse(stopped["active"])
        self.assertFalse(self.layout.ledger.exists())

    def test_vpn_rung_canary_mismatches_remain_fenced_before_helpers(self) -> None:
        cases = (
            ("compatibility", {}, self.request("up", contract_digest="c" * 64)),
            ("reset", {}, self.canary_supervisor_request("reset")),
            (
                "contract",
                {},
                self.canary_supervisor_request("up", contract_digest="f" * 64),
            ),
            ("rung", {"rung": "direct"}, self.canary_supervisor_request("up")),
            ("profile", {"route_profile": "direct"}, self.canary_supervisor_request("up")),
            ("host", {"host_id": "f" * 64}, self.canary_supervisor_request("up")),
            ("schema", {"schema_version": 3}, self.canary_supervisor_request("up")),
        )
        for label, updates, request in cases:
            with self.subTest(label=label):
                self.write_vpn_rung_canary(**updates)
                before = len(self.runner.calls)
                with self.assertRaisesRegex(
                    module.BrokerError, "release switching/rollback is fenced"
                ):
                    self.broker.execute(request)
                self.assertEqual(len(self.runner.calls), before)
                self.assertFalse(self.layout.ledger.exists())

        self.write_vpn_rung_canary()
        self.layout.canary_terminal.write_text("{}\n", encoding="ascii")
        self.layout.canary_terminal.chmod(0o444)
        with self.assertRaisesRegex(
            module.BrokerError, "release switching/rollback is fenced"
        ):
            self.broker.execute(self.canary_supervisor_request("up"))
        self.layout.canary_terminal.unlink()

        self.set_selection_phase("CANARY")
        with self.assertRaisesRegex(module.BrokerError, "exact READY selection"):
            self.broker.execute(self.canary_supervisor_request("up"))
        self.set_selection_phase("READY")

        self.layout.selection.chmod(0o600)
        selection = json.loads(self.layout.selection.read_text(encoding="utf-8"))
        selection["evidence_sha256"] = "0" * 64
        self.layout.selection.write_text(json.dumps(selection), encoding="utf-8")
        self.layout.selection.chmod(0o444)
        with self.assertRaisesRegex(module.BrokerError, "exact READY selection"):
            self.broker.execute(self.canary_supervisor_request("up"))
        self.set_selection_phase("READY")

        self.layout.deny.chmod(0o600)
        self.layout.deny.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "install",
                    "from_release": self.release_id,
                    "to_release": self.release_id,
                }
            ),
            encoding="ascii",
        )
        self.layout.deny.chmod(0o444)
        with self.assertRaisesRegex(
            module.BrokerError, "release switching/rollback is fenced"
        ):
            self.broker.execute(self.canary_supervisor_request("up"))

    def test_legacy_migration_mode_operation_matrix_is_closed(self) -> None:
        with self.assertRaises(module.BrokerError):
            self.request("migrate-legacy").validate()
        supervisor = module.Request(
            operation="migrate-legacy",
            mode="supervisor",
            caller_uid=self.uid,
            release_id=self.release_id,
            owner_epoch="supervisor-epoch",
            generation=1,
            listen_port=1080,
        )
        with self.assertRaises(module.BrokerError):
            supervisor.validate()
        with self.assertRaises(module.BrokerError):
            self.handoff_request("status").validate()
        wrong_port = self.handoff_request()
        wrong_port = module.Request(
            operation=wrong_port.operation,
            mode=wrong_port.mode,
            caller_uid=wrong_port.caller_uid,
            release_id=wrong_port.release_id,
            owner_epoch=wrong_port.owner_epoch,
            generation=wrong_port.generation,
            listen_port=1081,
        )
        with self.assertRaises(module.BrokerError):
            wrong_port.validate()

    def test_public_parser_rejects_abbreviations_and_duplicate_options(self) -> None:
        argv = [
            "--operation", "up",
            "--mode", "supervisor",
            "--release-id", "a" * 64,
            "--owner-epoch", "epoch-a",
            "--generation", "1",
            "--listen-port", "11082",
            "--contract-digest", "b" * 64,
            "--vpn-max-tries", "3",
            "--vpn-ranking-version", "v1",
            "--vpn-countries", "",
            "--vpn-prefer-countries", "",
            "--vpn-blocked-countries", "",
            "--caller-pid", "1",
            "--caller-start-ticks", "1",
            "--caller-boot-id", "11111111-2222-3333-4444-555555555555",
            "--deadline-monotonic-ns", "1",
        ]
        self.assertEqual(module._parser().parse_args(argv).operation, "up")
        for hostile in (
            [*argv, "--operation", "reset"],
            [*argv, "--oper", "reset"],
            [*argv, "--owner-epoch", "replacement"],
        ):
            with (
                self.subTest(hostile=hostile[-2:]),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                module._parser().parse_args(hostile)

    def test_legacy_migration_rejects_unknown_nested_active_and_hostile_entries(self) -> None:
        hostile = (
            ("unknown", lambda work: (work / "unknown").write_bytes(b"x")),
            ("pid", lambda work: (work / "openvpn.pid").write_bytes(b"123\n")),
            ("start", lambda work: (work / "openvpn.start").write_bytes(b"456\n")),
            ("candidate", lambda work: (work / "candidates.tsv").write_bytes(b"x")),
            ("nested", lambda work: (work / "nested").mkdir()),
            (
                "symlink",
                lambda work: (
                    (work / "list.csv").unlink(),
                    (work / "list.csv").symlink_to(work / "parsed.tsv"),
                ),
            ),
            (
                "fifo",
                lambda work: (
                    (work / "list.csv").unlink(),
                    os.mkfifo(work / "list.csv", 0o644),
                ),
            ),
            ("wrong-mode", lambda work: (work / "up.sh").chmod(0o777)),
        )
        for label, mutate in hostile:
            with self.subTest(label=label):
                work = self.make_inert_legacy_workdir()
                mutate(work)
                before = sorted(path.name for path in work.iterdir())
                with self.assertRaises(module.BrokerError):
                    self.execute_first_install_bootstrap_migration()
                self.assertEqual(sorted(path.name for path in work.iterdir()), before)
                shutil.rmtree(work)

    def test_legacy_migration_rejects_work_and_file_mount_identity_changes(self) -> None:
        work = self.make_inert_legacy_workdir()
        with mock.patch.object(
            self.broker,
            "_fd_mount_id",
            side_effect=(101, 202),
        ), self.assertRaisesRegex(module.BrokerError, "unsafe legacy VPN work"):
            self.execute_first_install_bootstrap_migration()
        self.assertTrue((work / "list.csv").exists())
        shutil.rmtree(work)

        work = self.make_inert_legacy_workdir()

        def mount_id(descriptor: int) -> int:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            return 202 if target.endswith("/list.csv") else 101

        with mock.patch.object(
            self.broker,
            "_fd_mount_id",
            side_effect=mount_id,
        ), self.assertRaisesRegex(module.BrokerError, "unsafe legacy VPN file"):
            self.execute_first_install_bootstrap_migration()
        self.assertTrue((work / "list.csv").exists())
        shutil.rmtree(work)

    def test_legacy_migration_diagnostic_fingerprints_hostile_names(self) -> None:
        work = self.make_inert_legacy_workdir()
        sentinel = "SECRET-legacy-name"
        hostile_name = "\x1b]8;;attacker.invalid\x07" + sentinel + "\r\b"
        (work / hostile_name).write_bytes(b"x")
        (work / "openvpn.pid").write_bytes(b"123\n")

        with self.assertRaises(module.BrokerError) as caught:
            self.execute_first_install_bootstrap_migration()

        detail = str(caught.exception)
        expected = module._name_set_fingerprint({hostile_name, "openvpn.pid"})
        self.assertEqual(
            detail,
            "active or unknown legacy VPN work entries: "
            f"active_count=1 unknown_count=1 entries_sha256={expected}",
        )
        self.assertNotIn(sentinel, detail)
        self.assertTrue(all(character.isprintable() for character in detail))
        shutil.rmtree(work)

    def test_legacy_migration_rejects_every_active_or_ambiguous_root_state(self) -> None:
        active_checks = (
            ("namespace", "_namespace_exists", True),
            ("tun", "_tun_alive", True),
            ("listener", "_listener_owner", 999),
            ("openvpn", "_legacy_openvpn_processes", (321,)),
        )
        for label, method, result in active_checks:
            with self.subTest(label=label):
                work = self.make_inert_legacy_workdir()
                with mock.patch.object(self.broker, method, return_value=result):
                    with self.assertRaises(module.BrokerError):
                        self.execute_first_install_bootstrap_migration()
                self.assertTrue(work.exists())
                shutil.rmtree(work)

        self.broker._write_phase(
            self.request("up"), "PREPARED", vpn=None, relay=None
        )
        with self.assertRaises(module.BrokerError):
            self.execute_first_install_bootstrap_migration()
        self.assertTrue(self.layout.ledger.exists())

    def test_listener_scan_rejects_wildcard_ipv6_ownerless_and_ambiguous_rows(self) -> None:
        broker = module.Broker(
            self.layout,
            expected_root_uid=self.uid,
            runner=lambda *_args, **_kwargs: Result(
                0,
                'LISTEN 0 128 0.0.0.0:1080 0.0.0.0:* users:(("one",pid=71,fd=3))\n'
                'LISTEN 0 128 [::]:1080 [::]:* users:(("one",pid=71,fd=4))\n',
            ),
        )
        self.assertEqual(broker._listener_owner(1080), 71)

        for label, output in (
            ("ownerless", "LISTEN 0 128 0.0.0.0:1080 0.0.0.0:*\n"),
            (
                "ambiguous",
                'LISTEN 0 128 127.0.0.1:1080 0.0.0.0:* users:(("a",pid=1,fd=3))\n'
                'LISTEN 0 128 [::]:1080 [::]:* users:(("b",pid=2,fd=4))\n',
            ),
        ):
            with self.subTest(label=label):
                broker.runner = lambda *_args, _output=output, **_kwargs: Result(
                    0, _output
                )
                with self.assertRaises(module.BrokerError):
                    broker._listener_owner(1080)

    def test_namespace_and_tun_inspection_fail_closed_on_errors_and_bad_json(self) -> None:
        broker = module.Broker(
            self.layout, expected_root_uid=self.uid, runner=lambda *_a, **_k: Result(1)
        )
        with self.assertRaises(module.BrokerError):
            broker._namespace_exists()

        def corrupt(argv, **_kwargs):
            if tuple(argv) == ("ip", "netns", "list"):
                return Result(0, "grokvpn (id: 9)\n")
            return Result(0, "{not-json")

        broker.runner = corrupt
        self.assertTrue(broker._namespace_exists())
        with self.assertRaises(module.BrokerError):
            broker._tun_alive()

        def link_failure(argv, **_kwargs):
            if tuple(argv) == ("ip", "netns", "list"):
                return Result(0, "grokvpn\n")
            return Result(2, "", "cannot inspect")

        broker.runner = link_failure
        with self.assertRaises(module.BrokerError):
            broker._tun_alive()

    def test_handoff_broker_argv_and_cleanup_order_are_exact(self) -> None:
        release = self.base / "handoff-user-release"
        release.mkdir()
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (release / "release.json").write_text(
            json.dumps({"release_id": self.release_id}), encoding="ascii"
        )
        argv_record = self.base / "handoff-broker.argv"
        fake_broker = self.base / "handoff-fake-broker"
        fake_broker.write_text(
            "#!/bin/bash\n"
            f"printf '%s\\0' \"$@\" > {str(argv_record)!r}\n"
            "if [[ \"${1:-}\" == --operation && \"${2:-}\" == status ]]; then\n"
            "  printf '%s\\n' '{\"ok\":true,\"active\":false,\"namespace_alive\":false,\"tun_alive\":false,\"host_tun_alive\":false,\"vpn_alive\":false,\"relay_alive\":false,\"relay_pid\":null,\"root_artifact_residue\":false,\"ledger\":null}'\n"
            "else\n"
            "  printf '{\"ok\":true}\\n'\n"
            "fi\n",
            encoding="utf-8",
        )
        fake_broker.chmod(0o755)
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.base / "home"),
            "GROK_TESTING": "1",
            "GROK_TEST_CONTROL_DIR": str(self.base / "control"),
            "GROK_TEST_VPN_BROKER": str(fake_broker),
            "GROK_HANDOFF_MODE": "1",
            "GROK_HANDOFF_OWNER_EPOCH": "handoff-test-epoch",
            "GROK_HANDOFF_RELEASE_ID": self.release_id,
            "GROK_PROXY_PORT": "1080",
        }
        private = Path(environment["HOME"]) / "grok-proxy"
        private.mkdir(parents=True, mode=0o775)
        legacy_lock = private / ".grok-remote.lock"
        legacy_lock.write_bytes(b"")
        legacy_lock.chmod(0o664)
        (private / ".egress.state").write_text("local:test\n", encoding="ascii")
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_broker_call migrate-legacy >/dev/null',
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = argv_record.read_bytes().rstrip(b"\0").decode("ascii").split("\0")
        parsed = module._parser().parse_args(values)
        self.assertEqual(parsed.operation, "migrate-legacy")
        self.assertEqual(parsed.mode, "compatibility-handoff")

        recovery_environment = dict(environment)
        recovery_environment["GROK_HANDOFF_RECOVERY_MODE"] = "1"
        recovery_result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_broker_call recover 1 >/dev/null',
            ],
            text=True,
            capture_output=True,
            env=recovery_environment,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(recovery_result.returncode, 0)

        ordinary_result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_broker_call recover >/dev/null',
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(ordinary_result.returncode, 0)

        status_result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_broker_call status >/dev/null',
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(status_result.returncode, 0, status_result.stderr)
        values = argv_record.read_bytes().rstrip(b"\0").decode("ascii").split("\0")
        parsed = module._parser().parse_args(values)
        self.assertEqual(parsed.operation, "status")
        self.assertEqual(parsed.mode, "supervisor")

        handoff_vpn_down = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_down',
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            handoff_vpn_down.returncode, 0, handoff_vpn_down.stderr
        )
        values = argv_record.read_bytes().rstrip(b"\0").decode("ascii").split("\0")
        parsed = module._parser().parse_args(values)
        self.assertEqual(parsed.operation, "status")
        self.assertEqual(parsed.mode, "supervisor")

        order = self.base / "handoff-order"
        shell = f'''
. {str(release / "egress.sh")!r}
compatibility_handoff_validate() {{ return 0; }}
active_rung() {{ printf 'local:test'; }}
assert_legacy_lock_held() {{
  ! flock -n "$PRIVATE_DIR/.grok-remote.lock" -c true
}}
vpn_broker_call() {{
  assert_legacy_lock_held || return 91
  printf 'broker:%s\\n' "$1" >> {str(order)!r}
  case "$1" in
    migrate-legacy) ;;
    status) printf '%s\\n' '{{"ok":true,"active":false,"namespace_alive":false,"tun_alive":false,"host_tun_alive":false,"vpn_alive":false,"relay_alive":false,"relay_pid":null,"root_artifact_residue":false,"ledger":null}}' ;;
    *) return 94 ;;
  esac
}}
local_down() {{ assert_legacy_lock_held || return 92; printf 'local-down\\n' >> {str(order)!r}; }}
clear_active() {{ assert_legacy_lock_held || return 93; printf 'clear\\n' >> {str(order)!r}; rm -f "$STATE"; }}
port_owner_pid() {{ return 0; }}
port_listening() {{ return 1; }}
begin_recovery_transition
compatibility_handoff_command
'''
        result = subprocess.run(
            ["/bin/bash", "-c", shell],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            order.read_text(encoding="ascii").splitlines(),
            [
                "broker:migrate-legacy",
                "local-down",
                "broker:status",
                "local-down",
                "broker:status",
                "clear",
                "broker:migrate-legacy",
                "broker:status",
                "clear",
            ],
        )
        self.assertEqual(legacy_lock.stat().st_mode & 0o777, 0o600)

    def test_standalone_handoff_requests_exact_public_recovery_admission(self) -> None:
        release = self.base / "handoff-admission-release"
        module_dir = release / "grok_ms"
        module_dir.mkdir(parents=True)
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        argv_record = module_dir / "admission.argv"
        (module_dir / "release_admission.py").write_text(
            "import pathlib, sys\n"
            "pathlib.Path(__file__).with_name('admission.argv').write_bytes("
            "b'\\0'.join(value.encode('utf-8') for value in sys.argv[1:]))\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        control = self.base / "handoff-admission-control"
        control.mkdir()
        (control / "install.lock").write_bytes(b"")
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.base / "handoff-admission-home"),
            "GROK_TESTING": "1",
            "GROK_TEST_ROOT_RELEASE_CONTROL": str(control),
            "GROK_HANDOFF_MODE": "1",
        }

        def admission_argv(
            *arguments: str,
            selected_environment: dict[str, str] | None = None,
        ) -> list[str]:
            argv_record.unlink(missing_ok=True)
            result = subprocess.run(
                ["/bin/bash", str(release / "egress.sh"), *arguments],
                text=True,
                capture_output=True,
                env=selected_environment or environment,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 78, result.stderr)
            return [
                value.decode("utf-8")
                for value in argv_record.read_bytes().split(b"\0")
            ]

        exact = admission_argv("compatibility-handoff")
        self.assertEqual(exact[-1], "--public-recovery")
        self.assertEqual(exact[:2], [str(release), str(release / "egress.sh")])
        self.assertTrue(exact[2].isdigit())

        for arguments in (("status",), ("compatibility-handoff", "extra")):
            with self.subTest(arguments=arguments):
                self.assertNotIn("--public-recovery", admission_argv(*arguments))

        provider_environment = {
            **environment,
            "GROK_HANDOFF_MODE": "0",
            "GROK_PROVIDER_MODE": "1",
        }
        for verb in ("provider-recover", "provider-prove-empty"):
            with self.subTest(verb=verb):
                exact = admission_argv(
                    verb,
                    "home:windows",
                    selected_environment=provider_environment,
                )
                self.assertEqual(
                    exact[-2:],
                    ["--public-recovery", "--provider-recovery"],
                )
        for verb in ("provider-up", "provider-next", "provider-stop"):
            with self.subTest(verb=verb):
                ordinary = admission_argv(
                    verb,
                    "home:windows",
                    selected_environment=provider_environment,
                )
                self.assertNotIn("--public-recovery", ordinary)
                self.assertNotIn("--provider-recovery", ordinary)

        partial = {
            **provider_environment,
            "GROK_RELEASE_CANARY_FD": "9",
        }
        argv_record.unlink(missing_ok=True)
        rejected = subprocess.run(
            [
                "/bin/bash",
                str(release / "egress.sh"),
                "provider-up",
                "home:windows",
            ],
            text=True,
            capture_output=True,
            env=partial,
            timeout=10,
            check=False,
        )
        self.assertEqual(rejected.returncode, 78, rejected.stderr)
        self.assertFalse(argv_record.exists())

    def test_provider_canary_admission_closes_capability_before_transport(self) -> None:
        release = self.base / "provider-canary-admission-release"
        module_dir = release / "grok_ms"
        module_dir.mkdir(parents=True)
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (module_dir / "release_admission.py").write_text(
            "import os, sys\n"
            "os.fstat(int(sys.argv[4]))\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        control = self.base / "provider-canary-admission-control"
        control.mkdir()
        install_lock = control / "install.lock"
        install_lock.write_bytes(b"")
        install_lock.chmod(0o644)
        authorization = control / "canary-auth.lock"
        authorization.write_bytes(b"")
        authorization.chmod(0o600)
        descriptor = os.open(authorization, os.O_RDONLY | os.O_CLOEXEC)
        authorization_identity = os.fstat(descriptor)
        install_lock_identity = install_lock.stat()
        runtime = self.base / "provider-canary-runtime"
        runtime.mkdir(mode=0o700)
        home = self.base / "provider-canary-home"
        (home / "grok-proxy").mkdir(parents=True)
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(home),
            "ORIGINAL_CANARY_FD": str(descriptor),
            "EXPECTED_AUTH_DEV": str(authorization_identity.st_dev),
            "EXPECTED_AUTH_INO": str(authorization_identity.st_ino),
            "EXPECTED_LOCK_DEV": str(install_lock_identity.st_dev),
            "EXPECTED_LOCK_INO": str(install_lock_identity.st_ino),
            "GROK_TESTING": "1",
            "GROK_TEST_ROOT_RELEASE_CONTROL": str(control),
            "GROK_PROVIDER_MODE": "1",
            "GROK_PROVIDER_OWNER_EPOCH": "provider-canary-owner",
            "GROK_INTERLOCK_OWNER_EPOCH": "provider-canary-owner",
            "GROK_PROVIDER_TRANSITION_ID": "provider-canary-transition",
            "GROK_PROVIDER_GENERATION": "1",
            "GROK_EGRESS_RUNTIME_DIR": str(runtime),
            "GROK_PROVIDER_INVENTORY": str(runtime / "inventory.json"),
            "GROK_PROXY_PORT": "11880",
            "GROK_REQUIRE_MODEL": "grok-4.5",
            "GROK_PROVIDER_CONTRACT_DIGEST": "b" * 64,
            "GROK_ACTIVE_RELEASE_ID": "a" * 64,
            "GROK_PROVIDER_DEADLINE_NS": str(time.monotonic_ns() + 10**10),
            "GROK_PROVIDER_HOME_LABEL": "windows",
            "GROK_PROVIDER_HOME_HOST": "100.64.0.20",
            "GROK_PROVIDER_HOME_USER": "alice",
            "GROK_PROVIDER_HOME_PORT": "22",
            "GROK_RELEASE_CANARY_FD": str(descriptor),
            "GROK_RELEASE_CANARY_RELEASE_ID": "a" * 64,
        }
        command = f'''
. {str(release / "egress.sh")!r}
require_frozen_egress_release provider-up home:windows
[[ ! -e "/proc/$$/fd/$ORIGINAL_CANARY_FD" ]]
[[ ! -e "/proc/$$/fd/$EGRESS_SELF_RELEASE_LOCK_FD" ]]
[[ ! -v GROK_RELEASE_CANARY_FD ]]
[[ ! -v GROK_RELEASE_CANARY_RELEASE_ID ]]
/usr/bin/python3 - "$EXPECTED_AUTH_DEV" "$EXPECTED_AUTH_INO" \
  "$EXPECTED_LOCK_DEV" "$EXPECTED_LOCK_INO" <<'PY'
import os
import pathlib
import sys

targets = {{
    (int(sys.argv[1]), int(sys.argv[2])),
    (int(sys.argv[3]), int(sys.argv[4])),
}}
for entry in pathlib.Path("/proc/self/fd").iterdir():
    try:
        value = os.fstat(int(entry.name))
    except OSError:
        continue
    if (value.st_dev, value.st_ino) in targets:
        raise SystemExit(1)
if "GROK_RELEASE_CANARY_FD" in os.environ:
    raise SystemExit(2)
if "GROK_RELEASE_CANARY_RELEASE_ID" in os.environ:
    raise SystemExit(3)
PY
'''
        try:
            result = subprocess.run(
                ["/bin/bash", "-c", command],
                text=True,
                capture_output=True,
                env=environment,
                pass_fds=(descriptor,),
                timeout=10,
                check=False,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_provider_admission_failure_closes_descriptors_and_preserves_code(self) -> None:
        release = self.base / "provider-admission-failure-release"
        module_dir = release / "grok_ms"
        module_dir.mkdir(parents=True)
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (module_dir / "release_admission.py").write_text(
            "import os, sys\n"
            "os.fstat(int(sys.argv[4]))\n"
            "raise SystemExit(37)\n",
            encoding="utf-8",
        )
        control = self.base / "provider-admission-failure-control"
        control.mkdir()
        install_lock = control / "install.lock"
        install_lock.write_bytes(b"")
        authorization = control / "canary-auth.lock"
        authorization.write_bytes(b"")
        descriptor = os.open(authorization, os.O_RDONLY | os.O_CLOEXEC)
        runtime = self.base / "provider-admission-failure-runtime"
        runtime.mkdir(mode=0o700)
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.base / "provider-admission-failure-home"),
            "ORIGINAL_CANARY_FD": str(descriptor),
            "GROK_TESTING": "1",
            "GROK_TEST_ROOT_RELEASE_CONTROL": str(control),
            "GROK_PROVIDER_MODE": "1",
            "GROK_PROVIDER_OWNER_EPOCH": "provider-admission-failure-owner",
            "GROK_PROVIDER_TRANSITION_ID": "provider-admission-failure-transition",
            "GROK_PROVIDER_GENERATION": "1",
            "GROK_EGRESS_RUNTIME_DIR": str(runtime),
            "GROK_PROVIDER_INVENTORY": str(runtime / "inventory.json"),
            "GROK_PROXY_PORT": "11881",
            "GROK_REQUIRE_MODEL": "grok-4.5",
            "GROK_PROVIDER_CONTRACT_DIGEST": "b" * 64,
            "GROK_ACTIVE_RELEASE_ID": "a" * 64,
            "GROK_PROVIDER_DEADLINE_NS": str(time.monotonic_ns() + 10**10),
            "GROK_PROVIDER_HOME_LABEL": "windows",
            "GROK_PROVIDER_HOME_HOST": "100.64.0.20",
            "GROK_PROVIDER_HOME_USER": "alice",
            "GROK_PROVIDER_HOME_PORT": "22",
            "GROK_RELEASE_CANARY_FD": str(descriptor),
            "GROK_RELEASE_CANARY_RELEASE_ID": "a" * 64,
        }
        command = f'''
. {str(release / "egress.sh")!r}
if require_frozen_egress_release provider-up home:windows; then
  exit 99
else
  rc=$?
fi
[[ "$rc" == 37 ]]
[[ ! -e "/proc/$$/fd/$ORIGINAL_CANARY_FD" ]]
[[ ! -e "/proc/$$/fd/$EGRESS_SELF_RELEASE_LOCK_FD" ]]
[[ ! -v GROK_RELEASE_CANARY_FD ]]
[[ ! -v GROK_RELEASE_CANARY_RELEASE_ID ]]
'''
        try:
            result = subprocess.run(
                ["/bin/bash", "-c", command],
                text=True,
                capture_output=True,
                env=environment,
                pass_fds=(descriptor,),
                timeout=10,
                check=False,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_handoff_stops_identity_only_iphone_startup(self) -> None:
        release = self.base / "identity-only-handoff-release"
        release.mkdir()
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (release / "release.json").write_text(
            json.dumps({"release_id": self.release_id}), encoding="ascii"
        )
        home = self.base / "identity-only-handoff-home"
        private = home / "grok-proxy"
        private.mkdir(parents=True, mode=0o775)
        legacy_lock = private / ".grok-remote.lock"
        legacy_lock.write_bytes(b"")
        legacy_lock.chmod(0o664)
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(home),
            "GROK_TESTING": "1",
            "GROK_TEST_CONTROL_DIR": str(self.base / "identity-only-control"),
            "GROK_HANDOFF_MODE": "1",
            "GROK_HANDOFF_OWNER_EPOCH": "handoff-test-epoch",
            "GROK_HANDOFF_RELEASE_ID": self.release_id,
            "GROK_PROXY_PORT": "1080",
        }
        marker = self.base / "identity-only-sidecar.pid"
        shim = self.base / "partial-write-shim"
        shim.mkdir()
        (shim / "sitecustomize.py").write_text(
            "import os\n"
            "_real_write = os.write\n"
            "_partial_done = False\n"
            "def _partial_write(fd, data):\n"
            "    global _partial_done\n"
            "    if not _partial_done and len(data) > 1:\n"
            "        _partial_done = True\n"
            "        return _real_write(fd, data[:max(1, len(data) // 2)])\n"
            "    return _real_write(fd, data)\n"
            "os.write = _partial_write\n",
            encoding="ascii",
        )
        shell = f'''
. {str(release / "egress.sh")!r}
export PYTHONPATH={str(shim)!r}
compatibility_handoff_validate() {{ return 0; }}
vpn_broker_call() {{
  [[ "$1" != status ]] || printf '%s\n' '{{"ok":true,"active":false,"namespace_alive":false,"tun_alive":false,"host_tun_alive":false,"vpn_alive":false,"relay_alive":false,"relay_pid":null,"root_artifact_residue":false,"ledger":null}}'
}}
clear_active() {{ rm -f -- "$STATE"; }}
port_owner_pid() {{ return 0; }}
port_listening() {{ return 1; }}
iphone_prepare_state
(
  iphone_process_identity write "$BASHPID" || exit 125
  printf '%s\n' "$BASHPID" > {str(marker)!r}
  exec /bin/sleep 60
) >/dev/null 2>&1 &
sidecar=$!
for _ in $(seq 1 100); do
  [[ -s "$IPHONE_PID_IDENTITY" && -s {str(marker)!r} ]] && break
  kill -0 "$sidecar" 2>/dev/null || break
  sleep 0.01
done
[[ -s "$IPHONE_PID_IDENTITY" && ! -e "$IPHONE_PID" && ! -e "$IPHONE_SOCKET" ]] || exit 94
compatibility_handoff_command
rc=$?
if kill -0 "$sidecar" 2>/dev/null; then
  kill -KILL "$sidecar" 2>/dev/null || true
  wait "$sidecar" 2>/dev/null || true
  exit 95
fi
wait "$sidecar" 2>/dev/null || true
[[ ! -e "$IPHONE_PID_IDENTITY" && ! -L "$IPHONE_PID_IDENTITY" ]] || exit 96
exit "$rc"
'''
        result = subprocess.run(
            ["/bin/bash", "-c", shell],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_lock_rejects_unsafe_busy_and_holder_death(self) -> None:
        release = self.base / "lock-user-release"
        release.mkdir()
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (release / "release.json").write_text(
            json.dumps({"release_id": self.release_id}), encoding="ascii"
        )
        home = self.base / "lock-home"
        private = home / "grok-proxy"
        private.mkdir(parents=True, mode=0o775)
        lock = private / ".grok-remote.lock"
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(home),
            "GROK_TESTING": "1",
            "GROK_TEST_CONTROL_DIR": str(self.base / "lock-control"),
            "GROK_HANDOFF_MODE": "1",
            "GROK_HANDOFF_OWNER_EPOCH": "handoff-test-epoch",
            "GROK_HANDOFF_RELEASE_ID": self.release_id,
        }
        command = (
            f'. {str(release / "egress.sh")!r}; '
            "acquire_legacy_session_lock && legacy_session_lock_check; "
            "rc=$?; release_legacy_session_lock; exit $rc"
        )

        lock.write_bytes(b"")
        lock.chmod(0o777)
        result = subprocess.run(
            ["/bin/bash", "-c", command],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

        lock.unlink()
        target = private / "lock-target"
        target.write_bytes(b"")
        target.chmod(0o600)
        lock.symlink_to(target)
        result = subprocess.run(
            ["/bin/bash", "-c", command],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        lock.unlink()
        lock.write_bytes(b"")

        lock.chmod(0o664)
        held = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run(
                ["/bin/bash", "-c", command],
                env=environment,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)

        holder_pid = self.base / "legacy-holder.pid"
        parent = subprocess.Popen(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; '
                "acquire_legacy_session_lock || exit; "
                f"printf '%s\\n' \"$LEGACY_LOCK_PID\" > {str(holder_pid)!r}; "
                "sleep 30",
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not holder_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(holder_pid.exists())
            helper = int(holder_pid.read_text(encoding="ascii"))
            parent.kill()
            parent.wait(timeout=5)
            deadline = time.monotonic() + 5
            while Path(f"/proc/{helper}").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{helper}").exists())
            descriptor = os.open(lock, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait()

        child_death = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; '
                "acquire_legacy_session_lock || exit; "
                "kill -KILL \"$LEGACY_LOCK_PID\"; sleep 0.1; "
                "legacy_session_lock_check",
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(child_death.returncode, 0)

    def test_handoff_blocks_active_vpn_and_recreated_residue_without_adoption(self) -> None:
        release = self.base / "blocked-handoff-release"
        release.mkdir()
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (release / "release.json").write_text(
            json.dumps({"release_id": self.release_id}), encoding="ascii"
        )
        home = self.base / "blocked-home"
        private = home / "grok-proxy"
        private.mkdir(parents=True, mode=0o775)
        legacy_lock = private / ".grok-remote.lock"
        legacy_lock.write_bytes(b"")
        legacy_lock.chmod(0o664)
        (private / ".egress.state").write_text("vpn\n", encoding="ascii")
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(home),
            "GROK_TESTING": "1",
            "GROK_TEST_CONTROL_DIR": str(self.base / "blocked-control"),
            "GROK_HANDOFF_MODE": "1",
            "GROK_HANDOFF_OWNER_EPOCH": "handoff-test-epoch",
            "GROK_HANDOFF_RELEASE_ID": self.release_id,
        }
        effects = self.base / "blocked-effects"
        shell = f'''
. {str(release / "egress.sh")!r}
compatibility_handoff_validate() {{ return 0; }}
active_rung() {{ printf 'vpn'; }}
vpn_broker_call() {{ printf '%s\\n' "$1" >> {str(effects)!r}; return 1; }}
iphone_down() {{ printf 'iphone-down\\n' >> {str(effects)!r}; }}
local_down() {{ printf 'local-down\\n' >> {str(effects)!r}; }}
clear_active() {{ printf 'adopted-or-cleared\\n' >> {str(effects)!r}; }}
compatibility_handoff_command
'''
        result = subprocess.run(
            ["/bin/bash", "-c", shell],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            effects.read_text(encoding="ascii").splitlines(), ["migrate-legacy"]
        )

        effects.unlink()
        residue = self.base / "recreated-root-residue"
        shell = f'''
. {str(release / "egress.sh")!r}
compatibility_handoff_validate() {{ return 0; }}
active_rung() {{ printf 'local:test'; }}
vpn_broker_call() {{
  printf '%s\\n' "$1" >> {str(effects)!r}
  if [[ "$1" == migrate-legacy && -e {str(residue)!r} ]]; then return 1; fi
  [[ "$1" != status ]] || printf '%s\\n' '{{"ok":true,"active":false,"namespace_alive":false,"tun_alive":false,"host_tun_alive":false,"vpn_alive":false,"relay_alive":false,"relay_pid":null,"root_artifact_residue":false,"ledger":null}}'
}}
local_down() {{ : > {str(residue)!r}; }}
clear_active() {{ printf 'cleared\\n' >> {str(effects)!r}; }}
compatibility_handoff_command
'''
        result = subprocess.run(
            ["/bin/bash", "-c", shell],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            effects.read_text(encoding="ascii").splitlines(),
            ["migrate-legacy", "migrate-legacy"],
        )

        residue.unlink()
        effects.unlink()
        shell = f'''
. {str(release / "egress.sh")!r}
compatibility_handoff_validate() {{ return 0; }}
active_rung() {{ printf 'local:test'; }}
vpn_broker_call() {{
  printf '%s\\n' "$1" >> {str(effects)!r}
  [[ "$1" != status ]] || printf '%s\\n' '{{"ok":true,"active":false,"namespace_alive":false,"tun_alive":false,"host_tun_alive":false,"vpn_alive":false,"relay_alive":false,"relay_pid":null,"root_artifact_residue":true,"ledger":null}}'
}}
local_down() {{ return 0; }}
clear_active() {{ printf 'cleared\\n' >> {str(effects)!r}; }}
port_owner_pid() {{ return 0; }}
port_listening() {{ return 1; }}
compatibility_handoff_command
'''
        result = subprocess.run(
            ["/bin/bash", "-c", shell],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            effects.read_text(encoding="ascii").splitlines(),
            [
                "migrate-legacy", "migrate-legacy", "status",
            ],
        )

    def test_owner_arbitration_idempotence_and_exact_cleanup(self) -> None:
        self.broker.execute(self.request("up"))
        self.assertTrue(self.runner.tun)
        self.assertTrue(self.broker.relay_running)
        self.assertEqual(
            self.broker.spawned_helper,
            self.release / self.root_files["relay"],
        )
        again = self.broker.execute(self.request("up"))
        self.assertTrue(again["idempotent"])
        with self.assertRaises(module.BrokerError):
            self.broker.execute(self.request("down", port=18081))
        self.broker.execute(self.request("down"))
        self.assertFalse(self.runner.tun)
        self.assertFalse(self.broker.relay_running)
        self.assertFalse(self.layout.ledger.exists())

    def test_status_requires_exact_vpn_tun_namespace_and_relay(self) -> None:
        self.broker.execute(self.request("up"))
        status = self.broker.execute(self.request("status"))
        self.assertTrue(status["active"])
        self.broker.relay_running = False
        status = self.broker.execute(self.request("status"))
        self.assertFalse(status["active"])
        self.assertFalse(status["relay_alive"])

    def test_root_vpn_identity_requires_the_complete_fixed_openvpn_argv(self) -> None:
        broker = module.Broker(
            self.layout,
            expected_root_uid=self.uid,
            runner=self.runner,
        )
        pid = os.getpid()
        start = broker._proc_start_ticks(pid)
        self.layout.vpn_start.parent.mkdir(parents=True, exist_ok=True)
        self.layout.vpn_start.write_text(f"{start}\n", encoding="ascii")
        self.layout.vpn_start.chmod(0o600)
        self.layout.vpn_boot.write_text(
            f"{broker._boot_id()}\n", encoding="ascii"
        )
        self.layout.vpn_boot.chmod(0o600)
        record = {
            "pid": pid,
            "start_ticks": start,
            "boot_id": broker._boot_id(),
            "uid": self.uid,
            "pidfile": str(self.layout.vpn_pid),
            "scope": scope_record(),
        }
        complete = (
            "/usr/sbin/openvpn",
            "--config", str(self.layout.vpn_work / "vpngate.ovpn"),
            "--dev", "tun-grok",
            "--up", str(self.layout.vpn_work / "up.sh"),
        )
        with mock.patch.object(broker, "_proc_args", return_value=complete), \
             mock.patch.object(broker.operation_scopes, "contains", return_value=True):
            self.assertTrue(broker._vpn_process_matches(record))
        poisoned = (
            "/usr/sbin/openvpn",
            "--config", str(self.layout.vpn_work / "vpngate.ovpn"),
            "--dev", "tun-grok",
            "--up", str(self.layout.vpn_work / "up.sh"),
            "--daemon", "grok-vpngate",
        )
        with mock.patch.object(broker, "_proc_args", return_value=poisoned), \
             mock.patch.object(broker.operation_scopes, "contains", return_value=True):
            self.assertFalse(broker._vpn_process_matches(record))
        for daemon_form in (("--daemon", "anything"), ("--daemon=anything",)):
            with self.subTest(daemon_form=daemon_form), \
                 mock.patch.object(
                     broker, "_proc_args", return_value=complete + daemon_form
                 ), mock.patch.object(
                     broker.operation_scopes, "contains", return_value=True
                 ):
                self.assertFalse(broker._vpn_process_matches(record))

    def test_partial_boot_identity_uuid_is_bounded_but_cleanup_compatible(self) -> None:
        self.layout.vpn_work.mkdir(mode=0o700)
        self.layout.vpn_boot.write_text(
            f"{self.broker._boot_id()}\n", encoding="ascii"
        )
        self.layout.vpn_boot.chmod(0o600)
        self.assertEqual(self.layout.vpn_boot.stat().st_size, 37)
        self.broker._remove_partial_vpn_identity(None)
        self.assertFalse(self.layout.vpn_boot.exists())

    def test_relay_pidfd_signal_requires_post_open_identity_revalidation(self) -> None:
        relay = self.release / "socks-netns.py"
        request = self.request("down")
        broker = module.Broker(
            self.layout, expected_root_uid=self.uid, runner=self.runner
        )
        record = {
            "pid": os.getpid(),
            "start_ticks": broker._proc_start_ticks(os.getpid()),
            "boot_id": broker._boot_id(),
            "uid": self.uid,
            "pidfile": str(self.base / "unused.pid"),
            "listen_port": request.listen_port,
            "helper": str(relay),
        }
        descriptor = os.open("/dev/null", os.O_RDONLY)
        with mock.patch.object(
            broker, "_relay_process_matches", side_effect=[True, False]
        ), mock.patch("os.pidfd_open", return_value=descriptor), mock.patch(
            "signal.pidfd_send_signal"
        ) as send:
            with self.assertRaisesRegex(module.BrokerError, "after pidfd_open"):
                broker._stop_relay(record, request, relay)
        send.assert_not_called()

    def test_vpn_try_cap_and_derived_operation_timeout_share_one_envelope(self) -> None:
        accepted = self.request("up", vpn_max_tries=8)
        accepted.validate()
        self.assertEqual(self.broker._operation_timeout("up", accepted), 360.0)
        self.assertEqual(self.broker._operation_timeout("down", accepted), 45.0)
        with self.assertRaises(module.BrokerError):
            self.request("up", vpn_max_tries=9).validate()

    def test_empty_blocked_country_argument_round_trips_and_validates(self) -> None:
        values = [
            "--operation", "status",
            "--mode", "compatibility",
            "--release-id", self.release_id,
            "--owner-epoch", f"compat-{self.uid}",
            "--generation", "0",
            "--listen-port", "18080",
            "--contract-digest", "0" * 64,
            "--vpn-max-tries", "1",
            "--vpn-ranking-version", module._VPN_RANKING_VERSION,
            "--vpn-countries", "VN",
            "--vpn-prefer-countries", "VN",
            "--vpn-blocked-countries", "",
            "--caller-pid", "0",
            "--caller-start-ticks", "0",
            "--caller-boot-id", "",
            "--deadline-monotonic-ns", "0",
        ]
        parsed = module._parser().parse_args(values)
        request = module.Request(
            operation=parsed.operation,
            mode=parsed.mode,
            caller_uid=self.uid,
            release_id=parsed.release_id,
            owner_epoch=parsed.owner_epoch,
            generation=parsed.generation,
            listen_port=parsed.listen_port,
            contract_digest=parsed.contract_digest,
            vpn_max_tries=parsed.vpn_max_tries,
            vpn_ranking_version=parsed.vpn_ranking_version,
            vpn_countries=module._country_tuple(parsed.vpn_countries),
            vpn_prefer_countries=module._country_tuple(parsed.vpn_prefer_countries),
            vpn_blocked_countries=module._country_tuple(parsed.vpn_blocked_countries),
            caller_pid=parsed.caller_pid,
            caller_start_ticks=parsed.caller_start_ticks,
            caller_boot_id=parsed.caller_boot_id,
            deadline_monotonic_ns=parsed.deadline_monotonic_ns,
        )
        request.validate()
        self.assertEqual(request.vpn_blocked_countries, ())

    def test_proc_args_preserves_empty_broker_arguments(self) -> None:
        values = [
            "--operation", "status",
            "--mode", "compatibility",
            "--release-id", self.release_id,
            "--owner-epoch", f"compat-{self.uid}",
            "--generation", "0",
            "--listen-port", "18080",
            "--contract-digest", "0" * 64,
            "--vpn-max-tries", "1",
            "--vpn-ranking-version", module._VPN_RANKING_VERSION,
            "--vpn-countries", "",
            "--vpn-prefer-countries", "VN",
            "--vpn-blocked-countries", "",
            "--caller-pid", "0",
            "--caller-start-ticks", "0",
            "--caller-boot-id", "",
            "--deadline-monotonic-ns", "0",
        ]
        launched_values = [*values, ""]
        process = subprocess.Popen(
            [
                sys.executable,
                "-c", "import time; time.sleep(30)",
                *launched_values,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        try:
            deadline = time.monotonic() + 2
            argv: tuple[str, ...] = ()
            while time.monotonic() < deadline:
                argv = self.broker._proc_args(process.pid)
                if argv[-len(launched_values):] == tuple(launched_values):
                    break
                time.sleep(0.005)
            self.assertEqual(argv[-len(launched_values):], tuple(launched_values))
            parsed = module._parser().parse_args(
                list(argv[-len(launched_values):-1])
            )
            self.assertEqual(parsed.vpn_countries, "")
            self.assertEqual(parsed.vpn_blocked_countries, "")
            self.assertEqual(parsed.caller_boot_id, "")
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_proc_args_rejects_unterminated_cmdline(self) -> None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"python3\0broker")
        os.close(write_fd)
        with mock.patch("os.open", return_value=read_fd):
            with self.assertRaisesRegex(module.BrokerError, "unterminated"):
                self.broker._proc_args(os.getpid())

    def test_direct_internal_guard_parent_is_not_authorized_as_public_broker(self) -> None:
        self.assertFalse(module._root_guard_parent_is_public_broker(os.getpid()))

    def test_supervisor_relay_pidfile_uses_canonical_short_workspace_tag(self) -> None:
        broker = module.Broker(
            self.layout,
            expected_root_uid=self.uid,
            runner=self.runner,
        )
        owner = "0123456789abcdef0123456789abcdef"
        generation = 7
        port = 11882
        tag = hashlib.sha256(
            owner.encode("ascii")
            + b"\0"
            + str(generation).encode("ascii")
            + b"\0"
            + str(port).encode("ascii")
        ).hexdigest()[:24]
        home = self.base / "home"
        workspace = home / ".local/state/grok-proxy/control/p" / tag
        workspace.mkdir(parents=True, mode=0o700)
        request = module.Request(
            operation="status",
            mode="supervisor",
            caller_uid=self.uid,
            release_id=self.release_id,
            owner_epoch=owner,
            generation=generation,
            listen_port=port,
        )
        with mock.patch.object(broker, "_home", return_value=home):
            self.assertEqual(broker._relay_pidfile(request), workspace / "backend.pid")

    def test_real_egress_compatibility_argv_matches_closed_broker_cli(self) -> None:
        release = self.base / "user-release"
        release.mkdir()
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (release / "release.json").write_text(
            json.dumps({"release_id": self.release_id}), encoding="ascii"
        )
        argv_record = self.base / "broker.argv"
        fake_broker = self.base / "fake-broker"
        fake_broker.write_text(
            "#!/bin/bash\n"
            f"printf '%s\\0' \"$@\" > {str(argv_record)!r}\n"
            "printf '{\"ok\":true}\\n'\n",
            encoding="utf-8",
        )
        fake_broker.chmod(0o755)
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.base / "home"),
            "GROK_TESTING": "1",
            "GROK_TEST_VPN_BROKER": str(fake_broker),
            "GROK_PROXY_PORT": "18080",
            "GROK_VPN_MAX_TRIES": "4",
            "VPNGATE_COUNTRIES": "VN JP",
            "VPNGATE_PREFER": "KR TH",
            "GROK_BLOCKED_CC": "DE FR",
        }
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_broker_call status >/dev/null',
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = argv_record.read_bytes().rstrip(b"\0").decode("ascii").split("\0")
        parsed = module._parser().parse_args(values)
        request = module.Request(
            operation=parsed.operation,
            mode=parsed.mode,
            caller_uid=self.uid,
            release_id=parsed.release_id,
            owner_epoch=parsed.owner_epoch,
            generation=parsed.generation,
            listen_port=parsed.listen_port,
            contract_digest=parsed.contract_digest,
            vpn_max_tries=parsed.vpn_max_tries,
            vpn_ranking_version=parsed.vpn_ranking_version,
            vpn_countries=module._country_tuple(parsed.vpn_countries),
            vpn_prefer_countries=module._country_tuple(parsed.vpn_prefer_countries),
            vpn_blocked_countries=module._country_tuple(parsed.vpn_blocked_countries),
            caller_pid=parsed.caller_pid,
            caller_start_ticks=parsed.caller_start_ticks,
            caller_boot_id=parsed.caller_boot_id,
            deadline_monotonic_ns=parsed.deadline_monotonic_ns,
        )
        request.validate()
        self.assertEqual(request.vpn_countries, ("VN", "JP"))
        self.assertEqual(request.vpn_prefer_countries, ("KR", "TH"))
        self.assertEqual(request.vpn_blocked_countries, ("DE", "FR"))

    def test_real_egress_provider_argv_freezes_contract_identity_and_policy(self) -> None:
        release = self.base / "provider-release"
        release.mkdir()
        shutil.copy2(ROOT / "egress.sh", release / "egress.sh")
        (release / "release.json").write_text(
            json.dumps({"release_id": self.release_id}), encoding="ascii"
        )
        argv_record = self.base / "provider-broker.argv"
        fake_broker = self.base / "provider-fake-broker"
        fake_broker.write_text(
            "#!/bin/bash\n"
            f"printf '%s\\0' \"$@\" > {str(argv_record)!r}\n"
            "printf '{\"ok\":true}\\n'\n",
            encoding="utf-8",
        )
        fake_broker.chmod(0o755)
        owner = "0123456789abcdef0123456789abcdef"
        digest = "b" * 64
        runtime = self.base / "provider-runtime"
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.base / "home"),
            "GROK_TESTING": "1",
            "GROK_TEST_VPN_BROKER": str(fake_broker),
            "GROK_PROVIDER_MODE": "1",
            "GROK_PROVIDER_OWNER_EPOCH": owner,
            "GROK_PROVIDER_TRANSITION_ID": "transition-1",
            "GROK_PROVIDER_GENERATION": "7",
            "GROK_EGRESS_RUNTIME_DIR": str(runtime),
            "GROK_PROVIDER_INVENTORY": str(runtime / "inventory.json"),
            "GROK_PROXY_PORT": "18081",
            "GROK_REQUIRE_MODEL": "grok-test",
            "GROK_PROVIDER_CONTRACT_DIGEST": digest,
            "GROK_ACTIVE_RELEASE_ID": self.release_id,
            "GROK_PROVIDER_DEADLINE_NS": str(
                time.monotonic_ns() + 60_000_000_000
            ),
            "GROK_PROVIDER_VPN_NAMESPACE": "grokvpn",
            "GROK_PROVIDER_VPN_MAX_TRIES": "5",
            "GROK_PROVIDER_VPN_RANKING_VERSION": "vpngate-score-uptime-v1",
            "GROK_PROVIDER_VPN_COUNTRIES": "VN JP",
            "GROK_PROVIDER_VPN_BLOCKED_COUNTRIES": "DE FR",
            "GROK_VPN_NETNS": "grokvpn",
            "GROK_VPN_MAX_TRIES": "5",
            "VPNGATE_COUNTRIES": "VN JP",
            "GROK_BLOCKED_CC": "DE FR",
        }
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'. {str(release / "egress.sh")!r}; vpn_broker_call status >/dev/null',
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = argv_record.read_bytes().rstrip(b"\0").decode("ascii").split("\0")
        parsed = module._parser().parse_args(values)
        request = module.Request(
            operation=parsed.operation,
            mode=parsed.mode,
            caller_uid=self.uid,
            release_id=parsed.release_id,
            owner_epoch=parsed.owner_epoch,
            generation=parsed.generation,
            listen_port=parsed.listen_port,
            contract_digest=parsed.contract_digest,
            vpn_max_tries=parsed.vpn_max_tries,
            vpn_ranking_version=parsed.vpn_ranking_version,
            vpn_countries=module._country_tuple(parsed.vpn_countries),
            vpn_prefer_countries=module._country_tuple(parsed.vpn_prefer_countries),
            vpn_blocked_countries=module._country_tuple(parsed.vpn_blocked_countries),
            caller_pid=parsed.caller_pid,
            caller_start_ticks=parsed.caller_start_ticks,
            caller_boot_id=parsed.caller_boot_id,
            deadline_monotonic_ns=parsed.deadline_monotonic_ns,
        )
        request.validate()
        self.assertEqual(request.mode, "supervisor")
        self.assertEqual(request.contract_digest, digest)
        self.assertEqual(request.vpn_countries, ("VN", "JP"))
        self.assertEqual(request.vpn_prefer_countries, request.vpn_countries)
        self.assertEqual(request.vpn_blocked_countries, ("DE", "FR"))

    def test_real_provider_empty_proof_rejects_every_broker_residue_field(self) -> None:
        clean = {
            "ok": True,
            "active": False,
            "namespace_alive": False,
            "tun_alive": False,
            "host_tun_alive": False,
            "vpn_alive": False,
            "relay_alive": False,
            "relay_pid": None,
            "root_artifact_residue": False,
            "ledger": None,
        }
        script = f'''
. {str(ROOT / "egress.sh")!r}
provider_validate_context() {{ return 0; }}
provider_validate_rung() {{ return 0; }}
provider_validate_frozen_rung() {{ return 0; }}
port_owner_pid() {{ return 0; }}
vpn_broker_call() {{ printf '%s\\n' "$BROKER_STATUS"; }}
EG_RUNTIME_DIR={str(self.base / "absent-provider-runtime")!r}
provider_prove_empty_command vpn
'''
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.base / "provider-empty-home"),
            "GROK_TESTING": "1",
            "GROK_TEST_CONTROL_DIR": str(self.base / "provider-empty-control"),
        }

        def invoke(status: dict[str, object]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                env={**environment, "BROKER_STATUS": json.dumps(status)},
                timeout=10,
                check=False,
            )

        self.assertEqual(invoke(clean).returncode, 0)
        for name in (
            "active", "namespace_alive", "tun_alive", "host_tun_alive",
            "vpn_alive", "relay_alive", "root_artifact_residue",
        ):
            with self.subTest(residue=name):
                dirty = dict(clean)
                dirty[name] = True
                self.assertNotEqual(invoke(dirty).returncode, 0)
        for name, value in (("relay_pid", 123), ("ledger", {"phase": "FAILED"})):
            with self.subTest(residue=name):
                dirty = dict(clean)
                dirty[name] = value
                self.assertNotEqual(invoke(dirty).returncode, 0)
        malformed = dict(clean)
        malformed.pop("vpn_alive")
        self.assertNotEqual(invoke(malformed).returncode, 0)

    def test_next_replaces_only_vpn_identity_and_preserves_owned_relay(self) -> None:
        self.broker.execute(self.request("up"))
        before = json.loads(self.layout.ledger.read_text(encoding="utf-8"))
        self.broker.execute(self.request("next"))
        after = json.loads(self.layout.ledger.read_text(encoding="utf-8"))
        self.assertNotEqual(after["vpn"], before["vpn"])
        self.assertEqual(after["relay"], before["relay"])
        self.assertTrue(self.broker.relay_running)

    def test_frozen_policy_is_owner_identity_and_only_reconstructed_helper_env(self) -> None:
        policy = {
            "contract_digest": "b" * 64,
            "vpn_max_tries": 4,
            "vpn_ranking_version": "vpngate-score-uptime-v1",
            "vpn_countries": ("VN", "JP"),
            "vpn_prefer_countries": ("VN", "JP"),
            "vpn_blocked_countries": ("DE", "FR"),
        }
        self.broker.execute(self.request("up", **policy))
        helper_env = self.runner.environments[-1]
        self.assertEqual(helper_env["VPNGATE_COUNTRIES"], "VN JP")
        self.assertEqual(helper_env["GROK_BLOCKED_CC"], "DE FR")
        self.assertEqual(helper_env["VPNGATE_CANDIDATES"], "4")
        helper_options = [
            options
            for call, options in zip(self.runner.calls, self.runner.call_options)
            if call and call[-1] == "up" and call[0].endswith("vpngate-connect.sh")
        ][-1]
        self.assertTrue(helper_options["close_fds"])
        self.assertEqual(helper_options["cwd"], "/")
        with self.assertRaises(module.BrokerError):
            self.broker.execute(
                self.request("next", **{**policy, "contract_digest": "c" * 64})
            )

    def test_release_deny_and_relay_manifest_tamper_fail_closed(self) -> None:
        self.layout.deny.write_text("{}", encoding="ascii")
        with self.assertRaises(module.BrokerError):
            self.broker.execute(self.request("up"))
        self.assertFalse(self.broker.execute(self.request("status"))["active"])
        self.assertTrue(self.broker.execute(self.request("down"))["idempotent"])
        self.assertFalse(self.broker.execute(self.request("recover"))["recovered"])
        self.layout.deny.unlink()
        helper = self.release / "socks-netns.py"
        helper.chmod(0o755)
        helper.write_text("changed", encoding="ascii")
        with self.assertRaises(module.BrokerError):
            self.broker.execute(self.request("up"))

    def test_supervisor_fence_schema_is_closed_and_owner_exact(self) -> None:
        home = self.base / "fence-home"
        request = self.supervisor_request("status")
        fence = self.write_fence(home, request.owner_epoch)
        with mock.patch.object(self.broker, "_home", return_value=home):
            self.broker._fence(request)
            base = self.fence_record(request.owner_epoch)
            mutations = {
                "missing": {key: value for key, value in base.items() if key != "phase"},
                "extra": {**base, "unexpected": True},
                "schema": {**base, "schema_version": 2},
                "pid-bool": {**base, "pid": True},
                "boot": {**base, "boot_id": "not-a-boot-id"},
                "phase": {**base, "phase": "ACTIVE"},
                "owner": {**base, "owner_epoch": "supervisor-owner-b"},
                "release": {**base, "release_id": "b" * 64},
            }
            for label, value in mutations.items():
                with self.subTest(label=label):
                    fence.write_text(json.dumps(value), encoding="ascii")
                    fence.chmod(0o600)
                    with self.assertRaises(module.BrokerError):
                        self.broker._fence(request)

    def test_recover_rejects_a_different_authenticated_owner(self) -> None:
        home = self.base / "cross-owner-home"
        owner_a = self.supervisor_request("up", owner="supervisor-owner-a")
        owner_b = self.supervisor_request("recover", owner="supervisor-owner-b")
        self.write_fence(home, owner_a.owner_epoch)
        with mock.patch.object(self.broker, "_home", return_value=home):
            self.broker.execute(owner_a)
            self.write_fence(home, owner_b.owner_epoch)
            with self.assertRaisesRegex(module.BrokerError, "does not own"):
                self.broker.execute(owner_b)
        ledger = json.loads(self.layout.ledger.read_text(encoding="ascii"))
        self.assertEqual(ledger["owner_epoch"], owner_a.owner_epoch)
        self.assertEqual(ledger["phase"], "ACTIVE")

    def test_killed_broker_operation_group_is_durably_recoverable(self) -> None:
        helper = self.base / "blocking-vpn-helper.py"
        ready = self.base / "blocking-helper.ready"
        descendant_file = self.base / "blocking-descendant.pid"
        helper.write_text(
            "#!/usr/bin/python3\n"
            "import os, pathlib, signal, time\n"
            f"ready = pathlib.Path({str(ready)!r})\n"
            f"descendant_file = pathlib.Path({str(descendant_file)!r})\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    descendant_file.write_text(f'{os.getpid()}\\n')\n"
            "    time.sleep(60)\n"
            "    raise SystemExit(0)\n"
            "ready.write_text(f'{os.getpid()}\\n')\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        request = self.request("down")
        child = os.fork()
        if child == 0:
            try:
                broker = module.Broker(
                    self.layout,
                    expected_root_uid=self.uid,
                    runner=subprocess.run,
                )
                broker._write_phase(
                    request,
                    "DRAINING",
                    vpn=None,
                    relay=None,
                    operation=None,
                )
                broker._invoke(
                    helper,
                    ROOT / "vpn-broker",
                    "down",
                    request,
                    phase="DRAINING",
                    vpn=None,
                    relay=None,
                )
            finally:
                os._exit(0)
        record: dict[str, object] | None = None
        descendant = 0
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.layout.ledger.exists():
                    value = json.loads(self.layout.ledger.read_text(encoding="ascii"))
                    if value.get("operation") is not None and ready.exists() and descendant_file.exists():
                        descendant_text = descendant_file.read_text(encoding="ascii").strip()
                        if descendant_text.isdecimal():
                            record = value["operation"]
                            descendant = int(descendant_text)
                            break
                time.sleep(0.01)
            self.assertIsNotNone(record, "operation effect was not durably bracketed")
            assert record is not None
            self.assertEqual(os.getpgid(descendant), record["pgid"])
            self.assertTrue(
                module.ExactCgroupV2Scope(self.uid).contains(
                    record["scope"], descendant
                )
            )
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            child = 0
            deadline = time.monotonic() + 5
            while Path(f"/proc/{record['pid']}").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            recovery = module.Broker(
                self.layout,
                expected_root_uid=self.uid,
                runner=subprocess.run,
            )
            recovery._recover_operation(
                request,
                phase="DRAINING",
                vpn=None,
                relay=None,
                operation=record,
            )
            self.assertFalse(recovery._process_group_exists(record["pgid"]))
            self.assertFalse(Path(record["scope"]["scope_path"]).exists())
            ledger = recovery._load_ledger()
            self.assertIsNotNone(ledger)
            self.assertIsNone(ledger["operation"])
            # Exact recovery is convergent if replayed after the group is gone.
            recovery._recover_operation(
                request,
                phase="DRAINING",
                vpn=None,
                relay=None,
                operation=record,
            )
        finally:
            if child:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            if record is not None and Path(record["scope"]["scope_path"]).exists():
                try:
                    module.ExactCgroupV2Scope(self.uid).reconcile(
                        record["scope"], 5.0
                    )
                except (module.BrokerError, OSError):
                    pass

    def test_real_cgroup_scope_transfers_to_new_vpn_and_reconciles_old_vpn(self) -> None:
        helper = self.base / "fake-openvpn-helper.py"
        helper.write_text(
            "#!/usr/bin/python3\n"
            "import os, pathlib, subprocess, sys, time\n"
            f"pidfile = pathlib.Path({str(self.layout.vpn_pid)!r})\n"
            f"startfile = pathlib.Path({str(self.layout.vpn_start)!r})\n"
            f"bootfile = pathlib.Path({str(self.layout.vpn_boot)!r})\n"
            f"config = {str(self.layout.vpn_work / 'vpngate.ovpn')!r}\n"
            f"upscript = {str(self.layout.vpn_work / 'up.sh')!r}\n"
            "pidfile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
            "child = subprocess.Popen(\n"
            "    ['/usr/sbin/openvpn', '-c', 'import time; time.sleep(60)',\n"
            "     '--config', config, '--dev', 'tun-grok', '--up', upscript],\n"
            "    executable='/usr/bin/python3', stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)\n"
            "raw = pathlib.Path(f'/proc/{child.pid}/stat').read_text(encoding='ascii')\n"
            "start = raw[raw.rfind(')') + 2:].split()[19]\n"
            "pidfile.write_text(f'{child.pid}\\n', encoding='ascii')\n"
            "startfile.write_text(f'{start}\\n', encoding='ascii')\n"
            "bootfile.write_text(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text(), encoding='ascii')\n"
            "for path in (pidfile, startfile, bootfile): path.chmod(0o600)\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        request = self.request("up")
        broker = module.Broker(
            self.layout, expected_root_uid=self.uid, runner=subprocess.run
        )
        first = second = None
        try:
            broker._write_phase(
                request, "PREPARED", vpn=None, relay=None, operation=None
            )
            first = broker._invoke(
                helper,
                ROOT / "vpn-broker",
                "up",
                request,
                phase="PREPARED",
                vpn=None,
                relay=None,
            )
            self.assertIsNotNone(first)
            assert first is not None
            self.assertTrue(broker._vpn_process_matches(first))
            self.assertTrue(broker.operation_scopes.contains(first["scope"], first["pid"]))

            next_request = self.request("next")
            second = broker._invoke(
                helper,
                ROOT / "vpn-broker",
                "next",
                next_request,
                phase="PREPARED",
                vpn=first,
                relay=None,
            )
            self.assertIsNotNone(second)
            assert second is not None
            self.assertNotEqual(first["scope"], second["scope"])
            self.assertFalse(Path(first["scope"]["scope_path"]).exists())
            self.assertTrue(broker._vpn_process_matches(second))
        finally:
            for record in (second, first):
                if record is not None and Path(record["scope"]["scope_path"]).exists():
                    try:
                        broker.operation_scopes.reconcile(record["scope"], 5.0)
                    except module.BrokerError:
                        pass
            broker._remove_partial_vpn_identity(None)

    def test_helper_output_is_drained_but_fails_at_fixed_memory_bound(self) -> None:
        helper = self.base / "oversized-helper.py"
        helper.write_text(
            "#!/usr/bin/python3\n"
            "import os\n"
            "data = b'x' * 65536\n"
            "for _ in range(17): os.write(1, data)\n",
            encoding="ascii",
        )
        helper.chmod(0o755)
        request = self.request("down")
        broker = module.Broker(
            self.layout, expected_root_uid=self.uid, runner=subprocess.run
        )
        broker._write_phase(
            request, "DRAINING", vpn=None, relay=None, operation=None
        )
        with self.assertRaisesRegex(module.BrokerError, "output exceeded"):
            broker._invoke(
                helper,
                ROOT / "vpn-broker",
                "down",
                request,
                phase="DRAINING",
                vpn=None,
                relay=None,
            )
        ledger = broker._load_ledger()
        self.assertIsNotNone(ledger)
        self.assertEqual(ledger["phase"], "FAILED")
        self.assertIsNone(ledger["operation"])

    def test_operation_record_from_another_boot_never_signals_a_live_group(self) -> None:
        process = subprocess.Popen(
            ["/usr/bin/sleep", "30"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            current_boot = self.broker._boot_id()
            other_boot = ("0" if current_boot[0] != "0" else "1") + current_boot[1:]
            record = {
                "pid": process.pid,
                "start_ticks": self.broker._proc_start_ticks(process.pid),
                "pgid": process.pid,
                "uid": self.uid,
                "helper": "/root/old-release/vpngate-connect.sh",
                "verb": "up",
                "guard": "/root/old-release/vpn-broker",
                "argv": ["/usr/bin/sleep", "30"],
                "boot_id": other_boot,
                "scope": scope_record(),
            }
            self.assertTrue(self.broker._operation_record_shape(record))
            with self.assertRaises(module.BrokerError):
                self.broker._stop_operation_group(record)
            self.assertIsNone(process.poll())
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)

    def test_current_boot_orphan_pgid_is_never_accepted_without_exact_scope(self) -> None:
        process = subprocess.Popen(
            ["/usr/bin/sleep", "30"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        record = {
            "pid": process.pid,
            "start_ticks": self.broker._proc_start_ticks(process.pid),
            "pgid": process.pid,
            "uid": self.uid,
            "helper": "/root/old-release/vpngate-connect.sh",
            "verb": "up",
            "guard": "/root/old-release/vpn-broker",
            "argv": ["/usr/bin/sleep", "30"],
            "boot_id": self.broker._boot_id(),
            "scope": scope_record(99),
        }
        try:
            with self.assertRaises(module.BrokerError):
                self.broker._stop_operation_group(record)
            self.assertIsNone(process.poll())
        finally:
            process.kill()
            process.wait(timeout=5)

    def test_unrecorded_populated_exact_cgroup_fences_without_signaling(self) -> None:
        scopes = module.ExactCgroupV2Scope(self.uid)
        empty = scopes.create(scopes.plan())
        scopes.plan()
        self.assertFalse(Path(empty["scope_path"]).exists())
        scope = scopes.create(scopes.plan())
        process = subprocess.Popen(
            ["/usr/bin/sleep", "30"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            scopes.attach(scope, process.pid)
            with self.assertRaisesRegex(module.BrokerError, "unrecorded populated"):
                scopes.plan()
            self.assertIsNone(process.poll())
        finally:
            try:
                scopes.reconcile(scope, 5.0)
            except module.BrokerError:
                if process.poll() is None:
                    process.kill()
            process.wait(timeout=5)

    def test_recover_converges_and_is_idempotent(self) -> None:
        self.broker.execute(self.request("up"))
        result = self.broker.execute(self.request("recover"))
        self.assertTrue(result["recovered"])
        result = self.broker.execute(self.request("recover"))
        self.assertFalse(result["recovered"])

    def test_partial_teardown_attempts_vpn_cleanup_and_retains_failed_ledger(self) -> None:
        self.broker.execute(self.request("up"))
        self.broker.stop_failure = True
        with self.assertRaises(module.BrokerError):
            self.broker.execute(self.request("down"))
        self.assertFalse(self.runner.namespace, "VPN helper down was not attempted")
        ledger = json.loads(self.layout.ledger.read_text(encoding="utf-8"))
        self.assertEqual(ledger["phase"], "FAILED")
        self.assertTrue(self.broker.relay_running)

    def test_unowned_namespace_is_never_destroyed_by_owner_scoped_down(self) -> None:
        self.runner.namespace = True
        with self.assertRaises(module.BrokerError):
            self.broker.execute(self.request("down"))
        helper_down = [call for call in self.runner.calls if call[-1:] == ("down",)]
        self.assertEqual(helper_down, [])

    def test_base_spawn_uses_only_manifest_relay_and_inherited_pid_descriptor(self) -> None:
        captured: dict[str, object] = {}
        fd, name = tempfile.mkstemp(dir=self.base)
        pidfile = Path(name)

        class Process:
            pid = os.getpid()

            @staticmethod
            def poll():
                return None

        def spawn(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return Process()

        broker = module.Broker(
            self.layout,
            expected_root_uid=self.uid,
            runner=self.runner,
            spawner=spawn,
        )
        broker._open_relay_pidfile = lambda _request: (fd, pidfile)
        broker._relay_alive = lambda _record, _request, _relay: True
        relay = self.release / "socks-netns.py"
        broker._spawn_relay(self.request("up"), relay)
        argv = captured["argv"]
        kwargs = captured["kwargs"]
        self.assertEqual(argv[1], str(relay))
        self.assertIn("--pid-fd", argv)
        self.assertEqual(kwargs["pass_fds"], (fd,))
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_persistent_relay_and_vpn_child_do_not_inherit_release_lock(self) -> None:
        lock_path = self.base / "install.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.set_inheritable(lock_fd, True)
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        spawned: list[int] = []
        relay_processes: list[subprocess.Popen] = []
        try:
            relay_marker = self.base / "relay-fds"
            relay_script = self.base / "relay-check.py"
            relay_script.write_text(
                "#!/usr/bin/python3\n"
                "import os, pathlib, sys, time\n"
                f"lock_path = {str(lock_path)!r}\n"
                f"marker = pathlib.Path({str(relay_marker)!r})\n"
                "pid_fd = int(sys.argv[sys.argv.index('--pid-fd') + 1])\n"
                "os.write(pid_fd, f'{os.getpid()}\\n'.encode('ascii'))\n"
                "targets = []\n"
                "for name in os.listdir('/proc/self/fd'):\n"
                "    try: targets.append(os.readlink('/proc/self/fd/' + name))\n"
                "    except OSError: pass\n"
                "marker.write_text('leaked' if lock_path in targets else 'closed')\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            relay_script.chmod(0o755)
            relay_runtime = self.base / "relay-runtime"
            relay_runtime.mkdir(mode=0o700)
            relay_pidfile = relay_runtime / "backend.pid"
            def spawn_relay(argv, **kwargs):
                process = subprocess.Popen(argv, **kwargs)
                relay_processes.append(process)
                return process

            broker = module.Broker(
                self.layout,
                expected_root_uid=self.uid,
                runner=subprocess.run,
                spawner=spawn_relay,
            )

            def open_pidfile(_request):
                descriptor = os.open(
                    relay_pidfile, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600
                )
                return descriptor, relay_pidfile

            broker._open_relay_pidfile = open_pidfile
            broker._relay_alive = lambda _record, _request, _relay: relay_marker.exists()
            relay_record = broker._spawn_relay(self.request("up"), relay_script)
            self.assertEqual(relay_processes[-1].pid, relay_record["pid"])
            self.assertEqual(relay_marker.read_text(encoding="ascii"), "closed")

            vpn_marker = self.base / "vpn-fds"
            vpn_child_pid = self.base / "vpn-child.pid"
            vpn_helper = self.base / "vpn-helper.py"
            vpn_helper.write_text(
                "#!/usr/bin/python3\n"
                "import os, pathlib, time\n"
                f"lock_path = {str(lock_path)!r}\n"
                f"marker = pathlib.Path({str(vpn_marker)!r})\n"
                f"pidfile = pathlib.Path({str(vpn_child_pid)!r})\n"
                "pid = os.fork()\n"
                "if pid:\n"
                "    pidfile.write_text(f'{pid}\\n')\n"
                "    raise SystemExit(0)\n"
                "os.setsid()\n"
                "null = os.open('/dev/null', os.O_RDWR)\n"
                "for descriptor in (0, 1, 2): os.dup2(null, descriptor)\n"
                "if null > 2: os.close(null)\n"
                "targets = []\n"
                "for name in os.listdir('/proc/self/fd'):\n"
                "    try: targets.append(os.readlink('/proc/self/fd/' + name))\n"
                "    except OSError: pass\n"
                "marker.write_text('leaked' if lock_path in targets else 'closed')\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            vpn_helper.chmod(0o755)
            invoke_request = self.request("down")
            broker._write_phase(
                invoke_request,
                "DRAINING",
                vpn=None,
                relay=None,
                operation=None,
            )
            broker._invoke(
                vpn_helper,
                ROOT / "vpn-broker",
                "down",
                invoke_request,
                phase="DRAINING",
                vpn=None,
                relay=None,
            )
            deadline = time.monotonic() + 5
            while not vpn_marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(vpn_marker.exists(), "VPN child did not publish its FD check")
            spawned.append(int(vpn_child_pid.read_text(encoding="ascii")))
            self.assertEqual(vpn_marker.read_text(encoding="ascii"), "closed")
        finally:
            for process in relay_processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            for pid in spawned:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
