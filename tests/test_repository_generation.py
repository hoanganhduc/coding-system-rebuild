#!/usr/bin/env python3
"""Hostile fixtures for the authenticated repository-generation boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin/lib/repository_generation.py"
SPEC = importlib.util.spec_from_file_location("repository_generation", HELPER)
assert SPEC is not None and SPEC.loader is not None
generation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generation)


class RepositoryGenerationTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, str, str]:
        repository = root / "repository"
        (repository / "bin").mkdir(parents=True)
        (repository / "system/platform").mkdir(parents=True)
        (repository / "bin/helper.sh").write_text(
            "#!/bin/sh\nprintf 'safe-helper:'\n", encoding="utf-8"
        )
        (repository / "bin/helper.sh").chmod(0o755)
        (repository / "bin/fixture_module.py").write_text(
            "VALUE = 'safe-module'\n", encoding="utf-8"
        )
        (repository / "bin/transitive.py").write_text(
            "#!/usr/bin/python3\n"
            "import importlib.util\n"
            "from pathlib import Path\n"
            "import sys\n"
            "root = Path(__file__).resolve().parents[1]\n"
            "spec = importlib.util.spec_from_file_location('fixture_module', root / 'bin/fixture_module.py')\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "VALUE = module.VALUE\n"
            "print(VALUE + ':' + (root / 'system/platform' / (sys.argv[1] + '.txt')).read_text().strip(), end='')\n",
            encoding="utf-8",
        )
        (repository / "bin/transitive.py").chmod(0o755)
        (repository / "bin/install.sh").write_text(
            "#!/bin/sh\nprintf ':safe-install\\n'\n", encoding="utf-8"
        )
        (repository / "bin/install.sh").chmod(0o755)
        (repository / "bin/restore.sh").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "root=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd -P)\n"
            "\"$root/bin/helper.sh\"\n"
            "/usr/bin/python3 -I -B \"$root/bin/transitive.py\" \"$1\"\n"
            "\"$root/bin/install.sh\"\n",
            encoding="utf-8",
        )
        (repository / "bin/restore.sh").chmod(0o755)
        for arch in ("arm64", "amd64"):
            (repository / "system/platform" / f"{arch}.txt").write_text(
                f"safe-data-{arch}\n", encoding="utf-8"
            )
        (repository / "system/platform-current").symlink_to("platform/amd64.txt")
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Generation Test",
                "-c",
                "user.email=generation@example.invalid",
                "commit",
                "-qm",
                "generation fixture",
            ],
            cwd=repository,
            check=True,
        )
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=repository, text=True
        ).strip()
        return repository, commit, tree

    def publish(self, root: Path) -> tuple[Path, Path, str, str]:
        repository, commit, tree = self.fixture(root)
        stream = io.BytesIO()
        generation.emit_stream(repository, commit, tree, stream)
        stream.seek(0)
        generations = root / "generations"
        generations.mkdir(mode=0o755)
        target = generation.publish_stream(
            stream,
            generations,
            commit,
            tree,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        return repository, target, commit, tree

    def verify(self, target: Path, commit: str, tree: str) -> None:
        generation.verify_generation(
            target.parent,
            commit,
            tree,
            uid=os.getuid(),
            gid=os.getgid(),
        )

    def test_raw_generation_preserves_modes_symlink_and_both_arch_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _repository, target, commit, tree = self.publish(Path(temporary))
            self.verify(target, commit, tree)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((target / "bin/restore.sh").stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((target / "system/platform/arm64.txt").stat().st_mode), 0o444)
            self.assertTrue((target / "system/platform-current").is_symlink())
            self.assertEqual(
                os.readlink(target / "system/platform-current"), "platform/amd64.txt"
            )
            for arch in ("arm64", "amd64"):
                observed = subprocess.run(
                    [str(target / "bin/restore.sh"), arch],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(
                    observed.stdout,
                    f"safe-helper:safe-module:safe-data-{arch}:safe-install\n",
                )

    def test_checkout_helper_import_and_data_swaps_never_reach_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, target, commit, tree = self.publish(Path(temporary))
            stop = threading.Event()

            def swap_checkout() -> None:
                values = ("evil-a", "evil-b")
                index = 0
                while not stop.is_set():
                    value = values[index % 2]
                    for path, payload in (
                        (repository / "bin/helper.sh", f"#!/bin/sh\nprintf '{value}:'\n"),
                        (repository / "bin/fixture_module.py", f"VALUE = '{value}'\n"),
                        (repository / "system/platform/arm64.txt", value + "\n"),
                        (repository / "bin/install.sh", f"#!/bin/sh\nprintf ':{value}\\n'\n"),
                    ):
                        replacement = path.with_name(path.name + ".swap")
                        replacement.write_text(payload, encoding="utf-8")
                        if path.suffix in {".sh", ".py"}:
                            replacement.chmod(0o755)
                        os.replace(replacement, path)
                    index += 1

            racer = threading.Thread(target=swap_checkout, daemon=True)
            racer.start()
            try:
                observed = [
                    subprocess.run(
                        [str(target / "bin/restore.sh"), "arm64"],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    for _ in range(24)
                ]
            finally:
                stop.set()
                racer.join(timeout=5)
            self.verify(target, commit, tree)
            self.assertTrue(all(item.returncode == 0 for item in observed))
            self.assertEqual(
                {item.stdout for item in observed},
                {"safe-helper:safe-module:safe-data-arm64:safe-install\n"},
            )

    def test_reuse_verifies_the_entire_published_tree_and_rejects_extras(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, target, commit, tree = self.publish(root)
            second = io.BytesIO()
            generation.emit_stream(repository, commit, tree, second)
            second.seek(0)
            self.assertEqual(
                generation.publish_stream(
                    second,
                    target.parent,
                    commit,
                    tree,
                    uid=os.getuid(),
                    gid=os.getgid(),
                ),
                target,
            )
            target.chmod(0o755)
            (target / "unexpected").write_text("extra\n", encoding="utf-8")
            target.chmod(0o555)
            third = io.BytesIO()
            generation.emit_stream(repository, commit, tree, third)
            third.seek(0)
            with self.assertRaisesRegex(generation.GenerationError, "missing or extra"):
                generation.publish_stream(
                    third,
                    target.parent,
                    commit,
                    tree,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

    def test_mutated_bytes_modes_links_and_marker_fail_closed(self) -> None:
        cases = ("bytes", "mode", "hardlink", "symlink", "marker")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                _repository, target, commit, tree = self.publish(Path(temporary))
                if case == "bytes":
                    path = target / "system/platform/amd64.txt"
                    path.chmod(0o644)
                    path.write_text("evil\n", encoding="utf-8")
                    path.chmod(0o444)
                elif case == "mode":
                    (target / "bin/restore.sh").chmod(0o755)
                elif case == "hardlink":
                    path = target / "system/platform/amd64.txt"
                    path.chmod(0o644)
                    os.link(path, Path(temporary) / "second-link")
                    path.chmod(0o444)
                elif case == "symlink":
                    target.chmod(0o755)
                    (target / "system").chmod(0o755)
                    path = target / "system/platform-current"
                    path.unlink()
                    path.symlink_to("platform/arm64.txt")
                    (target / "system").chmod(0o555)
                    target.chmod(0o555)
                else:
                    target.chmod(0o755)
                    path = target / generation.MARKER_NAME
                    path.chmod(0o644)
                    path.write_text("{}\n", encoding="utf-8")
                    path.chmod(0o444)
                    target.chmod(0o555)
                with self.assertRaises(generation.GenerationError):
                    self.verify(target, commit, tree)

    def test_unsupported_object_and_escaping_symlink_are_rejected(self) -> None:
        commit = "a" * 40
        with self.assertRaisesRegex(generation.GenerationError, "unsupported"):
            generation.parse_inventory(
                b"160000 commit " + b"b" * 40 + b"\tvendor\0"
            )
        self.assertEqual(generation._safe_link("safe/link", b"../target"), "../target")
        with self.assertRaisesRegex(generation.GenerationError, "escaping"):
            generation._safe_link("link", b"../outside")
        self.assertRegex(commit, r"^[0-9a-f]{40}$")

    @staticmethod
    def decode_stream(payload: bytes) -> tuple[dict[str, object], list[tuple[dict[str, object], bytes]]]:
        stream = io.BytesIO(payload)
        assert stream.read(len(generation.STREAM_MAGIC)) == generation.STREAM_MAGIC
        header = json.loads(stream.readline())
        records: list[tuple[dict[str, object], bytes]] = []
        for _index in range(header["count"]):
            record = json.loads(stream.readline())
            data = stream.read(record["size"])
            assert stream.read(1) == b"\n"
            records.append((record, data))
        assert stream.read() == b"END\n"
        return header, records

    @staticmethod
    def encode_stream(
        header: dict[str, object], records: list[tuple[dict[str, object], bytes]]
    ) -> bytes:
        output = io.BytesIO()
        output.write(generation.STREAM_MAGIC)
        header = {**header, "count": len(records)}
        output.write(
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
        for record, payload in records:
            output.write(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
                + b"\n"
            )
            output.write(payload + b"\n")
        output.write(b"END\n")
        return output.getvalue()

    def test_root_receiver_reconstructs_tree_and_rejects_structural_stream_tampering(self) -> None:
        for case in ("omit", "add", "rename", "mode", "nesting", "reorder"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repository, commit, tree = self.fixture(root)
                emitted = io.BytesIO()
                generation.emit_stream(repository, commit, tree, emitted)
                header, records = self.decode_stream(emitted.getvalue())
                if case == "omit":
                    records.pop()
                elif case == "add":
                    record, payload = records[-1]
                    records.append(({**record, "path": "zz-added-valid-blob"}, payload))
                elif case == "rename":
                    record, payload = records[-1]
                    records[-1] = ({**record, "path": "zz-renamed"}, payload)
                elif case == "mode":
                    index = next(
                        index
                        for index, (record, _payload) in enumerate(records)
                        if record["git_mode"] == "100644"
                    )
                    record, payload = records[index]
                    records[index] = ({**record, "git_mode": "100755"}, payload)
                elif case == "nesting":
                    record, payload = records[-1]
                    records[-1] = ({**record, "path": "zz-nested/renamed"}, payload)
                else:
                    records.reverse()
                generation_root = root / "generations"
                generation_root.mkdir(mode=0o755)
                with self.assertRaises(generation.GenerationError):
                    generation.publish_stream(
                        io.BytesIO(self.encode_stream(header, records)),
                        generation_root,
                        commit,
                        tree,
                        uid=os.getuid(),
                        gid=os.getgid(),
                    )
                self.assertFalse(
                    (generation_root / f"{commit}-{tree}").exists(),
                    "a structurally tampered stream must never publish",
                )

    def test_publication_is_atomic_across_crash_before_and_after_rename(self) -> None:
        for point in ("before", "after"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repository, commit, tree = self.fixture(root)
                generation_root = root / "generations"
                generation_root.mkdir(mode=0o755)

                def emitted() -> io.BytesIO:
                    value = io.BytesIO()
                    generation.emit_stream(repository, commit, tree, value)
                    value.seek(0)
                    return value

                original = generation._rename_noreplace
                if point == "before":
                    replacement = mock.Mock(
                        side_effect=generation.GenerationError("synthetic pre-rename crash")
                    )
                else:
                    def replacement(source: Path, target: Path) -> None:
                        original(source, target)
                        raise generation.GenerationError("synthetic post-rename crash")

                with mock.patch.object(generation, "_rename_noreplace", replacement):
                    with self.assertRaisesRegex(generation.GenerationError, "synthetic"):
                        generation.publish_stream(
                            emitted(),
                            generation_root,
                            commit,
                            tree,
                            uid=os.getuid(),
                            gid=os.getgid(),
                        )
                target = generation_root / f"{commit}-{tree}"
                if point == "before":
                    self.assertFalse(target.exists())
                else:
                    self.verify(target, commit, tree)
                self.assertEqual(
                    generation.publish_stream(
                        emitted(),
                        generation_root,
                        commit,
                        tree,
                        uid=os.getuid(),
                        gid=os.getgid(),
                    ),
                    target,
                )

    def test_stage0_restore_and_install_are_generation_bound(self) -> None:
        stage0 = (ROOT / "restore-ubuntu.sh").read_text(encoding="utf-8")
        restore = (ROOT / "bin/restore.sh").read_text(encoding="utf-8")
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        self.assertIn("cat-file blob", stage0)
        self.assertIn("repository-generation-$GENERATION_HELPER_SHA256.py", stage0)
        self.assertIn("$BOUND_GENERATION_HELPER\" publish", stage0)
        self.assertIn("CSR_STAGE0_REPOSITORY_GENERATION", stage0)
        self.assertIn("repository_generation.py\" verify", restore)
        self.assertNotIn('-C "$REPO" rev-parse HEAD', restore)
        authenticated = install.split("if [[ $DEGRADED_MODE -eq 0 ]]", 1)[1].split(
            "SIGNED_OWNER_FILE", 1
        )[0]
        self.assertIn("repository_generation.py\" verify", authenticated)
        self.assertNotIn("verify_restore_checkout", authenticated)

    def test_owner_authority_is_owner_controlled_and_never_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            uid, gid = os.getuid(), os.getgid()
            root = generation.owner_generation_root(home=home, uid=uid, gid=gid, create=True)
            self.assertEqual(root, home / ".local/share/coding-system/repository-generations")
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            (home / ".local/share").chmod(0o770)
            with self.assertRaisesRegex(generation.GenerationError, "unsafe"):
                generation.owner_generation_root(home=home, uid=uid, gid=gid, create=False)
            (home / ".local/share").chmod(0o700)
            with self.assertRaisesRegex(generation.GenerationError, "unsafe"):
                generation.owner_generation_root(home=home, uid=uid + 1, gid=gid, create=False)
            with mock.patch.object(generation.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(generation.GenerationError, "never published by root"):
                    generation.main(["publish", "--owner", "--commit", "a" * 40, "--tree", "b" * 40])

    def test_owner_copy_of_a_verified_generation_rechecks_every_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            _repository, source, commit, tree = self.publish(base)
            home = base / "home"
            home.mkdir(mode=0o700)
            uid, gid = os.getuid(), os.getgid()
            owner_root = generation.owner_generation_root(home=home, uid=uid, gid=gid, create=True)
            stream = io.BytesIO()
            generation.emit_generation(source, commit, tree, stream, uid=uid, gid=gid)
            stream.seek(0)
            copy = generation.publish_stream(stream, owner_root, commit, tree, uid=uid, gid=gid)
            self.assertEqual(copy, owner_root / f"{commit}-{tree}")
            self.verify(copy, commit, tree)
            self.assertEqual(
                (copy / "bin/helper.sh").read_bytes(), (source / "bin/helper.sh").read_bytes()
            )
            self.assertEqual(os.readlink(copy / "system/platform-current"), "platform/amd64.txt")
            # A source changed after its publication is never copied.
            helper = source / "bin/helper.sh"
            source.chmod(0o755)
            (source / "bin").chmod(0o755)
            helper.chmod(0o755)
            helper.write_text("#!/bin/sh\nprintf 'evil'\n", encoding="utf-8")
            with self.assertRaises(generation.GenerationError):
                generation.emit_generation(source, commit, tree, io.BytesIO(), uid=uid, gid=gid)

    def test_owner_publication_cli_follows_home_without_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository, commit, tree = self.fixture(base)
            home = base / "home"
            home.mkdir(mode=0o700)
            environment = {**os.environ, "HOME": os.fspath(home)}
            emitted = subprocess.run(
                ["/usr/bin/python3", "-I", "-B", os.fspath(HELPER), "emit",
                 "--repository", os.fspath(repository), "--commit", commit, "--tree", tree],
                capture_output=True, check=True, env=environment,
            )
            published = subprocess.run(
                ["/usr/bin/python3", "-I", "-B", os.fspath(HELPER), "publish", "--owner",
                 "--commit", commit, "--tree", tree],
                input=emitted.stdout, capture_output=True, check=False, env=environment,
            )
            self.assertEqual(published.returncode, 0, published.stderr)
            expected = home / ".local/share/coding-system/repository-generations" / f"{commit}-{tree}"
            self.assertEqual(published.stdout.decode().strip(), os.fspath(expected))
            verified = subprocess.run(
                ["/usr/bin/python3", "-I", "-B", os.fspath(HELPER), "verify", "--owner",
                 "--commit", commit, "--tree", tree, "--path", os.fspath(expected)],
                capture_output=True, check=False, env=environment,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_scheduled_code_runs_from_the_owner_generation(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")
        select = install.split("select_repository() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("emit-generation --path \"$REPO\"", select)
        self.assertIn("publish --owner", select)
        self.assertIn('ln -s -- "$target" "$temporary"', select)
        self.assertNotIn("sudo", select)
        update = (ROOT / "bin/publish-repository-generation.sh").read_text(encoding="utf-8")
        self.assertIn("publish --owner", update)
        self.assertIn("never as root", update)
        self.assertNotIn("sudo", update)


if __name__ == "__main__":
    unittest.main()
