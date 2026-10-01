#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("resolve_escrow_shares", ROOT / "bin/resolve-escrow-shares.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class ShareResolutionTests(unittest.TestCase):
    def fixture(self, root: Path, indexes: tuple[int, ...]) -> tuple[Path, list[dict[str, object]]]:
        inbox = root / "inbox"
        generation = inbox / "escrow" / "escrow-fixture-0001"
        generation.mkdir(parents=True, mode=0o700)
        os.chmod(inbox, 0o700)
        os.chmod(inbox / "escrow", 0o700)
        records = []
        for index in range(1, 5):
            raw = f"shamir-v1:{index}:fixture-{index}\n".encode("ascii")
            records.append({"index": index, "file": f"share-{index:02d}.txt", "sha256": digest(raw)})
            if index in indexes:
                path = generation / f"share-{index:02d}.txt"
                path.write_bytes(raw)
                path.chmod(0o600)
        return inbox, records

    def test_exactly_two_matching_shares_are_selected_in_index_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox, records = self.fixture(Path(directory), (3, 1))
            selected = MODULE.discover_share_files(inbox, "escrow-fixture-0001", records)
            self.assertEqual([path.name for path in selected], ["share-01.txt", "share-03.txt"])

    def test_one_or_three_shares_are_ambiguous(self) -> None:
        for indexes in ((1,), (1, 2, 3)):
            with self.subTest(indexes=indexes), tempfile.TemporaryDirectory() as directory:
                inbox, records = self.fixture(Path(directory), indexes)
                with self.assertRaises(MODULE.ResolutionError):
                    MODULE.discover_share_files(inbox, "escrow-fixture-0001", records)

    def test_unexpected_generation_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox, records = self.fixture(Path(directory), (1, 2))
            extra = inbox / "escrow/escrow-fixture-0001/note.txt"
            extra.write_text("not allowed", encoding="utf-8")
            extra.chmod(0o600)
            with self.assertRaises(MODULE.ResolutionError):
                MODULE.discover_share_files(inbox, "escrow-fixture-0001", records)


if __name__ == "__main__":
    unittest.main()
