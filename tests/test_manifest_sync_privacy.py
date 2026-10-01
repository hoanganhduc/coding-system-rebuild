#!/usr/bin/env python3
"""Privacy rules of the capture engine (bin/lib/manifest_sync.py).

Each test builds a throwaway repository holding copies of the engine and the
leak scanner, a synthetic MANIFEST.yaml, and a fixture home, then runs the
engine against them.  The engine must keep private material out of the public
tree: orphans and backup files are never captured, forbidden file kinds and
denylist entries are refused, template outputs are redacted, and --apply
publishes nothing unless the rendered tree passes the leak scan and every
public entry carries an owner review.  Matched values are never printed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANARY = "canary-private-9Hq4Tz"               # stands in for a private denylist entry
GMAIL = "someone.private@" + "gmail.com"        # split so the repository scanners skip it
USER_ID = "1234" + "5678"
MANIFEST = """\
schema: coding-system.manifest.v1
home_placeholder: "{{ HOME }}"
global_exclude: ["*.new", "*.bak*", "*.backup*", "skills/vendor/**"]
roots: [.tool]
entries:
  - id: tool-account
    root: .tool
    match: ["account.json"]
    class: public-template
    dest_dir: agents/tool
    template: [home-substitute, key-redact]
    keys: [api_token]
  - id: tool-settings
    root: .tool
    match: ["settings.json"]
    class: public-copy
    dest_dir: agents/tool
    template: [strip-projects]
  - id: tool-core
    root: .tool
    match: ["config.json", "notes.md", "skills"]
    class: public-copy
    dest_dir: agents/tool
  - id: tool-exclude
    root: .tool
    match: ["cache"]
    class: exclude-generated
"""


class ManifestSyncPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="manifest-privacy-test-"))
        self.repo = self.tmp / "repo"
        self.home = self.tmp / "home"
        for rel in ("bin/leak-scan.sh", "bin/review-manifest.py", "bin/lib/manifest_sync.py",
                    "bin/lib/public_export.py", "bin/lib/leak_scan_extra.py"):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, self.repo / rel)
        (self.repo / "MANIFEST.yaml").write_text(MANIFEST)
        self.denylist = self.tmp / "denylist.txt"
        self.denylist.write_text("# private test denylist\n" + CANARY + "\n")
        self.write(".tool/config.json", '{"theme": "dark"}\n')
        self.write(".tool/notes.md", "plain notes\n")
        self.write(".tool/skills/a/SKILL.md", "# skill a\n")
        self.write(".tool/cache/blob.txt", "cached\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel: str, text: str | bytes) -> Path:
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text)
        return path

    def run_sync(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        full_env = dict(os.environ)
        full_env.update({"CSR_HOME_OVERRIDE": str(self.home), "CSR_DENYLIST": str(self.denylist)})
        full_env.update(env)
        return subprocess.run([sys.executable, "-B", str(self.repo / "bin/lib/manifest_sync.py"),
                               "--repo", str(self.repo), *args],
                              env=full_env, text=True, capture_output=True)

    def approve(self) -> None:
        """Record an owner review of the current public entries, as the review tool would."""
        sys.path.insert(0, str(self.repo / "bin/lib"))
        try:
            import manifest_sync
            import yaml
            manifest = yaml.safe_load((self.repo / "MANIFEST.yaml").read_text())
            items = manifest_sync.review_items(manifest, str(self.repo))
        finally:
            sys.path.pop(0)
            sys.modules.pop("manifest_sync", None)
        (self.repo / "MANIFEST.review.json").write_text(json.dumps(
            {"schema": "coding-system.manifest-review.v1", "entries": items}, indent=1) + "\n")

    def report(self) -> dict:
        return json.loads((self.repo / ".staging" / "sync-report.json").read_text())

    def staged(self, rel: str) -> Path:
        return self.repo / ".staging" / rel

    def assertNoValues(self, result: subprocess.CompletedProcess) -> None:
        for value in (CANARY, GMAIL, USER_ID):
            self.assertNotIn(value, result.stdout + result.stderr)

    # ------------------------------------------------------------ baseline
    def test_clean_dry_run_passes(self) -> None:
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.staged("agents/tool/config.json").is_file())
        self.assertFalse(self.staged("agents/tool/cache").exists())

    def test_clean_apply_publishes_scanned_outputs_and_removes_stage(self) -> None:
        self.approve()
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repo / "agents/tool/config.json").read_text(), '{"theme": "dark"}\n')
        self.assertTrue(self.report()["applied"])
        self.assertEqual(list((self.repo / ".staging").glob("apply-*")), [])

    # ------------------------------------------------------------ classification
    def test_orphan_is_excluded_with_warning_not_error(self) -> None:
        self.write(".tool/newtool-state/data.txt", "unknown\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unclassified", result.stdout)
        self.assertIn(".tool/newtool-state", self.report()["orphans"])
        self.assertFalse(self.staged("agents/tool/newtool-state").exists())

    def test_global_exclude_keeps_backup_new_and_vendor_files_out(self) -> None:
        for rel in ("skills/a/SKILL.md.new", "skills/a/run.py.bak-20260101", "skills/a/x.py.backup.1772979283",
                    "skills/vendor/README.md"):
            self.write(".tool/" + rel, "leftover\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for rel in ("skills/a/SKILL.md.new", "skills/a/run.py.bak-20260101", "skills/a/x.py.backup.1772979283",
                    "skills/vendor/README.md"):
            self.assertFalse(self.staged("agents/tool/" + rel).exists(), rel)
        self.assertTrue(self.staged("agents/tool/skills/a/SKILL.md").is_file())

    def test_forbidden_file_kinds_are_refused_in_public_classes(self) -> None:
        cases = {
            "skills/a/sessions/s1.jsonl": "session",
            "skills/a/history.jsonl": "history",
            "skills/a/state.sqlite": "database",
            "skills/a/cache.db-wal": "database",
            "skills/a/blob.bin": "database",
            "skills/a/installation_id": "installation id",
            "skills/a/svc.service.owner.json": "owner/tunnel",
            "skills/a/feedback/f.json": "feedback",
            "skills/{{ WORKSPACE }}/x.md": "unrendered placeholder",
        }
        for rel, rule in cases.items():
            with self.subTest(rel=rel):
                data = b"SQLite format 3\x00" + b"\x00" * 64 if rel.endswith("blob.bin") else "x\n"
                path = self.write(".tool/" + rel, data)
                try:
                    result = self.run_sync()
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("forbidden in a public class (%s)" % rule, result.stderr)
                    self.assertFalse(self.staged("agents/tool/" + rel).exists())
                finally:
                    path.unlink()

    def test_forbidden_literal_match_is_refused_without_the_file(self) -> None:
        manifest = MANIFEST.replace('match: ["config.json", "notes.md", "skills"]',
                                    'match: ["config.json", "notes.md", "skills", "history.jsonl"]')
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("forbidden in a public class (history)", result.stderr)

    # ------------------------------------------------------------ denylist
    def test_denylist_entry_is_refused_and_never_written(self) -> None:
        self.write(".tool/notes.md", "host " + CANARY + " here\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("private denylist entry", result.stderr)
        self.assertIn("notes.md:1", result.stderr)
        self.assertFalse(self.staged("agents/tool/notes.md").exists())
        self.assertNoValues(result)

    def test_apply_requires_the_denylist(self) -> None:
        self.approve()
        result = self.run_sync("--apply", CSR_DENYLIST=str(self.tmp / "missing.txt"))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("denylist", result.stderr)
        self.assertFalse((self.repo / "agents").exists())

    # ------------------------------------------------------------ staging scan gate
    def test_apply_publishes_nothing_when_the_staging_scan_fails(self) -> None:
        self.approve()
        self.write(".tool/notes.md", "contact " + GMAIL + "\n")
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("leak scan", result.stderr)
        self.assertFalse((self.repo / "agents").exists())
        self.assertFalse(self.report()["applied"])
        self.assertEqual(list((self.repo / ".staging").glob("apply-*")), [])
        self.assertNoValues(result)

    def test_dry_run_reports_scan_failure(self) -> None:
        self.write(".tool/notes.md", "contact " + GMAIL + "\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("FINDING [email]", result.stdout)
        self.assertIn("leak scan", result.stderr)
        self.assertNoValues(result)

    # ------------------------------------------------------------ redaction
    def test_template_outputs_redact_email_and_identifier_values(self) -> None:
        self.write(".tool/account.json", json.dumps({
            "api_token": "tok-" + "A1b2C3d4E5f6G7h8",
            "user_id": USER_ID,
            "owner": GMAIL,
        }) + "\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = self.staged("agents/tool/account.json.template").read_text()
        self.assertIn("{{ EMAIL }}", text)
        self.assertIn("{{ USER_ID }}", text)
        self.assertIn("{{ API_TOKEN }}", text)
        for value in (GMAIL, USER_ID, "A1b2C3d4E5f6G7h8"):
            self.assertNotIn(value, text)

    def test_strip_projects_drops_home_paths_from_json_lists(self) -> None:
        self.write(".tool/settings.json", json.dumps({
            "model": "m1",
            "trustedWorkspaces": [str(self.home / "Research" / "private-project"), "/opt/shared"],
        }) + "\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(self.staged("agents/tool/settings.json").read_text())
        self.assertEqual(data, {"model": "m1", "trustedWorkspaces": ["/opt/shared"]})

    # ------------------------------------------------------------ owner review
    def test_unreviewed_public_entries_block_apply_but_not_dry_run(self) -> None:
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not owner-reviewed", result.stdout)
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("not owner-reviewed", result.stderr)
        self.assertFalse((self.repo / "agents").exists())

    def test_changed_public_entry_needs_a_new_review(self) -> None:
        self.approve()
        self.assertEqual(self.run_sync("--apply").returncode, 0)
        manifest = MANIFEST.replace('match: ["config.json", "notes.md", "skills"]',
                                    'match: ["config.json", "notes.md", "skills", "extra"]')
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("tool-core", result.stderr)

    def test_widening_global_exclude_needs_a_new_review(self) -> None:
        self.approve()
        manifest = MANIFEST.replace('"*.backup*", ', "")
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("global_exclude", result.stderr)

    def test_review_pins_every_entry_the_order_and_scanner_exceptions(self) -> None:
        changes = {
            "tool-exclude": lambda m: m.replace('match: ["cache"]', 'match: ["cache", "tmp"]'),
            "manifest-layout": lambda m: m.replace(
                "  - id: tool-exclude\n    root: .tool\n    match: [\"cache\"]\n    class: exclude-generated\n", ""
            ).replace("entries:\n", "entries:\n  - id: tool-exclude\n    root: .tool\n"
                      "    match: [\"cache\"]\n    class: exclude-generated\n"),
        }
        for item, change in changes.items():
            with self.subTest(item=item):
                (self.repo / "MANIFEST.yaml").write_text(MANIFEST)
                self.approve()
                (self.repo / "MANIFEST.yaml").write_text(change(MANIFEST))
                result = self.run_sync("--apply")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(item, result.stderr)
        (self.repo / "MANIFEST.yaml").write_text(MANIFEST)
        self.approve()
        (self.repo / "leak-scan-exceptions.yaml").write_text(
            "exceptions:\n  - {path: x, class: email, line: 1, reason: test, proof: test}\n")
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("scanner-exceptions", result.stderr)

    # ------------------------------------------------------------ manifest structure
    def test_unknown_class_is_refused(self) -> None:
        (self.repo / "MANIFEST.yaml").write_text(MANIFEST.replace("class: exclude-generated", "class: private"))
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("unknown class", result.stderr)
        self.assertFalse(self.staged("agents").exists())

    def test_unsafe_destination_is_refused(self) -> None:
        manifest = MANIFEST.replace("    class: public-copy\n    dest_dir: agents/tool\n\"\"\"", "")
        manifest = MANIFEST.replace('match: ["config.json", "notes.md", "skills"]\n    class: public-copy\n'
                                    '    dest_dir: agents/tool',
                                    'match: ["config.json", "notes.md", "skills"]\n    class: public-copy\n'
                                    '    dest_dir: ../escape')
        self.assertNotEqual(manifest, MANIFEST)
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("unsafe dest_dir", result.stderr)
        self.assertFalse((self.repo.parent / "escape").exists())
        self.assertFalse((self.repo / "escape").exists())

    def test_duplicate_entry_ids_are_refused(self) -> None:
        manifest = MANIFEST + ("  - id: tool-core\n    root: .tool\n    match: [\"extra\"]\n"
                               "    class: public-copy\n    dest_dir: agents/tool\n")
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("duplicate manifest entry id: tool-core", result.stderr)

    def test_dry_run_output_inside_the_repository_is_refused(self) -> None:
        for out in (self.repo, self.repo / "agents"):
            with self.subTest(out=out):
                result = self.run_sync("--out", str(out))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("must be under .staging", result.stderr)
                self.assertFalse((self.repo / "agents").exists())

    # ------------------------------------------------------------ content that hides from the scan
    def test_exemption_marker_cannot_hide_captured_content(self) -> None:
        cases = {
            "contact " + GMAIL + "  # LEAKSCAN-EXEMPT\n": "scanner exemption marker",
            "host " + CANARY + "  # LEAKSCAN-EXEMPT\n": "private denylist entry",
        }
        for text, message in cases.items():
            with self.subTest(message=message):
                self.write(".tool/notes.md", text)
                result = self.run_sync()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.staged("agents/tool/notes.md").exists())
                self.assertNoValues(result)

    def test_binary_files_pass_only_as_images_or_fonts(self) -> None:
        png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 16
        refused = {
            "skills/a/blob.dat": b"\x00contact " + GMAIL.encode() + b"\n",
            "skills/a/late.txt": b"a" * 9000 + b"\x00contact " + GMAIL.encode() + b"\n",
            "skills/a/logo.png": png + CANARY.encode(),
        }
        for rel, data in refused.items():
            with self.subTest(rel=rel):
                path = self.write(".tool/" + rel, data)
                try:
                    result = self.run_sync()
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertFalse(self.staged("agents/tool/" + rel).exists())
                    self.assertNoValues(result)
                finally:
                    path.unlink()
        self.write(".tool/skills/a/logo.png", png)
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.staged("agents/tool/skills/a/logo.png").read_bytes(), png)

    def test_outputs_the_scan_cannot_read_are_refused(self) -> None:
        cases = {"skills/a/node_modules/pkg/index.js": "inside a tree the leak scan skips",
                 "skills/a/big.txt": "larger than the leak scan reads"}
        for rel, message in cases.items():
            with self.subTest(rel=rel):
                path = self.write(".tool/" + rel, "module.exports = 1\n")
                if rel.endswith("big.txt"):
                    os.truncate(path, 21 * 1024 * 1024)
                try:
                    result = self.run_sync()
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertFalse(self.staged("agents/tool/" + rel).exists())
                finally:
                    path.unlink()

    def test_global_exclude_matches_directory_names_and_nested_paths(self) -> None:
        for rel in ("skills/b.bak/config.json", "skills/nested/skills/vendor/x.md"):
            self.write(".tool/" + rel, "leftover\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.staged("agents/tool/skills/b.bak").exists())
        self.assertFalse(self.staged("agents/tool/skills/nested/skills/vendor").exists())

    def test_key_redact_and_template_ids_cover_numbers_and_prefixed_keys(self) -> None:
        self.write(".tool/account.json", json.dumps({
            "api_token": int("1234" + "5678901"),
            "zotero_user_id": int("123" + "4567"),
            "telegram_chat_id": int("-100" + "1234567"),
        }) + "\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(self.staged("agents/tool/account.json.template").read_text())
        self.assertEqual(data, {"api_token": "{{ API_TOKEN }}", "zotero_user_id": "{{ USER_ID }}",
                                "telegram_chat_id": "{{ CHAT_ID }}"})

    def test_strip_projects_reads_jsonc_and_drops_tilde_and_object_items(self) -> None:
        home_item = str(self.home / "Research" / "p2")
        self.write(".tool/settings.json", "// managed file\n{\n  \"model\": \"m1\", /* note */\n"
                   "  \"trustedFolders\": [\"~/Research/secret-proj\", {\"path\": \"%s\"}, \"/opt/shared\",],\n}\n"
                   % home_item)
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = self.staged("agents/tool/settings.json").read_text()
        self.assertEqual(json.loads(text), {"model": "m1", "trustedFolders": ["/opt/shared"]})
        self.write(".tool/settings.json", "{\"trustedFolders\": [\"%s\"" % home_item)
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("strip-projects cannot parse", result.stderr)

    # ------------------------------------------------------------ publication
    def test_publication_preflight_blocks_every_write(self) -> None:
        self.approve()
        (self.repo / "agents/tool/config.json").mkdir(parents=True)
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("publication target is a directory", result.stderr)
        self.assertFalse((self.repo / "agents/tool/notes.md").exists())

    def test_authoritative_snapshot_skips_globally_excluded_files(self) -> None:
        manifest = MANIFEST.replace("roots: [.tool]", "roots: [.tool, src]") + (
            "  - id: src-mirror\n    root: src\n    match: [\"lib\"]\n    class: public-copy\n"
            "    dest_dir: system/src\n    authoritative: true\n")
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        self.write("src/lib/a.sh", "#!/bin/sh\necho current\n")
        self.write("src/lib/a.sh.bak", "#!/bin/sh\necho old\n")
        (self.repo / "system").mkdir()
        self.approve()
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repo / "system/src/lib/a.sh").read_text(), "#!/bin/sh\necho current\n")
        self.assertFalse((self.repo / "system/src/lib/a.sh.bak").exists())

    def test_blocked_destination_stops_the_authoritative_exchange_too(self) -> None:
        manifest = MANIFEST.replace("roots: [.tool]", "roots: [.tool, src]") + (
            "  - id: src-mirror\n    root: src\n    match: [\"main.sh\"]\n    class: public-copy\n"
            "    dest_dir: system/src\n    authoritative: true\n")
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        self.write("src/main.sh", "#!/bin/sh\necho clean\n")
        (self.repo / "system").mkdir()
        self.approve()
        (self.repo / "agents/tool/config.json").mkdir(parents=True)
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("publication target is a directory", result.stderr)
        self.assertFalse((self.repo / "system/src/main.sh").exists())

    def test_publish_refuses_bytes_changed_after_the_scan(self) -> None:
        render = self.tmp / "render"
        (render / "agents").mkdir(parents=True)
        (render / "agents/a.txt").write_text("scanned\n")
        sys.path.insert(0, str(self.repo / "bin/lib"))
        try:
            import manifest_sync
            digests = manifest_sync._tree_digests(str(render))
            (render / "agents/a.txt").write_text("changed " + GMAIL + "\n")
            with self.assertRaises(manifest_sync.SyncError):
                manifest_sync._publish_rendered_tree(str(render), str(self.repo), digests)
        finally:
            sys.path.pop(0)
            sys.modules.pop("manifest_sync", None)
        self.assertFalse((self.repo / "agents/a.txt").exists())

    def test_publish_checks_every_destination_before_the_first_write(self) -> None:
        render = self.tmp / "render"
        (render / "agents").mkdir(parents=True)
        (render / "agents/a.txt").write_text("first\n")
        (render / "agents/b.txt").write_text("second\n")
        (self.repo / "agents/b.txt").mkdir(parents=True)
        sys.path.insert(0, str(self.repo / "bin/lib"))
        try:
            import manifest_sync
            digests = manifest_sync._tree_digests(str(render))
            with self.assertRaises(manifest_sync.SyncError):
                manifest_sync._publish_rendered_tree(str(render), str(self.repo), digests)
        finally:
            sys.path.pop(0)
            sys.modules.pop("manifest_sync", None)
        self.assertFalse((self.repo / "agents/a.txt").exists())

    def test_missing_scanner_fails_closed(self) -> None:
        (self.repo / "bin/leak-scan.sh").unlink()
        result = self.run_sync()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("leak scanner missing", result.stderr)

    def test_apply_scans_with_the_denylist_required(self) -> None:
        (self.repo / "bin/leak-scan.sh").write_text(
            "#!/usr/bin/env bash\n[[ ${CSR_REQUIRE_DENYLIST:-} == 1 ]] && exit 0\n"
            "echo 'FINDING [denylist not required]'\nexit 2\n")
        self.approve()
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_symlink_report_is_scanned_before_publication(self) -> None:
        self.approve()
        (self.home / ".tool/skills/a/link").symlink_to("/srv/" + GMAIL + "/data")
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("FINDING [email]", result.stdout)
        self.assertFalse((self.repo / ".staging-symlinks-observed.tsv").exists())
        self.assertNoValues(result)

    def test_authoritative_stage_is_scanned_before_its_exchange(self) -> None:
        manifest = MANIFEST.replace("roots: [.tool]", "roots: [.tool, src]") + (
            "  - id: src-mirror\n    root: src\n    match: [\"main.sh\"]\n    class: public-copy\n"
            "    dest_dir: system/src\n    authoritative: true\n")
        (self.repo / "MANIFEST.yaml").write_text(manifest)
        self.write("src/main.sh", "#!/bin/sh\n# contact " + GMAIL + "\n")
        self.approve()
        result = self.run_sync("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("authoritative staged output failed the leak scan", result.stderr)
        self.assertFalse((self.repo / "system/src/main.sh").exists())
        self.assertNoValues(result)

    def test_review_tool_reports_and_refuses_non_interactive_approval(self) -> None:
        tool = [sys.executable, "-B", str(self.repo / "bin/review-manifest.py"), "--repo", str(self.repo)]
        result = subprocess.run(tool, text=True, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("tool-core", result.stdout)
        result = subprocess.run(tool + ["--approve", "tool-core"], text=True, capture_output=True,
                                stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("interactive", result.stderr)
        self.assertFalse((self.repo / "MANIFEST.review.json").exists())
        self.approve()
        result = subprocess.run(tool, text=True, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


COMPONENT_UNITS = (
    "openclaw-gateway.service", "send-queue-worker.service", "openclaw-sage-worker.service",
    "openclaw-manim-worker.service", "openclaw-email-worker.service",
    "openclaw-zulip-delivery-worker.service", "openclaw-zalo-delivery-worker.service",
    "openclaw-googlechat-delivery-worker.service", "openclaw-whatsapp-delivery-worker.service",
    "rss_news_digest_bot.service", "rss_news_digest_bot.timer",
    "moltbook-relay.service", "moltbook-relay.timer",
)


class RepositoryManifestTests(unittest.TestCase):
    """Classification decisions of the checked-in MANIFEST.yaml."""

    @classmethod
    def setUpClass(cls) -> None:
        import yaml
        cls.entries = yaml.safe_load((ROOT / "MANIFEST.yaml").read_text(encoding="utf-8"))["entries"]
        cls.secrets = (ROOT / "secrets/secrets-manifest.yaml").read_text(encoding="utf-8")

    def classes(self, root: str, name: str) -> set[str]:
        return {e["class"] for e in self.entries if e.get("root") == root and name in e.get("match", [])}

    def test_codex_rules_ride_in_the_recovery_set_not_the_public_tree(self) -> None:
        # approved command rules name private machines and paths
        self.assertEqual(self.classes(".codex", "rules"), {"private-archive"})
        self.assertIn("path: .codex/rules/,", self.secrets)

    def test_component_owned_units_are_delegated_not_captured(self) -> None:
        # the openclaw-bot service transaction installs these; the live copies can
        # carry private values such as the owner's RSS schedule
        for unit in COMPONENT_UNITS:
            with self.subTest(unit=unit):
                self.assertEqual(self.classes(".config/systemd/user", unit), {"delegate"})
        for unit in ("openclaw-gateway.service.d", "coding-system-scheduler-canary.timer",
                     "xvfb-99.service", "grok-remote-boot-revalidate.service"):
            with self.subTest(unit=unit):
                self.assertEqual(self.classes(".config/systemd/user", unit), {"public-template"})

    def test_timer_schedule_dropins_are_generated_not_captured(self) -> None:
        # rendered from host.v1.json and the owner's private schedule settings
        for directory in ("rss_news_digest_bot.timer.d", "coding-system-scheduler-canary.timer.d"):
            with self.subTest(directory=directory):
                self.assertEqual(self.classes(".config/systemd/user", directory), {"exclude-generated"})

    def test_local_coder_and_exit_forensics_units_are_public_templates(self) -> None:
        # Step 5.6: the units restore from public skeletons; the tunnel owner file and
        # the research-compute config ride in the recovery set instead.
        for unit in ("chatgpt-local-coder.service", "chatgpt-local-coder.service.d",
                     "chatgpt-local-coder-tunnel.service", "chatgpt-local-coder-tunnel-health.service",
                     "chatgpt-local-coder-tunnel-health.timer", "exit-forensics.service"):
            with self.subTest(unit=unit):
                self.assertEqual(self.classes(".config/systemd/user", unit), {"public-template"})
        self.assertEqual(
            self.classes(".config/systemd/user", "chatgpt-local-coder-tunnel.service.owner.json"),
            {"exclude-private-data"},
        )
        self.assertEqual(self.classes(".local/bin", "exit-forensics.sh"), {"public-template"})
        self.assertEqual(
            self.classes(".local/libexec/chatgpt-local-coder", "tunnel-health.sh"), {"public-template"}
        )
        self.assertIn(".config/systemd/user/chatgpt-local-coder-tunnel.service.owner.json", self.secrets)
        self.assertIn(".local/share/ai-agents-skills/research-compute/config/", self.secrets)


if __name__ == "__main__":
    unittest.main()
