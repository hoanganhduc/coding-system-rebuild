from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"


class WorkflowSecurityTests(unittest.TestCase):
    def test_every_external_action_is_pinned_to_a_full_commit(self) -> None:
        observed = 0
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            source = workflow.read_text(encoding="utf-8")
            for match in re.finditer(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)", source, re.M):
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                observed += 1
                self.assertRegex(
                    reference,
                    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$",
                    f"mutable or malformed action reference in {workflow.name}: {reference}",
                )
        self.assertGreater(observed, 0)

    def test_checkout_never_persists_a_writeable_workflow_token(self) -> None:
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            source = workflow.read_text(encoding="utf-8")
            checkouts = len(re.findall(r"uses:\s*actions/checkout@", source))
            disabled = len(re.findall(r"persist-credentials:\s*false", source))
            self.assertEqual(
                disabled,
                checkouts,
                f"checkout credential persistence is not disabled in {workflow.name}",
            )

    def test_openclaw_publish_permissions_are_job_scoped(self) -> None:
        source = (WORKFLOWS / "openclaw-sandbox.yml").read_text(encoding="utf-8")
        global_permissions, jobs = source.split("jobs:", 1)
        self.assertIn("permissions:\n  contents: read", global_permissions)
        self.assertNotIn("packages: write", global_permissions)
        self.assertNotIn("id-token: write", global_permissions)
        build, publish = jobs.split("  publish-index:", 1)
        self.assertIn("      packages: write", build)
        self.assertIn("      id-token: write", build)
        self.assertIn("      attestations: write", build)
        self.assertIn("      packages: write", publish)
        self.assertNotIn("      id-token: write", publish)
        self.assertNotIn("      attestations: write", publish)

    def test_openclaw_sandbox_push_publishes_only_after_owner_opt_in(self) -> None:
        source = (WORKFLOWS / "openclaw-sandbox.yml").read_text(encoding="utf-8")
        build, publish = source.split("jobs:", 1)[1].split("  publish-index:", 1)
        self.assertIn(
            "    if: github.event_name == 'workflow_dispatch'"
            " || vars.OPENCLAW_SANDBOX_AUTO_PUBLISH == 'true'\n",
            build,
        )
        self.assertIn("    needs: build\n", publish)
        # a job-level condition (always(), !cancelled(), failure() ...) could run it after a skipped build
        self.assertNotIn("\n    if:", publish)

    def test_openclaw_sandbox_latest_tag_moves_only_from_main(self) -> None:
        source = (WORKFLOWS / "openclaw-sandbox.yml").read_text(encoding="utf-8")
        steps = [step for step in source.split("      - ") if ":latest" in step]
        self.assertEqual(len(steps), 1)
        self.assertIn("        if: github.ref == 'refs/heads/main'\n", steps[0])


if __name__ == "__main__":
    unittest.main()
