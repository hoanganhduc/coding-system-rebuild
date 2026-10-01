from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AAS_ROOT = ROOT.parent / "ai-agents-skills"
HELPER = ROOT / "bin/openclaw-skill-inventory.py"
SPEC = importlib.util.spec_from_file_location("openclaw_skill_inventory", HELPER)
assert SPEC is not None and SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


EXPECTED_SKILLS = [
    "classroom50",
    "autonomous-research-loop",
    "course-canvas",
    "course-db",
    "course-google-classroom",
    "vnu-eoffice",
]


class OpenClawSkillInventoryTests(unittest.TestCase):
    def test_pinned_inventory_is_the_exact_six_skill_file_closure(self) -> None:
        inventory = INVENTORY.build_inventory(AAS_ROOT)

        self.assertEqual(inventory["skills"], EXPECTED_SKILLS)
        self.assertEqual(inventory["runtime_backed_excluded"], ["getscipapers-requester"])

    def test_manifest_driven_inventory_does_not_silently_omit_new_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_manifests(
                root,
                {
                    "classroom50": {"supported_agents": ["openclaw"]},
                    "new-openclaw-skill": {"supported_agents": ["openclaw"]},
                    "runtime-only": {"supported_agents": ["openclaw"]},
                    "codex-only": {"supported_agents": ["codex"]},
                },
                {"runtime-only": {}},
            )
            for skill in ("classroom50", "new-openclaw-skill"):
                source = root / "canonical/skills" / skill / "SKILL.md"
                source.parent.mkdir(parents=True)
                source.write_text(f"---\nname: {skill}\n---\n", encoding="utf-8")

            inventory = INVENTORY.build_inventory(root)

            self.assertEqual(inventory["skills"], ["classroom50", "new-openclaw-skill"])
            self.assertEqual(inventory["runtime_backed_excluded"], ["runtime-only"])

    def test_install_phase_loops_inventory_before_target_state_gate(self) -> None:
        install = (ROOT / "bin/install.sh").read_text(encoding="utf-8")

        inventory_index = install.index("bin/openclaw-skill-inventory.py")
        loop_index = install.index('for OPENCLAW_SKILL in "${OPENCLAW_SKILL_FILES[@]}"')
        apply_index = install.index('--skill "$OPENCLAW_SKILL" --action-class "$OPENCLAW_ACTION_CLASS"')
        verify_index = install.index('python3 "$REPO/bin/verify-target-state.py"')
        self.assertLess(inventory_index, loop_index)
        self.assertLess(loop_index, apply_index)
        self.assertLess(apply_index, verify_index)
        self.assertIn('"$HOME/.openclaw/skills/$OPENCLAW_SKILL/SKILL.md"', install)

    @staticmethod
    def write_manifests(
        root: Path,
        skills: dict[str, object],
        runtime_skills: dict[str, object],
    ) -> None:
        manifest = root / "manifest"
        manifest.mkdir(parents=True)
        (manifest / "profiles.yaml").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profiles": {"complete-restore": {"skills": ["*"]}},
                }
            ),
            encoding="utf-8",
        )
        (manifest / "skills.yaml").write_text(
            json.dumps({"schema_version": 1, "skills": skills}),
            encoding="utf-8",
        )
        (manifest / "runtime.yaml").write_text(
            json.dumps({"schema_version": 1, "skills": runtime_skills}),
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
