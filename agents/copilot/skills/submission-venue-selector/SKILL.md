---
name: "submission-venue-selector"
description: "Evidence-gated journal and conference venue selection for scholarly drafts; deliverable rankings require comparator-paper evidence."
metadata:
  short-description: "Evidence-gated journal and conference venue selection for scholarly drafts; deliverable rankings require comparator-paper evidence."
---

<!-- Managed by ai-agents-skills. Generated target: copilot. Install mode: reference. -->

# submission-venue-selector

This is a thin adapter for agents that cannot load symlinked skills.

Canonical skill source:

- `~/ai-agents-skills/canonical/skills/submission-venue-selector/SKILL.md`

Before using this skill, read the canonical source file above and follow
its instructions. Related reference files live next to that source file
in the same skill directory.


## Mandatory Delivery Gate

Do not deliver a ranked venue shortlist unless every ranked venue
has comparator-paper evidence. Bibliography overlap and offline
placeholders are discovery signals only. If comparator evidence is
missing, report `incomplete analysis` and `not-ready`.
