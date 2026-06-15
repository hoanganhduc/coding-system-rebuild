# Multi-Agent Review: `tikz-draw` Skill Implementation Plan

Date: 2026-04-19
Target plan:
- [tikz-draw-skill-implementation-plan.md](/home/<user>/tikz-draw-skill-implementation-plan.md)

## Scope And Coverage

This was a multi-agent review of the implementation plan against the current local Codex and Claude environments.

Inspected directly in the main thread:

- [tikz-draw-skill-implementation-plan.md](/home/<user>/tikz-draw-skill-implementation-plan.md)
- [config.toml](/home/<user>/.codex/config.toml)
- [AGENTS.md](/home/<user>/.codex/AGENTS.md)
- [openclaw-research SKILL.md](/home/<user>/.codex/skills/openclaw-research/SKILL.md)
- [deep-research-workflow SKILL.md](/home/<user>/.codex/skills/deep-research-workflow/SKILL.md)
- [run_deep_research_workflow.sh](/home/<user>/.codex/runtime/workspace/skills/deep-research-workflow/run_deep_research_workflow.sh)
- [run_skill.sh](/home/<user>/.codex/runtime/run_skill.sh)
- [settings.json](/home/<user>/.claude/settings.json)
- [CLAUDE.md](/home/<user>/.claude/CLAUDE.md)
- [deep-research.md](/home/<user>/.claude/commands/deep-research.md)
- [deep-research SKILL.md](/home/<user>/.claude/skills/deep-research/SKILL.md)
- [analysis template](/home/<user>/.claude/skills/deep-research/templates/analysis.md)
- [report template](/home/<user>/.claude/skills/deep-research/templates/report.md)
- [_run.sh](/home/<user>/.claude/skills/_run.sh)
- [verification-patterns.md](/home/<user>/.claude/docs/verification-patterns.md)
- [ERRORS.md](/home/<user>/.claude/learnings/ERRORS.md)

Also incorporated:

- one implementation-failure reviewer
- one Codex-adaptation reviewer
- one Claude-adaptation reviewer
- one synthesis reviewer

Important correction from direct inspection:

- `~/.claude/data/runs` does exist locally as a symlink, so the failure risk is not a missing runs root.
- The real risk is that the plan does not define explicit creation, ownership, and path rules for deeper run-specific figure directories under that root.

## Evidence Summary

- The plan’s overall direction is sound: structure-first TikZ generation, self-contained per-platform runtime, no phase-1 global settings changes, and single-agent research integration before multi-agent expansion.
- The highest-risk mismatches are operational, not conceptual: current wrappers force fixed working directories, current research workflows do not yet define a figure-brief handoff contract, and Claude’s public surface is command-first rather than skill-first.
- Codex triggering depends heavily on `SKILL.md` frontmatter quality, especially `description`, while the current plan spends more detail on skill body behavior than on trigger design.
- Claude’s current settings and conventions make `/tikz` the right public interface, with the underlying skill likely private via frontmatter rather than user-facing.

## Issues That Need To Be Fixed To Avoid Implementation Failures

- Define an explicit path contract before implementation. Both wrappers change cwd:
  - [_run.sh](/home/<user>/.claude/skills/_run.sh)
  - [run_skill.sh](/home/<user>/.codex/runtime/run_skill.sh)
  The plan currently allows “user-specified directory or run directory” output without saying how paths are canonicalized. This is a real failure risk given the prior hardcoded-workspace issue in [ERRORS.md](/home/<user>/.claude/learnings/ERRORS.md).

- Reconcile the helper API now. The plan currently mixes:
  - shared contract `spec` / `render`
  - skill modes `spec` / `render`
  - Codex runtime helper `new --spec PATH --out DIR`
  This should become one stable verb set before any implementation or tests are written.

- Add a concrete deep-research handoff artifact. Current research workflows only scaffold or describe `sources.md`, `analysis.md`, and `report.md`:
  - [run_deep_research_workflow.sh](/home/<user>/.codex/runtime/workspace/skills/deep-research-workflow/run_deep_research_workflow.sh)
  - [deep-research SKILL.md](/home/<user>/.claude/skills/deep-research/SKILL.md)
  The plan needs a defined `figure-brief` schema or section with ownership, path, and `S*` source linkage. Without that, the promised handoff is not verifiable.

- Standardize the Claude public/private interface. The current plan says deep research may hand off to “`/tikz` or the `tikz-draw` skill”, but Claude is command-first and `disableSkillShellExecution` is enabled in [settings.json](/home/<user>/.claude/settings.json). The plan should make `/tikz` the public path and the skill the implementation behind it, likely with `user-invocable: false`.

- Expand verification to include wiring checks, not just content checks. [verification-patterns.md](/home/<user>/.claude/docs/verification-patterns.md) explicitly requires `Exists`, `Substantive`, `Wired`, and `Functional`. The current plan’s verification section is too close to happy-path behavior only.

## Suggestions For Improvements

- Add one canonical source-of-truth rule for shared assets under `/home/<user>/tasks/tikz-draw-skill/`, plus an explicit sync step into `~/.codex` and `~/.claude`. Right now the plan risks drift by saying “author outside, then copy into both trees” without naming the canonical source.

- Introduce stable artifact IDs such as `F1`, `F2` alongside `S1`, `S2`. This will make report references cleaner than raw file paths.

- Treat the LaTeX toolchain as `doctor`-verified rather than operationally assumed. The host does have the expected binaries, but the skill contract should still gate compile/review through `doctor`.

- Make the verification matrix stricter:
  - path creation
  - malformed spec handling
  - missing toolchain behavior
  - duplicate registration checks on Claude
  - wrapper invocation checks on both platforms

- Narrow any documentation claims about the current Claude run layout. `~/.claude/data/runs` exists, but the plan should acknowledge that it is a symlinked run root and still define how deeper `deep-research/<run_id>/figures/` and `tikz-draw/<run_id>/` directories get created.

- Keep the runtime `README.txt` question low priority. There is some tension with Codex skill-creator guidance against extra docs, but current runtime helpers already include a small [README.txt](/home/<user>/.codex/runtime/workspace/skills/deep-research-workflow/README.txt). This should not block implementation.

## Codex-Adaptation Suggestions

- Make the Codex trigger surface frontmatter-first in `~/.codex/skills/tikz-draw/SKILL.md`. The plan should explicitly specify a strong `description` field with trigger phrases such as:
  - draw in TikZ
  - convert diagram to TikZ
  - refactor coordinate-heavy TikZ
  - extract standalone TikZ from Beamer/LaTeX
  - create source-linked LaTeX figure from research findings

- Keep the Codex layout narrow:
  - root skill: `SKILL.md` plus shallow `references/`
  - runtime helper: `~/.codex/runtime/workspace/skills/tikz-draw/`
  - avoid broad or redundant top-level documentation

- Narrow `openclaw-research` routing. [openclaw-research SKILL.md](/home/<user>/.codex/skills/openclaw-research/SKILL.md) is the default research router and should not broadly hand off to `tikz-draw` whenever an answer “needs a maintained artifact”. Limit that to explicit TikZ/diagram requests. Use `deep-research-workflow` as the post-analysis handoff point for source-linked figure generation.

- If Codex deep-research templates gain figure sections, update all linked handoff docs together:
  - [deep-research-analysis.md](/home/<user>/.codex/templates/deep-research-analysis.md)
  - [deep-research-report.md](/home/<user>/.codex/templates/deep-research-report.md)
  - [source-handoff.md](/home/<user>/.codex/skills/deep-research-workflow/references/source-handoff.md)
  - `output-structure.md`
  Leaving the reference docs optional will create drift in the current Codex workflow.

- Add a TikZ row to the main Codex operator surfaces:
  - [AGENTS.md](/home/<user>/.codex/AGENTS.md)
  - [research-quick-actions.md](/home/<user>/.codex/instructions/research-quick-actions.md)

- Add an explicit Codex artifact convention such as `<DIR>/<subdir>/figures/` plus `F*` IDs so generated figures are not only mentioned in prose.

## Claude-Adaptation Suggestions

- Make `/tikz` the only public name in user-facing Claude docs. Do not keep “`/tikz` or the `tikz-draw` skill” wording in public routing.

- Model the Claude implementation on existing command style:
  - `**Runner:** bash ~/.claude/skills/_run.sh skills/tikz-draw/run_tikz_draw.sh <args>`
  - flat command matrix for `doctor`, `spec`, `render`, `check`, `compile`, `review`, `extract`
  This matches current command surfaces like [zotero.md](/home/<user>/.claude/commands/zotero.md) and [sage.md](/home/<user>/.claude/commands/sage.md).

- Add normal Claude skill frontmatter to `~/.claude/skills/tikz-draw/SKILL.md`, likely including `user-invocable: false` if `/tikz` is the public interface. This aligns with current command-backed skill wiring guidance in [verification-patterns.md](/home/<user>/.claude/docs/verification-patterns.md).

- Update Claude deep-research wording from strict three-phase language to something like:
  - `Search -> Analyze -> optional Figure -> Write`
  - or `Phase 2.5: Figure`
  Otherwise [deep-research.md](/home/<user>/.claude/commands/deep-research.md) and [deep-research SKILL.md](/home/<user>/.claude/skills/deep-research/SKILL.md) will become internally inconsistent.

- Add `/tikz` to both Claude routing surfaces in [CLAUDE.md](/home/<user>/.claude/CLAUDE.md):
  - slash-command table
  - automatic routing block

- Because subprocess env is scrubbed and Bash calls are hook-wrapped in [settings.json](/home/<user>/.claude/settings.json), the Claude runner should:
  - set any required env explicitly
  - avoid relying on ambient `TEXINPUTS` or cwd state
  - prefer coarse-grained wrapper calls rather than many tiny Bash invocations

- Use a dedicated direct-use run root such as `~/.claude/data/runs/tikz-draw/<run_id>/` and make creation explicit, rather than implying inheritance from deep-research paths.

## Residual Uncertainties

- This review was a plan-to-environment review, not a re-audit of the three upstream TikZ research memos.

- No future `tikz-draw` implementation was executed. Runtime behavior remains unverified until the skill exists and is tested through both wrappers.

- The exact best placement for a runtime `README.txt` is lower-confidence than the other findings. The direct blocker is not the README question; it is path handling, handoff contract definition, and routing/wiring clarity.

- The best final shape of the handoff artifact is still open. The review only establishes that a concrete artifact or schema is required, not whether it should be JSON, Markdown, or both.
