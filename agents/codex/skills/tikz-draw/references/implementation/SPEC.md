# Spec: `tikz-draw` For Codex And Claude

## Objective

- Build a narrow `tikz-draw` capability for both Codex and Claude that generates, extracts, refactors, checks, compiles, and reviews structural TikZ.
- Integrate that capability into the existing single-agent deep-research workflows through a concrete `figure-brief.json` handoff.
- Keep the two platforms aligned on core behavior while respecting their real public surfaces:
  - Codex: skill-triggered
  - Claude: `/tikz` command-triggered
- Make document-facing TikZ outputs automatically fit `\textwidth` by wrapping each `tikzpicture` in `adjustbox` with `max width=\textwidth`.

## Assumptions

1. Phase 1 does not change global settings in `~/.codex/config.toml` or `~/.claude/settings*.json`.
2. Claude’s public interface is `/tikz`; the underlying Claude skill is private via frontmatter.
3. Codex triggering depends primarily on strong `SKILL.md` frontmatter, especially `description`.
4. Shared schema, snippet, and style assets live canonically under `~/tasks/tikz-draw-skill/shared/`.
5. Deep-research integration is post-analysis only in phase 1.
6. All runner paths and output paths must be normalized to absolute host paths before execution.
7. Phase-1 document-facing outputs must not emit a bare top-level `tikzpicture`; they must use the required `adjustbox` wrapper.

## Commands

- Build:
  - `n/a`
- Test:
  - `bash ~/.codex/runtime/run_skill.sh skills/tikz-draw/run_tikz_draw.sh doctor`
  - `bash ~/.claude/skills/_run.sh skills/tikz-draw/run_tikz_draw.sh doctor`
- Lint:
  - `bash -n ~/.codex/runtime/workspace/skills/tikz-draw/run_tikz_draw.sh`
  - `bash -n ~/.claude/skills/tikz-draw/run_tikz_draw.sh`
  - `python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py ~/.codex/skills/tikz-draw`
- Run:
  - `bash ~/.codex/runtime/run_skill.sh skills/tikz-draw/run_tikz_draw.sh render --spec <ABS_SPEC> --out <ABS_OUT_DIR>`
  - `bash ~/.claude/skills/_run.sh skills/tikz-draw/run_tikz_draw.sh render --spec <ABS_SPEC> --out <ABS_OUT_DIR>`

## Project Structure

- Files or directories expected to change:
  - `~/tikz-draw-skill-implementation-plan.md`
  - `~/tasks/tikz-draw-skill/`
  - `~/.codex/skills/tikz-draw/`
  - `~/.codex/runtime/workspace/skills/tikz-draw/`
  - `~/.codex/AGENTS.md`
  - `~/.codex/instructions/research-quick-actions.md`
  - `~/.codex/skills/openclaw-research/SKILL.md`
  - `~/.codex/skills/deep-research-workflow/SKILL.md`
  - `~/.codex/templates/deep-research-analysis.md`
  - `~/.codex/templates/deep-research-report.md`
  - `~/.codex/skills/deep-research-workflow/references/source-handoff.md`
  - `~/.codex/skills/deep-research-workflow/references/output-structure.md`
  - `~/.claude/skills/tikz-draw/`
  - `~/.claude/commands/tikz.md`
  - `~/.claude/CLAUDE.md`
  - `~/.claude/commands/deep-research.md`
  - `~/.claude/skills/deep-research/SKILL.md`
  - `~/.claude/skills/deep-research/templates/analysis.md`
  - `~/.claude/skills/deep-research/templates/report.md`
- Relevant boundaries:
  - Do not change unrelated research skills or global routing beyond TikZ-specific additions.
  - Do not introduce runtime coupling between `~/.codex` and `~/.claude`.
  - Do not bypass the existing wrappers.

## Testing Strategy

- Unit:
  - schema validation for `diagram.schema.json` and `figure-brief.schema.json`
  - shell syntax checks on both runners
  - deterministic prevention-check tests on intentionally bad snippets
- Integration:
  - Codex deep-research analysis -> `figure-brief.json` -> `tikz-draw` -> report artifact reference
  - Claude deep-research analysis -> `figure-brief.json` -> `/tikz` -> report artifact reference
  - direct `render` without a prewritten brief auto-allocates the documented platform run root
  - wrapper-based doctor/render/check/compile/review flows on both platforms
  - standalone output and embeddable snippet both preserve the same `adjustbox` width-fit wrapper
- Manual:
  - flowchart with `positioning`
  - tree with `forest`
  - commutative diagram with `tikz-cd`
  - refactor of coordinate-heavy TikZ
  - research-driven summary figure with `S*` and `F*` IDs
  - confirm generated `.tex` uses `adjustbox{max width=\textwidth}` around `tikzpicture`
  - confirm standalone compile targets use plain `standalone` class, not `standalone[tikz]`, when the required `adjustbox` wrapper is present

## Boundaries

- Always:
  - use absolute host paths
  - use one stable helper API
  - keep `/tikz` public on Claude and the skill private
  - keep Codex triggering frontmatter-first
  - preserve `S*` source IDs through research-to-figure handoff
  - wrap document-facing `tikzpicture` output in `adjustbox` with `max width=\textwidth`
- Ask first:
  - changing global Codex or Claude settings
  - widening the feature beyond structural TikZ and related extraction/refactoring
  - changing non-TikZ research workflows beyond necessary handoff additions
- Never:
  - hardcode `/workspace`
  - rely on inherited cwd state
  - rely on implicit Claude skill-shell execution as the public interface
  - make Codex or Claude depend on each other at runtime

## Success Criteria

- [ ] A canonical shared source tree exists under `~/tasks/tikz-draw-skill/shared/`.
- [ ] Codex has a working `tikz-draw` skill plus runtime helper with the stable API.
- [ ] Claude has a working private `tikz-draw` skill plus public `/tikz` command with the stable API.
- [ ] Both platforms implement explicit absolute-path and run-root handling.
- [ ] Both deep-research workflows can emit and consume `figure-brief.json`.
- [ ] Both platforms generate document-facing output with the required `adjustbox{max width=\textwidth}` wrapper.
- [ ] Verification covers `Exists`, `Substantive`, `Wired`, and `Functional`.
- [ ] At least one end-to-end research-to-TikZ scenario works on each platform.

## Open Questions

- Should `figure-brief` live as JSON only, or JSON plus a mirrored markdown summary?
- Should the review verdict be plain text only, or structured JSON plus human-readable summary?
- Do we want a small shared installer/sync script in phase 1, or keep install/copy steps manual first?
