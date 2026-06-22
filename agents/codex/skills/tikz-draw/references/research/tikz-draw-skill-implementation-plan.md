# Plan: Implement `tikz-draw` for Codex and Claude and Integrate It into Existing Research Workflows

Date: 2026-04-19
Basis:
- [tikz-codex-claude-deep-research.md](/home/hoanganhduc/tikz-codex-claude-deep-research.md)
- [tikz-codex-claude-internet-extended-research.md](/home/hoanganhduc/tikz-codex-claude-internet-extended-research.md)
- [tikz-codex-claude-repo-research.md](/home/hoanganhduc/tikz-codex-claude-repo-research.md)

## Scope

This plan covers:

- implementing a new `tikz-draw` skill in `~/.codex`
- implementing a new `tikz-draw` skill in `~/.claude`
- integrating that skill into the current single-agent deep-research workflows in both environments
- adding the minimum routing and artifact conventions needed for reliable research-to-TikZ handoff

This plan does not assume immediate changes to global model defaults in `~/.codex/config.toml` or `~/.claude/settings*.json`.

Assumption:

- phase 1 integration targets the existing single-agent deep-research flows first
- multi-agent handoff integration is phase 2, after the base skill is stable

## Evidence Summary

The three research passes converged on the same implementation requirements:

1. Better TikZ comes from a structure-first workflow, not from one-shot prompting.
2. The skill should generate an intermediate structural spec before final TikZ.
3. The skill should route by diagram family to a package or library such as `positioning`, `matrix`, `fit`, `graphs`, `graphdrawing`, `forest`, `tikz-cd`, `automata`, `mindmap`, or `pgf-umlsd`.
4. Validation should be a loop: prevention checks, compile, review, repair.
5. Repository-backed practice supports snippet-first authoring, reusable style files, explicit node dimensions, banned unsafe scaling, directed label placement, and a reviewer pass.
6. Cross-tool parity works best with aligned root instructions plus deeper references, not with one giant prompt file.

## Current Local State

Inspected local state relevant to this plan:

- Codex root instructions live in `~/.codex/AGENTS.md`.
- Codex research routing currently points users to `openclaw-research` and `deep-research-workflow`.
- Codex deep research currently uses:
  - `~/.codex/skills/deep-research-workflow/SKILL.md`
  - `~/.codex/templates/deep-research-sources.md`
  - `~/.codex/templates/deep-research-analysis.md`
  - `~/.codex/templates/deep-research-report.md`
  - `~/.codex/runtime/workspace/skills/deep-research-workflow/run_deep_research_workflow.sh`
- Claude root instructions live in `~/.claude/CLAUDE.md`.
- Claude research entrypoints currently use:
  - `~/.claude/commands/deep-research.md`
  - `~/.claude/skills/deep-research/SKILL.md`
  - `~/.claude/skills/deep-research/templates/{sources,analysis,report}.md`
- There is currently no `tikz`, `diagram`, or `beamer` skill directory under either `~/.codex/skills/` or `~/.claude/skills/`.
- Current Codex global config is `model = "gpt-5.4"` with `model_reasoning_effort = "xhigh"` in [config.toml](/home/hoanganhduc/.codex/config.toml).
- Current Claude settings enable always-thinking, disable adaptive thinking via env, force max effort via env, and set `disableSkillShellExecution = true` in [settings.json](/home/hoanganhduc/.claude/settings.json).
- The local LaTeX toolchain already includes `latexmk`, `pdflatex`, `xelatex`, `lualatex`, `dvisvgm`, and `pdf2svg`.
- Current deep-research docs in both environments do not mention TikZ routing or figure-generation handoffs.

## Execution-Ready Decisions

This section supersedes any conflicting implementation detail below the original research-derived intent. The plan is now execution-ready on these decisions:

1. One stable helper API across both platforms:
   - `doctor`
   - `spec`
   - `render`
   - `check`
   - `compile`
   - `review`
   - `extract`
2. One canonical source of truth for shared assets:
   - `/home/hoanganhduc/tasks/tikz-draw-skill/shared/`
3. One concrete research handoff artifact:
   - `figure-brief.json`
4. Codex public entrypoint:
   - skill trigger via strong `SKILL.md` frontmatter
5. Claude public entrypoint:
   - `/tikz`
   - underlying skill is private via frontmatter
6. TikZ width-fit rule:
   - generated `tikzpicture` content is wrapped in `adjustbox` with `max width=\textwidth`
7. No phase-1 global settings changes in either `~/.codex` or `~/.claude`

## Design Principles

1. Keep runtime self-contained inside each tool's home directory. Do not make Codex depend on `~/.claude` at runtime or Claude depend on `~/.codex` at runtime.
2. Prefer workflow and validation controls over global model-setting changes.
3. Treat research-generated diagrams as evidence-linked artifacts, not decorative output.
4. Keep the feature narrow in phase 1: structural TikZ generation, extraction, and refactoring.
5. Keep shared logic aligned, but respect the real platform surface:
   - Codex is skill-first
   - Claude is command-first

## Canonical Source Of Truth

The canonical authoring workspace is:

- `/home/hoanganhduc/tasks/tikz-draw-skill/`

The canonical shared assets live under:

- `/home/hoanganhduc/tasks/tikz-draw-skill/shared/`

Planned shared contents:

- `shared/spec-schema/diagram.schema.json`
- `shared/spec-schema/figure-brief.schema.json`
- `shared/snippets/`
- `shared/checks/`
- `shared/examples/`
- `shared/styles/tikz_styles.tex`
- `shared/styles/tikz_palette.tex`

Install targets remain self-contained copies under:

- `~/.codex/skills/tikz-draw/`
- `~/.codex/runtime/workspace/skills/tikz-draw/`
- `~/.claude/skills/tikz-draw/`
- `~/.claude/commands/tikz.md`

Phase-1 sync rule:

- edit shared source first
- then copy/install into Codex and Claude trees
- do not hand-edit both installed copies independently

## Stable Helper API

Both platforms will use the same logical helper API:

- `doctor`
- `spec`
- `render`
- `check`
- `compile`
- `review`
- `extract`

### Command semantics

- `doctor`
  - verify binaries, output directories, and required shared assets
- `spec`
  - create or normalize a structural diagram spec from prompt input, notes, or a `figure-brief.json`
- `render`
  - generate `.tex` from an existing spec
  - by default, wrap `tikzpicture` in `adjustbox` using `max width=\textwidth`
- `check`
  - run deterministic prevention checks without compiling
- `compile`
  - build PDF and optional SVG artifacts
- `review`
  - emit a short verdict with specific failures
- `extract`
  - convert an existing Beamer or LaTeX figure block into a standalone artifact set

### Required arguments

All path-bearing commands must accept absolute host paths and internally normalize relative paths to absolute host paths before any file I/O.

No helper may assume:

- `/workspace`
- current shell cwd
- inherited `TEXINPUTS`
- inherited PATH additions beyond what the wrapper explicitly sets

## Width-Fit Rendering Rule

This is a hard requirement for phase 1.

All generated TikZ outputs intended for document use must wrap the `tikzpicture` in `\adjustbox{max width=\textwidth}{...}`.

Reference form:

```tex
\adjustbox{max width=\textwidth}{%
\begin{tikzpicture}
...
\end{tikzpicture}
}
```

Implications:

- standalone compile targets must include `\usepackage{adjustbox}`
- standalone compile targets should use plain `\documentclass[border=...]{standalone}` and load TikZ packages explicitly
  - verified locally: `standalone[tikz]` breaks the required `adjustbox` wrapper for `tikzpicture`, `forest`, and `tikz-cd` examples in this environment
- embeddable outputs for a draft such as `main.tex` must preserve the same `adjustbox` wrapper
- `check` must verify that the wrapper is present
- `render` is not allowed to emit a bare top-level `tikzpicture` unless a future override is explicitly added

## Path And Run-Root Contract

This is mandatory because both wrappers force a fixed cwd:

- Claude: [_run.sh](/home/hoanganhduc/.claude/skills/_run.sh)
- Codex: [run_skill.sh](/home/hoanganhduc/.codex/runtime/run_skill.sh)

### Hard rules

1. Every input path is converted to an absolute host path before the wrapper call or at script start.
2. Every output directory is created explicitly by the helper before writing.
3. No script may hardcode `/workspace`.
4. Scripts must honor:
   - `OPENCLAW_WORKSPACE` on Claude
   - `CODEX_RUNTIME_WORKSPACE` and `OPENCLAW_WORKSPACE` on Codex

### Default run roots

Direct Codex use:

- `~/.codex/runs/tikz-draw/<run_id>/`

Direct Claude use:

- `~/.claude/data/runs/tikz-draw/<run_id>/`

Codex deep-research integration:

- `<research_root>/figures/`

Claude deep-research integration:

- `~/.claude/data/runs/deep-research/<run_id>/figures/`

The helper must create the deeper figure directory if missing. The plan does not assume that `deep-research/<run_id>/figures/` already exists.

Direct `render` and `extract` flows should allocate the documented direct-use run roots automatically when `--out-dir` is omitted.

## Shared Contracts

### Trigger intent

The feature should trigger for:

- draw this in TikZ
- convert this diagram to TikZ
- make this TikZ more structural
- create a LaTeX figure from these research findings
- refactor this coordinate-heavy TikZ
- extract a standalone TikZ figure from Beamer or LaTeX

### Non-goals

- generic SVG art
- raster illustration
- freehand or photorealistic graphics
- non-LaTeX diagram generation unless the user explicitly wants derived exports from TikZ

### Structural diagram spec

```json
{
  "diagram_family": "flowchart|dag|tree|matrix|automaton|mindmap|sequence|commutative|network|custom",
  "tikz_backend": "positioning|matrix|fit|graphs|graphdrawing|forest|tikz-cd|automata|mindmap|pgf-umlsd|raw-tikz",
  "title": "string",
  "global_styles": {},
  "nodes": [],
  "edges": [],
  "groups": [],
  "layout_constraints": [],
  "validation_rules": []
}
```

### Research handoff contract

The deep-research workflows will hand off via `figure-brief.json` with this minimum shape:

```json
{
  "figure_id": "F1",
  "title": "string",
  "purpose": "What the figure should explain",
  "source_ids": ["S1", "S3"],
  "diagram_family": "flowchart|dag|tree|matrix|automaton|mindmap|sequence|commutative|network|custom",
  "backend_hint": "optional package or library preference",
  "content_requirements": [],
  "layout_constraints": [],
  "output_dir": "/absolute/host/path"
}
```

For research-driven briefs, `source_ids` should contain the supporting `S*` ids.

For direct-use bootstrap created by `render` or `spec` without a prewritten brief, `source_ids` may be an empty list.

This artifact is the required boundary between:

- research analysis
- TikZ generation

### Output forms

Phase 1 should produce two document-facing forms from the same spec:

- standalone compile target
- embeddable snippet

Both must preserve the `adjustbox` width-fit wrapper.

## Codex Implementation Plan

### Install layout

- `~/.codex/skills/tikz-draw/SKILL.md`
- `~/.codex/skills/tikz-draw/references/diagram-family-router.md`
- `~/.codex/skills/tikz-draw/references/prompt-contract.md`
- `~/.codex/skills/tikz-draw/references/reviewer-checks.md`
- `~/.codex/skills/tikz-draw/references/snippet-gallery.md`
- `~/.codex/runtime/workspace/skills/tikz-draw/SKILL.md`
- `~/.codex/runtime/workspace/skills/tikz-draw/run_tikz_draw.sh`
- optional runtime `scripts/` and `assets/`

### Triggering

The Codex trigger surface must be frontmatter-first.

`~/.codex/skills/tikz-draw/SKILL.md` must use a strong `description` that covers:

- draw in TikZ
- convert diagram to TikZ
- refactor coordinate-heavy TikZ
- extract standalone TikZ from Beamer/LaTeX
- create source-linked LaTeX figure from research findings

The body should stay concise and route details into `references/`.

### Runtime helper

Codex helper entrypoint:

- `bash ~/.codex/runtime/run_skill.sh skills/tikz-draw/run_tikz_draw.sh <subcommand> ...`

The helper will implement the stable API above, not `new`.

Codex render rule:

- standalone and embeddable outputs must both include the `adjustbox` width-fit wrapper

### Routing changes

Update:

- [AGENTS.md](/home/hoanganhduc/.codex/AGENTS.md)
- [research-quick-actions.md](/home/hoanganhduc/.codex/instructions/research-quick-actions.md)
- [openclaw-research SKILL.md](/home/hoanganhduc/.codex/skills/openclaw-research/SKILL.md)
- [deep-research-workflow SKILL.md](/home/hoanganhduc/.codex/skills/deep-research-workflow/SKILL.md)

Routing rule:

- `openclaw-research` routes to `tikz-draw` only for explicit TikZ or diagram-generation requests
- `deep-research-workflow` may hand off to `tikz-draw` after analysis only when the requested deliverable explicitly includes a structural figure or the analyst records a figure candidate

### Deep-research integration

Modify:

- [deep-research-analysis.md](/home/hoanganhduc/.codex/templates/deep-research-analysis.md)
- [deep-research-report.md](/home/hoanganhduc/.codex/templates/deep-research-report.md)
- [source-handoff.md](/home/hoanganhduc/.codex/skills/deep-research-workflow/references/source-handoff.md)
- `output-structure.md`

Add:

- `Figure candidates`
- `Selected figure brief`
- `Figure source ids`
- `Generated figure artifacts`

Codex artifact convention:

- figures live in `<research_root>/figures/`
- figure IDs use `F1`, `F2`, ...

## Claude Implementation Plan

### Public and private surfaces

Public Claude entrypoint:

- `/tikz`

Private implementation surface:

- `~/.claude/skills/tikz-draw/SKILL.md`

Required Claude skill frontmatter:

- `user-invocable: false`
- normal `name` and `description`
- `disable-model-invocation` decided during implementation, but documented explicitly

### Install layout

- `~/.claude/skills/tikz-draw/SKILL.md`
- `~/.claude/skills/tikz-draw/references/diagram-family-router.md`
- `~/.claude/skills/tikz-draw/references/prompt-contract.md`
- `~/.claude/skills/tikz-draw/references/reviewer-checks.md`
- `~/.claude/skills/tikz-draw/references/snippet-gallery.md`
- `~/.claude/skills/tikz-draw/run_tikz_draw.sh`
- `~/.claude/commands/tikz.md`

### Command shape

`~/.claude/commands/tikz.md` should follow the existing command style with:

- `**Runner:** bash ~/.claude/skills/_run.sh skills/tikz-draw/run_tikz_draw.sh <args>`
- flat entries for:
  - `doctor`
  - `spec`
  - `render`
  - `check`
  - `compile`
  - `review`
  - `extract`

Claude render rule:

- standalone and embeddable outputs must both include the `adjustbox` width-fit wrapper

### Claude runtime behavior

Because of current Claude settings in [settings.json](/home/hoanganhduc/.claude/settings.json):

- do not rely on inline skill-shell execution as the public path
- set env explicitly inside the runner
- prefer coarse-grained wrapper calls
- do not rely on inherited cwd state

### Routing changes

Update:

- [CLAUDE.md](/home/hoanganhduc/.claude/CLAUDE.md)
- [deep-research.md](/home/hoanganhduc/.claude/commands/deep-research.md)
- [deep-research SKILL.md](/home/hoanganhduc/.claude/skills/deep-research/SKILL.md)
- `~/.claude/skills/deep-research/templates/analysis.md`
- `~/.claude/skills/deep-research/templates/report.md`

Add `/tikz` to both:

- the slash-command table
- the automatic routing block

Use only `/tikz` in public docs, not “`/tikz` or the skill”.

### Deep-research integration

Change Claude deep-research wording to:

- `Search -> Analyze -> optional Figure -> Write`

or equivalent `Phase 2.5: Figure`.

Add:

- `Figure opportunities`
- `Selected figure brief`
- `Figure source ids`
- `Generated TikZ artifacts`

Claude artifact conventions:

- direct-use path: `~/.claude/data/runs/tikz-draw/<run_id>/`
- deep-research figure path: `~/.claude/data/runs/deep-research/<run_id>/figures/`
- the helper creates the deeper directory if missing

## Settings Strategy

### Codex

Do not change [config.toml](/home/hoanganhduc/.codex/config.toml) in phase 1.

Reason:

- current settings are global
- workflow and output-contract fixes should come first

### Claude

Do not change [settings.json](/home/hoanganhduc/.claude/settings.json) or `settings.local.json` in phase 1.

Reason:

- settings are global
- the implementation should fit the current command-first surface first

## Prevention And Review Rules

At minimum, implement:

- reject autosized boxed nodes when explicit dimensions are required
- reject nontrivial diagrams without a coordinate-map or structural placement plan
- reject bare `scale=` usage without explicit node-scaling intent
- require directed placement for ambiguous edge labels
- prefer semantic node names
- prefer reusable styles over inline repetition
- reject document-facing output that omits the required `adjustbox{max width=\\textwidth}` wrapper

Review output verdicts:

- `APPROVED`
- `NEEDS_REVISION`
- `REJECTED`

## Acceptance Criteria

1. Codex and Claude each have a self-contained implementation target for `tikz-draw`.
2. Both sides expose the same stable helper API.
3. Codex triggers reliably from skill frontmatter.
4. Claude uses `/tikz` as the public command and the underlying skill is private.
5. Both deep-research workflows can emit and consume a concrete `figure-brief.json`.
6. Both standalone and embeddable outputs wrap `tikzpicture` in `adjustbox` with `max width=\textwidth`.
7. The final research report can reference generated figure artifacts by `F*` ID and `S*` source IDs.
8. A sample figure can be generated into:
   - `.tex`
   - `.pdf`
   - `.svg` when requested
   - a review verdict

## Verification Plan

Verification must cover all four levels from the current Claude verification guidance:

- exists
- substantive
- wired
- functional

### Wiring checks

Codex:

- skill directory exists
- runtime helper exists
- runner path resolves
- AGENTS and research routing docs mention `tikz-draw`

Claude:

- command file exists
- command runner path resolves
- skill exists with correct frontmatter
- no duplicate public registration
- `CLAUDE.md` lists and routes `/tikz`

### Functional checks

For both platforms:

- `doctor` succeeds
- a known-good snippet compiles
- a malformed spec fails clearly
- an intentionally bad diagram fails `check`
- `review` emits a non-empty verdict
- rendered document-facing output contains the required `adjustbox` wrapper

### Integration checks

For both platforms:

- a research analysis artifact can record a figure candidate
- a `figure-brief.json` can be created from that analysis
- TikZ generation can consume that brief
- final report references `F*` plus `S*`

### Minimum scenarios

1. flowchart with `positioning`
2. tree with `forest`
3. commutative diagram with `tikz-cd`
4. refactor of coordinate-heavy TikZ
5. research-driven summary diagram from `figure-brief.json`
6. standalone plus embeddable output pair, both width-fitted with `adjustbox`

## Recommended Build Order

1. Create execution artifacts in `/home/hoanganhduc/tasks/tikz-draw-skill/`.
2. Add shared schema files and shared snippet/style/check assets.
3. Implement Codex `tikz-draw` skill plus runtime helper.
4. Implement Claude private skill plus `/tikz` command.
5. Add Codex deep-research handoff and template changes.
6. Add Claude deep-research handoff and template changes.
7. Run wiring checks.
8. Run wrapper-based smoke tests.
9. Run one end-to-end research-to-TikZ scenario per platform.
10. Only then consider multi-agent research integration.

## Risks

- path handling and artifact creation are the main implementation risks
- command/skill registration drift is the main Claude integration risk
- trigger discoverability is the main Codex integration risk
- compile success alone is insufficient without wiring verification

## Implementation Decision

Proceed with one narrow `tikz-draw` implementation per platform, one canonical shared source tree, one stable helper API, one explicit `figure-brief.json` handoff contract, no phase-1 global settings changes, and single-agent deep-research integration before multi-agent integration.
