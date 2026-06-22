# Deep Research: Repository-Backed Claude/Codex Settings and Skills for Better, More Structural TikZ

Date: 2026-04-19
Extends:
- [tikz-codex-claude-deep-research.md](/home/hoanganhduc/tikz-codex-claude-deep-research.md)
- [tikz-codex-claude-internet-extended-research.md](/home/hoanganhduc/tikz-codex-claude-internet-extended-research.md)

## Scope

This pass focuses on public GitHub and GitLab repository artifacts rather than vendor docs or papers.

Inspected evidence includes:

- repository `AGENTS.md`
- repository `CLAUDE.md`
- repository `SKILL.md`
- repository reference docs and snippet galleries tied to those configs
- a GitLab monorepo issue documenting merged repository conventions

Search goal:

- find shared Claude/Codex settings or skill patterns directly relevant to drawing TikZ pictures better
- identify which patterns are concrete enough to integrate into a local Claude/Codex workflow

Excluded on purpose:

- generic agent-config repos with no concrete TikZ or LaTeX diagram workflow
- forum advice
- unsupported claims not grounded in inspected repository files

## Coverage and limits

This is a targeted repository scan, not an exhaustive census of all GitHub/GitLab repositories.

Important limits:

- Most strong hits were Claude-first repository workflows. Among the inspected repositories, only a smaller subset explicitly packaged both Claude and Codex variants.
- Public GitLab repository browsing was materially noisier than GitHub code search, so the GitLab evidence here is stronger on cross-tool repository conventions than on TikZ-specific workflows.
- Some repository READMEs contain self-reported benchmark claims. Those are included only as repository-authored claims, not independent validation.

## Executive Summary

Yes: there are repository-backed Claude/Codex settings and skills worth integrating for TikZ work.

The strongest reusable pattern across inspected repos is:

1. start from a constrained snippet or intermediate structure
2. enforce prevention rules before compile
3. compile standalone
4. run a measurement-based TikZ review pass
5. export SVG or slide assets only after validation

The clearest repository-backed integration candidates are:

- a dual-file cross-tool instruction layout: `CLAUDE.md` plus `AGENTS.md`, kept aligned, with deeper refs loaded on demand
- a `new-diagram` skill for snippet-first diagram creation
- an `extract-tikz` skill for rebuilding standalone SVG assets from Beamer source
- a `tikz-reviewer` or `/tikz` audit pass with explicit geometry checks
- a snippet gallery with coordinate-map comments, explicit node dimensions, and banned unsafe scaling patterns

The most important repository-level shift is this:

- good TikZ workflows are not just “prompt better”
- they are repository workflows with pre-checks, compile loops, reusable styles, and reviewer passes

## Highest-Value Repository Findings

### 1. The best cross-tool packaging pattern is dual `CLAUDE.md` + `AGENTS.md` with progressive references

**Observation.** GitLab’s monorepo agent-instructions work item documents a repository convention where `CLAUDE.md` and `AGENTS.md` at the same directory level are identical, exist at multiple directory depths, can reference additional markdown in a same-level `.ai/` directory, and are enforced by a `doctor` lint/fix script. [G1]

**Observation.** `Noi1r/beamer-skill` explicitly ships both a Claude Code `SKILL.md` and a Codex CLI `AGENTS.md`, with detailed rules moved into a `references/` directory. Its README describes this as the platform split: full `SKILL.md` for Claude, lighter `AGENTS.md` + references for Codex. [R1][R2]

**Inference.** The strongest shared Claude/Codex repository pattern is not one giant prompt file. It is:

- a thin root instruction file per platform
- referenced subdocs for specialized workflows
- repo-local parity/sync rules

**Recommendation.** If you want one workflow that works well across Claude and Codex, adopt:

- `CLAUDE.md`
- `AGENTS.md`
- `references/tikz-*.md` or `.ai/tikz-*.md`

Keep the root files short and route specialized TikZ rules into referenced docs.

### 2. The strongest direct TikZ skill stack is snippet-first creation plus prevention and review loops

**Observation.** `pedrohcgs/claude-code-my-workflow` includes a `new-diagram` skill that scaffolds new TikZ diagrams from a snippet gallery instead of starting from scratch, then runs a prevention pre-check, standalone compile, and reviewer loop. [R3]

**Observation.** The same repo’s `extract-tikz` skill rebuilds TikZ from Beamer source into standalone PDF and SVG assets, but first checks freshness against the Beamer source and runs a prevention pre-check before compiling. [R4]

**Observation.** The snippet gallery states every snippet compiles standalone and satisfies explicit prevention rules: explicit node dimensions, coordinate-map comments, no bare `scale=`, and directional edge-label keywords. [R5]

**Inference.** The most mature TikZ workflow found in repositories is not “generate TikZ directly from prose.” It is:

- choose a diagram family snippet
- adapt it
- run static prevention checks
- compile
- run visual/measured review

**Recommendation.** Integrate a local skill with exactly these entry points:

- `new-diagram`
- `extract-tikz`
- `tikz-review`

This is a stronger integration target than a single all-purpose “tikz helper” prompt.

### 3. Repository authors repeatedly ban the same TikZ failure modes

**Observation.** `tikz-prevention.md` in `pedrohcgs/claude-code-my-workflow` bans:

- autosized boxed nodes without explicit dimensions
- diagrams with 3+ nodes lacking a coordinate-map comment
- bare `scale=X` without node scaling
- edge labels without directional placement keywords

It also prefers canonical snippets and one `tikzpicture` per idea. [R6]

**Observation.** `MixtapeTools` frames the same issue as “prevention vs repair”: a repair pass cannot reliably save diagrams built with autosized nodes, missing directional keywords, or unsafe scaling. Its `/tikz` audit is explicitly a residual repair tool, not the primary defense. [R7]

**Observation.** `Noi1r/beamer-skill` also encodes recurring TikZ rules: no label overlaps, computed rather than hardcoded plotted points, spacing rules for short-arrow labels, and review loops for complex diagrams. [R8][R2]

**Inference.** Across independent repositories, the recurring shared settings are:

- explicit node geometry
- explicit label placement
- no naive scaling
- compile and review after every change

These are the closest thing to shared “TikZ settings” across Claude/Codex ecosystems.

**Recommendation.** Treat the following as hard local defaults:

- `explicit_box_dimensions = true`
- `require_coordinate_map_comment = true` for nontrivial diagrams
- `ban_bare_scale = true`
- `require_edge_label_direction = true`
- `compile_after_edit = true`

### 4. Measurement-based TikZ review is the clearest repository-level quality gate

**Observation.** `MixtapeTools` documents a six-pass TikZ collision audit:

- cross-slide consistency
- Bezier-depth checks
- label-gap calculations
- arrow-label positioning checks
- boundary checks against shapes
- margin checks

with explicit formulas and minimum clearances. [R7]

**Observation.** `pedrohcgs/claude-code-my-workflow` includes a `tikz-measurement.md` file with the same style of geometry-based passes, including Bezier depth calculations, safe distances, label-width estimation, and boundary rules. [R9]

**Observation.** `Noi1r/beamer-skill` includes review-loop and checklist rules for complex TikZ diagrams, including computed intersections and plotted-point accuracy via `\pgfmathsetmacro`. [R8]

**Inference.** The most valuable missing layer in many Codex/Claude TikZ setups is not generation guidance but a post-generation reviewer that can say:

- where the overlap is
- which formula it violated
- what to move

**Recommendation.** Integrate a dedicated `tikz-reviewer` pass with:

- static checks for banned patterns
- formula-backed geometry checks
- a short verdict scale: `APPROVED`, `NEEDS REVISION`, `REJECTED`

### 5. Reusable style/component files outperform inline TikZ styling

**Observation.** `onurerenarpaci/uwaterloo-beamer-claude` centralizes reusable TikZ and LaTeX definitions in `components/`, explicitly says not to redefine styles inline inside slide files, and keeps graph styles in a dedicated `graph-styles.tex`. [R10]

**Observation.** The same `CLAUDE.md` prescribes a reusable component workflow:

- add component files in `components/`
- load them in the preamble
- keep slides content-only

and compile/export slide images for inspection using `build.sh`. [R10]

**Observation.** `Noi1r/beamer-skill` also uses a reusable semantic-color and preamble pattern for Beamer/TikZ work in Codex-facing `AGENTS.md`. [R2]

**Inference.** A strong Claude/Codex TikZ workflow should push style/state out of the generated diagram and into shared style files or preambles.

**Recommendation.** Integrate:

- one shared `tikz_styles.tex`
- one shared palette file
- one or more family-specific snippet files

and instruct the agent to reuse these rather than redefine styles inline.

### 6. Structural intermediate representations exist in repository practice, not just in papers

**Observation.** `sholtomaud/latex-energese` uses `AGENTS.md` to drive a JSON-first diagramming workflow for a LaTeX package: parse JSON, validate schema, compute layout, render PGF shapes, run visual regression tests against reference images, and document a workflow for turning images into structured JSON examples. [R11]

**Inference.** The earlier recommendation to use an intermediate diagram spec before emitting TikZ is reinforced by repository practice, not only by papers or vendor docs.

**Recommendation.** For your own integration, prefer an intermediate object such as:

```json
{
  "diagram_family": "dag | flowchart | timeline | plot | tree | custom",
  "nodes": [],
  "edges": [],
  "layout": {},
  "styles": {},
  "validation": {}
}
```

Then render TikZ from that object instead of generating raw coordinate-heavy TikZ immediately.

### 7. Transferable non-TikZ drawing rules still point in the same direction: names, anchors, layering, shared themes

**Observation.** `GiggleLiu/ProblemReductionPaper` is Typst/CeTZ rather than TikZ, but its `.claude/rules/typst-drawing.md` requires naming referenced objects, connecting by named anchors rather than raw coordinates, using layers explicitly, and storing layout as data structures. [R12]

**Inference.** Even outside TikZ, repository-authored drawing guidance converges on the same structural principle:

- reference named objects
- attach through anchors
- keep layering explicit
- centralize theme/style decisions

**Recommendation.** Add a Claude/Codex guardrail for TikZ:

- prefer named nodes plus anchors over ad hoc coordinates for connections
- prefer `fit`, `matrix`, `positioning`, `chains`, or family-native packages where possible

### 8. TikZ asset workflows often need output-format-aware handling

**Observation.** In `alvaretto/proyecto-r-exams-icfes-matematicas-optimizado`, a documented TikZ failure came from generating PNGs in temporary paths for later LaTeX compilation. The fix was conditional rendering: direct TikZ emission for LaTeX/PDF output and `include_tikz()` only for HTML paths, plus a repair skill to automate recurrence handling. [R13]

**Inference.** If your Claude/Codex workflow targets multiple outputs, TikZ rendering should be format-aware.

**Recommendation.** If you need PDF plus HTML/Quarto:

- keep TikZ source canonical
- render directly to PDF where possible
- export SVG/PNG only as derived artifacts

### 9. Theme packs are possible, but they are lower priority than structure and validation

**Observation.** `yzlnew/infra-skills` ships an Anthropic-themed TikZ flowchart template with explicit color tokens, node styles, connector styles, orthogonal routing rules, and group containers. [R14]

**Observation.** `onurerenarpaci/uwaterloo-beamer-claude` similarly centralizes a branded visual language via preamble/theme/component files. [R10]

**Inference.** Theme packs are a valid integration layer, but they matter less than prevention, snippets, and review.

**Recommendation.** Add theme support only after structural and validation layers exist. A good order is:

1. snippet gallery
2. prevention checks
3. compile/review loop
4. SVG export
5. optional themes

## Best Integration Candidates

### A. `tikz-structural-diagrams` skill

Best-supported design:

- input: diagram request
- output step 1: structural spec
- output step 2: snippet or package choice
- output step 3: generated TikZ
- output step 4: compile/review status

Repository basis:

- `latex-energese` JSON-first workflow [R11]
- `pedrohcgs` snippet-first creation flow [R3][R5]

### B. `tikz-reviewer` skill

Best-supported features:

- static prevention checks
- geometry-based overlap checks
- cited formulas in findings
- verdict: `APPROVED` / `NEEDS REVISION` / `REJECTED`

Repository basis:

- `MixtapeTools` `/tikz` audit [R7]
- `pedrohcgs` `tikz-measurement.md` + reviewer loop [R9][R3][R4]

### C. Snippet gallery

Best-supported inventory to start with:

- DAG
- mediation DAG
- flowchart
- timeline
- regression scatter
- event study
- supply-demand

Repository basis:

- `pedrohcgs` snippet gallery [R5]
- `Noi1r` common patterns in `tikz-standards.md` [R8]

### D. Shared style/preamble files

Best-supported contents:

- semantic colors
- node/edge styles
- arrow styles
- compact label helpers
- optional theme tokens

Repository basis:

- `uwaterloo-beamer-claude` component model [R10]
- `Noi1r` Codex-facing Beamer/TikZ preamble [R2]
- `infra-skills` Anthropic theme tokens [R14]

### E. Dual-platform repository instructions

Best-supported packaging:

- `CLAUDE.md`
- `AGENTS.md`
- referenced markdown docs for TikZ specifics
- optional lint/sync enforcement

Repository basis:

- GitLab monorepo conventions [G1]
- `Noi1r/beamer-skill` platform split [R1][R2]

## Lower-Priority or Conditional Integrations

### AI raster diagram generation

`K-Dense-AI/claude-scientific-writer` includes a `scientific-schematics` skill, but it is image-generation-first rather than TikZ-first. It may be useful for non-TikZ illustrations, but it is not the best direct integration for structural TikZ authoring. [R15]

### Theme-only packs

Theme repositories are useful after the structural workflow exists. On their own, they do not solve the main TikZ failure modes.

### Generic diagram registries

Generic diagram-skill indexes are less useful unless they ship concrete TikZ workflows, snippet libraries, or validation logic.

## Recommended Local Build Order

If the goal is to improve Claude/Codex TikZ output in a practical repository setup, the best repository-backed order is:

1. Create a shared `CLAUDE.md` + `AGENTS.md` pair for TikZ tasks.
2. Add `references/tikz-prevention.md` with hard banned patterns.
3. Add `references/tikz-measurement.md` with formula-backed checks.
4. Add a `templates/tikz-snippets/` gallery for common diagram families.
5. Add a `new-diagram` skill that starts from snippets, not blank TikZ.
6. Add an `extract-tikz` or `compile-to-svg` skill for derived assets.
7. Add a `tikz-reviewer` pass after compile.
8. Only then add theme packs or branded visual tokens.

## Bottom Line

The strongest repository-backed answer is:

- yes, there are shared Claude/Codex settings worth integrating
- the best ones are workflow settings, not model knobs

The most defensible integration set from inspected repositories is:

- dual `CLAUDE.md` + `AGENTS.md`
- snippet-first authoring
- prevention linting
- standalone compile
- geometry-based TikZ review
- reusable style files
- optional SVG export

The clearest directly reusable repositories were:

- `pedrohcgs/claude-code-my-workflow`
- `scunning1975/MixtapeTools`
- `Noi1r/beamer-skill`
- `sholtomaud/latex-energese`
- `onurerenarpaci/uwaterloo-beamer-claude`

## Sources

### Repository Sources

- [R1] `Noi1r/beamer-skill` README: cross-tool packaging, Codex/Claude split, installation, benchmark claims.  
  https://github.com/Noi1r/beamer-skill/blob/b73d48a07c064ce2c9c80d6bf8b01b70ec6f7651/README.md

- [R2] `Noi1r/beamer-skill` Codex-facing `AGENTS.md`: Beamer/TikZ workflow, reference preamble, hard rules, verification.  
  https://github.com/Noi1r/beamer-skill/blob/b73d48a07c064ce2c9c80d6bf8b01b70ec6f7651/beamer/AGENTS.md

- [R3] `pedrohcgs/claude-code-my-workflow` `new-diagram` skill.  
  https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/skills/new-diagram/SKILL.md

- [R4] `pedrohcgs/claude-code-my-workflow` `extract-tikz` skill.  
  https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/skills/extract-tikz/SKILL.md

- [R5] `pedrohcgs/claude-code-my-workflow` TikZ snippet gallery.  
  https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/templates/tikz-snippets/README.md

- [R6] `pedrohcgs/claude-code-my-workflow` TikZ prevention rules.  
  https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/rules/tikz-prevention.md

- [R7] `scunning1975/MixtapeTools` TikZ collision audit README.  
  https://github.com/scunning1975/MixtapeTools/blob/8b29a481d15870d941b1027065ebfdf21e083522/skills/tikz/README.md

- [R8] `Noi1r/beamer-skill` TikZ standards reference.  
  https://github.com/Noi1r/beamer-skill/blob/b73d48a07c064ce2c9c80d6bf8b01b70ec6f7651/beamer/references/tikz-standards.md

- [R9] `pedrohcgs/claude-code-my-workflow` TikZ measurement rules.  
  https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/rules/tikz-measurement.md

- [R10] `onurerenarpaci/uwaterloo-beamer-claude` `CLAUDE.md`: reusable components, no inline styles, build/export workflow.  
  https://github.com/onurerenarpaci/uwaterloo-beamer-claude/blob/b18276d4b76f150fca872f0f673beb369141ad6d/CLAUDE.md

- [R11] `sholtomaud/latex-energese` `AGENTS.md`: JSON-first structured diagram workflow, tests, visual regression.  
  https://github.com/sholtomaud/latex-energese/blob/1a911f73341029cde554b43d4f73a256e14469c0/AGENTS.md

- [R12] `GiggleLiu/ProblemReductionPaper` Typst drawing rules.  
  https://github.com/GiggleLiu/ProblemReductionPaper/blob/2591076dba3c92841ca378ce5d0f348febb3c34b/.claude/rules/typst-drawing.md

- [R13] `alvaretto/proyecto-r-exams-icfes-matematicas-optimizado` documented TikZ automation fix for format-aware rendering.  
  https://github.com/alvaretto/proyecto-r-exams-icfes-matematicas-optimizado/blob/e35ca644e7f819541466ea73bdd130252e429d24/.claude/docs/casos-resueltos/2025-12-19-cilindro-tikz.md

- [R14] `yzlnew/infra-skills` Anthropic-themed TikZ flowchart template.  
  https://github.com/yzlnew/infra-skills/blob/f8bf7bec0a5943f4561fdb9c6e8c77e160e88f49/tikz-flowchart/themes/anthropic.md

- [R15] `K-Dense-AI/claude-scientific-writer` scientific-schematics skill.  
  https://github.com/K-Dense-AI/claude-scientific-writer/blob/2f80d2aed0e6b555944ec528674148fb0d7c39fc/.claude/skills/scientific-schematics/SKILL.md

### GitLab Repository Artifact

- [G1] GitLab monorepo work item documenting merged conventions for repo-level `CLAUDE.md` + `AGENTS.md`, `.ai` references, local overrides, and `doctor` linting.  
  https://gitlab.com/gitlab-org/gitlab/-/work_items/594821
