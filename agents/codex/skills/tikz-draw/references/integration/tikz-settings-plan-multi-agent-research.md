# Multi-Agent Repo-Backed Research: TikZ Settings/Skills vs Current Plan

## Scope And Limits

This is a targeted multi-agent repo-backed research pass on how others configure Codex/Claude-adjacent skills, commands, and rules to produce correct and visually strong TikZ pictures. It is not an exhaustive census of all public repositories.

Comparison target:
- [current cross-platform plan](/home/hoanganhduc/tasks/tikz-semantic-verifier-codex-integration-plan.md)

Local comparison anchors:
- [prior repo research](/home/hoanganhduc/.codex/skills/tikz-draw/references/research/tikz-codex-claude-repo-research.md)
- [round 1 findings](/home/hoanganhduc/.codex/runs/agent_group_discuss/tikz-settings-research-20260419-202302/round_01.md)
- [round 2 synthesis](/home/hoanganhduc/.codex/runs/agent_group_discuss/tikz-settings-research-20260419-202302/round_02.md)

## Evidence Inspected

### Local
- [current plan](/home/hoanganhduc/tasks/tikz-semantic-verifier-codex-integration-plan.md)
- [prior repo research](/home/hoanganhduc/.codex/skills/tikz-draw/references/research/tikz-codex-claude-repo-research.md)
- [round 1 findings](/home/hoanganhduc/.codex/runs/agent_group_discuss/tikz-settings-research-20260419-202302/round_01.md)

### Directly Re-Checked In This Run
- `pedrohcgs/claude-code-my-workflow` `new-diagram` skill:
  <https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/skills/new-diagram/SKILL.md>
- `pedrohcgs/claude-code-my-workflow` `tikz-prevention.md`:
  <https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/rules/tikz-prevention.md>
- `scunning1975/MixtapeTools` TikZ audit:
  <https://github.com/scunning1975/MixtapeTools/blob/8b29a481d15870d941b1027065ebfdf21e083522/skills/tikz/README.md>
- `sholtomaud/latex-energese` `AGENTS.md`:
  <https://github.com/sholtomaud/latex-energese/blob/1a911f73341029cde554b43d4f73a256e14469c0/AGENTS.md>

### Repo Signals Used By The Panel
- `pedrohcgs/claude-code-my-workflow` `extract-tikz`, `tikz-measurement`, and snippet gallery
- `Noi1r/beamer-skill` packaging and TikZ standards
- `onurerenarpaci/uwaterloo-beamer-claude` shared component/style pattern
- GitLab `CLAUDE.md`/`AGENTS.md` parity convention

These were surfaced in the saved repo research and independently reused by the panel, but I only directly re-fetched the highest-impact examples listed above in this run.

## High-Confidence Findings

### 1. The strongest pattern is upstream structure and prevention, not downstream rescue

Direct evidence:
- `new-diagram` explicitly says to start from snippet gallery content rather than writing TikZ from scratch, then run prevention pre-check, standalone compile, and reviewer loop.
- `MixtapeTools` explicitly says `/tikz` is a repair tool and cannot reliably rescue bad upstream generation.

Inference:
- Semantic verification should be the final gate, not the whole workflow. Upstream authoring constraints are part of what makes downstream verification reliable.

### 2. The strongest repeated hard rules are stable and specific

Direct evidence from `tikz-prevention.md`:
- explicit boxed-node dimensions
- coordinate-map comments for nontrivial diagrams
- no bare `scale=`
- directional keywords on every edge label
- use canonical snippets
- one `tikzpicture` per idea

Inference:
- These are strong candidates for first-class named rules in the current plan, not just informal author guidance.

### 3. Numeric review contracts are stronger than vague visual checks

Direct evidence:
- `MixtapeTools` documents fixed passes, minimum clearances, bend-angle formulas, gap calculations, and re-audit rules.
- `new-diagram` requires reviewer citations from `tikz-measurement.md`.

Inference:
- The current plan needs a concrete `review-visual` contract with rule IDs and numeric thresholds if it wants repo-grade review quality.

### 4. Shared assets are a repeated quality lever

Direct evidence:
- `new-diagram` relies on snippet gallery assets.
- `latex-energese` uses a JSON-first and reference-image oriented structure.
- The broader repo research repeatedly found shared styles/components rather than inline duplication.

Inference:
- Shared starter specs/snippets and shared style files should be treated as core quality infrastructure, not optional polish.

## Comparison With The Current Plan

### Already Covered Well

- The plan already separates source/static checks from rendered semantic verification.
- The additive rollout is correct: keep legacy source-only review behavior while semantic review is introduced.
- Manifest-first semantics and explicit `--work-dir` remain good design choices.
- The family-scoped rollout for `dag`, `tree`, and `flowchart` matches repo reality.
- The cross-platform Codex/Claude split with shared semantics and platform-specific entrypoints is directionally right.

### Missing And Worth Integrating Now

#### `P0`
- Expand the source preflight into a named shared rule set reused by `check`, `extract`, and semantic `review`.
- Add explicit rules for:
  - boxed-node dimensions
  - coordinate-map requirement
  - bare `scale=` ban
  - directional edge-label placement
  - extract freshness / source-of-truth checks
- Add a `review-visual` contract with:
  - named passes
  - numeric thresholds
  - formula-backed findings
  - bounded fix/recompile/re-audit loop

#### `P1`
- Add snippet/starter-spec-backed authoring for the supported families.
- Add shared style/component files instead of relying on inline reusable style fragments.
- Expand manifests and reports with:
  - `rule_hits`
  - `rule_refs`
  - `source_hash`
  - `source_mtime`
  - `extracted_from`
  - `freshness_status`

#### `P2`
- Add explicit parity verification between Codex and Claude wrappers:
  - verb lists
  - flags
  - help text
  - report schemas
  - rule IDs
  - mismatch codes

## Reject Or Defer

### Reject
- Human or subagent visual approval as the semantic oracle.
- Pixel-perfect visual regression as the primary semantic gate.
- Blanket “no scale ever”.

### Defer
- Repo-wide `CLAUDE.md`/`AGENTS.md` parity beyond the TikZ surface.
- Theme packs and Beamer-pedagogy rules.
- SVG mirroring as a core verifier requirement.
- Full command productization into separate `new-diagram` and `extract-tikz` commands if scope is tight.

## Concrete Plan Edits

1. In source preflight, replace the current short rule list with a named shared static-rule layer.

Suggested starter IDs:
- `P1_BOXED_NODE_DIMENSIONS`
- `P2_COORDINATE_MAP`
- `P3_BARE_SCALE`
- `P4_DIRECTIONAL_EDGE_LABELS`
- `P5_EXTRACT_FRESHNESS`

2. Add a shared static-check module requirement used by:
- `check`
- `extract`
- semantic `review`
- both Codex and Claude wrappers

3. Add a measured `review-visual` phase before semantic approval, with:
- pass IDs
- numeric thresholds
- formula-backed explanations
- bounded repair loop

4. Expand the artifact manifest with freshness metadata:
- `source_hash`
- `source_mtime`
- `extracted_from`
- `freshness_status`

5. Expand the report schema with machine-readable rule references:
- `rule_hits`
- `rule_refs`
- `mismatch_codes`
- visual-review findings block

6. Add shared assets to the planned file set:
- `references/tikz-prevention.md`
- `references/tikz-measurement.md`
- `templates/tikz-snippets/`
- shared `tikz_styles.tex` or family component files

7. Add parity verification tasks for Codex and Claude wrappers.

## Bottom Line

The current plan is strong on semantic-verifier architecture and rollout discipline. The missing value is upstream: repo-backed authoring constraints, measured visual review, freshness gating for extraction, and shared snippet/style assets. Those should be integrated before treating the semantic verifier as sufficient on its own.

## Source Ledger

### Local
- [current plan](/home/hoanganhduc/tasks/tikz-semantic-verifier-codex-integration-plan.md)
- [prior repo research](/home/hoanganhduc/.codex/skills/tikz-draw/references/research/tikz-codex-claude-repo-research.md)
- [round 1 findings](/home/hoanganhduc/.codex/runs/agent_group_discuss/tikz-settings-research-20260419-202302/round_01.md)
- [round 2 synthesis](/home/hoanganhduc/.codex/runs/agent_group_discuss/tikz-settings-research-20260419-202302/round_02.md)

### External
- <https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/skills/new-diagram/SKILL.md>
- <https://github.com/pedrohcgs/claude-code-my-workflow/blob/034e30d879f2124b1799d09194c7d8bc01564ee4/.claude/rules/tikz-prevention.md>
- <https://github.com/scunning1975/MixtapeTools/blob/8b29a481d15870d941b1027065ebfdf21e083522/skills/tikz/README.md>
- <https://github.com/sholtomaud/latex-energese/blob/1a911f73341029cde554b43d4f73a256e14469c0/AGENTS.md>
