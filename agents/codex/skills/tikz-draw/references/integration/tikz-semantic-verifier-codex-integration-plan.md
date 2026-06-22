# Cross-Platform Integration Plan: Semantic Verifier for `tikz-draw`

Date: 2026-04-19

## Scope

This plan covers Codex and Claude integration of a semantic verifier for generated TikZ figures into the existing `tikz-draw` workflows.

In scope:

- Codex runtime helper and skill docs under `~/.codex/`
- Claude private skill, `/tikz` command, and deep-research handoff under `~/.claude/`
- rendered-artifact semantic verification for structural TikZ families
- command/API changes needed to support strong review verdicts
- verification gates and rollout order across both platforms

Out of scope for this plan:

- global Codex config changes
- global Claude config changes
- universal support for arbitrary TikZ art

## Evidence Summary

Inspected local evidence:

- current Codex skill surface: [SKILL.md](/home/hoanganhduc/.codex/skills/tikz-draw/SKILL.md)
- current Codex runtime helper: [tikz_draw.py](/home/hoanganhduc/.codex/runtime/workspace/skills/tikz-draw/tikz_draw.py)
- current implementation baseline: [SPEC.md](/home/hoanganhduc/.codex/skills/tikz-draw/references/implementation/SPEC.md)
- current research recommendation: [tikz-semantic-verifier-deep-research.md](/home/hoanganhduc/tikz-semantic-verifier-deep-research.md)
- current graph helper: [graph_verifier.py](/home/hoanganhduc/.codex/runtime/workspace/skills/graph-verifier/graph_verifier.py)
- current Claude skill surface: [SKILL.md](/home/hoanganhduc/.claude/skills/tikz-draw/SKILL.md)
- current Claude public command: [tikz.md](/home/hoanganhduc/.claude/commands/tikz.md)
- current Claude runtime helper: [tikz_draw.py](/home/hoanganhduc/.claude/skills/tikz-draw/tikz_draw.py)
- current Claude runner: [_run.sh](/home/hoanganhduc/.claude/skills/_run.sh)
- current Claude deep-research handoff: [deep-research/SKILL.md](/home/hoanganhduc/.claude/skills/deep-research/SKILL.md)
- latest repo-backed comparison: [tikz-settings-plan-multi-agent-research.md](/home/hoanganhduc/tasks/tikz-settings-plan-multi-agent-research.md)

Confirmed baseline facts:

- `tikz-draw` currently exposes `doctor/spec/render/check/compile/review/extract`
- `check` and `review` are source-only and do not inspect rendered PDF semantics
- current supported render families are `flowchart`, `dag`, `tree`, and `commutative`
- `graph-verifier` can validate explicit graph payloads but cannot extract semantics from TikZ or PDF
- Claude’s public entrypoint is `/tikz`, backed by a private `tikz-draw` skill
- Claude deep research already has a post-Phase-2 `figure-brief.json` handoff into `/tikz`

Confirmed dependency status in the current Codex environment:

- `networkx` is installed: `2.8.8`
- `PyMuPDF` / `fitz` is not installed
- `shapely` is not installed
- `svgelements` is not installed

Confirmed dependency status in the current Claude runtime path:

- `networkx` is installed: `2.8.8`
- `PyMuPDF` / `fitz` is not installed
- `shapely` is not installed
- `svgelements` is not installed

Main design implication:

- both platforms must start with a dependency gate and family-scoped rollout
- strong semantic approval must depend on a shared semantic target plus rendered-artifact extraction
- the semantic contract should be shared, but platform entrypoints and install paths remain platform-specific

## Objective

Add a shared semantic verification layer to `tikz-draw` so that `APPROVED` can mean the same thing on Codex and Claude:

1. the source passes structural preflight checks
2. the figure compiles successfully
3. the rendered artifact preserves the intended structure for a supported family
4. the figure also passes a bounded, measured visual-review contract for supported checks

## Non-Goals

- do not replace the existing `check` preflight with PDF analysis
- do not make Codex and Claude depend on each other at runtime
- do not promise strong verification for unsupported families
- do not use raw source parsing alone as the semantic oracle

## Target Command Model

Keep the current verbs and add the new semantic-review verbs:

- `doctor`: environment and asset checks
- `spec`: create `figure-brief.json` and `diagram.json`
- `render`: create `.tex` and manifest artifacts
- `check`: static preflight on source and guardrails
- `compile`: deterministic PDF/SVG build
- `review-visual`: measured visual-review pass with bounded findings
- `verify-semantic`: rendered-artifact semantic comparison
- `review`: aggregate static and semantic checks when semantic inputs are explicitly provided
- `extract`: extract existing TikZ blocks into managed artifacts

Platform entrypoints:

- Codex:
  - underlying helper: `bash ~/.codex/runtime/run_skill.sh skills/tikz-draw/run_tikz_draw.sh <verb> ...`
  - user-facing routing remains the Codex `tikz-draw` skill trigger
- Claude:
  - underlying helper: `bash ~/.claude/skills/_run.sh skills/tikz-draw/run_tikz_draw.sh <verb> ...`
  - public interface remains `/tikz`
  - the underlying Claude `tikz-draw` skill stays private

Primary semantic-review contract:

- semantic `compile`, `verify-semantic`, and semantic `review` are manifest-first
- the canonical artifact manifest is the existing `<stem>.artifacts.json` file already emitted by `render`
- the future semantic CLI will consume that manifest through `--artifacts <path>`
- semantic operations must also use an explicit `--work-dir`
- semantic compile and review must never compile in place beside a shared or user-supplied source file by default

Rollout compatibility rule:

- during rollout, legacy `review --tex` remains source-only and backward-compatible
- semantic review is additive first:
  - `review-visual --artifacts ... --work-dir ...`
  - `verify-semantic --artifacts ... --work-dir ...`
  - `review --semantic --artifacts ... --work-dir ...`
- on Claude, `/tikz` must keep the same conservative public behavior until semantic review is explicitly requested or automatically wired after the semantic path stabilizes
- only after the semantic path is stable should either platform consider changing the default `review` behavior

Required manifest fields for semantic workflows:

- `run_id`
- `run_root`
- `work_dir`
- `figure_id`
- `diagram_family`
- `figure_brief`
- `diagram_spec`
- `standalone_tex`
- `figure_tex`
- `pdf`
- optional `svg`
- `source_hash`
- `source_mtime`
- `extracted_from`
- `freshness_status`
- `render_semantics`
- `semantic_review`
- `semantic_target_present`

Platform run-root rules:

- Codex direct-use runs: `~/.codex/runs/tikz-draw/<run_id>/`
- Codex deep-research-driven figures: the existing deep-research run root, typically `.../figures/`
- Claude direct-use runs: `~/.claude/data/runs/tikz-draw/<run_id>/`
- Claude deep-research-driven figures: `~/.claude/data/runs/deep-research/<run_id>/figures/`

Extract-path rule:

- `extract` alone does not qualify a figure for strong semantic approval
- extracted figures must first bootstrap or confirm a semantic target, then compile and verify through the same manifest-backed path

## Target Verdict Model

Do not overload semantic verdicts with blocked or unsupported states.

Recommended report fields:

```json
{
  "review_status": "COMPLETE",
  "family": "dag",
  "static_status": "PASS",
  "visual_status": "PASS",
  "compile_status": "PASS",
  "semantic_status": "PASS",
  "semantic_verdict": "APPROVED",
  "supported_family": true,
  "mismatches": [],
  "mismatch_codes": [],
  "rule_hits": [],
  "rule_refs": [],
  "warnings": [],
  "visual_review": {
    "passes_run": [],
    "findings": []
  },
  "evidence": {
    "figure_brief": "path",
    "diagram_spec": "path",
    "standalone_tex": "path",
    "pdf": "path",
    "render_semantics": "path",
    "semantic_review": "path"
  }
}
```

Status model:

- `review_status`:
  - `COMPLETE`
  - `BLOCKED_INPUT`
  - `BLOCKED_ENVIRONMENT`
  - `UNSUPPORTED_FAMILY`
  - `TOOL_ERROR`
- `static_status`:
  - `PASS`
  - `FAIL`
  - `SKIPPED`
  - `BLOCKED`
- `visual_status`:
  - `PASS`
  - `FAIL`
  - `SKIPPED`
  - `BLOCKED`
- `compile_status`:
  - `PASS`
  - `FAIL`
  - `SKIPPED`
  - `BLOCKED`
- `semantic_status`:
  - `PASS`
  - `FAIL`
  - `SKIPPED`
  - `BLOCKED`
- `semantic_verdict`:
  - `APPROVED`
  - `NEEDS_REVISION`
  - `REJECTED`
  - `null`

Fail-closed rules:

- `APPROVED` only when:
  - `review_status = COMPLETE`
  - `static_status = PASS`
  - `visual_status = PASS`
  - `compile_status = PASS`
  - `semantic_status = PASS`
- semantic mismatch yields `NEEDS_REVISION`
- visual-review mismatch yields `NEEDS_REVISION`
- static or compile failure yields `REJECTED`
- missing semantic target yields `review_status = BLOCKED_INPUT` and `semantic_verdict = null`
- missing required verifier dependencies yields `review_status = BLOCKED_ENVIRONMENT` and `semantic_verdict = null`
- unsupported family yields `review_status = UNSUPPORTED_FAMILY` and `semantic_verdict = null`

Exit-code policy:

- `0`: `APPROVED`
- `1`: complete review with `NEEDS_REVISION` or `REJECTED`
- `3`: blocked input, including missing semantic target
- `4`: unsupported family
- `5`: blocked environment, including missing semantic-verifier dependencies
- `6`: tool or internal verifier error
- preserve subprocess nonzero codes only for hard command-execution failures outside the structured review contract

## Recommended Architecture

### 1. Keep source preflight separate

Do not overload `check` with PDF logic. Keep `check` as the fast deterministic source gate:

- required `adjustbox` environment wrapper:
  - `\begin{adjustbox}{max width=\textwidth}`
  - `...`
  - `\end{adjustbox}`
- no `standalone[tikz]`
- no bare `scale=`
- known unsafe patterns such as named-node `-- cycle`
- explicit boxed-node dimensions for boxed, text-bearing nodes
- coordinate-map comments for nontrivial diagrams
- directional keywords on edge labels
- extract freshness and source-of-truth checks for extracted figures

Shared static-rule layer:

- define named shared rules and reuse them across `check`, `extract`, and semantic `review`
- initial rule IDs should include:
  - `P1_BOXED_NODE_DIMENSIONS`
  - `P2_COORDINATE_MAP`
  - `P3_BARE_SCALE`
  - `P4_DIRECTIONAL_EDGE_LABELS`
  - `P5_EXTRACT_FRESHNESS`
- keep one checker implementation per platform wrapper boundary, but keep rule semantics, rule IDs, and report fields shared across Codex and Claude

### 2. Add measured visual review before semantic approval

Add a bounded `review-visual` stage or equivalent report block in semantic review:

- named passes with stable IDs
- numeric thresholds where practical
- formula-backed findings for geometry-sensitive failures
- bounded fix and re-audit loop
- machine-readable report output through `rule_hits`, `rule_refs`, and visual-review findings

Initial scope for measured visual review:

- label-gap width checks
- shape-boundary clearance
- slide or page-edge margins
- plotted-point or curve-placement checks where the family declares them

This is still proposed behavior, not a statement about the current live helper.

### 3. Add rendered-artifact extraction

Primary extractor:

- `PyMuPDF Page.get_drawings()`
- `PyMuPDF Page.get_text("words")`

Secondary or future extractor:

- SVG normalization via `Page.get_svg_image(text_as_path=False)` or `dvisvgm`
- SVG parsing via `ElementTree` and `svgelements`
- SVG support remains optional until the PDF-first path is stable

Required install contract:

- Codex supported install target:
  - `~/.codex/runtime/workspace/.local/lib/python<major.minor>/site-packages`
- Claude supported install target:
  - `~/.claude/.local`
- required pinned dependencies for the semantic path on both platforms:
  - `PyMuPDF` / `fitz`
  - `shapely`
- optional dependency:
  - `svgelements`
- `doctor` must import-check these modules under the wrapped platform runtime and report:
  - required vs optional
  - detected version
  - import path

### 3. Reconstruct semantics by family

Each supported family should have its own reconstruction step.

Phase-1 strong-support families for both platforms:

- `dag`
- `tree`
- `flowchart`

Phase-2 support:

- `commutative`

Later or optional:

- `graph`
- `automaton`

Reason for this order:

- Codex already renders `dag`, `tree`, and `flowchart`
- these families reduce naturally to node-edge structures plus typed nodes
- `commutative` needs direction and label extraction that is slightly more specialized

### 4. Compare against declared semantics

Strong approval should compare the reconstructed render semantics against:

- `diagram.json` first
- `figure-brief.json` second, mainly for provenance and coarse expectations

For graph-like families, use `networkx` with explicit `node_match` and `edge_match`.

For geometry-sensitive checks, use `shapely` for:

- snapping text boxes to nearby shapes
- intersection and containment logic
- arrow endpoint association
- overlap and collision checks when they matter semantically

Matching policy:

- graph-property-only checks are never sufficient for approval
- matching must compare explicit node identity, labels, edge endpoints, direction, and family-specific constraints
- for verifier-covered families, the plan must either:
  - require unique visible labels, or
  - add verifier-visible identity anchors so rendered nodes can be matched back to spec nodes without ambiguity

Required intermediate contracts:

- `RenderIR`:
  - page size
  - coordinate system
  - text boxes
  - path primitives
  - closed shapes
  - arrowhead candidates
  - bounding boxes
  - extractor version
  - manifest reference
- `SemanticReviewReport`:
  - status fields
  - verdict
  - mismatch codes
  - warnings
  - evidence paths
  - tolerance summary

## Phased Rollout

### Phase 0: Environment bootstrap and dependency gate

Goal:

- make both runtime environments explicit before semantic logic is added

Tasks:

- add a pinned dependency file for the semantic-verifier stack
- choose and document the supported install target for each platform
- extend `doctor` to import-check:
  - `fitz`
  - `shapely`
  - optional `svgelements`
- make `doctor` emit:
  - required vs optional classification
  - versions
  - import paths
  - TeX toolchain versions
- document Codex wrapper vs Claude wrapper import behavior:
  - Codex via `~/.codex/runtime/run_skill.sh`
  - Claude via `~/.claude/skills/_run.sh`

Verification gate:

- rollout does not proceed until `doctor` passes for required semantic-verifier dependencies on both platforms

### Phase 1: Contract lock and additive CLI skeleton

Goal:

- lock the artifact, work-dir, status/verdict, and CLI contracts before family logic is added on either platform

Tasks:

- make the semantic path manifest-first via `--artifacts`
- add explicit `--work-dir`
- define the `RenderIR` and semantic-review report schemas
- define the shared static-rule layer and initial rule IDs
- define the measured `review-visual` report contract
- add `verify-semantic` to the Codex helper and the Claude helper
- add a shared family router shape with explicit handlers on both platforms
- return blocked/unsupported states through the status model
- keep legacy `review --tex` source-only during rollout
- add semantic review only through explicit semantic mode or semantic inputs
- on Claude, define how `/tikz review` maps to the new additive semantic mode without breaking existing `/tikz review --tex` behavior
- keep root user-facing docs thin and push prevention / measurement detail into referenced docs so Codex and Claude can stay aligned without duplicating large rule blocks

Verification gate:

- `review` is no longer the only review entrypoint
- semantic review can be invoked explicitly without breaking the legacy static path
- exit codes and report fields are documented and testable on both platforms
- rule IDs, report-field names, and measured-review pass IDs are locked before family logic lands

### Phase 2: PDF extraction layer

Goal:

- convert compiled PDF output into a family-agnostic render-semantic intermediate representation shared across both platforms

Tasks:

- add a PDF loader using PyMuPDF
- extract vector path primitives and text boxes
- normalize coordinates and store them in `render-semantics.json`
- record extractor version and manifest reference
- keep extractor output family-agnostic
- add extractor-only tests on frozen PDFs

Verification gate:

- extractor output must be deterministic on repeated runs over the same PDF
- extractor correctness must be independently testable, not only through end-to-end family review
- tolerance-based normalization must be defined before fixture approval
- Codex and Claude must emit the same `RenderIR` schema for the same fixture set

### Phase 3: Strong semantics for `dag`, `tree`, and `flowchart`

Goal:

- make `APPROVED` meaningful for the currently most valuable Codex families

Tasks:

- reconstruct nodes by joining text boxes and nearby enclosing shapes
- infer directed edges from linework and arrowheads
- compare node identities, edge endpoints, directions, and typed-node constraints against `diagram.json`
- for `tree`, validate rooted hierarchy and parent-child structure
- for `flowchart`, validate node-type expectations such as `decision` vs `box` where the spec declares them
- define duplicate-label handling for verifier-covered families
- add metamorphic tests that preserve semantics under benign layout variation
- add canonical starter specs or snippets for `dag`, `tree`, and `flowchart`
- use those starter assets to seed fixture corpora and mutation suites
- add shared family style or component assets instead of relying on inline reusable style fragments where stable reuse is possible

Verification gate:

- replace one-good / one-bad fixtures with mutation suites per family:
  - missing node
  - extra node
  - missing edge
  - extra edge
  - reversed edge
  - wrong node label
  - wrong edge label
  - wrong node type where applicable
  - duplicate visible labels
  - layout-only variations that should still pass
- the original `-- cycle` closure failure mode should fail semantic verification if it changes adjacency
- Codex and Claude must agree on verdict and mismatch codes for the shared family fixtures

### Phase 4: Manifest-backed semantic review orchestration

Goal:

- wire staged compile and semantic review into one safe path on both platforms

Tasks:

- make semantic `compile` operate from `--work-dir`, not in place
- make `verify-semantic` consume `--artifacts` plus `--work-dir`
- make semantic `review` aggregate static, compile, and semantic results when semantic inputs are provided
- keep legacy `review --tex` unchanged by default
- fix the extract path:
  - `extract` emits or updates an artifact manifest
  - `extract` records `source_hash`, `source_mtime`, `extracted_from`, and `freshness_status`
  - extracted figures remain blocked from strong approval until a semantic target is bootstrapped or confirmed
- Codex integration:
  - wire the updated helper and skill docs
- Claude integration:
  - wire the updated helper
  - update `/tikz` routing and examples
  - preserve the private-skill / public-command split
  - keep `/tikz` aligned with Claude deep-research `figure-brief.json` handoff

Verification gate:

- semantic review through the staged manifest-backed path must work for render-generated figures
- extracted figures must fail closed with blocked-input status until a semantic target is added
- extracted figures must also fail closed when freshness is unknown or stale for workflows that require source-of-truth confirmation
- Claude `/tikz` and Claude deep-research figure handoff must preserve the same `F*` and `S*` artifacts through semantic review

### Phase 5: `commutative`, docs, and default-switch decision

Goal:

- support the remaining currently rendered family and finalize user-facing behavior

Tasks:

- add the `commutative` family verifier
- add commuting-square mutation fixtures:
  - swapped arrow labels
  - reversed arrows
  - wrong object placement
- update [SKILL.md](/home/hoanganhduc/.codex/skills/tikz-draw/SKILL.md) to document `verify-semantic`
- keep root docs thin and reference dedicated prevention, measurement, snippet, and semantic-review docs
- add strong-approval semantics to Codex-facing usage examples
- update any Codex deep-research or TikZ references that currently imply semantic review is already the default
- update [SKILL.md](/home/hoanganhduc/.claude/skills/tikz-draw/SKILL.md), [tikz.md](/home/hoanganhduc/.claude/commands/tikz.md), and Claude deep-research references to document the semantic path
- keep `/tikz` as the public Claude entrypoint and the skill private
- make an explicit decision on whether `review` should remain opt-in for semantic mode or switch defaults later

Verification gate:

- docs and runtime help must agree on command names, arguments, and verdict semantics on both platforms
- Codex and Claude wrappers must agree on verbs, flags, rule IDs, mismatch codes, and report-schema field names

## File Touchpoints

Primary implementation files:

- [tikz_draw.py](/home/hoanganhduc/.codex/runtime/workspace/skills/tikz-draw/tikz_draw.py)
- [run_tikz_draw.sh](/home/hoanganhduc/.codex/runtime/workspace/skills/tikz-draw/run_tikz_draw.sh)
- [SKILL.md](/home/hoanganhduc/.codex/skills/tikz-draw/SKILL.md)
- [tikz_draw.py](/home/hoanganhduc/.claude/skills/tikz-draw/tikz_draw.py)
- [run_tikz_draw.sh](/home/hoanganhduc/.claude/skills/tikz-draw/run_tikz_draw.sh)
- [SKILL.md](/home/hoanganhduc/.claude/skills/tikz-draw/SKILL.md)
- [tikz.md](/home/hoanganhduc/.claude/commands/tikz.md)
- [deep-research/SKILL.md](/home/hoanganhduc/.claude/skills/deep-research/SKILL.md)
- [deep-research.md](/home/hoanganhduc/.claude/commands/deep-research.md)

Likely new files under the same runtime skill directory:

- `semantic_verify.py`
- `pdf_extract.py`
- `family_verifiers.py`
- `geometry_utils.py`
- `requirements-semantic-verifier.txt`

Likely new or updated assets:

- `assets/checks/review-rules.md`
- `assets/checks/tikz-prevention.md`
- `assets/checks/tikz-measurement.md`
- `assets/spec-schema/diagram.schema.json`
- `assets/spec-schema/render-semantics.schema.json`
- `assets/spec-schema/semantic-review.schema.json`
- `assets/templates/tikz-snippets/`
- shared style or component files such as `assets/styles/tikz_styles.tex`
- example fixtures under `assets/examples/` or a dedicated verifier-fixtures directory

Recommended design rule:

- keep semantic-verifier logic inside `tikz-draw`
- keep the semantic contract shared across platforms, but keep platform wrappers and docs platform-specific
- do not shell out to `graph-verifier` for core review decisions

Reason:

- `graph-verifier` is a helpful reference but it is not render-aware and its CLI returns coarse graph properties only

## Verification Plan

### Static checks

- `bash -n ~/.codex/runtime/workspace/skills/tikz-draw/run_tikz_draw.sh`
- `bash -n ~/.claude/skills/tikz-draw/run_tikz_draw.sh`
- syntax validation of new Python modules
- parity check that Codex and Claude wrappers expose the same verb lists, required args, rule IDs, and report-field names for shared semantic features

### Environment checks

- `doctor` must report:
  - required semantic-verifier dependency availability
  - import paths and versions
  - TeX toolchain versions
- the pinned semantic-verifier install target must match what each wrapped runtime imports
- Codex and Claude `doctor` outputs must agree on required dependency readiness before shared-family rollout proceeds

### Functional checks

- shared static-rule tests:
  - boxed-node dimension violations
  - missing coordinate-map comment
  - bare `scale=`
  - missing directional edge labels
  - stale or unknown extract freshness
- measured visual-review tests:
  - label-gap failures
  - boundary-clearance failures
  - margin failures
  - benign layout-only cases that should still pass
- extractor-only tests:
  - same PDF run twice
  - same semantics under translation or spacing variation
  - benign decorative group boxes ignored when not semantically relevant
- `dag` mutation suite
- `tree` mutation suite
- `flowchart` mutation suite
- later `commutative` mutation suite

### Integration checks

- `render -> check -> compile --artifacts -> review-visual -> verify-semantic -> review --semantic`
- `review --semantic` with missing PDF but valid semantic artifacts compiles in a staged work dir, not in place
- `extract -> freshness check -> bootstrap or confirm semantic spec -> compile -> review-visual -> verify-semantic`
- direct-mode bootstrap run root under `~/.codex/runs/tikz-draw/<run_id>/`
- direct-use Claude run root under `~/.claude/data/runs/tikz-draw/<run_id>/`
- Claude deep-research handoff:
  - `figure-brief.json` after Phase 2
  - `/tikz` render
  - semantic review through the same manifest-backed path

### Regression checks

- current static preflight rules must keep working
- existing direct render flows for supported families must still succeed even when semantic verification is unavailable
- legacy `review --tex` remains source-only during rollout
- supported-family semantic review must never silently approve when semantic dependencies are missing
- supported-family semantic review must never silently approve when required static-rule metadata or extract freshness state is missing
- graph-property-only assertions are debug-only and never pass criteria
- Claude `/tikz` public behavior remains stable while the semantic path is additive
- Claude deep-research figure handoff remains post-analysis only and keeps `F*` / `S*` linkage

## Risks and Failure Modes

### Risk: dependency mismatch

Current environment evidence shows `fitz`, `shapely`, and `svgelements` are missing on both platforms. This is the first implementation blocker.

Mitigation:

- pin the supported install target under each platform runtime:
  - Codex runtime workspace
  - Claude `~/.claude/.local`
- make `doctor` fail clearly when required semantic-verifier dependencies are missing
- keep SVG-related packages optional until the PDF-first path is stable

### Risk: overclaiming support

If `review` returns `APPROVED` for families without a real family verifier, the integration fails its main purpose.

Mitigation:

- use fail-closed blocked/unsupported states rather than approval-style verdicts
- reserve `APPROVED` for complete supported-family semantic review only

### Risk: PDF extraction ambiguity

Rendered TikZ can produce vector paths that are not trivially attributable to nodes or arrows.

Mitigation:

- begin with the current structured families only
- require `diagram.json` as the primary semantic target
- keep the extraction model explicit and inspectable in JSON
- define tolerance policy and duplicate-label handling before family approval is enabled

### Risk: weak fixture coverage

A verifier can pass one good and one bad fixture while still approving many wrong diagrams.

Mitigation:

- require mutation suites per family
- add extractor-only tests
- use metamorphic tests for geometry-invariant semantics
- prohibit graph-property-only pass criteria

### Risk: API churn

Changing `review` behavior can break existing expectations.

Mitigation:

- keep `check` unchanged
- add `verify-semantic` first
- keep legacy `review --tex` source-only during rollout
- make any later default switch an explicit post-stability decision
- on Claude, preserve `/tikz` as the public command and the private skill boundary while the underlying helper changes

### Risk: platform drift

Codex and Claude can diverge if one platform lands contract or fixture changes first.

Mitigation:

- keep the semantic contract shared:
  - manifest fields
  - render-IR schema
  - review-report schema
  - verdict and mismatch codes
- require shared fixtures for supported families
- update platform docs and wrappers in the same rollout phase

## Recommended Order of Execution

1. Land the dependency bootstrap:
   - pinned install path
   - pinned dependency file
   - `doctor` import/version checks on Codex and Claude
2. Lock the contracts:
   - `--artifacts`
   - `--work-dir`
   - shared static-rule IDs
   - measured visual-review report block
   - render-IR schema
   - semantic-review schema
   - status/verdict model
   - exit-code table
3. Add the shared static checker and additive `review-visual` / `verify-semantic` CLI skeletons on both helpers without changing default review behavior.
4. Land starter snippets or starter specs plus shared style assets for the first supported families.
5. Land PDF extraction to `render-semantics.json` plus extractor-only tests, and keep the schema shared.
6. Implement strong verification for `dag`, `tree`, and `flowchart` with mutation suites, freshness-aware extract handling, and shared mismatch codes.
7. Wire staged semantic review and fix the extract bootstrap path on both platforms, including Claude `/tikz` and deep-research handoff.
8. Add `commutative`, then update Codex and Claude docs and decide whether either platform should ever change the default `review` behavior.

## Immediate Next Step

The next concrete action should be a small spec-and-tasks slice for the revised Phase 0 and Phase 1 on both platforms:

- pinned dependency/install contract
- artifact and work-dir contract
- shared static-rule and `review-visual` contract
- status/verdict and exit-code contract
- additive `review-visual` and `verify-semantic` CLI skeleton
- review compatibility policy
- Claude `/tikz` and deep-research integration touchpoints

That keeps the first implementation pass small enough to verify before starter-asset rollout, PDF extraction, family-specific logic, and any default review-behavior decision land on either platform.
