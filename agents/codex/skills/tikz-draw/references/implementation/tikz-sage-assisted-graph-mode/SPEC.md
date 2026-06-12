# Spec: Sage-Assisted On-Demand Graph Mode

## Objective

- Add a follow-on graph mode for `tikz-draw` that uses SageMath only when needed.
- Preserve the existing Phase 6 graph path as the default trusted baseline for already-supported graph requests.
- Define explicit trigger rules so `tikz-draw` can decide when to stay on the baseline graph path and when to invoke Sage-assisted handling.
- Define a stable Sage-assisted contract so Sage supplies graph semantics and layout data, while `tikz-draw` still owns render, compile, and review.

## Assumptions

1. The current Phase 6 `graph` family remains the trusted baseline and must not regress.
2. The current `tikz-draw` review contract remains in force:
   - `check`
   - `review-visual`
   - `verify-semantic`
   - `review`
3. Sage-assisted mode is graph-only; it is not a generic arbitrary-Sage execution lane.
4. The first Sage-assisted slice should still target finite graphs that can be rendered by the current graph renderer.
5. Cross-platform behavior matters: Codex and Claude should agree on trigger rules, accepted graph inputs, and reported status fields.
6. In the current live implementation, graph realization already routes through `run_sage_graph_query(...)`; the first Sage-assisted implementation slice is therefore about routing semantics, allowed input forms, and contract separation, not about removing Sage from already-supported graph requests.

## Trigger Rules

- Stay on the baseline graph path when:
  - the request matches an existing baseline shorthand or supported layout path
  - no richer graph family, transformation, or layout request is present
  - the user did not explicitly ask for Sage or SageMath
- Route to Sage-assisted mode when any of these are true:
  - the user explicitly asks for Sage or SageMath
  - the graph family is outside the baseline shorthand surface but can be represented through a constrained Sage graph constructor
  - the requested layout exceeds the local non-Sage layout surface
  - the request needs graph-theoretic construction or transformation before rendering
  - the brief or request already carries a constrained Sage graph spec
- Reject or ask first when:
  - the input requires unrestricted arbitrary Sage code
  - the request is not graph-shaped
  - the requested Sage result would fall outside the current renderer/verifier scope

Implementation note for slice 1:

- `baseline` vs `sage-assisted` is a routing distinction at the request/contract layer.
- Both paths may still end up using Sage for graph realization in the first slice.
- The point of slice 1 is to stop treating every richer graph request as an ad hoc widening of the baseline parser.

## Sage-Assisted Contract

### Input contract

- `tikz-draw` remains the public entrypoint.
- The graph brief or direct request may include:
  - `diagram_family: graph`
  - `graph_mode: auto | local | sage`
  - `graph_request`
  - `graph_constructor`
  - `graph_params`
  - `graph_layout`
  - `show_labels`
  - optional highlight or partition fields
- Allowed Sage-assisted graph inputs in the first slice:
  - constrained named constructors such as `graphs.<Constructor>(...)`
  - constrained structured constructor + params forms that normalize into a named Sage constructor
  - explicit user requests for Sage-backed graph construction
- Not allowed by default:
  - unrestricted free-form Sage programs
  - non-graph Sage domains
  - arbitrary extracted TikZ pretending to be a Sage-backed graph brief

### Output contract

- The Sage adapter must return normalized graph data, not final document-facing TeX.
- Required returned fields:
  - `backend: sage`
  - `sage_version`
  - `constructor`
  - `layout`
  - `vertices`
  - `edges`
  - `directed`
  - `multiedges`
  - `loops`
  - `positions`
  - `graph_metadata`
- Optional returned fields:
  - `invariants`
  - `partitions`
  - `highlight_vertices`
  - `highlight_edges`
- `tikz-draw` then converts that normalized graph payload into the existing graph spec and artifact flow.

### Status contract

- Expected routing/report states:
  - `BASELINE_GRAPH_PATH`
  - `SAGE_ASSISTED_GRAPH_PATH`
  - `SAGE_REQUEST_REQUIRED`
  - `SAGE_REQUEST_UNSUPPORTED`
  - `SAGE_BACKEND_UNAVAILABLE`
  - `SAGE_OUTPUT_INVALID`
- Review outcomes remain under the existing review/verifier contract; the routing status must not be confused with semantic approval.

## Commands

- Verify planning artifacts:
  - `sed -n '1,260p' /home/<user>/tasks/tikz-sage-assisted-graph-mode/SPEC.md`
  - `sed -n '1,220p' /home/<user>/tasks/tikz-sage-assisted-graph-mode/tasks/plan.md`
  - `sed -n '1,220p' /home/<user>/tasks/tikz-sage-assisted-graph-mode/tasks/todo.md`
- Future implementation verification:
  - `python3 ~/.codex/runtime/workspace/skills/tikz-draw/semantic_parity_check.py`
  - `python3 ~/.codex/runtime/workspace/skills/tikz-draw/semantic_regression_runner.py --platform both`

## Project Structure

- New planning workspace:
  - `/home/<user>/tasks/tikz-sage-assisted-graph-mode/`
- Likely implementation touchpoints:
  - `~/.codex/runtime/workspace/skills/tikz-draw/tikz_draw.py`
  - `~/.codex/runtime/workspace/skills/tikz-draw/sage_graph_backend.py`
  - `~/.codex/runtime/workspace/skills/tikz-draw/family_verifiers.py`
  - `~/.codex/skills/tikz-draw/SKILL.md`
  - `~/.claude/skills/tikz-draw/tikz_draw.py`
  - `~/.claude/skills/tikz-draw/sage_graph_backend.py`
  - `~/.claude/skills/tikz-draw/family_verifiers.py`
  - `~/.claude/skills/tikz-draw/SKILL.md`
  - `~/.claude/commands/tikz.md`
- Relevant boundaries:
  - do not replace the current graph renderer with raw Sage LaTeX by default
  - do not weaken the current semantic-verifier gate

## First Implementation Slice

- Goal:
  - introduce explicit routing semantics and reporting for baseline vs Sage-assisted graph requests without changing the current trusted render/review pipeline
- Concrete code touchpoints:
  - `~/.codex/runtime/workspace/skills/tikz-draw/tikz_draw.py`
    - add graph routing fields to brief/bootstrap handling
    - add a route-selection helper for baseline vs Sage-assisted graph requests
    - record routing status and backend-used fields in the manifest/report path
  - `~/.codex/runtime/workspace/skills/tikz-draw/sage_graph_backend.py`
    - split current query extraction into:
      - baseline graph request normalization
      - Sage-assisted request validation
      - normalized Sage output contract enforcement
    - keep constrained constructor validation explicit
  - `~/.codex/runtime/workspace/skills/tikz-draw/semantic_parity_check.py`
    - add parity checks for new routing fields and any new doc tokens
  - `~/.codex/skills/tikz-draw/SKILL.md`
    - document baseline vs Sage-assisted graph routing at a thin-doc level
  - `~/.claude/skills/tikz-draw/tikz_draw.py`
  - `~/.claude/skills/tikz-draw/sage_graph_backend.py`
  - `~/.claude/skills/tikz-draw/SKILL.md`
  - `~/.claude/commands/tikz.md`
- Deferred from slice 1:
  - new graph rendering logic
  - new family verifier logic
  - new graph extraction logic
  - replacing the current baseline graph path

## Testing Strategy

- Unit:
  - route-selection logic for `baseline` vs `sage-assisted`
  - normalization of allowed graph requests into Sage constructor payloads
  - validation of Sage adapter output fields
- Integration:
  - one request that stays on the baseline graph path
  - one request that routes to Sage because the graph family exceeds baseline shorthand support
  - one request that routes to Sage because the layout exceeds local baseline support
  - one request that correctly fails with `SAGE_REQUEST_UNSUPPORTED`
- Manual:
  - inspect one routed local graph manifest
  - inspect one routed Sage graph manifest
  - inspect one semantic review JSON from each path

## Boundaries

- Always:
  - keep `tikz-draw` as the public orchestrator
  - keep Sage as a semantic/layout backend, not the default final renderer
  - keep the Phase 6 graph path available as the default trusted baseline
  - separate routing status from semantic review verdicts
- Ask first:
  - allowing unrestricted arbitrary Sage code
  - adding non-graph Sage-assisted modes
  - broadening into arbitrary extracted graph TikZ with Sage reconstruction
- Never:
  - silently replace a working local graph path with Sage when no Sage-only benefit exists
  - bypass the existing artifact, compile, and review flow by returning raw Sage LaTeX as the final output

## Success Criteria

- [ ] A separate planning slice exists for Sage-assisted on-demand graph mode.
- [ ] The trigger rules for `baseline` vs `sage-assisted` routing are explicit.
- [ ] The allowed Sage-assisted input forms are explicit.
- [ ] The normalized Sage output contract is explicit.
- [ ] The boundaries clearly exclude unrestricted arbitrary Sage execution.
- [ ] The relationship to the existing Phase 6 baseline is explicit.
- [ ] The first implementation slice names concrete file touchpoints and stays honest that both paths may still use Sage for realization initially.

## Open Questions

- Should `graph_mode: auto | local | sage` be user-visible, or remain an internal routing detail at first?
- Should the first Sage-assisted slice normalize only named constructors, or also a constrained edge-list-to-`Graph(...)` path?
- Should a user request that explicitly says “use Sage” override a working baseline path, or only prefer Sage when it adds real capability?
