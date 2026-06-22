# Spec: Phase 6 Sage-Backed Graph Family

## Objective

- Add one generic `graph` family to `tikz-draw` instead of adding graph classes one by one.
- Use SageMath as the graph constructor and layout backend for the first graph-family slice.
- Support at least:
  - Petersen graph
  - Johnson graph $$J(5,3)$$
- Add graph rendering plus semantic verification for rendered finite graphs without requiring per-family TikZ logic.

## Follow-on Direction

- Keep the completed Phase 6 slice as the baseline trusted graph path.
- Do **not** treat future graph growth as manual expansion of built-in constructor lists inside `tikz-draw`.
- Prefer a Sage-assisted on-demand graph mode for richer graph requests:
  - `tikz-draw` continues to own brief -> spec -> render -> check -> compile -> review
  - Sage is invoked when the request needs broader graph construction, layout selection, or graph-theoretic support than the local shorthand path provides
  - rendered output should still flow through the existing artifact, visual-review, and semantic-review contracts
- Keep this as a controlled graph-only backend mode, not unrestricted arbitrary Sage execution.

## Assumptions

1. The current supported semantic families `flowchart`, `dag`, `tree`, and supported-square `commutative` remain unchanged and must not regress.
2. The local Sage runner is available through the Codex runtime skill wrapper and returns JSON strings in its `output` field.
3. The first `graph` family may stay narrow in two ways:
   - graph construction is Sage-backed but request parsing only needs a few shorthands plus an explicit `sage:` constructor path
   - semantic verification may remain renderer-specific to the current graph renderer
4. The first graph renderer can rely on absolute node coordinates from Sage layout output.
5. The first graph semantic verifier may match nodes by rendered geometry against expected coordinates, then compare an undirected edge set.

## Commands

- Test:
  - `python3 ~/.codex/runtime/workspace/skills/tikz-draw/semantic_regression_runner.py --platform codex --fixture petersen_graph`
  - `python3 ~/.codex/runtime/workspace/skills/tikz-draw/semantic_regression_runner.py --platform codex --fixture johnson_5_3`
  - `python3 ~/.codex/runtime/workspace/skills/tikz-draw/semantic_regression_runner.py --platform both`
- Lint:
  - `bash -n ~/.codex/runtime/workspace/skills/tikz-draw/run_tikz_draw.sh`
  - `bash -n ~/.claude/skills/tikz-draw/run_tikz_draw.sh`
  - `python3 -c "import ast, pathlib; ast.parse(pathlib.Path('<file>').read_text())"`
- Run:
  - `python3 ~/.codex/runtime/workspace/skills/tikz-draw/semantic_parity_check.py`

## Project Structure

- Files or directories expected to change:
  - `/home/hoanganhduc/tasks/tikz-semantic-verifier/`
  - `~/.codex/runtime/workspace/skills/tikz-draw/`
  - `~/.codex/skills/tikz-draw/`
  - `~/.claude/skills/tikz-draw/`
  - `~/.claude/commands/tikz.md`
- New graph-generation logic should live as a helper module under the `tikz-draw` skill, not as ad hoc shell snippets embedded throughout the renderer.

## Testing Strategy

- Unit:
  - graph-request parsing into a Sage constructor
  - Sage result parsing into a graph spec
  - coordinate normalization for rendering
  - graph-node matching from rendered circle geometry
  - undirected edge-set comparison for graph semantics
- Integration:
  - Petersen graph renders, compiles, and semantically approves
  - Johnson graph $$J(5,3)$$ renders, compiles, and semantically approves
- Mutation suite:
  - Petersen missing edge
  - Petersen extra edge
  - Johnson missing edge
  - Johnson extra edge or wrong adjacency
- Manual:
  - inspect one Sage-backed graph spec
  - inspect one graph `render-semantics.json`
  - inspect one graph semantic-review JSON

## Boundaries

- Always:
  - keep the graph-family integration generic at the TikZ-family level
  - keep Sage as the graph constructor/layout backend, not as a replacement for `tikz-draw`
  - prefer a Sage-assisted on-demand backend mode over manually broadening hard-coded constructor support in `tikz-draw`
  - keep mutation cases fixed-target: rendered graph changes, semantic target does not
- Ask first:
  - using unrestricted arbitrary Sage code outside a constrained graph-constructor path
  - supporting arbitrary extracted graph TikZ in this slice
  - broadening to non-graph Sage domains
- Never:
  - add `Petersen` or `Johnson` as separate `diagram_family` values
  - silently depend on graph labels being visible in the rendered PDF unless the renderer explicitly enables them

## Success Criteria

- [x] `graph` is added as a supported `diagram_family`.
- [x] The graph family uses SageMath to generate graph vertices, edges, and layout coordinates.
- [x] Petersen and Johnson $$J(5,3)$$ pass semantic review on Codex and Claude.
- [x] The graph regression suite reproduces missing-edge and extra-edge failures.
- [x] The full regression suite still passes on both platforms.

## Open Questions

- Should the first graph-family parser support only explicit `sage:` constructors plus a few shorthands, or also a richer natural-language parser?
- Should the first graph renderer show vertex labels by default for small graphs, or hide them and rely on geometry-only verification?
- For the next graph slice, should `tikz-draw` expose an explicit Sage-assisted mode that activates only when local shorthand/layout support is insufficient?
