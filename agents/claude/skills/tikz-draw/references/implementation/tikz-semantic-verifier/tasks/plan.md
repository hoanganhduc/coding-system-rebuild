# Plan

## Phases

1. Lock the Phase 6 graph-family contract.
   - Replace the completed commutative slice with a Sage-backed generic graph-family scope.
2. Add the Sage graph backend.
   - Parse graph requests, call the Sage runner, and convert the result into a graph spec.
3. Add graph rendering and semantic verification.
   - Render graph nodes and edges from Sage coordinates and verify rendered graphs as finite undirected graphs.
4. Promote the regression suite.
   - Add Petersen and Johnson fixtures plus adjacency mutations.
5. Update parity and docs.
   - Reflect `graph` support in the thin docs and parity checks.
6. Verify end to end.
   - Run syntax checks, parity, targeted graph fixtures, and the full suite.

## Follow-on Direction

1. Keep the current Phase 6 graph slice as the default trusted path.
2. Do not scale graph support by manually adding more hard-coded constructor cases to `tikz-draw`.
3. Add a Sage-assisted on-demand graph mode instead.
   - Detect when the graph request exceeds the local shorthand or layout surface.
   - Call Sage for graph construction, layout, and graph metadata only when needed.
   - Keep final rendering, artifacts, compile flow, and review inside `tikz-draw`.
4. Keep the Sage-assisted mode constrained.
   - graph-only
   - no unrestricted arbitrary Sage execution
   - no replacement of the existing verified renderer/reviewer contract by raw Sage LaTeX output

## Dependencies

- The current regression runner remains the main verification harness.
- The graph family depends on the local Sage runner being reachable from both Codex and Claude surfaces.
- The current PDF extractor and shape recovery remain the substrate for graph semantic review.

## Risks

- Risk: the Sage runner becomes a hidden runtime dependency that the helper surface does not expose.
  - Mitigation: add explicit doctor/reporting and clear error messages for graph-family requests.
- Risk: graph semantic matching overfits one layout and breaks on legitimate coordinate variation.
  - Mitigation: normalize expected and actual coordinates before matching and keep the first slice tied to the current graph renderer.
- Risk: the first graph parser is too narrow for user requests.
  - Mitigation: support explicit `sage:` constructors plus Petersen and Johnson shorthands first.
- Risk: future graph growth drifts into ad hoc constructor-by-constructor expansion.
  - Mitigation: make the next growth path an explicit Sage-assisted on-demand mode rather than continuing to widen local hard-coded parsing case by case.
- Risk: the graph suite collides with the existing family logic or drifts between Codex and Claude.
  - Mitigation: mirror the backend, suite, and docs in the same slice and keep parity checking hashes.

## Verification checkpoints

- After phase 1:
  - task artifacts describe the graph-family integration consistently
- After phase 2:
  - Sage-backed graph specs can be generated locally
- After phase 3:
  - one graph good case semantically approves
- After phase 4:
  - Petersen and Johnson fixtures exist with mutations
- After phase 5:
  - parity and docs reflect graph support
- After phase 6:
  - targeted graph passes and the full suite passes on both platforms
