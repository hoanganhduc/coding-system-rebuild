# Multi-Agent Review: Codex Semantic Verifier Plan

Date: 2026-04-19

Target plan:
[tikz-semantic-verifier-codex-integration-plan.md](/home/<user>/tasks/tikz-semantic-verifier-codex-integration-plan.md)

## Highest-Priority Changes

1. Add a pinned dependency and install contract.
   - specify where `fitz`/PyMuPDF and `shapely` are installed from and loaded from
   - make `doctor` import-check semantic-verifier modules and emit versions/import paths

2. Make the semantic flow manifest-first with explicit staged work dirs.
   - `manifest.json` becomes the primary artifact contract
   - semantic `compile`, `verify-semantic`, and `review` operate from `--work-dir`, not source-directory mutation
   - extracted figures need a semantic-target bootstrap before strong approval

3. Split operational status from semantic verdict.
   - blocked/unsupported/unverified states must not be expressed as approval-style verdicts
   - add an exit-code table for automation

4. Keep semantic review additive first.
   - add `verify-semantic`
   - keep legacy `review --tex` source-only unless semantic inputs are provided
   - revisit the default only after the semantic path is stable

5. Define render-IR and review-report contracts before family logic.
   - add explicit `render-semantics.json` and review report schemas
   - test extractor correctness independently

6. Replace weak fixture gates with mutation suites.
   - include missing/extra edges, reversed arrows, label drift, duplicate labels, node-type mutation, and tolerance-preserving layout variants
   - ban graph-property-only pass criteria

## Keep Unchanged

- `check` stays source-only
- `diagram.json` stays the primary semantic target
- rollout still starts with `dag`, `tree`, and `flowchart`
- semantic verification stays inside `tikz-draw`
- PDF-first extraction remains primary

## Recommended Revised Rollout

1. dependency bootstrap and `doctor` import checks
2. manifest/work-dir/status-verdict/exit-code contract lock
3. additive `verify-semantic` CLI
4. extractor implementation plus extractor-only tests
5. `dag`, `tree`, `flowchart` verifiers with mutation fixtures
6. staged semantic review wiring and extract bootstrap fix
7. `commutative`, docs, and only then consider changing default `review`

## Open Questions

- Should semantic review remain opt-in permanently, or become the default later?
- Are there existing callers that depend on the current `review` exit-code behavior?
