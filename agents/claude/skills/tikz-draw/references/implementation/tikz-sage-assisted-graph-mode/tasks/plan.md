# Plan

## Phases

1. Lock the routing objective.
   - Define Sage-assisted mode as a follow-on to the completed Phase 6 graph slice, not a replacement for it.
2. Lock trigger rules.
   - Specify when graph requests stay on the baseline graph path, when they route to Sage-assisted handling, and when they should be rejected or escalated.
3. Lock the Sage-assisted contract.
   - Define allowed inputs, normalized outputs, and routing/report status fields.
4. Lock implementation touchpoints.
   - Identify the adapter, router, docs, and parity surfaces that would need to change in a future implementation slice.
5. Lock verification expectations.
   - Define the minimum routing and review cases that must pass before implementation can be called safe.

## First code-touch slice

1. Add routing metadata in `tikz_draw.py`.
   - Introduce explicit graph routing fields in the brief/spec/bootstrap flow.
   - Add manifest/report fields for routing status and backend used.
2. Refactor `sage_graph_backend.py` into clearer layers.
   - Baseline graph request normalization.
   - Sage-assisted request validation.
   - normalized Sage output validation.
3. Mirror the same behavior on Claude.
   - Keep Codex and Claude helpers aligned at the parser, manifest, and doc surface.
4. Update parity and thin docs.
   - Extend parity checks and user-facing docs so the new routing contract cannot drift silently.
5. Verify the slice.
   - Run syntax checks and parity, then confirm the new planning-defined route fields and statuses appear where expected.

## Dependencies

- The current Phase 6 graph slice remains the baseline graph path.
- The current semantic-verifier and regression infrastructure remain the verification substrate.
- The Sage research report is the evidence base for why an on-demand backend mode is preferable to constructor-by-constructor expansion.
- The current live code already realizes graphs through Sage; slice 1 therefore separates routing semantics first rather than trying to remove Sage from supported graph requests immediately.

## Risks

- Risk: the new mode is underspecified and quietly turns into unrestricted arbitrary Sage execution.
  - Mitigation: define allowed inputs narrowly and state forbidden forms explicitly.
- Risk: routing rules become ambiguous and differ between Codex and Claude.
  - Mitigation: define routing statuses and trigger conditions centrally in the planning slice before implementation.
- Risk: the Sage-assisted path is treated as a raw renderer replacement.
  - Mitigation: keep the contract explicit that Sage returns normalized graph semantics, not final TeX.
- Risk: the phrase “use Sage when needed” is implemented dishonestly even though the current baseline already uses Sage for graph realization.
  - Mitigation: make slice 1 explicitly about routing semantics and reporting, not about pretending the baseline path is non-Sage today.
- Risk: a future implementation bypasses the trusted Phase 6 local path too aggressively.
  - Mitigation: specify that the baseline path remains the default unless Sage is explicitly required or beneficial.

## Verification checkpoints

- After phase 1:
  - the new planning slice explicitly positions Sage-assisted mode as a follow-on, not a replacement
- After phase 2:
  - baseline vs Sage-assisted routing rules are stated concretely
- After phase 3:
  - the allowed input forms, normalized output fields, and routing statuses are explicit
- After phase 4:
  - likely implementation touchpoints are listed for both Codex and Claude
- After phase 5:
  - verification expectations cover both routing correctness and review compatibility
- After the first code-touch slice:
  - `tikz_draw.py`, `sage_graph_backend.py`, parity, and thin docs have explicit routing/report surface updates mapped out
