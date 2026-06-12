# TikZ Draw Review Rules

These are the review-stage expectations after `render`, `check`, and usually `compile`.

## Verdicts

- `APPROVED`
- `NEEDS_REVISION`
- `REJECTED`

## Review dimensions

1. Structural correctness
   - backend matches diagram family
   - node and edge relationships match the spec or `figure-brief`
2. Width-fit contract
   - diagram is wrapped in `adjustbox{max width=\textwidth}`
   - standalone output loads `adjustbox`
3. Layout hygiene
   - labels are placed explicitly where needed
   - spacing is readable after width-fit scaling
   - no obvious overlap or clipping
4. Maintainability
   - named styles instead of repeated inline fragments
   - semantic node names where possible
   - grouping and alignment use structural libraries
5. Traceability
   - figure outputs preserve `figure_id`
   - research-driven diagrams preserve `source_ids`

## Review notes format

Each review should be concise and concrete:

- verdict
- failed rules
- file path
- one-line corrective action per failed rule

## Width-fit caveat

`adjustbox` scales text as well as geometry. This is expected behavior in phase 1 and should not be flagged as a defect unless the brief explicitly asks to keep text size fixed.
