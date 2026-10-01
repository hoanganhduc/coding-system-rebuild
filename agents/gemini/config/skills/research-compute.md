---
name: "research-compute"
description: "Route heavy-compute planning and execution handoff across the unified five-lane broker."
---

<!-- Managed by ai-agents-skills. Generated target: antigravity. Source: entrypoint-alias:research-compute.md. -->

# Research Compute Entrypoint

Route heavy-compute planning through the unified `research_compute` broker exposed
by `modal-research-compute`. Its recommended order is
`local > Kaggle > Modal > Hetzner > GitHub Actions`; a valid custom order may
reorder or omit remote lanes but keeps local first, and explicit backend overrides
are honored. Run local resource checks and a small
sample before offload when practical. Each remote lane must pass its own
readiness and safety gate before dispatch.

Use `run plan` as the decision boundary. Execute a selected Kaggle or Hetzner
lane through its corresponding lane skill; `run submit` dispatches only
Modal/GitHub Actions. Execute an accepted local plan under the broker's reported
worker limits.

Backing skill: `kaggle-research-compute`, `modal-research-compute`, `hetzner-research-compute`
