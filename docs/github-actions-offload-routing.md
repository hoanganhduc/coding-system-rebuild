# GitHub Actions offload routing

How the `research_compute` broker uses GitHub Actions as a compute backend, alongside
local and Modal. Full design + rationale: [github-actions-experiment-runner-plan.md](github-actions-experiment-runner-plan.md).

> **GitHub Actions ToS compliance.** GitHub's Additional Product Terms restrict Actions on
> GitHub‑hosted runners to *"the production, testing, deployment, or publication of the
> software project associated with the repository,"* and forbid *"disproportionate"* /
> serverless burden; misuse can disable the repo or account. In this system, Actions compute
> runs **only inside a private research repo**, executes **that repo's own committed
> experiment code** (params are DATA, never executed), as that project's own validation,
> **budget‑gated** and kept **proportionate**, and is the **last** automatic backend (after
> local and Modal). It is never a general compute pool — heavy compute goes to Modal/local.
> Source: GitHub *Terms for Additional Products and Features → GitHub Actions*.

## Routing
Automatic order is **`local → Modal → GitHub Actions`** (`routing_order`): the planner takes
the first backend that is feasible and within budget. Naming a backend (`policy.backend =
local|modal|gha`) **overrides** the order; an over‑budget/infeasible named backend is
**refused**, not silently switched. Because Modal covers a superset of GHA, GHA is essentially
the explicit‑choice / Modal‑unavailable lane.

## Budget (every backend, every submit, fail‑closed)
- **GHA** — minutes. The backend queries the billing usage API and a local **reservation
  ledger** (`…/research-compute/gha-reservations.jsonl`), reserves the **worst case**
  (`ceil(timeout) × OS‑multiplier × matrix‑cells`) before dispatch, refuses if it would exceed
  remaining included minutes (or the per‑repo `monthly_minute_budget`), and reconciles to
  actual on completion. If the budget can't be verified ⇒ **refuse** (`gha_enabled` is off by
  default; `gha doctor` requires a classic PAT with billing‑read + a GitHub budget > $0).
- **Modal** — dollars (existing `per_job_cost_cap_usd`, default applies if unset).

## Registering a research repo
Each target is a **private** repo with an in‑repo `experiments/` runner + `experiment.yml`
(`workflow_dispatch`, `run-name: exp-<job_id>`, `timeout-minutes`, `result-<job_id>` artifact).
Config (`research-compute.toml`):
```toml
[gha]
enabled = true
included_minutes = 0          # 0 = auto from the account plan
[gha.repos.my_experiments]
repo = "hoanganhduc/PrivateResearchRepo"
ref = "main"
workflow = "experiment.yml"
runtime = "python"               # python | sage | cpp
experiment = "my_sweep"
runner_os = "linux"              # multiplier: linux 1x, windows 2x, macos 10x
timeout_minutes = 30
monthly_minute_budget = <minutes>
```
Submit: a manifest with `{"gha_target":"my_experiments","policy":{"backend":"gha"},"payload":{"parameters":{…}}}`.
The broker dispatches → correlates by `run-name` → `gh run download`s the result here.

## Reference (verified 2026‑06‑13)
`hoanganhduc/PrivateResearchRepo` (private) runs four experiment types on GitHub Actions —
**Python** (`my_sweep`, the TS_k theorem check), **C++** (`my_search`, 100 M trees in 50 s),
**SageMath** (`my_enum`, cross‑checks Python), and a **`runner_limits`** probe (reached
n=19 in a 120 s budget). Confirmed private‑repo runner = **2 CPU / 7.75 GB / 15 GB disk**.
