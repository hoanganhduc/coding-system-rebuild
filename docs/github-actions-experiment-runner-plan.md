# Implementation plan (v2.2) — per‑research‑repo, in‑repo GitHub Actions experiment runner

Status: PLAN v2.2 (routing order corrected 2026‑06‑13). Owner: hoanganhduc.

GitHub Actions is added as a **niche, ToS‑compliant** compute lane for the `research_compute`
broker — alongside (not replacing) Modal and local. The "free public‑repo compute pool" idea is
**rejected** as a ToS violation.

## Implementation outcome (2026-06-13)

Built and verified live. Key deviations from this plan, found during implementation:
- **Single source of truth**: ai-agents-skills is cloned to `~/ai-agents-skills` (the `external/`
  vendoring is dropped for it); the installer creates the skill `SKILL.md` symlinks pointing
  back at it, so the install source and the symlinks always agree.
- **Run model**: the broker installs to each target's **runtime root** and runs via
  `run_skill.sh`; the documented `~/.claude/skills/_run.sh skills/modal-research-compute/…` call
  is forwarded there by a **broker-scoped `_run.sh` shim**. Migrating the *other* skills to this
  model is deferred (it would relocate their config/secrets).
- **`bootstrap`**: a broker subcommand generates `research-compute.toml`, authenticates `gh`,
  checks deps, and runs `doctor` — one command to set up a host.
- **Phase 8 applies**: the restore installs the broker with
  `install --apply --real-system --backup-replace` from `~/ai-agents-skills` (a plain
  `make install` is only a dry-run); the per-install config rides the secrets zip and the legacy
  in-`~/.claude` snapshot is delegated/removed.
- **Verified live**: an end-to-end `submit --wait` of a parameter sweep on a private research
  repo dispatched a GitHub Actions run, budget-gated and reconciled, and fetched the result
  back. Runbook: the installed `github-actions-offload-routing` skill instruction (delivered by ai-agents-skills).

**Changelog**
- **v2** (adversarial review): replaced the English‑only budget guard with a concrete
  **two‑layer budget guarantee** (§3), a **limits table** (§2), worst‑case reservation,
  fail‑closed accounting, recovery/reconciliation.
- **v2.2** (routing): the **automatic** order of consideration is **local → Modal → GitHub
  Actions** — prefer local, escalate to Modal only when needed, GHA last. **Naming a tool in the
  request overrides the order** and forces that backend. Whichever backend is chosen (auto or
  override) **still passes its budget gate** (§3.0). *(Supersedes the v2.1 "opt‑in" draft, which
  misread the requirement — remote is not opt‑in; it is auto‑ordered with an explicit override.)*

---

## 0. Goal & non‑goals
**Goal.** A *private* research repo runs *its own* committed experiment code on GitHub Actions
as that project's validation, dispatched/collected by the broker, results pulled back here.
**Non‑goals.** No generic "run arbitrary payload" dispatcher; no public‑repo compute; no
serverless/compute‑pool use; **no run that fails its backend budget gate**; GHA is never
preferred over local or Modal automatically (it is last in the order, §3.0).

---

## 1. Hard constraints (every Actions compute MUST satisfy all)
Per GitHub [Terms for Additional Products and Features → Actions](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features)
(no disproportionate/serverless burden; on hosted runners, nothing "unrelated to the…software
project associated with the repository"; misuse can disable repos/accounts):

1. **Private repo only** — broker verifies `gh repo view <repo> --json visibility` == `PRIVATE`, else refuse.
2. **In‑repo committed code only** — params via `workflow_dispatch` inputs, treated as **data** (schema‑parsed, never executed). A lint (§5.1) forbids `eval`/`python -c`/`bash -c`/`curl|sh`/interpolating `inputs.*` into an exec position.
3. **The compute *is* the repo's validation** — never bolted onto an unrelated repo.
4. **Mandatory per‑job `timeout-minutes`** committed in the workflow (`< 360`; never absent — the default would be the 6 h kill). Budget reserves against this, not an estimate.
5. **Budget‑gated, checked every time** — no dispatch without passing the §3 budget gate; **fail‑closed** if the gate can't verify.
6. **Proportionate** — within included minutes by default; per‑job + per‑repo + global caps (§3.7).
7. **Self‑hosted exception** — the "unrelated" clause is *hosted‑only*; a private repo MAY use a self‑hosted arm64 runner, but **dispatch‑only** and with a workflow guard so a fork PR can never reach `runs-on: self-hosted` (§5.4).
8. **Auto‑order + explicit override.** Automatically, backends are considered in the fixed order **local → Modal → GitHub Actions**; the planner picks the most‑preferred one that is *feasible* and *within budget* (§3.0). Naming a tool ("use GitHub Actions" / "use Modal" / "run locally", or manifest `policy.backend`) **overrides the order** — still subject to that backend's budget gate.

---

## 2. GitHub Actions limits & how each is handled (authoritative)
Verified against GitHub's [Actions limits](https://docs.github.com/en/actions/reference/limits),
[minute multipliers](https://docs.github.com/en/billing/reference/actions-minute-multipliers),
and 2025–2026 billing changelogs.

| Limit | Value (June 2026) | Handling |
|---|---|---|
| Job runtime | **6 h** hosted (GitHub kills it) | mandatory `timeout-minutes < 360`; reserve against it; checkpoint partial results; >6 h ⇒ Modal |
| Workflow run | **35 days** total (incl. waits) | long work ⇒ Modal; split‑resume = NEW dispatches |
| Reruns | **50** per workflow (Apr 2026) | resume = new dispatch, never rerun |
| Matrix | **256** jobs / run | broker expands matrix locally, **rejects > 256**, chunks bigger sweeps |
| Concurrency | Free 20 / Pro 40 / Team 60 / Ent 500 | planner estimates wall‑clock = `ceil(cells/concurrency) × runtime`; budget reserves for **all** cells |
| API rate | **1000 req/hr/repo** (`GITHUB_TOKEN`, shared) | poll ≥ 20 s + backoff on 403/429; cache billing calls |
| Artifact storage | Free **500 MB** / Pro 1 GB / Team 2 GB | short `retention-days`; delete after `gh run download`; size in preflight; upload‑fail = first‑class error |
| Minute multiplier | Linux **1×**, Windows **2×**, macOS **10×** | cost = `ceil(min) × multiplier`; `runner_os` in registry; reject unknown multiplier |
| Round‑up | every job → whole minute | `ceil()` in every estimate |
| Included minutes (private) | Free 2 000 / Pro 3 000 / Team 3 000 / Ent 50 000 /mo | the primary budget the broker tracks (§3) |
| Spending limit / budget | **$0 blocks** private‑repo Actions (even free tier needs limit > $0) | owner sets a GitHub **Budget** as the hard backstop (§3.1); $0 ⇒ ceiling = remaining included minutes |

---

## 3. Routing order, override & budget (local + Modal + GitHub Actions)

### 3.0 The routing decision
**(a) Automatic order = `local → Modal → GitHub Actions`.** With no explicit instruction, the
planner selects the **most‑preferred backend that can *feasibly* run the job AND passes that
backend's budget gate (c)**: prefer **local**; escalate to **Modal** only when local can't
(size / time / GPU / disk); use **GitHub Actions** only when neither local nor Modal is suitable.
Because Modal covers a superset of GHA's capabilities, GHA is **rarely chosen automatically** —
in practice it is the last resort / the explicit‑choice lane. The order is config
(`routing_order`, default `[local, modal, gha]`).

**(b) Explicit override.** If the request names a backend (or manifest `policy.backend: <B>`),
use **B**, overriding the order — **still subject to B's budget gate (c)**. If B is over budget
or infeasible, **refuse** (in override mode the planner does **not** silently switch backends).

**(c) Budget gate — every backend, checked every time, fail‑closed.**
- **local**: the existing local resource check (RAM/disk/time) — no money.
- **GHA**: a **minutes** budget (included pool) via the reservation ledger (§3.1–3.5).
- **Modal**: a **dollars** budget — per‑job **and** cumulative monthly cap, in a parallel
  reservation ledger; worst‑case = `estimated_cost × safety_factor` (or manifest
  `constraints.max_cost_usd`). **If no Modal budget is set, the default `per_job_cost_cap_usd`
  applies** (never unbounded).
In **automatic** mode a backend that is over budget or infeasible is **skipped to the next in
the order**; in **override** mode it is **refused**. If a backend's budget can't be verified ⇒
treat as over budget (skip/refuse). Explicit per‑request values may only **lower** a cap.

The rest of §3 details the **GHA** minute machinery (the hard case — a lagged external billing
API); Modal reuses the same reservation/worst‑case/fail‑closed pattern with a local cost ledger.

### 3.1 Layer A — GitHub‑native budget (hard, GitHub‑enforced backstop)
Owner sets a GitHub **Budget** on Actions with **"stop usage when budget limit is reached"**.
GitHub itself then **blocks** Actions when exhausted, so the account *cannot* exceed it regardless
of broker bugs. (A literal `$0` budget blocks *all* Actions incl. free tier; set it **> $0** with
stop‑usage to use the included minutes while still blocking overage.)
[Setting up budgets](https://docs.github.com/en/billing/how-tos/set-up-budgets) · [Actions billing](https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions).

### 3.2 Layer B — broker reservation ledger (live, proactive gate)
**Billing source (verified):** the legacy `/settings/billing/actions` endpoint is **deprecated**
(confirmed live: HTTP 410 "moved"); use the enhanced‑billing **usage API**
(`GET …/settings/billing/usage`, `X-GitHub-Api-Version: 2026-03-10`) — **daily totals only**,
**lags by design**, user endpoint **public‑preview**, needs a **classic PAT with the `user`/
billing scope**. ⇒ **API is a slow reconciliation backstop, not the live gate.**
[usage API GA](https://github.blog/changelog/2026-06-04-api-access-to-billing-usage-reports-now-generally-available/) · [billing usage](https://docs.github.com/en/rest/billing/usage).

**Live gate = local reservation ledger** `…/research-compute/gha-reservations.jsonl` (file+lock).
On **every `submit`** (atomic): `billed_used` ← usage API (cached; **fail‑closed** on error/no‑scope);
`reserved` ← Σ non‑reconciled entries; `available = included − billed_used − reserved` (and the
Layer‑A $ ceiling); `worst_case = Σ_cells ceil(min(timeout,360)) × OS_multiplier` (matrix
expanded locally; reject > 256); refuse if over, else **reserve then dispatch**; on terminal
conclusion **reconcile** to actual billed minutes (`gh run view --json`), refund the rest.

### 3.3 Worst‑case, not estimate
Reserving `timeout × cells × multiplier` means even a hung job that runs to its cap was already
debited — silent over‑spend is impossible. Estimates affect *routing/feasibility* only.

### 3.4 Probe is local, not GHA
Calibration sizing (§6) runs on **local** compute — never burns billed Actions minutes.

### 3.5 Caps, circuit breaker, kill switches
`config`: per‑job cap, per‑repo monthly cap, **global daily‑minute circuit breaker**, per‑repo
`enabled`, global `gha_enabled` (default off — GHA isn't even in the order until enabled).
`gha doctor` validates: classic PAT with billing‑read (`user`), usage API reachable, Layer‑A
budget > $0 with stop‑usage, repos private+registered — else `gha_enabled=false`.

---

## 4. The canonical ToS notice + where it MUST appear
Drop‑in block (single source — copy verbatim):
> **GitHub Actions ToS compliance.** GitHub's Additional Product Terms restrict Actions on
> GitHub‑hosted runners to *"the production, testing, deployment, or publication of the software
> project associated with the repository,"* and forbid *"disproportionate"* / serverless burden;
> misuse can disable the repo or account. Here, Actions compute runs **only inside a private
> research repo**, runs **that repo's own committed experiment code** (never an injected payload),
> as that project's own validation, **budget‑gated** and kept **proportionate**, and is the
> **last** automatic backend (after local and Modal). It is never a general compute pool.

**Scope — only where Actions is used/documented *as a computation backend*.** Ordinary CI (the
rebuild's `rehearsal.yml`, the blog's Jekyll build/deploy, the Codespaces `install-degraded`
build) is normal project CI and does **not** carry the notice.

| Repo | File (NEW unless noted) |
|---|---|
| coding-system-rebuild | this plan (`github-actions-experiment-runner-plan.md`) |
| ai-agents-skills | `canonical/instructions/github-actions-offload-routing.md`; `canonical/skills/github-actions-compute/SKILL.md`; `…/research_compute/github_actions_backend.py` (docstring); `…/research_compute/planner.py` (`gha` branch comment) |
| research-repo-template | `README.md`, `.github/workflows/experiment.yml` header |
| hoanganhduc.github.io (blog) | NEW post on the experiment‑runner pattern |

**NOT here:** `rehearsal.yml`, `docs/CI.md`, `.devcontainer/bootstrap.sh`, `docs/CODESPACES.md`,
README blog link. `bin/tos-notice-check.sh` scans only for compute‑backend markers and fails if
such a mention lacks the notice.

---

## 5. Architecture

### 5.1 Per‑research‑repo layout (the in‑repo runner)
```
R/ src/…  experiments/<name>.json  .github/workflows/experiment.yml  README.md(+notice)
```
`experiment.yml`: `on: workflow_dispatch` (inputs `{experiment, params_json, job_id}`) + optional
`matrix`; **`run-name: exp-${{ inputs.job_id }}`**; a hard **`timeout-minutes`**; runs
`python -m R.run --experiment <name> --params <json>` (**in‑repo code; params parsed as data**);
uploads `result-<job_id>.json` **and** `status-<job_id>.json` with **`if: always()`**; short
`retention-days`. A **workflow lint** fails on `eval`/`-c`/`curl|sh`/`inputs.*`‑in‑exec.

### 5.2 Reusable runner (`workflow_call`)
Standardises checkout, runtime, `timeout-minutes`, artifact naming, the `run-name` key, a
matrix‑size guard (reject > 256). Pinned from the template; per‑repo exec‑line edits forbidden.

### 5.3 Broker integration (in `…/research_compute/`)
- `planner.py` implements §3.0: walk `routing_order` (or the override), pick the first backend
  that is feasible + budget‑OK; in override mode refuse instead of switching.
- `github_actions_backend.py` (`submit/wait/fetch`): `submit` enforces §1 + the §3 budget gate
  then `gh workflow run`; **correlate** by `run-name == exp-<job_id>` (poll ≥ 20 s, backoff;
  un‑correlated‑recent ⇒ *possibly‑running*, keep the reservation); `fetch` `gh run download`
  (missing ⇒ partial via `status-<job_id>.json`), then **reconcile** + delete the artifact.
- `modal_backend.py`: add the parallel **$ budget ledger** + per‑job/monthly cap so Modal is
  gated identically (default `per_job_cost_cap_usd` if unset).
- `config`: `routing_order`, `modal_budget:{per_job_usd,monthly_usd}`, `gha_repos` registry +
  §3.5 caps/breaker + `gha_enabled` (off).

### 5.4 Self‑hosted (optional, arm64)
Free minutes ⇒ §3 minute budget N/A; instead a **broker‑side wall‑clock ceiling** + a workflow
guard (`if: workflow_dispatch && repo‑owner`) so a fork PR can never reach `runs-on: self-hosted`.

---

## 6. Routing & resource sizing
**Automatic order `local → Modal → GitHub Actions` (§3.0a); explicit tool mention overrides
(§3.0b); every chosen backend passes its budget gate (§3.0c).** Among the order, the planner
takes the first feasible+in‑budget backend, so it stays as low as possible (free local) and
escalates only when forced; GHA, being last and capability‑subset of Modal, is essentially the
explicit‑choice lane. Failover follows the order (e.g. GHA throttled/over‑6 h → next is *not* a
lower tier, so it errors unless Modal is also a candidate); never silently downgrade an override.

**Sizing — estimate → probe(local) → cap → escalate → learn:** param estimate → rough tier;
**local** probe measures per‑unit and extrapolates; hard ceilings + checkpointing (split via
**new dispatches**, not reruns); persist actuals `(template, param‑sig) → measured` to
`…/research-compute/estimates.jsonl` and refine.

---

## 7. Risks & decisions
- **GHA is last in the auto order and a capability subset of Modal** ⇒ it is almost never chosen
  automatically. **Decision:** that's intended — GHA is for explicit use / cost‑sensitive niches;
  keep `gha_enabled` off until deliberately turned on.
- **Modal is now budget‑gated too** (it wasn't). **Decision:** add the $ ledger; default cap if
  unset; this is a behavior change but only *refuses over‑budget* jobs, never reorders them.
- **Billing API lagged/daily/preview + classic‑PAT‑only.** **Decision:** Layer A = hard guarantee;
  Layer B ledger = live gate; API only reconciles.
- **$0 budget blocks everything.** **Decision:** `gha doctor` requires budget > $0 with stop‑usage.
- **Self‑hosted has no GitHub kill switch.** **Decision:** broker time ceiling + fork‑PR guard; optional.

---

## 8. Verification (must pass before enabling `gha_enabled`)
1. **No over‑spend, every time:** two near‑simultaneous `submit`s whose combined worst‑case exceeds budget ⇒ second refused (ledger).
2. **Matrix total:** Σ‑cells worst‑case over budget ⇒ whole sweep refused; > 256 cells rejected.
3. **Worst‑case:** a job that runs to `timeout-minutes` never exceeds its reservation.
4. **Multipliers:** macOS/Windows costed at 10×/2× with round‑up.
5. **Fail‑closed:** billing read removed/unreachable ⇒ that backend treated as over budget (skipped/refused).
6. **Layer A:** GitHub budget set low ⇒ GitHub blocks the run; broker reconciles cleanly.
7. **ToS/security:** broker refuses public‑repo + non‑registered targets; the `experiment.yml` lint trips on `eval`/`inputs.*`‑in‑exec.
8. **Recovery:** a timed‑out job still returns `status-<job_id>.json`; reservation reconciles to actual; resume = new dispatch.
9. **Probe is local** (zero GHA minutes for sizing).
10. **Order + override:** with no instruction, a local‑sized job runs **local**; a job too big for local but fitting Modal runs **Modal** (not GHA); naming `gha` forces GHA within budget (overriding the order); a **named** backend that's over budget is **refused**, not silently switched; in auto mode an over‑budget tier is **skipped to the next**.
11. `bin/tos-notice-check.sh` passes; re‑pin `ai-agents-skills`; `make verify` clean.

---

### Phasing
0 Spec sign‑off → 1 ToS notices + `tos-notice-check.sh` → 2 reusable runner + private template →
3 **routing‑order + budget layer** (`routing_order`, `gha doctor`, reservation ledgers for GHA
*and* Modal, the §3.0 decision) + backends → 4 example repo + blog → 5 verification (§8).
**Phase 3 is a prerequisite for any real remote dispatch — Modal included.**

---

## 9. Live test on a private research repo (concretizes Phase 2 and is the push gate)
Test repo: a **private research repo**. The in‑repo runner (`experiments/`) runs the repo's
**own committed** compute (reusing the repo's existing `main(job)`/CLI convention), parameterised
by dispatch inputs only.

**Three task types (one per runtime) + a limits probe — all on the repo's own research:**
- **Python** — the repo's own theorem check over all generated combinatorial objects up to a size
  `n`, for a parameter `k`. Pure stdlib; `ubuntu-latest`.
- **SageMath** — re-runs the check under SageMath and cross‑checks the Python result. Runs in
  `container: sagemath/sagemath:10.8` (the image pull is itself a useful cost/limit data point).
- **C/C++** — a `g++ -O2` enumerator (the fast path) reaching larger `n` than Python does.
  `ubuntu-latest`.
- **`runner_limits` probe** — reports cores/RAM/disk and runs a scaling `n`‑sweep with
  checkpointing until a soft time budget, recording how far it got → measures GHA's practical limit.

**Templates (≥ 2, reusing the broker families):** `enumerate_objects`, `counterexample_search`,
`parameter_sweep` ((n,k) grid via `matrix`), and `runner_probe`.
Each maps `{runtime, experiment, params}`.

**Workflow** `.github/workflows/experiment.yml`: `workflow_dispatch` `{runtime, experiment,
params_json, job_id}` + `run-name: exp-${{ inputs.job_id }}` + a per‑runtime job with
`timeout-minutes`; uploads `result-<job_id>.json` + `status-<job_id>.json` (`if: always()`); short
`retention-days`. ToS notice in `experiments/README.md` + the workflow header.

**Gate:** this test (dispatch → correct JSON back here → recorded limits) must pass **before** the
broker repos (`coding-system-rebuild`, `ai-agents-skills`) are pushed.
