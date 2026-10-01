# Modal offload routing (Claude)

Use the `modal-research-compute` skill (slash: `/research-compute`) when a task involves any of the following:

- exhaustive enumeration
- counterexample search
- large parameter sweeps
- branch-heavy experiments likely to exceed local memory or disk limits
- batch OCR, VLM, embedding, reranking, or other GPU-suitable workloads
- research code generation where the resulting computation should run remotely, not locally

## Routing rules

1. Prefer the broker boundary over direct `modal` SDK calls from Claude's main flow.
2. Prefer remote CPU or high-memory CPU for branching search, enumeration, and counterexample workflows.
3. Prefer GPU only when the payload is explicitly GPU-suitable (`gpu`, `tensor`, `embedding`, `rerank`, `vlm`, `ocr`, `spectral` markers) or the job constraints request GPU.
4. Always run `plan` before `submit`. `plan` is side-effect-free; read the decision and risk flags first.
5. Run `doctor` once per host before the first `submit` to confirm Modal SDK/CLI/auth are wired.

## Host bootstrap

Linux (local + remote Ubuntu):

```bash
python3 -m pip install --user --upgrade modal
# if blocked by "externally-managed-environment":
# python3 -m pip install --user --break-system-packages --upgrade modal
```

```bash
modal token set --profile default
```

Windows (native, PowerShell):

```powershell
# If the Claude venv exists, use it; otherwise py -3 -m pip
if (Test-Path "$env:USERPROFILE\.claude\.venv\Scripts\python.exe") {
  & "$env:USERPROFILE\.claude\.venv\Scripts\python.exe" -m pip install --upgrade modal
} else {
  py -3 -m pip install --upgrade modal
}
```

```powershell
& "$env:USERPROFILE\.claude\.venv\Scripts\modal.exe" token set --profile default
# or: modal token set --profile default
```

## Command patterns

Linux:

```bash
bash ~/.claude/skills/_run.sh skills/modal-research-compute/run_modal_research_compute.sh doctor
bash ~/.claude/skills/_run.sh skills/modal-research-compute/run_modal_research_compute.sh plan job.json
bash ~/.claude/skills/_run.sh skills/modal-research-compute/run_modal_research_compute.sh submit job.json --wait --timeout 300
bash ~/.claude/skills/_run.sh skills/modal-research-compute/run_modal_research_compute.sh wait <job_id> --timeout 600
bash ~/.claude/skills/_run.sh skills/modal-research-compute/run_modal_research_compute.sh fetch <job_id> --dest ./.research-compute-out
```

Windows (PowerShell):

```powershell
& "$env:USERPROFILE\.claude\skills\modal-research-compute\run_modal_research_compute.bat" doctor
& "$env:USERPROFILE\.claude\skills\modal-research-compute\run_modal_research_compute.bat" plan C:\path\to\job.json
& "$env:USERPROFILE\.claude\skills\modal-research-compute\run_modal_research_compute.bat" submit C:\path\to\job.json --wait --timeout 300
```

## Result handling

- Broker control-plane state persists under `broker_state_root`:
  - local Linux: `~/.local/share/claude/research-compute` (outside the `~/.claude/` read-only bind mount)
  - remote Ubuntu: `~/.local/share/claude/research-compute` (or `~/.claude/memories/research-compute` if the install allows bash writes there)
  - Windows: `%USERPROFILE%\.claude\memories\research-compute`
- Fetched results materialize under the caller workspace at `./.research-compute/results/<job_id>/` by default. Use `fetch --dest <path>` to override.
- Remote logs are captured in `result.json` (stdout/stderr fields) and included in the fetched manifest.

## Secrets

- Modal auth lives in `~/.modal.toml` (Linux) or `%USERPROFILE%\.modal.toml` (Windows). **Never** copied between hosts.
- Claude config holds only the profile name, environment name, and deployment alias — no raw token values.
- Remote execution secrets (for individual templates) must be named Modal Secrets, scoped per environment.

## Skill deploy ownership

- Local Linux is the **authoritative `deploy`-authoring host** for Modal app `research-compute-claude`.
- Remote Ubuntu and Windows are **broker clients**: they call the already-deployed functions via `modal.Function.from_name(deployment_alias, ...)`.
- Do not redeploy from remote Ubuntu or Windows unless you deliberately promote one of them to the deploy host.
