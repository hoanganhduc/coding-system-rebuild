# TikZ-Draw Multi-Target Integration Plan

Status: plan only. No implementation has been performed.

## Goal

Integrate the current local `tikz-draw` Codex and Claude settings into:

- remote Codex: `{{ HOME }}/.codex`
- remote Claude: `{{ HOME }}/.claude`
- local Windows Codex: `/windows/Users/<user>/.codex`
- local Windows Claude: `/windows/Users/<user>/.claude`

The plan is adaptation-first. It treats Linux and Windows as different runtime targets, not as simple file-copy mirrors.

## Source Of Truth

Current local source-of-truth surfaces inspected:

- Codex core:
  - `~/.codex/skills/tikz-draw/`
  - `~/.codex/runtime/workspace/skills/tikz-draw/`
- Codex integration touchpoints:
  - `~/.codex/AGENTS.md`
  - `~/.codex/instructions/research-quick-actions.md`
  - `~/.codex/skills/deep-research-workflow/SKILL.md`
  - `~/.codex/templates/deep-research-analysis.md`
  - `~/.codex/templates/deep-research-report.md`
- Claude core:
  - `~/.claude/skills/tikz-draw/`
  - `~/.claude/commands/tikz.md`
- Claude integration touchpoints:
  - `~/.claude/CLAUDE.md`
  - `~/.claude/commands/deep-research.md`
  - `~/.claude/skills/deep-research/SKILL.md`
  - `~/.claude/skills/deep-research/templates/analysis.md`
  - `~/.claude/skills/deep-research/templates/report.md`

## Evidence Inspected

Confirmed local source details:

- Local Codex `tikz-draw` and local Claude `tikz-draw` both expose:
  - `doctor`
  - `spec`
  - `render`
  - `check`
  - `compile`
  - `review-visual`
  - `verify-semantic`
  - `review`
  - `extract`
- Local graph support is already Sage-assisted at runtime.
- Local `tikz-draw` source trees currently ship only `run_tikz_draw.sh`, not `run_tikz_draw.bat`.
- `tikz_draw.py` currently assumes:
  - `latexmk`
  - `pdflatex`
  - optional `dvisvgm`
  - `python3` in `doctor`
- `sage_graph_backend.py` currently assumes:
  - `bash`
  - `run_sage.sh`
  - POSIX-style Sage execution

Confirmed remote Ubuntu target state:

- `{{ HOME }}/.codex` exists with Codex runtime, skills, templates, deep-research, and sagemath surfaces.
- `{{ HOME }}/.claude` exists with Claude skills, commands, deep-research, and sagemath surfaces.
- No confirmed installed `tikz-draw` skill/config surface was found at the settings depth inspected.
- Remote Ubuntu toolchain confirmed:
  - `python3`
  - `latexmk`
  - `pdflatex`
  - `dvisvgm`
- Remote Ubuntu Python module state confirmed:
  - `fitz`: present
  - `shapely`: missing
  - `svgelements`: missing
- Remote Ubuntu does not have `rg`; rollout commands should assume POSIX basics like `find`, `grep`, and `sed`.
- Remote Claude contains stale `tikz-draw` run artifacts under its data tree, but not confirmed installed `tikz-draw` settings.

Confirmed Windows target state:

- `/windows/Users/<user>/.codex` exists with:
  - `AGENTS.md`
  - `config.toml`
  - `runtime/run_skill.bat`
  - `runtime/run_skill.ps1`
  - `runtime/workspace/skills/`
  - deep-research and sagemath surfaces
- `/windows/Users/<user>/.claude` exists with:
  - `CLAUDE.md`
  - `settings.json`
  - `settings.local.json`
  - `skills/_run.bat`
  - `skills/_run.sh`
  - deep-research and sagemath surfaces
- No confirmed installed `tikz-draw` surface was found in either Windows settings tree.
- Windows Codex runtime skills use explicit `.bat` launchers alongside `.sh` launchers.
- Windows Claude `_run.bat` rewrites `.sh` requests to `.bat`.
- Windows Codex has `~/.codex/.venv`.
- Windows Claude has `~/.claude/.venv`.
- Windows-side `.local` package roots were not found for Codex runtime workspace or Claude.
- Both Windows venvs are Python `3.10.2` and use `include-system-site-packages = true` with base Python at `C:\Python310`.
- Windows base Python filesystem confirms:
  - `fitz`: present
  - `shapely`: present
  - `svgelements`: not found
- Windows TeX Live filesystem confirms:
  - `C:\texlive\2024\bin\windows\latexmk.exe`
  - `C:\texlive\2024\bin\windows\pdflatex.exe`
  - `C:\texlive\2024\bin\windows\dvisvgm.exe`
- Windows Codex and Windows Claude already have `run_sage.bat`.
- Windows Claude does not currently have `commands/tikz.md`.
- Existing Windows deep-research and entrypoint docs inspected did not show `figure-brief`, `tikz-draw`, or `/tikz` routing.
- Native Windows binaries under `/windows/...` could not be executed from the current Linux environment because the mount is effectively `noexec` here, so Windows-native runtime checks could not be completed from this session.

## Key Conclusion

This is not a pure settings copy.

Linux targets are close to direct-install targets.

Windows targets require explicit runtime adaptation because the current local source-of-truth is Linux-first:

- launcher mismatch: only `.sh` exists for `tikz-draw`
- Sage backend mismatch: current code calls `bash ... run_sage.sh` even though Windows targets already provide `run_sage.bat`
- doctor mismatch: current code looks for `python3` while Windows skill launchers use `python.exe` from `.venv`
- Windows targets use `.venv`-based launch patterns rather than `.local`

## Incomplete Analysis

incomplete analysis

Material items not yet checked live:

- native execution of Windows Codex `tikz-draw` under `run_skill.bat` / `run_skill.ps1`
- native execution of Windows Claude `tikz-draw` under `_run.bat`
- whether Windows TeX Live binaries are already on `PATH` for the actual launcher environment
- whether the Windows venvs can import the observed base-Python packages at runtime exactly as expected
- whether Windows rollout should use the existing shared `.venv` or a dedicated `tikz-draw` venv

Because those areas were not executed live, this plan is an evidence-based integration plan, not a final guarantee that the Windows targets are already runtime-compatible end to end.

## Integration Scope

Windows post-integration acceptance artifact:

- [tikz-draw-windows-post-integration-checklist.md](~/tikz-draw-windows-post-integration-checklist.md)

Use that checklist after Windows rollout to verify file presence, launcher adaptation, dependency state, TeX availability, and one end-to-end smoke per Windows target.

### Codex Files To Sync Or Adapt

Core skill/runtime:

- `~/.codex/skills/tikz-draw/**`
- `~/.codex/runtime/workspace/skills/tikz-draw/**`

Codex routing/docs:

- `~/.codex/AGENTS.md`
- `~/.codex/instructions/research-quick-actions.md`
- `~/.codex/skills/deep-research-workflow/SKILL.md`
- `~/.codex/templates/deep-research-analysis.md`
- `~/.codex/templates/deep-research-report.md`

### Claude Files To Sync Or Adapt

Core skill/runtime:

- `~/.claude/skills/tikz-draw/**`
- `~/.claude/commands/tikz.md`

Claude routing/docs:

- `~/.claude/CLAUDE.md`
- `~/.claude/commands/deep-research.md`
- `~/.claude/skills/deep-research/SKILL.md`
- `~/.claude/skills/deep-research/templates/analysis.md`
- `~/.claude/skills/deep-research/templates/report.md`

## Required Adaptations Before Rollout

### 1. Windows launchers must be added

Required new files for Windows targets:

- Codex:
  - `runtime/workspace/skills/tikz-draw/run_tikz_draw.bat`
- Claude:
  - `skills/tikz-draw/run_tikz_draw.bat`

These must follow the existing Windows skill launcher pattern:

- Codex runtime skills typically invoke `%USERPROFILE%\.codex\.venv\Scripts\python.exe`
- Claude skills typically invoke `%USERPROFILE%\.claude\.venv\Scripts\python.exe`

### 2. Sage backend must be made launcher-aware

Current source assumes:

- `bash`
- `run_sage.sh`

Required adaptation:

- resolve `run_sage.bat` on Windows targets
- keep `run_sage.sh` on Linux targets
- avoid hard-coding shell choice in Windows mode

### 3. Doctor must become platform-aware

Current source checks `python3`.

Required adaptation:

- Linux targets:
  - keep `python3`
- Windows targets:
  - check the configured Python executable used by the `.bat` launcher
  - do not fail only because `python3` alias is absent

### 4. Dependency strategy must be target-specific

Remote Ubuntu:

- install or verify `shapely`
- optionally install `svgelements`
- keep `fitz` as already present

Windows Codex:

- base Python likely already satisfies `fitz` and `shapely` via `include-system-site-packages`
- verify whether `%USERPROFILE%\.codex\.venv` should remain the supported dependency home
- install `svgelements` only if the Windows policy wants feature parity with the optional Linux path

Windows Claude:

- base Python likely already satisfies `fitz` and `shapely` via `include-system-site-packages`
- prefer `%USERPROFILE%\.claude\.venv` unless a dedicated skill venv is intentionally introduced
- install `svgelements` only if the Windows policy wants feature parity with the optional Linux path

### 5. Routing/docs must be synchronized, not just runtime code

All targets currently lack some or all of:

- `tikz-draw` discovery entry
- deep-research `figure-brief` handoff guidance
- Claude `/tikz` public command

Those settings/doc changes are part of the integration scope, not optional follow-up work.

## Rollout Order

Use staged rollout in this order:

1. remote Ubuntu Codex
2. remote Ubuntu Claude
3. local Windows Codex
4. local Windows Claude

Reason:

- Linux targets are closer to the current source-of-truth.
- Windows targets require wrapper/runtime adaptation and should not be first.

## Per-Target Plan

### Phase A. Freeze Source Manifest

Before touching any target:

1. Record the exact local source-of-truth file manifest for:
   - Codex `tikz-draw`
   - Claude `tikz-draw`
   - all touched docs/integration files
2. Separate:
   - portable shared files
   - Linux-only current files
   - Windows-specific files to be created
3. Define a per-target backup list before overwriting anything.

### Phase B. Remote Ubuntu Codex

1. Backup existing target files that will be modified.
2. Install Codex core skill/runtime files.
3. Sync Codex routing/docs touchpoints.
4. Install missing semantic-verifier dependency:
   - `shapely`
5. Decide whether `svgelements` is required now or still optional.
6. Run verification:
   - syntax checks
   - `doctor`
   - direct `render`
   - `check`
   - `compile`
   - `review-visual`
   - `verify-semantic` on one supported family
7. Record any Ubuntu-specific deviations.

### Phase C. Remote Ubuntu Claude

1. Backup existing target files that will be modified.
2. Install Claude core skill files and new `/tikz` command.
3. Sync Claude routing/docs touchpoints.
4. Ensure Claude Python dependency target is consistent with its current layout.
5. Run verification:
   - syntax checks
   - `_run.sh` invocation of `doctor`
   - direct `render`
   - `check`
   - `compile`
   - `review-visual`
   - `verify-semantic`
6. Inspect stale `tikz-draw` run artifacts under Claude data and either:
   - leave them untouched but documented
   - or clean them only under an explicit cleanup step

### Phase D. Local Windows Codex

1. Add `run_tikz_draw.bat`.
2. Adapt the runtime code for Windows-safe:
   - Sage backend resolution
   - doctor executable checks
   - any shell assumptions
3. Sync Codex core files and routing/docs.
4. Choose and provision dependency target:
   - likely existing `%USERPROFILE%\.codex\.venv`, relying on base `C:\Python310` packages for `fitz` and `shapely`
5. Verify TeX tool availability on Windows.
6. Run Windows-native verification through:
   - `runtime/run_skill.bat`
   - and/or `runtime/run_skill.ps1`
7. Verify at least:
   - `doctor`
   - `render`
   - `check`
   - `compile`
   - `verify-semantic`
8. Complete the Windows Codex section in:
   - [tikz-draw-windows-post-integration-checklist.md](~/tikz-draw-windows-post-integration-checklist.md)

### Phase E. Local Windows Claude

1. Add `skills/tikz-draw/run_tikz_draw.bat`.
2. Install new `commands/tikz.md`.
3. Adapt the runtime code for Windows-safe:
   - Sage backend resolution
   - doctor executable checks
   - any shell assumptions
4. Sync Claude routing/docs touchpoints.
5. Provision dependencies into the supported Windows Claude Python environment:
   - likely existing `%USERPROFILE%\.claude\.venv`, relying on base `C:\Python310` packages for `fitz` and `shapely`
6. Verify TeX tool availability on Windows.
7. Run Windows-native verification through:
   - `skills/_run.bat`
8. Verify at least:
   - `doctor`
   - `render`
   - `check`
   - `compile`
   - `verify-semantic`
9. Complete the Windows Claude section in:
   - [tikz-draw-windows-post-integration-checklist.md](~/tikz-draw-windows-post-integration-checklist.md)

## Verification Gates

The rollout should not be declared complete for a target until all applicable gates pass.

### Gate 1. Discovery And Routing

- Codex target recognizes `tikz-draw` in its settings/docs
- Claude target recognizes `/tikz`
- deep-research docs mention `figure-brief` handoff

### Gate 2. Runtime Entry

- launcher resolves correctly:
  - Linux: `.sh`
  - Windows: `.bat`

### Gate 3. Dependency Health

- `doctor` reports the expected Python and TeX tools
- semantic-verifier dependencies are present for the target policy

### Gate 4. Figure Generation

- `render` produces artifacts in the correct platform run root
- output uses the required `adjustbox` environment form

### Gate 5. Compile

- standalone `.tex` compiles to PDF
- optional SVG path is either working or explicitly marked unavailable

### Gate 6. Semantic Review

- `review-visual` executes
- `verify-semantic` approves a supported smoke case

### Gate 7. Cross-Platform Drift

- parity-sensitive files are compared after sync
- docs, verbs, schemas, and routing fields stay aligned across Codex and Claude

### Gate 8. Windows Completion Sheet

- the Windows post-integration checklist is completed for Codex
- the Windows post-integration checklist is completed for Claude

## Recommended Implementation Strategy Once Approved

Use two implementation slices, not one large push:

### Slice 1. Linux Targets

Implement and verify:

- remote Ubuntu Codex
- remote Ubuntu Claude

This validates the sync/install plan against the least-adaptive targets first.

### Slice 2. Windows Targets

Implement and verify:

- Windows Codex
- Windows Claude

This slice should include explicit Windows launcher and platform-adaptation work before any runtime claims.

## Risks To Track

- Windows-specific launcher and shell assumptions are currently the largest adaptation risk.
- Windows native execution is still the largest unverified area because this session could not execute `/windows` binaries directly.
- Windows TeX toolchain is confirmed on disk but not yet confirmed on launcher `PATH`.
- Windows Python dependency surface is confirmed on disk for `fitz` and `shapely`, but not yet confirmed by native import execution.
- Remote Ubuntu host resolution to `openclaw` has been intermittently unstable during inspection.
- Remote Claude contains stale `tikz-draw` run artifacts that could confuse later verification if not treated carefully.

## Recommended Acceptance Standard

Do not claim full multi-target integration complete until:

- all four targets have the expected files in place
- all four targets pass their target-appropriate runtime entrypoints
- all four targets pass `doctor`
- all four targets complete at least one supported end-to-end TikZ smoke
- both Windows targets are verified with their actual native launcher paths, not inferred from the Linux source tree

## Current Recommendation

Proceed only after confirmation, and implement in two waves:

1. remote Ubuntu Codex + Claude
2. Windows Codex + Claude with wrapper/runtime adaptation

That is the safest path consistent with the evidence currently inspected.
