# TikZ-Draw Windows Post-Integration Checklist

Status: planning artifact only. Use this after Windows integration is completed.

## Purpose

This checklist defines what must exist and what must be verified for:

- Windows Codex at `C:\Users\hoanganhduc\.codex`
- Windows Claude at `C:\Users\hoanganhduc\.claude`

It is a post-integration acceptance sheet, not an implementation script.

## Windows Codex

### Must be installed in settings folders

Core skill metadata:

- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\SKILL.md`
- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\references\backend-routing.md`
- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\references\quality-gates.md`
- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\references\tikz-prevention.md`
- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\references\tikz-measurement.md`
- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\references\research\*`
- `C:\Users\hoanganhduc\.codex\skills\tikz-draw\references\implementation\*`

Runtime skill files:

- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\tikz_draw.py`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\sage_graph_backend.py`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\family_verifiers.py`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\pdf_extract.py`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\semantic_parity_check.py`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\semantic_regression_runner.py`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\requirements-semantic-verifier.txt`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\run_tikz_draw.sh`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\run_tikz_draw.bat`

Runtime assets:

- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\assets\checks\*`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\assets\spec-schema\*`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\assets\styles\*`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\assets\templates\tikz-snippets\*`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\assets\examples\semantic-regression\*`
- `C:\Users\hoanganhduc\.codex\runtime\workspace\skills\tikz-draw\assets\snippets\*`

Codex routing/docs:

- `C:\Users\hoanganhduc\.codex\AGENTS.md`
  - includes `tikz-draw` routing
- `C:\Users\hoanganhduc\.codex\instructions\research-quick-actions.md`
  - includes Windows Codex `tikz-draw` examples
- `C:\Users\hoanganhduc\.codex\skills\deep-research-workflow\SKILL.md`
  - includes `figure-brief` handoff to `tikz-draw`
- `C:\Users\hoanganhduc\.codex\templates\deep-research-analysis.md`
- `C:\Users\hoanganhduc\.codex\templates\deep-research-report.md`

### Must be checked after install

Python and launcher:

- `C:\Users\hoanganhduc\.codex\.venv\Scripts\python.exe` exists
- `run_tikz_draw.bat` uses the intended Python environment
- `run_tikz_draw.bat` can route all supported verbs

Sage backend:

- Windows Codex `tikz-draw` resolves `run_sage.bat`, not only `run_sage.sh`
- no Windows path depends on `bash` for the default Sage route

Dependencies:

- `fitz` imports successfully in the actual Windows Codex runtime
- `shapely` imports successfully in the actual Windows Codex runtime
- `svgelements` policy is explicit:
  - either installed
  - or intentionally optional and documented as such

TeX:

- `latexmk.exe` is reachable from the actual launch environment
- `pdflatex.exe` is reachable from the actual launch environment
- `dvisvgm.exe` is reachable if SVG output is part of the acceptance target

Behavior:

- `doctor` passes from `run_skill.bat`
- `render` succeeds for one supported family
- `check` succeeds on the generated figure
- `compile` produces a PDF
- `review-visual` executes
- `verify-semantic` approves one supported smoke case

Output contract:

- generated document-facing TikZ uses:
  - `\begin{adjustbox}{max width=\textwidth}`
  - `\end{adjustbox}`
- standalone output uses plain `standalone` class, not `standalone[tikz]`
- graph routing/report fields appear where expected

## Windows Claude

### Must be installed in settings folders

Core skill metadata:

- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\SKILL.md`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\references\backend-routing.md`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\references\quality-gates.md`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\references\tikz-prevention.md`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\references\tikz-measurement.md`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\references\research\*`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\references\implementation\*`

Skill/runtime files:

- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\tikz_draw.py`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\sage_graph_backend.py`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\family_verifiers.py`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\pdf_extract.py`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\semantic_regression_runner.py`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\requirements-semantic-verifier.txt`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\run_tikz_draw.sh`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\run_tikz_draw.bat`

Runtime assets:

- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\assets\checks\*`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\assets\spec-schema\*`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\assets\styles\*`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\assets\templates\tikz-snippets\*`
- `C:\Users\hoanganhduc\.claude\skills\tikz-draw\assets\examples\semantic-regression\*`

Claude routing/docs:

- `C:\Users\hoanganhduc\.claude\commands\tikz.md`
- `C:\Users\hoanganhduc\.claude\CLAUDE.md`
  - includes `/tikz`
- `C:\Users\hoanganhduc\.claude\commands\deep-research.md`
  - includes post-analysis `figure-brief` handoff to `/tikz`
- `C:\Users\hoanganhduc\.claude\skills\deep-research\SKILL.md`
  - includes `figure-brief` handoff
- `C:\Users\hoanganhduc\.claude\skills\deep-research\templates\analysis.md`
- `C:\Users\hoanganhduc\.claude\skills\deep-research\templates\report.md`

### Must be checked after install

Python and launcher:

- `C:\Users\hoanganhduc\.claude\.venv\Scripts\python.exe` exists
- `skills\_run.bat` can invoke `skills\tikz-draw\run_tikz_draw.bat`
- `run_tikz_draw.bat` uses the intended Python environment

Sage backend:

- Windows Claude `tikz-draw` resolves `run_sage.bat`, not only `run_sage.sh`
- no Windows path depends on `bash` for the default Sage route

Dependencies:

- `fitz` imports successfully in the actual Windows Claude runtime
- `shapely` imports successfully in the actual Windows Claude runtime
- `svgelements` policy is explicit:
  - either installed
  - or intentionally optional and documented as such

TeX:

- `latexmk.exe` is reachable from the actual launch environment
- `pdflatex.exe` is reachable from the actual launch environment
- `dvisvgm.exe` is reachable if SVG output is part of the acceptance target

Behavior:

- `doctor` passes from `_run.bat`
- `render` succeeds for one supported family
- `check` succeeds on the generated figure
- `compile` produces a PDF
- `review-visual` executes
- `verify-semantic` approves one supported smoke case

Output contract:

- generated document-facing TikZ uses:
  - `\begin{adjustbox}{max width=\textwidth}`
  - `\end{adjustbox}`
- standalone output uses plain `standalone` class, not `standalone[tikz]`
- `/tikz` examples and docs match the actual installed verbs and flags

## Shared Windows Acceptance

The Windows integration should not be considered complete until:

- both Windows targets have the required files in place
- both Windows targets have native `.bat` entrypoints for `tikz-draw`
- both Windows targets pass `doctor`
- both Windows targets can compile at least one supported TikZ figure
- both Windows targets pass one semantic smoke case
- both Windows targets have the intended deep-research to TikZ handoff wiring
- any remaining optional gap, such as `svgelements`, is documented explicitly rather than left implicit
