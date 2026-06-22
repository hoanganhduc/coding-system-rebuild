# Docling Integration Plan

Created: 2026-04-15
Updated: 2026-04-15 (implemented P0-P2)
Status: P0-P2 complete, P3-P4 pending

---

## 0. Prerequisites & Constraints

### Disk Space (CRITICAL)

| Filesystem | Total | Used | Free |
|---|---|---|---|
| Linux `/` (luks_root) | 197G | 185G | **1.9G** |
| Windows `/windows` (BitLocker) | 616G | 596G | **20G** |
| Remote Ubuntu | Unknown | Unknown | Unknown (check via SSH) |

**Linux is nearly full.** Estimated docling footprint:

| Component | Size |
|---|---|
| PyTorch CPU-only | ~800MB |
| Docling + deps (ONNX, Pillow, etc.) | ~400-600MB |
| Model downloads (`~/.cache/docling/models/`) | ~1-2GB |
| **Total** | **~2-3.5GB** |

**Mitigation — clear pip cache first:**
```bash
pip cache purge    # frees ~3.1GB from ~/.cache/pip/
```

Other clearable caches (optional):
- `~/.cache/selenium/` — 1.2GB (if not actively used)
- `~/.cache/thumbnails/` — 267MB

After clearing pip cache alone: ~5GB free — enough for installation.

### No GPU (all environments)

- Linux: no GPU
- Windows: no GPU
- Remote Ubuntu: no GPU
- Consequence: CPU-only PyTorch wheels, skip VLM/ASR pipelines, use `standard` pipeline only

### Dependency Isolation (CRITICAL)

System Python has **pydantic 1.10.7** (v1) at `/usr/lib/python3.10/site-packages/`. Docling requires **pydantic v2**. Existing Claude skills use a PYTHONPATH-based approach (`~/.claude/.local/`) that shares the system pydantic.

**Installing docling system-wide will break existing skills.**

Solution: dedicated virtualenv with its own pydantic v2. The skill runner, CLI, and MCP server all reference this venv explicitly. Existing skills remain untouched.

**Actual venv locations** (differs per OS due to filesystem constraints):
- **Linux**: `~/.local/share/docling-venv/` (`~/.claude/` has a read-only bind mount for bash)
- **Windows**: `~/.venv-docling/` (i.e., `C:\Users\hoanganhduc\.venv-docling\`)

### Tool Availability

| Tool | Linux | Windows | Notes |
|---|---|---|---|
| Python | 3.10.10 | 3.x in `.venv/` | Docling requires 3.10+ |
| pip | 23.0.1 | in `.venv/` | OK |
| uvx/uv | **Not installed** | **Not installed** | MCP config cannot use `uvx` |
| npx | 11.11.1 | Available | For other MCP servers |
| tesseract | **5.5.0** (eng, jpn, vie) | Not checked | Already installed on Linux |
| TESSDATA_PREFIX | `/usr/share/tessdata/` | N/A | eng, jpn, osd, vie languages |

---

## 1. What Is Docling

**Docling** (IBM Research / LF AI & Data Foundation) is an enterprise-grade document processing toolkit that converts diverse document formats into structured, AI-ready representations.

### Core Capabilities

| Capability | Details |
|---|---|
| **Format support** | PDF, DOCX, PPTX, XLSX, HTML, Markdown, LaTeX, images, audio/video, XML schemas |
| **PDF understanding** | Layout detection, reading order, table structure (97.9% cell accuracy), code blocks, formulas |
| **OCR engines** | EasyOCR, Tesseract, RapidOCR, OnnxTR, macOS Vision |
| **VLM pipelines** | Granite Docling, SmolDocling, Qwen2.5-VL, Pixtral (GPU required — not applicable) |
| **Enrichments** | Code extraction, formula to LaTeX, picture classification (16+ categories), chart to structured data |
| **Chunking** | HybridChunker (token-aware, RAG-optimized), HierarchicalChunker (structure-aware) |
| **Output formats** | Markdown, HTML, JSON, plain text, DocTags, WebVTT, YAML, CSV (tables) |
| **Confidence scoring** | 4-metric quality assessment (layout, OCR, parse, table) with grades |
| **MCP server** | Official `docling-mcp` — direct Claude Code / AI agent integration |
| **CLI** | `docling <SOURCE> [OPTIONS]` with full pipeline control |
| **Batch processing** | `converter.convert_all()` with streaming results |

### Gaps in Current Workflow That Docling Fills

| Gap | Current state | Docling fills how |
|---|---|---|
| **PDF text extraction** | Claude reads PDFs natively (good but limited for complex layouts) | Structured layout-aware parsing with reading order |
| **Table extraction** | No dedicated tool — relies on Claude's visual understanding | Cell-level extraction to DataFrame/CSV/HTML |
| **Formula extraction** | No tool — formulas seen as images | Converts to LaTeX strings |
| **DOCX/PPTX conversion** | Not supported | Full conversion to markdown |
| **OCR for scanned papers** | Not supported | Multiple OCR engines |
| **Chunking for RAG** | No pipeline | Token-aware chunking with context |
| **Batch paper processing** | Manual one-at-a-time | Stream multiple documents |
| **Document quality check** | None | Confidence scoring per page |

### Key Resources

- Repository: https://github.com/docling-project/docling
- Documentation: https://docling-project.github.io/docling/
- MCP Server: https://github.com/docling-project/docling-mcp
- Serve API: https://github.com/docling-project/docling-serve
- Technical Report: https://arxiv.org/abs/2408.09869
- PyPI: https://pypi.org/project/docling/

---

## 2. Environment Audit Summary

### Local Linux (`/home/hoanganhduc/.claude/`)

| Component | Status |
|---|---|
| Skills | 11 installed, all working |
| Slash commands | 9 (`/zotero`, `/review`, `/sage`, etc.) |
| Hooks | 7 (safety, self-improvement, compaction, notification, stop-review) |
| MCP servers | 2 active (sequential-thinking, github), 11 pending OAuth |
| Permissions | 100+ allow rules, 9 deny rules |
| Agents | 4 (math-explorer, proof-checker, literature-scout, paper-reviewer) |
| Data symlinks | calibre, research, job-queue, runs to openclaw-workspace |
| Python deps | `.local/` directory (PYTHONPATH-based, shares system pydantic v1) |
| Env vars | `CLAUDE_CODE_NO_FLICKER`, `DISABLE_GIT_INSTRUCTIONS`, `SUBPROCESS_ENV_SCRUB` |
| **Docling** | **Not installed** |

### Local Windows (`/windows/Users/hoanganhduc/.claude/`)

| Component | Status |
|---|---|
| Skills | 8 installed (same core set) |
| Slash commands | 9 (identical to Linux) |
| Hooks | 7 (identical structure; PostToolUse also catches `python`, `wsl`) |
| MCP servers | 2 active (sequential-thinking, github) |
| Permissions | ~66 allow rules (includes `wsl`, `.venv/Scripts/python.exe`) |
| Agents | 4 (identical) |
| Python | `.venv/` (Windows virtualenv with system-site-packages) |
| SageMath | Via `wsl -d Ubuntu-24.04` |
| Env vars | Only `SUBPROCESS_ENV_SCRUB` (missing `NO_FLICKER`, `DISABLE_GIT_INSTRUCTIONS`) |
| **Docling** | **Not installed** |

**Windows gaps vs Linux:**
- Missing env vars: `CLAUDE_CODE_NO_FLICKER`, `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS`
- Missing `Notification` hook (Linux uses `notify-send`)
- Missing `WebFetch(domain:pypi.org)` permission
- Uses `.venv/` instead of `.local/` directory

### Remote Ubuntu (`ubuntu@openclaw` — `{{ HOME }}/.claude/`)

| Component | Status |
|---|---|
| Access | Not mounted locally — requires SSH |
| OpenClaw bot | v2026.3.24, 40+ messaging channels |
| Workspace | `{{ HOME }}/.npm-global/lib/node_modules/openclaw/` |
| Config | `~/.openclaw/openclaw.json` + `~/.openclaw/workspace/` |
| Claude Code | Status unknown — may not have `~/.claude/` configured |
| **Docling** | **Unknown / likely not installed** |

---

## 3. Integration Plan

### Integration A: Docling MCP Server (highest impact, lowest effort)

Add `docling-mcp` to `.mcp.json` on all environments. Gives Claude Code a `convert_document()` tool callable from any conversation.

**Linux** (uses dedicated venv python):
```json
"docling": {
  "command": "/home/hoanganhduc/.claude/.venv-docling/bin/python",
  "args": ["-m", "docling_mcp"],
  "env": {
    "TESSDATA_PREFIX": "/usr/share/tessdata/"
  }
}
```

**Windows** (dedicated venv):
```json
"docling": {
  "command": "~/.venv-docling/Scripts/python.exe",
  "args": ["-m", "docling_mcp"]
}
```

**Ubuntu** (dedicated venv, if uvx not available):
```json
"docling": {
  "command": "{{ HOME }}/.claude/.venv-docling/bin/python",
  "args": ["-m", "docling_mcp"],
  "env": {
    "TESSDATA_PREFIX": "/usr/share/tessdata/"
  }
}
```

### Integration B: New `/docling` Slash Command

Dedicated skill for document conversion, table extraction, OCR, and batch processing.

Use cases:
- "Convert this PPTX to markdown"
- "Extract tables from paper.pdf"
- "OCR this scanned document"
- "Convert all PDFs in this folder to markdown"
- "Chunk this paper for embedding"

### Integration C: Enhance `/review` Skill

Use docling as optional pre-processing step for PDF papers before review.

```
Current:  PDF -> Claude reads PDF directly -> review
Enhanced: PDF -> docling -> structured markdown with tables/formulas -> review
```

### Integration D: Enhance `/zotero` Skill

After `zot get` retrieves a PDF, optionally run docling to extract structured text, tables, or specific sections.

Add `zot extract` subcommand:
```bash
zot extract "Smith 2024" --to markdown
zot extract "Smith 2024" --tables-only --to csv
zot extract "Smith 2024" --ocr
```

### Integration E: Permissions & Environment Updates

Add docling CLI, Python package, and documentation domains to all environments.

### Integration F: Confidence-Based Quality Filtering

When processing papers in batch (e.g., digest pipelines), use docling's confidence scoring to flag low-quality conversions for manual review.

---

## 4. Installation (per-environment)

### Linux

```bash
# Step 0: Free disk space (REQUIRED — only 1.9GB free)
pip cache purge                          # frees ~3.1GB

# Step 1: Create dedicated venv (isolates from system pydantic v1)
python3 -m venv ~/.venv-docling
source ~/.venv-docling/bin/activate

# Step 2: CPU-only PyTorch (saves ~2GB vs CUDA wheels)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu

# Step 3: Docling with tesserocr (tesseract 5.5.0 already installed)
pip install "docling[tesserocr]"

# Step 4: MCP server
pip install docling-mcp

# Step 5: Download models (layout + table structure — CPU inference)
docling-tools models download

# Step 6: Verify
docling --help
deactivate
```

**Verify from outside venv:**
```bash
~/.venv-docling/bin/docling --help
~/.venv-docling/bin/python -m docling_mcp --help
```

### Windows

```powershell
# Step 1: Create dedicated venv
python -m venv ~/.venv-docling

# Step 2: Install (no tesseract on Windows — use rapidocr)
~/.venv-docling/Scripts/pip.exe install torch torchvision --index-url https://download.pytorch.org/whl/cpu
~/.venv-docling/Scripts/pip.exe install "docling[rapidocr]"
~/.venv-docling/Scripts/pip.exe install docling-mcp

# Step 3: Download models
~/.venv-docling/Scripts/docling-tools.exe models download
```

### Remote Ubuntu

```bash
ssh ubuntu@openclaw

# Check disk space first
df -h /

# Check if tesseract installed
tesseract --version 2>/dev/null

# Create dedicated venv
python3 -m venv ~/.venv-docling
source ~/.venv-docling/bin/activate

pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
# If tesseract available:
pip install "docling[tesserocr]"
# Otherwise:
pip install "docling[rapidocr]"
pip install docling-mcp
docling-tools models download
deactivate
```

---

## 5. OCR Engine Strategy

| Engine | Linux | Windows | Ubuntu |
|---|---|---|---|
| **Tesserocr** | **Default** (tesseract 5.5.0 installed, eng+jpn+vie) | Not available (no system tesseract) | Check and use if available |
| **RapidOCR** | Fallback (install with `pip install "docling[rapidocr]"`) | **Default** (CPU-optimized ONNX, no system deps) | Fallback |
| **EasyOCR** | Skip (too slow on CPU) | Skip | Skip |

**TESSDATA_PREFIX** on Linux: `/usr/share/tessdata/`

**Available languages** on Linux: eng, jpn, osd, vie

Python usage:
```python
# Linux: Tesserocr (default — tesseract 5.5.0 already installed)
from docling.datamodel.pipeline_options import TesseractOcrOptions
ocr_options = TesseractOcrOptions(lang=["eng"])
# Vietnamese: TesseractOcrOptions(lang=["vie"])

# Windows / fallback: RapidOCR
from docling.datamodel.pipeline_options import RapidOcrOptions
ocr_options = RapidOcrOptions(lang=["en"])
```

Adding more tesseract languages later:
```bash
sudo pacman -S tesseract-data-<lang>   # Arch Linux
# or download .traineddata to /usr/share/tessdata/
```

---

## 6. Settings Updates

### `.mcp.json` — add to all environments

See Integration A above. Key: use venv python path, not uvx (uvx not installed).

### `settings.local.json` — add to all environments

```json
"Bash(~/.venv-docling/bin/docling:*)",
"Bash(~/.venv-docling/bin/docling-tools:*)",
"Bash(~/.venv-docling/bin/python:*)"
```

Windows also needs:
```json
"Bash(~/.venv-docling/Scripts/docling.exe:*)",
"Bash(~/.venv-docling/Scripts/python.exe:*)",
"WebFetch(domain:docling-project.github.io)",
"WebFetch(domain:pypi.org)"
```

(Linux already has `WebFetch(domain:docling-project.github.io)` and `WebFetch(domain:pypi.org)`.)

### `settings.json` — add environment variable (all environments)

```json
"DOCLING_ARTIFACTS_PATH": "~/.cache/docling/models",
"TESSDATA_PREFIX": "/usr/share/tessdata/"
```

(TESSDATA_PREFIX only on Linux/Ubuntu where tesseract is installed.)

---

## 7. Skill Config Template

```json
{
  "venv_path": "~/.venv-docling",
  "ocr_engine": "tesserocr",
  "ocr_lang": ["eng"],
  "tessdata_prefix": "/usr/share/tessdata/",
  "pipeline": "standard",
  "device": "cpu",
  "do_table_structure": true,
  "do_formula_enrichment": true,
  "do_code_enrichment": false,
  "fallback_ocr": {
    "engine": "rapidocr",
    "install_cmd": "pip install 'docling[rapidocr]'"
  },
  "platform_overrides": {
    "windows": {
      "ocr_engine": "rapidocr",
      "venv_path": "~/.venv-docling"
    }
  }
}
```

---

## 8. Skill Runner Integration

The existing skill runner (`~/.claude/skills/_run.sh`) uses PYTHONPATH + `.local/`. Docling must NOT use that path — it has its own venv.

**Pattern for docling skill script** (`~/.claude/skills/docling/run_docling.sh`):
```bash
#!/usr/bin/env bash
set -euo pipefail

DOCLING_VENV="${HOME}/.claude/.venv-docling"

if [[ ! -d "$DOCLING_VENV" ]]; then
  echo '{"status":"error","message":"Docling venv not found. Run installation first."}' >&2
  exit 1
fi

# Activate docling venv (isolated from system pydantic v1)
source "$DOCLING_VENV/bin/activate"

# Set tesseract data path if available
if command -v tesseract &>/dev/null; then
  export TESSDATA_PREFIX="${TESSDATA_PREFIX:-/usr/share/tessdata/}"
fi

# Dispatch subcommand
case "${1:-help}" in
  convert)  shift; docling "$@" ;;
  python)   shift; python3 "$@" ;;
  models)   shift; docling-tools models "$@" ;;
  help)     docling --help ;;
  *)        echo "Unknown subcommand: $1"; exit 1 ;;
esac
```

This script is called directly (not via `_run.sh`) to avoid PYTHONPATH contamination from `.local/`.

---

## 9. Environment Differences

| Setting/Feature | Linux | Windows | Ubuntu (remote) |
|---|---|---|---|
| **GPU** | None | None | None |
| **PyTorch** | CPU-only wheels | CPU-only wheels | CPU-only wheels |
| **OCR engine (default)** | Tesserocr (5.5.0 installed) | RapidOCR (no system tesseract) | Check; tesserocr if available |
| **OCR languages** | eng, jpn, vie | en (RapidOCR) | Check tesseract --list-langs |
| **VLM pipeline** | Skip (CPU impractical) | Skip | Skip |
| **Pipeline** | `standard` only | `standard` only | `standard` only |
| **Python venv** | `~/.venv-docling/` | `~/.venv-docling/` | `~/.venv-docling/` |
| **System Python** | 3.10.10 (pydantic v1) | 3.x in `.venv/` | Check |
| **MCP command** | venv `python -m docling_mcp` | venv `python -m docling_mcp` | venv `python -m docling_mcp` |
| **Model cache** | `~/.cache/docling/models/` | `%LOCALAPPDATA%/docling/` | `~/.cache/docling/models/` |
| **TESSDATA_PREFIX** | `/usr/share/tessdata/` | N/A | Check |
| **Disk free** | ~1.9GB (clear pip cache first) | ~20GB | Check via SSH |

---

## 10. Implementation Priority

| Priority | Task | Effort | Impact | Prereq |
|---|---|---|---|---|
| **P0** | Clear pip cache on Linux | 1 min | Frees ~3.1GB | None |
| **P0** | Create docling venv + install on Linux | 15 min | Core capability | Disk space |
| **P0** | Add docling MCP to Linux `.mcp.json` | 1 min | All conversations get convert_document | Venv exists |
| **P1** | Create `/docling` slash command + skill (Linux) | 30 min | Dedicated skill with triggers | Venv exists |
| **P1** | Add permissions to Linux `settings.local.json` | 2 min | Allow unattended CLI usage | None |
| **P2** | Replicate to Windows | 30 min | Cross-env parity | None |
| **P2** | Fix Windows env var / permission gaps | 10 min | Bring Windows to parity | None |
| **P3** | Enhance `/review` with docling pre-processing | 1-2 hr | Better table/formula handling | Venv exists |
| **P3** | Add `zot extract` subcommand | 1-2 hr | Structured extraction from Zotero | Venv exists |
| **P4** | Install on remote Ubuntu | 30 min | Needs SSH access | SSH access |
| **P4** | Chunking pipeline for RAG over Zotero corpus | 4+ hr | Large project | All above |

---

## 11. Windows Parity Fixes (bonus)

| Gap | Fix |
|---|---|
| Missing `CLAUDE_CODE_NO_FLICKER` env var | Add to `settings.json` env block |
| Missing `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS` | Add to `settings.json` env block |
| Missing `Notification` hook | Add Windows toast notification or skip |
| Missing `WebFetch(domain:pypi.org)` | Add to `settings.local.json` |
| Missing `WebFetch(domain:docling-project.github.io)` | Add to `settings.local.json` |

---

## 12. Rollback Plan

If docling installation causes problems:

```bash
# Remove the dedicated venv (zero impact on existing skills)
rm -rf ~/.venv-docling/

# Remove MCP entry from .mcp.json (revert the "docling" key)

# Remove permissions from settings.local.json (revert added lines)

# Clear model cache if disk space needed
rm -rf ~/.cache/docling/
```

The dedicated venv approach means **removal is clean** — no system packages touched, no `.local/` contamination, no pydantic conflict possible.

---

## 13. Key Decisions

| Decision | Rationale |
|---|---|
| **Dedicated venv (`~/.venv-docling/`)** | System has pydantic v1; docling needs v2; existing skills use `.local/` with system pydantic. Isolation prevents breakage. |
| **Tesserocr as Linux default** | Tesseract 5.5.0 already installed with eng+jpn+vie. No extra system packages needed. Faster than EasyOCR on CPU. |
| **RapidOCR as Windows default** | No system tesseract on Windows. RapidOCR is Python-only, CPU-optimized via ONNX Runtime. |
| **Venv python for MCP, not uvx** | uvx/uv not installed on any environment. Venv python path is explicit and reliable. |
| **Clear pip cache before install** | Only 1.9GB free on Linux root. Pip cache is 3.1GB of stale wheels. |
| **CPU-only PyTorch wheels** | No GPU anywhere. Saves ~2GB per environment. |
| **Skip VLM/ASR pipelines** | GPU required. Standard pipeline with layout models is sufficient on CPU. |
| **Separate skill runner (not via `_run.sh`)** | `_run.sh` sets PYTHONPATH to `.local/` which includes pydantic v1. Docling skill activates its own venv directly. |
| **Docling as optional pre-processing** | Claude's native PDF reading is good for most papers; docling adds value for complex layouts, scanned docs, tables. |
| **Separate `/docling` skill** | Keep skills independent; `/review` can call docling when needed. |

---

## 14. Python API Quick Reference

### Basic Conversion

```python
from docling.document_converter import DocumentConverter

converter = DocumentConverter()
result = converter.convert("file.pdf")
doc = result.document

markdown = doc.export_to_markdown()
html = doc.export_to_html()
text = doc.export_to_text()
```

### With OCR and Enrichments

```python
from docling.document_converter import DocumentConverter
from docling.datamodel.base_models import InputFormat
from docling.datamodel.pipeline_options import PdfPipelineOptions, TesseractOcrOptions

options = PdfPipelineOptions(
    do_ocr=True,
    ocr_options=TesseractOcrOptions(lang=["eng"]),
    do_table_structure=True,
    do_formula_enrichment=True,
)

converter = DocumentConverter(
    format_options={InputFormat.PDF: options}
)
result = converter.convert("scanned_paper.pdf")
```

### Table Extraction

```python
for table in result.document.tables:
    df = table.export_to_dataframe()
    df.to_csv("table.csv")
```

### Batch Processing

```python
from docling.datamodel.base_models import ConversionStatus

sources = ["doc1.pdf", "doc2.docx", "doc3.pptx"]
results = converter.convert_all(sources, raises_on_error=False)
for r in results:
    if r.status == ConversionStatus.SUCCESS:
        print(r.document.export_to_markdown())
```

### Chunking for RAG

```python
from docling_core.chunking import HybridChunker

chunker = HybridChunker(max_tokens=512)
chunks = chunker.chunk(doc)
for chunk in chunks:
    context = chunker.contextualize(chunk)  # metadata-enriched text
```

### CLI Quick Reference

```bash
DOCLING=~/.venv-docling/bin/docling

# Basic conversion
$DOCLING file.pdf --to md --output ./out

# With OCR (tesseract)
TESSDATA_PREFIX=/usr/share/tessdata/ $DOCLING scanned.pdf --do-ocr --ocr-engine tesseract --to md

# With table + formula extraction
$DOCLING paper.pdf --do-table-structure --do-formula-enrichment --to json

# Batch
$DOCLING *.pdf --to md --output ./converted

# From URL
$DOCLING https://arxiv.org/pdf/2408.09869 --to md
```
