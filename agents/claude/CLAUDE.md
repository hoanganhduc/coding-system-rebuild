# Research Assistant — Claude Code Self-Contained Skills

Claude Code has its own copy of all research skills, secrets, and runner under `~/.claude/`. No dependency on `~/.openclaw/` at runtime.

## Environment

All skill scripts live under `~/.claude/skills/`. To run any skill:

```bash
bash ~/.claude/skills/_run.sh skills/<skill>/run_<skill>.sh <args>
```

On Windows, use:

```bat
%USERPROFILE%\.claude\skills\_run.bat skills\<skill>\run_<skill>.bat <args>
```

The `_run.sh` wrapper sets `OPENCLAW_WORKSPACE`, `PYTHONPATH`, `OPENCLAW_SECRETS_FILE`, and `cd`s into `~/.claude/`.

## Slash commands

| Command | Skill | When to use |
|---------|-------|-------------|
| `/zotero` | Zotero library | Send, get, find, add, search papers; add local files (PDF/EPUB/any); manage collections |
| `/getscipapers` | GetSciPapers | Download papers NOT in Zotero by DOI/ISBN/title |
| `/review` | Annotated Review | Multi-phase paper review (4 phases: review, verify, trust, output) |
| `/digest` | Research Digest | arXiv + OpenAlex digest by tracked topics |
| `/rss` | RSS News Digest | RSS feed digests by tag (research, general, events, jobs) |
| `/tikz` | TikZ Draw | Draw, refactor, extract, compile, or review structural TikZ figures |
| `/sage` | SageMath | Graph theory, combinatorics, algebra computations (local) |
| `/calibre` | Calibre | Ebook library on Google Drive |
| `/research-team` | Multi-Agent Research | Structured research sessions (proof verification, problem exploration, manuscript review, formalization) |
| `/digest-bridge` | Digest Bridge | Extract IDs from digests → getscipapers manifests |
| `/research-compute` | Modal Research Compute | Route heavy compute (enumeration, counterexample search, sweeps, GPU) to Modal via the local broker — see `@docs/modal-offload-routing.md` |

---

@docs/multi-agent-templates.md

---

## Task routing (automatic)

When the user asks a research question, select the appropriate system:

1. **Multi-agent structured session** → use `/research-team` skill
   Triggers: "multi-agent review", "panel review", "deep review", "verify proof",
   "stress-test", "find holes", "attack problem", "open problem", "pre-submission",
   "formalize", "Lean proof"

2. **Nontrivial single-agent research** → use `research-briefing`, then `deep-research`
   Use this for deeper topic research, literature landscape work, or any report-style research pass that needs visible scoping before execution.

3. **Quick specialist delegation** → `@agent`
   - Computation, conjectures, small cases, counterexamples → `@math-explorer`
   - Single proof step or section correctness → `@proof-checker`
   - Related work, citations, literature survey → `@literature-scout`
   - Single-reviewer paper review → `@paper-reviewer`

4. **Direct tool operation** → `/slash command`
   - Paper retrieval → `/zotero`, `/getscipapers`
   - Digests → `/digest`, `/rss`
   - Explicit TikZ / structural diagrams → `/tikz`
   - One-liner computation → `/sage`

If task needs adversarial multi-party verification → (1). If task needs a deeper single-agent research pass → (2). If task needs a focused specialist → (3). If task is a tool operation → (4). Pick the right system without asking the user.

## Research flow gates

For nontrivial research:

1. run `research-briefing` first and show a short visible `Research Brief`
2. execute the chosen research path
3. run `research-report-reviewer` before presenting a draft as final and show short visible `Review Findings`
4. run `research-verification-gate` before any "done", "final", or "complete" claim and show a short visible `Delivery Check`

Keep these gates concise. If the task is trivial, say so and skip the heavier gates.

---

## Coding discipline

Three rules govern all code changes. Violating any one is a defect.

1. **Think before coding** — Before writing any code, state your assumptions about what the request means and what approach you will take. When the request is ambiguous, present the plausible interpretations and ask which one to pursue. When a simpler approach exists than the one implied, say so and justify the alternative. When confused, stop and ask rather than guessing.

2. **Goal-driven execution** — Convert vague requests into concrete, verifiable goals before touching code. Prefer test-first: write a failing test that encodes the goal, then make it pass. For multi-step tasks, state the full step-and-verify plan up front so each step can be checked independently.

3. **Surgical changes** — Match the surrounding code's style, naming, and patterns exactly. Every changed line must trace directly to the current request. If you notice unrelated problems (dead code, latent bugs, style violations), mention them in your response but do not fix them.

## Evidence-first claims

For audits, reviews, migrations, integrations, comparisons, or any recommendation the user will likely act on, follow `@docs/evidence-first-protocol.md`: scope before conclusion, inspect primary evidence, state coverage and certainty, expose blocked inspection, and say `incomplete analysis` when material scope is unchecked.

## Engineering lifecycle

For non-trivial engineering work (ambiguous requirements, multi-file, architectural, or more than one session), follow `@docs/engineering-lifecycle.md`: Spec → Plan → Tasks → Implement → Verify. Templates live in `~/.claude/templates/`. TaskCreate is for in-session tracking, not a replacement for a persisted spec.

## Verification & debugging references

- `@docs/verification-patterns.md` — Existence ≠ Implementation: 4-level checklist (exists, substantive, wired, functional)
- `@docs/common-bug-patterns.md` — 11-category debugging heuristic with symptom→category mapping

## Tradeoff analysis

When facing explicit tradeoffs (signals: "or", "versus", "on one hand", multiple viable approaches):
1. Name each approach in ≤5 words
2. State what each optimizes for and what it sacrifices
3. Recommend one with reasoning tied to current goals
4. Offer "Skip analysis — I've decided" escape

Keep to 3-5 bullets max. Never activate for rhetorical "or" or simple yes/no.

## MANDATORY: Document lookup order (highest priority)

When a document is required for **any** task (review, research, reading, etc.):

1. **FIRST** — search the **Zotero** library (10,000+ papers). If found, retrieve the PDF.
2. **SECOND** — search the **Calibre** ebook library. If found, retrieve from there.
3. **LAST** — search **online** (use getscipapers for papers, or web search for other documents).

This order is **strict** — never skip a step. Always exhaust the previous source before moving to the next.

**NEVER** use `curl` or `wget` to download from publisher sites (paywalled, will fail). `WebFetch` is allowed for open-access pages, abstracts, and metadata on publisher domains (dl.acm.org, link.springer.com, etc.) but will fail on paywalled full-text PDFs — use Zotero/getscipapers for those.

## MANDATORY: Paper ingest rules (when adding papers)

1. **arXiv/preprint itemType** — ALL arXiv papers, preprints, manuscripts MUST have `itemType` set to `manuscript` (NOT `preprint`). After `zot add`, if source is arXiv or itemType is `preprint`, immediately run:
   ```
   bash ~/.claude/skills/_run.sh skills/zotero/run_zot.sh update <key> --item-type manuscript
   ```

2. **PDF naming** — the tool auto-renames using ZotFile pattern `{%a_}{%y_}{%t} {[%T]}`. Verify in output.

3. **Collection assignment** — NEVER add papers without a collection. Flow:
   - List collections: `zot.py list-collections --tree --json`
   - Extract topics from paper metadata
   - Suggest matching collections + offer "Create new..."
   - User picks (e.g. "1,3")
   - If user picks a parent with subcollections, show subtree and ask which level
   - Run `zot add <id> --collection "X" --collection "Y"`

4. **Deduplication** — different versions (arXiv + journal) are intentionally separate items. Only deduplicate by exact DOI match.

5. **Collection pagination** — the Zotero API returns max 100 collections per page. If a collection is "not found", check additional pages before creating a new one.

## MANDATORY: Multi-result disambiguation

When a search returns multiple results:
1. Show a numbered list (title, authors, year)
2. Ask: "Which one? Reply with the number."
3. Wait for user reply
4. Use `--index N` to select

NEVER guess which paper the user wants.

## Math formatting

Inline math: `$$...$$`. Block math: ` ```math ` fence. NEVER use `$...$`, `\(...\)`, or `\[...\]`.

## SageMath notes

SageMath runs locally at `~/sage/sage`. Use for anything beyond basic Python: chromatic polynomials, Tutte polynomials, automorphism groups, spectral analysis, finite fields, parallel computation. For simple graph checks (connectivity, bipartiteness, degree), just write Python/NetworkX code directly.

## Annotated Review notes

The review skill produces 3 outputs: annotated LaTeX PDF, PyMuPDF annotated PDF, and companion HTML. It requires 4 phases with independent agents:
- Phase A (Reviewer) and Phase B (Verifier) MUST have separate, clean contexts
- Phase C (Trust Verifier) also gets a separate context
- Zotero integration is OFF by default — only use `--zotero-key` when user explicitly requests

## Research Digest notes

Topics tracked in `~/.claude/data/research/alerts/topics.tsv`. Digests output to `~/.claude/data/research/alerts/digests/latest-digest.md`. After running, always read and summarize the top findings.

## Self-improvement

Claude Code has a self-improving agent with structured learning logs:
- Learnings: `~/.claude/learnings/{LEARNINGS,ERRORS,FEATURE_REQUESTS}.md`
- Hooks: `~/.claude/hooks/self-improvement/{activator,error-detector,review,session-search}.sh`
- Review pending: `bash ~/.claude/hooks/self-improvement/review.sh`
- Search sessions: `bash ~/.claude/hooks/self-improvement/session-search.sh "<query>"`

Log non-obvious discoveries to learnings. Promote recurring patterns (Recurrence-Count >= 3) to memory or CLAUDE.md.

@docs/file-paths.md
@{{ HOME }}/.claude/instructions/manuscript-writing-style.md
@{{ HOME }}/.openclaw/workspace/data/writing-style.md

<!-- ai-agents-skills:agent-group-discuss:start -->
- `agent-group-discuss`: Multi-agent discussion, review, and research orchestration.

<!-- ai-agents-skills:agent-group-discuss:end -->

<!-- ai-agents-skills:annotated-review:start -->
- `annotated-review`: Annotated paper review workflow when both annotation and review are requested.

<!-- ai-agents-skills:annotated-review:end -->

<!-- ai-agents-skills:calibre:start -->
- `calibre`: Calibre ebook lookup and library helper workflows.

<!-- ai-agents-skills:calibre:end -->

<!-- ai-agents-skills:database-lookup:start -->
- `database-lookup`: Structured public scientific, biomedical, regulatory, materials, and economic database lookups.

<!-- ai-agents-skills:database-lookup:end -->


<!-- ai-agents-skills:deep-research-workflow:start -->
- `deep-research-workflow`: Phased source-preserving research workflow: search, analyze, write, with citation handoff.

<!-- ai-agents-skills:deep-research-workflow:end -->

<!-- ai-agents-skills:digest-bridge:start -->
- `digest-bridge`: Convert digest output into paper retrieval manifests.

<!-- ai-agents-skills:digest-bridge:end -->

<!-- ai-agents-skills:docling:start -->
- `docling`: Parse, convert, OCR, chunk, and analyze documents.

<!-- ai-agents-skills:docling:end -->

<!-- ai-agents-skills:formal-skeleton-helper:start -->
- `formal-skeleton-helper`: Generate minimal Lean-style theorem skeletons, namespace wrappers, and formal statement stubs.

<!-- ai-agents-skills:formal-skeleton-helper:end -->

<!-- ai-agents-skills:get-available-resources:start -->
- `get-available-resources`: Detect CPU, memory, disk, and optional accelerator availability before heavy local work.

<!-- ai-agents-skills:get-available-resources:end -->

<!-- ai-agents-skills:getscipapers-requester:start -->
- `getscipapers-requester`: External paper retrieval fallback after local library checks.

<!-- ai-agents-skills:getscipapers-requester:end -->

<!-- ai-agents-skills:graph-verifier:start -->
- `graph-verifier`: Lightweight graph sanity checks.

<!-- ai-agents-skills:graph-verifier:end -->

<!-- ai-agents-skills:modal-research-compute:start -->
- `modal-research-compute`: Route heavy compute jobs to Modal through a local broker.

<!-- ai-agents-skills:modal-research-compute:end -->

<!-- ai-agents-skills:model-router:start -->
- `model-router`: Choose an appropriate model, reasoning level, and role for subagents or multi-agent research work.

<!-- ai-agents-skills:model-router:end -->

<!-- ai-agents-skills:paper-lookup:start -->
- `paper-lookup`: External paper metadata and discovery fallback.

<!-- ai-agents-skills:paper-lookup:end -->

<!-- ai-agents-skills:paper-review:start -->
- `paper-review`: Single-agent paper review workflow.

<!-- ai-agents-skills:paper-review:end -->

<!-- ai-agents-skills:prose:start -->
- `prose`: Structured reproducible research and workflow orchestration.

<!-- ai-agents-skills:prose:end -->


<!-- ai-agents-skills:research-briefing:start -->
- `research-briefing`: Scope nontrivial research before execution with evidence plan and workflow recommendation.

<!-- ai-agents-skills:research-briefing:end -->

<!-- ai-agents-skills:research-digest-wrapper:start -->
- `research-digest-wrapper`: Run tracked-topic research digests.

<!-- ai-agents-skills:research-digest-wrapper:end -->


<!-- ai-agents-skills:research-report-reviewer:start -->
- `research-report-reviewer`: Review draft research reports for unsupported claims, ambiguity, and evidence gaps.

<!-- ai-agents-skills:research-report-reviewer:end -->

<!-- ai-agents-skills:research-verification-gate:start -->
- `research-verification-gate`: Final evidence, date, and gap check before delivery.

<!-- ai-agents-skills:research-verification-gate:end -->

<!-- ai-agents-skills:rss-news-digest:start -->
- `rss-news-digest`: Run and manage RSS digest workflows.

<!-- ai-agents-skills:rss-news-digest:end -->

<!-- ai-agents-skills:sagemath:start -->
- `sagemath`: Sage-backed math, graph theory, algebra, and verification.

<!-- ai-agents-skills:sagemath:end -->


<!-- ai-agents-skills:self-improving-agent:start -->
- `self-improving-agent`: Log durable learnings and propose canonical repo integration plans across install targets.

<!-- ai-agents-skills:self-improving-agent:end -->

<!-- ai-agents-skills:session-logs:start -->
- `session-logs`: Search prior local agent session logs when explicitly requested.

<!-- ai-agents-skills:session-logs:end -->


<!-- ai-agents-skills:source-research:start -->
- `source-research`: General web and source-gathering research workflow for current-information synthesis.

<!-- ai-agents-skills:source-research:end -->

<!-- ai-agents-skills:tikz-draw:start -->
- `tikz-draw`: Structural TikZ figure generation, compile, review, and semantic checks.

<!-- ai-agents-skills:tikz-draw:end -->

<!-- ai-agents-skills:vnthuquan:start -->
- `vnthuquan`: Vietnam Thu Quan ebook discovery, validation, dry-run download, and Calibre dry-run handoff.

<!-- ai-agents-skills:vnthuquan:end -->

<!-- ai-agents-skills:workspace-rearranger:start -->
- `workspace-rearranger`: Plan safe workspace organization with dry-run first, explicit apply, and no silent deletion.

<!-- ai-agents-skills:workspace-rearranger:end -->

<!-- ai-agents-skills:zotero:start -->
- `zotero`: Zotero paper search, retrieval, ingest, and collection workflow.

<!-- ai-agents-skills:zotero:end -->


<!-- ai-agents-skills:repo-management:start -->
## ai-agents-skills management notice

This agent home may contain files managed by the `ai-agents-skills`
repository. The repository is the source for reusable skill bodies,
optional workflow artifacts, dependency metadata, and installer state.
Local agent directories remain runtime targets and may still contain
user-owned files outside this managed block.

Use `plan` or `audit-system` before applying changes. Uninstall and
rollback remove only managed files and managed blocks recorded by this
installer.

Generated target: claude.
<!-- ai-agents-skills:repo-management:end -->

<!-- ai-agents-skills:cross-agent-delegation:start -->
- `cross-agent-delegation`: Cross-agent delegation packet contract for bounded parent-controlled handoffs.

<!-- ai-agents-skills:cross-agent-delegation:end -->

<!-- ai-agents-skills:draft-writing:start -->
- `draft-writing`: Claim-preserving draft writing workflow for controlled rewriting, polishing, and revision audits.

<!-- ai-agents-skills:draft-writing:end -->


<!-- ai-agents-skills:axiom-axle-mcp:start -->
- `axiom-axle-mcp`: Optional inert setup helper for AxiomMath AXLE MCP formal-proof assistance.

<!-- ai-agents-skills:axiom-axle-mcp:end -->

<!-- ai-agents-skills:lean-formalization-intake:start -->
- `lean-formalization-intake`: Optional local-first Lean formalization intake and suitability decision workflow.

<!-- ai-agents-skills:lean-formalization-intake:end -->

<!-- ai-agents-skills:lean-strict-verification-gate:start -->
- `lean-strict-verification-gate`: Scanner-first Lean artifact verification gate that separates typecheck status from claim support.

<!-- ai-agents-skills:lean-strict-verification-gate:end -->


<!-- ai-agents-skills:submission-venue-selector:start -->
- `submission-venue-selector`: Evidence-gated journal and conference venue selection for scholarly drafts; deliverable rankings require comparator-paper evidence.

- `submission-venue-selector` delivery gate: ranked recommendations require comparator-paper evidence for every ranked venue; otherwise report `incomplete analysis` and `not-ready`.
<!-- ai-agents-skills:submission-venue-selector:end -->

<!-- ai-agents-skills:autonomous-research-loop:start -->
- `autonomous-research-loop`: Run bounded autonomous research iterations with evidence gates, recovery ledgers, and optional cross-agent handoffs.

<!-- ai-agents-skills:autonomous-research-loop:end -->

<!-- ai-agents-skills:autonomous-research-loop-runtime:start -->
- `autonomous-research-loop-runtime`: Offline runtime helper for autonomous research loop ledger initialization, iteration appends, validation, status, and selftest.

<!-- ai-agents-skills:autonomous-research-loop-runtime:end -->

<!-- ai-agents-skills:lean-explore-mcp:start -->
- `lean-explore-mcp`: Optional inert LeanExplore MCP setup helper for Lean declaration search.

<!-- ai-agents-skills:lean-explore-mcp:end -->

<!-- ai-agents-skills:vnu-eoffice:start -->
- `vnu-eoffice`: Use VNU eOffice functions from any supported agent target: monitor updates, list latest incoming/outgoing documents, search by keyword, download attachments, and send requested files through Telegram.

<!-- ai-agents-skills:vnu-eoffice:end -->
