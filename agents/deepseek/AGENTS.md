# DeepSeek Research Assistant

DeepSeek research work in this workspace is backed by the Codex research stack under `~/.codex`. Use DeepSeek-native config, workspace instructions, skills, MCP, and modes; do not copy Codex runtime files or secrets into `~/.deepseek`.

## Scope And Defaults

- Current workspace: `~/.deepseek`.
- Verified command: `deepseek-tui`; the `deepseek` facade may be absent.
- Codex skill docs: `~/.codex/skills/`.
- Codex runtime runner: `bash ~/.codex/runtime/run_skill.sh`.
- Runtime-backed skills execute inside `~/.codex/runtime/workspace`.
- Do not depend on `~/.openclaw` or `~/.claude` unless the user explicitly asks for legacy data.
- Do not copy or print `~/.codex/auth.json`, runtime secrets, API keys, or provider credentials.

## Workflow Rules

1. Check relevant docs, helper scripts, skill instructions, project instructions, or `--help` before substantive action.
2. Show a short explicit plan before execution.
3. If the user asks only for analysis, planning, or verification, stop there.
4. For nontrivial research, use the sequence: Research Brief, research workflow, Review Findings, Delivery Check.
5. For factual claims, state inspected evidence, assumptions, and gaps. If material scope remains unchecked, say `incomplete analysis` and list what remains unchecked.
6. Run the narrowest meaningful verification after changing instructions, scripts, configs, or behavior-affecting files.

## DeepSeek Skill Behavior

- DeepSeek skills live in child directories containing `SKILL.md`.
- Use `/skills` to list skills and `/skill <name>` to activate a skill for the next user request.
- DeepSeek does not enforce Codex skill metadata, trigger rules, or `allowed-tools` fields.
- Each local DeepSeek skill is an adapter. It should inspect the canonical Codex skill doc, then follow the DeepSeek wrapper instructions.
- Workspace-local `.agents/skills` or `skills` directories can shadow global `~/.deepseek/skills`; verify `skills.selected` with `deepseek-tui doctor --json` when behavior is unexpected.

## Manuscript Writing Style

For mathematical manuscript or LaTeX paper-editing tasks, first read:

- `{{ HOME }}/.deepseek/instructions/manuscript-writing-style.md`
- `{{ HOME }}/.openclaw/workspace/data/writing-style.md`

The DeepSeek adapter points to the same remote canonical OpenClaw style source.
These profiles supplement the current paper's style and do not replace proof
checking, citation checking, or project instructions.

## Research Routing

Use `research-router` first when the request needs routing.

| User intent | DeepSeek skill |
| --- | --- |
| Scope nontrivial research | `research-briefing` |
| Phased source-preserving research | `deep-research-workflow` |
| General source gathering or current lookup | `openclaw-research` |
| Find, get, send, retrieve, add, or search for a paper | `zotero` |
| Ebook or Calibre-library operation | `calibre` |
| External paper retrieval fallback | `getscipapers_requester` |
| Parse, convert, chunk, or structurally analyze documents | `docling` |
| External paper metadata or discovery | `paper-lookup` |
| Structured public database lookup | `database-lookup` |
| Review a research draft before delivery | `research-report-reviewer` |
| Final delivery readiness check | `research-verification-gate` |
| Tracked-topic digest | `research_digest_wrapper` |
| RSS digest or feed management | `rss_news_digest` |
| Digest output to paper manifest | `digest_bridge` |
| Structural TikZ figures | `tikz-draw` |
| Heavy math or Sage-backed verification | `sagemath` |
| Lightweight graph sanity checks | `graph_verifier` |
| Heavy local compute preflight | `get-available-resources` |
| Explicit multi-agent discussion/review/research | `agent_group_discuss` |
| OpenProse-style structured workflow | `prose` |
| Codex sub-agent model choice | `smart_model_router` |
| Durable learning/error logging | `self_improving_agent` |

## Mandatory Paper Routing

When the user asks to get, send, find, retrieve, download, fetch, or share a paper, DOI, ISBN, or book:

1. Use `zotero` first.
2. For review tasks that need the document and no path/file was supplied, use `calibre` second.
3. Use `getscipapers_requester` only after the local-library path fails or when the user explicitly wants external retrieval.
4. Never replace this flow with direct `curl`, `wget`, publisher-site scraping, or ad hoc browser downloads.

If a search returns multiple results, show a numbered list with title, authors, and year. Ask the user which one they want and wait for the selected index.

## Runtime Command Pattern

Prefer the shared runner:

```bash
bash ~/.codex/runtime/run_skill.sh skills/<skill>/run_<tool>.sh <args>
```

Before running a runtime-backed skill for the first time in a session, prefer a `doctor` or `--help` command when available.

## Multi-Agent Work

Do not start multi-agent discussion, panel review, or parallel research unless the user explicitly asks for it and confirms the plan. When needed, route through the relevant Codex skill docs first.

## Settings Boundaries

- `~/.deepseek/config.toml` is startup config for provider, model, paths, shell, approval, sandbox, MCP, and feature policy.
- `~/.config/deepseek/settings.toml` is UI preference state.
- Do not create a startup config file unless defaults and environment variables are insufficient.
- Do not pin `sandbox_mode` until runtime preflight shows the required workspace access.

<!-- ai-agents-skills:annotated-review:start -->
- `annotated-review`: Annotated paper review workflow when both annotation and review are requested.

<!-- ai-agents-skills:annotated-review:end -->

<!-- ai-agents-skills:autonomous-research-loop:start -->
- `autonomous-research-loop`: Run bounded autonomous research iterations with evidence gates, recovery ledgers, and optional cross-agent handoffs.

<!-- ai-agents-skills:autonomous-research-loop:end -->

<!-- ai-agents-skills:autonomous-research-loop-runtime:start -->
- `autonomous-research-loop-runtime`: Offline runtime helper for autonomous research loop ledger initialization, iteration appends, validation, status, and selftest.

<!-- ai-agents-skills:autonomous-research-loop-runtime:end -->

<!-- ai-agents-skills:behavior-preserving-cleanup:start -->
- `behavior-preserving-cleanup`: Clarity-only edit pass behind a comprehension gate with verify-after-each-change so behavior stays fixed.

<!-- ai-agents-skills:behavior-preserving-cleanup:end -->

<!-- ai-agents-skills:calibre:start -->
- `calibre`: Calibre ebook lookup and library helper workflows.

<!-- ai-agents-skills:calibre:end -->

<!-- ai-agents-skills:cross-agent-delegation:start -->
- `cross-agent-delegation`: Cross-agent delegation packet contract for bounded parent-controlled handoffs.

<!-- ai-agents-skills:cross-agent-delegation:end -->

<!-- ai-agents-skills:decision-doubt-loop:start -->
- `decision-doubt-loop`: In-flight fresh-context adversarial review of a non-trivial decision before it stands.

<!-- ai-agents-skills:decision-doubt-loop:end -->

<!-- ai-agents-skills:deep-research-workflow:start -->
- `deep-research-workflow`: Phased source-preserving research workflow: search, analyze, write, with citation handoff.

<!-- ai-agents-skills:deep-research-workflow:end -->

<!-- ai-agents-skills:docling:start -->
- `docling`: Parse, convert, OCR, chunk, and analyze documents.

<!-- ai-agents-skills:docling:end -->

<!-- ai-agents-skills:draft-writing:start -->
- `draft-writing`: Claim-preserving draft writing workflow for controlled rewriting, polishing, and revision audits.

<!-- ai-agents-skills:draft-writing:end -->

<!-- ai-agents-skills:formal-skeleton-helper:start -->
- `formal-skeleton-helper`: Generate minimal Lean-style theorem skeletons, namespace wrappers, and formal statement stubs.

<!-- ai-agents-skills:formal-skeleton-helper:end -->

<!-- ai-agents-skills:get-available-resources:start -->
- `get-available-resources`: Detect CPU, memory, disk, and optional accelerator availability before heavy local work.

<!-- ai-agents-skills:get-available-resources:end -->

<!-- ai-agents-skills:intent-interview:start -->
- `intent-interview`: Elicit and confirm real intent one question at a time before any brief, spec, or code.

<!-- ai-agents-skills:intent-interview:end -->

<!-- ai-agents-skills:lean-explore-mcp:start -->
- `lean-explore-mcp`: Optional inert LeanExplore MCP setup helper for Lean declaration search.

<!-- ai-agents-skills:lean-explore-mcp:end -->

<!-- ai-agents-skills:lean-formalization-intake:start -->
- `lean-formalization-intake`: Optional local-first Lean formalization intake and suitability decision workflow.

<!-- ai-agents-skills:lean-formalization-intake:end -->

<!-- ai-agents-skills:lean-strict-verification-gate:start -->
- `lean-strict-verification-gate`: Scanner-first Lean artifact verification gate that separates typecheck status from claim support.

<!-- ai-agents-skills:lean-strict-verification-gate:end -->

<!-- ai-agents-skills:manim-math-animation:start -->
- `manim-math-animation`: Render Manim math animations (handwritten-style equation Write, equation morphing, emphasis) to a silent clip normalized for splicing into slides-to-video or standalone use.

<!-- ai-agents-skills:manim-math-animation:end -->

<!-- ai-agents-skills:modal-research-compute:start -->
- `modal-research-compute`: Route heavy compute jobs to Modal through a local broker.

<!-- ai-agents-skills:modal-research-compute:end -->

<!-- ai-agents-skills:paper-review:start -->
- `paper-review`: Single-agent paper review workflow.

<!-- ai-agents-skills:paper-review:end -->

<!-- ai-agents-skills:research-briefing:start -->
- `research-briefing`: Scope nontrivial research before execution with evidence plan and workflow recommendation.

<!-- ai-agents-skills:research-briefing:end -->

<!-- ai-agents-skills:research-report-reviewer:start -->
- `research-report-reviewer`: Review draft research reports for unsupported claims, ambiguity, and evidence gaps.

<!-- ai-agents-skills:research-report-reviewer:end -->

<!-- ai-agents-skills:research-verification-gate:start -->
- `research-verification-gate`: Final evidence, date, and gap check before delivery.

<!-- ai-agents-skills:research-verification-gate:end -->

<!-- ai-agents-skills:sagemath:start -->
- `sagemath`: Sage-backed math, graph theory, algebra, and verification.

<!-- ai-agents-skills:sagemath:end -->

<!-- ai-agents-skills:send-email:start -->
- `send-email`: Send email over SMTP using only the Python standard library: plain-text and HTML bodies, attachments, cc/bcc, reply-to, dry-run preview, connection verification, and redacted config inspection.

<!-- ai-agents-skills:send-email:end -->

<!-- ai-agents-skills:slides-to-video:start -->
- `slides-to-video`: Turn prepared slides (PNG/PDF/PPTX) into a narrated, captioned video in a chosen language and presenter role using only free tools; three-phase human-in-the-loop with an approval gate before rendering.

<!-- ai-agents-skills:slides-to-video:end -->

<!-- ai-agents-skills:source-grounded-decisions:start -->
- `source-grounded-decisions`: Ground version- and spec-sensitive decisions in cited authoritative sources; flag when unverified.

<!-- ai-agents-skills:source-grounded-decisions:end -->

<!-- ai-agents-skills:tikz-draw:start -->
- `tikz-draw`: Structural TikZ figure generation, compile, review, and semantic checks.

<!-- ai-agents-skills:tikz-draw:end -->

<!-- ai-agents-skills:url-to-screenshot:start -->
- `url-to-screenshot`: Capture a URL to a clean PNG screenshot with browser detection, cookie-consent dismissal, viewport or full-page modes, timeouts, SSRF-safe URL admission, and blank-output verification across Linux, macOS, and Windows.

<!-- ai-agents-skills:url-to-screenshot:end -->

<!-- ai-agents-skills:vnthuquan:start -->
- `vnthuquan`: Vietnam Thu Quan ebook discovery, validation, dry-run download, and Calibre dry-run handoff.

<!-- ai-agents-skills:vnthuquan:end -->

<!-- ai-agents-skills:vnu-eoffice:start -->
- `vnu-eoffice`: Route VNU eOffice requests to an existing vnu_eoffice package or CLI: monitor updates, list latest incoming/outgoing documents, search by keyword, download attachments, and send requested files through Telegram.

<!-- ai-agents-skills:vnu-eoffice:end -->


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

Generated target: deepseek.
<!-- ai-agents-skills:repo-management:end -->

<!-- ai-agents-skills:adversarial-boundary-gate:start -->
- `adversarial-boundary-gate`: Pre-delivery threat-model of trust boundaries and an abuse-case/injection check, delegating to a fresh-context security reviewer.

<!-- ai-agents-skills:adversarial-boundary-gate:end -->

<!-- ai-agents-skills:axiom-axle-mcp:start -->
- `axiom-axle-mcp`: Optional inert setup helper for AxiomMath AXLE MCP formal-proof assistance.

<!-- ai-agents-skills:axiom-axle-mcp:end -->

<!-- ai-agents-skills:database-lookup:start -->
- `database-lookup`: Structured public scientific, biomedical, regulatory, materials, and economic database lookups.

<!-- ai-agents-skills:database-lookup:end -->

<!-- ai-agents-skills:paper-lookup:start -->
- `paper-lookup`: External paper metadata and discovery fallback.

<!-- ai-agents-skills:paper-lookup:end -->

<!-- ai-agents-skills:prose:start -->
- `prose`: Structured reproducible research and workflow orchestration.

<!-- ai-agents-skills:prose:end -->

<!-- ai-agents-skills:session-logs:start -->
- `session-logs`: Search prior local agent session logs when explicitly requested.

<!-- ai-agents-skills:session-logs:end -->

<!-- ai-agents-skills:submission-venue-selector:start -->
- `submission-venue-selector`: Evidence-gated journal and conference venue selection for scholarly drafts; deliverable rankings require comparator-paper evidence.

- `submission-venue-selector` delivery gate: ranked recommendations require comparator-paper evidence for every ranked venue; otherwise report `incomplete analysis` and `not-ready`.
<!-- ai-agents-skills:submission-venue-selector:end -->

<!-- ai-agents-skills:url-to-screenshot-runtime:start -->
- `url-to-screenshot-runtime`: Runtime engine for url-to-screenshot: headless-browser CDP capture, SSRF-safe URL admission, consent dismissal, blank-output detection, and an offline self-test of the deterministic core.

<!-- ai-agents-skills:url-to-screenshot-runtime:end -->

<!-- ai-agents-skills:workspace-rearranger:start -->
- `workspace-rearranger`: Plan safe workspace organization with dry-run first, explicit apply, and no silent deletion.

<!-- ai-agents-skills:workspace-rearranger:end -->

<!-- ai-agents-skills:agent-group-discuss:start -->
- `agent-group-discuss`: Multi-agent discussion, review, and research orchestration.

<!-- ai-agents-skills:agent-group-discuss:end -->

<!-- ai-agents-skills:digest-bridge:start -->
- `digest-bridge`: Convert digest output into paper retrieval manifests.

<!-- ai-agents-skills:digest-bridge:end -->

<!-- ai-agents-skills:getscipapers-requester:start -->
- `getscipapers-requester`: External paper retrieval fallback after local library checks.

<!-- ai-agents-skills:getscipapers-requester:end -->

<!-- ai-agents-skills:graph-verifier:start -->
- `graph-verifier`: Lightweight graph sanity checks.

<!-- ai-agents-skills:graph-verifier:end -->

<!-- ai-agents-skills:model-router:start -->
- `model-router`: Choose an appropriate model, reasoning level, and role for subagents or multi-agent research work.

<!-- ai-agents-skills:model-router:end -->

<!-- ai-agents-skills:research-digest-wrapper:start -->
- `research-digest-wrapper`: Run tracked-topic research digests.

<!-- ai-agents-skills:research-digest-wrapper:end -->

<!-- ai-agents-skills:rss-news-digest:start -->
- `rss-news-digest`: Run and manage RSS digest workflows.

<!-- ai-agents-skills:rss-news-digest:end -->

<!-- ai-agents-skills:self-improving-agent:start -->
- `self-improving-agent`: Log durable learnings and propose canonical repo integration plans across install targets.

<!-- ai-agents-skills:self-improving-agent:end -->

<!-- ai-agents-skills:source-research:start -->
- `source-research`: General web and source-gathering research workflow for current-information synthesis.

<!-- ai-agents-skills:source-research:end -->
