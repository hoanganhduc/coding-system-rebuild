---
name: research-router
description: DeepSeek adapter that routes research requests to the Codex-backed local research skills.
---

# Research Router

Source policy: `~/.deepseek/AGENTS.md`

Source Codex references:

- `~/.codex/AGENTS.md`
- `~/.codex/instructions/research-quick-actions.md`

Before acting, inspect the relevant source policy or skill doc. If DeepSeek file tools cannot read `~/.codex`, use an approved shell read such as:

```bash
sed -n '1,220p' ~/.codex/skills/<skill>/SKILL.md
```

Routing:

- Nontrivial research setup: `research-briefing`
- Phased source-preserving research: `deep-research-workflow`
- General current/source gathering: `openclaw-research`
- Paper/library requests: `zotero` first
- Review document lookup after Zotero: `calibre`
- External retrieval fallback: `getscipapers_requester`
- Local document parsing: `docling`
- Literature metadata discovery: `paper-lookup`
- Structured public databases: `database-lookup`
- Draft/report review: `research-report-reviewer`
- Final delivery gate: `research-verification-gate`
- Tracked-topic digest: `research_digest_wrapper`
- RSS digest or feed management: `rss_news_digest`
- Digest-to-paper manifest bridge: `digest_bridge`
- Structural TikZ figures: `tikz-draw`
- Heavy math or Sage-backed verification: `sagemath`
- Lightweight graph checks: `graph_verifier`
- Local resource preflight for heavy work: `get-available-resources`
- Explicit multi-agent discussion/review/research: `agent_group_discuss`
- Structured OpenProse-style workflow: `prose`
- Codex sub-agent model choice: `smart_model_router`
- Durable learning/error logging: `self_improving_agent`

DeepSeek-specific behavior:

- `/skill research-router` activates this adapter for the next request.
- Do not assume Codex automatic skill triggers are enforced by DeepSeek.
- If the task needs action, show the user a short plan before execution.
- If multiple paper/book results appear, ask for the selected index instead of guessing.
- Do not activate multi-agent workflows unless the user explicitly asks for them and confirms the plan.
