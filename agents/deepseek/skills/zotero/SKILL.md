---
name: zotero
description: DeepSeek adapter for the Codex Zotero-first paper and library workflow.
---

# Zotero

Source Codex skill: `~/.codex/skills/zotero/SKILL.md`

Runtime command family: `bash ~/.codex/runtime/run_skill.sh skills/zotero/run_zot.sh ...`

Before acting, inspect the source Codex skill.

Common commands:

```bash
bash ~/.codex/runtime/run_skill.sh skills/zotero/run_zot.sh --json get "<query>"
```

```bash
bash ~/.codex/runtime/run_skill.sh skills/zotero/run_zot.sh add "<DOI or arXiv or URL>" --collection "<name>"
```

```bash
bash ~/.codex/runtime/run_skill.sh skills/zotero/run_zot.sh update <key> --item-type manuscript
```

DeepSeek-specific behavior:

- `/skill zotero` activates this adapter for the next request.
- Use Zotero first for paper requests.
- If results are ambiguous, show numbered candidates and wait for the selected index.
- Use `calibre` second for review tasks needing a document when Zotero does not satisfy the request.
- Use `getscipapers_requester` only as the external fallback.
