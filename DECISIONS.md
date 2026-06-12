# DECISIONS.md — append-only

Format: `YYYY-MM-DD  <decision> — <why>`. Never edit existing entries; only append.
OpenClaw-slice decisions continue in the OpenClaw rebuild plan §6, not here.

```
2026-06-12  Secrets archive: single AES-256 zip via 7-Zip CLI (-tzip -mem=AES256); SEVENZ resolved as 7zz||7z — Ubuntu package/binary naming varies; stock zip is ZipCrypto (broken), stock unzip cannot read AES zips
2026-06-12  Umbrella repo orchestrates openclaw-bot + ai-agents-skills as pinned clones via components.lock, not submodules — openclaw-bot was not yet a git repo; live checkouts already exist; external/ stays out of leak surface
2026-06-12  Secrets scope comprehensive: SSH keys, gh hosts.yml, tailscale authkey, docker config, all agent secret files, all ~/.config credentials, modal, rclone, bashrc env exports — user decision
2026-06-12  Heavy deps replicated natively as-is; no new dockerization — exact replication requirement; existing skills call host binaries by path
2026-06-12  Ollama excluded from rebuild (optional one-liner in docs) — verified unused: no model chain routes to it, digest LLM flags default off, zero inference traffic in 30 days
2026-06-12  elan/Lean kept; toolchains never archived (elan reinstalls from per-project lean-toolchain pins) — verified used by PrivateResearchRepo/PrivateProject formalization and lean-* skills
2026-06-12  make prepare installs everything by default with SKIP_* toggles + size warnings — user decision
2026-06-12  Personal-but-not-secret state (Claude memory, learnings, writing-style profile, zotero/calibre skill configs) rides in the encrypted zip — small, not regenerable
2026-06-12  make backup commits locally only; push always manual via make push (re-runs leak scan; first push also scans history) — leak-check false negative must not go public automatically
2026-06-12  Syncthing ignored entirely (not installed, not backed up) — user decision
2026-06-12  Personal work repos ignored entirely, including ~/openclaw-src — user decision; repos recoverable from GitHub; work content is out of system scope
2026-06-12  DeepSeek settings in OpenClaw ignored: openclaw.json template strips deepseek plugin/provider/model-primaries to {{ DEFAULT_PRIMARY_MODEL }} — user decision; custom plugin lived in ignored ~/openclaw-src; DeepSeek CLI agents (~/.codewhale, ~/.deepseek) remain fully in scope
2026-06-12  Tailscale TLS pair in ~/openclaw-src NOT archived — referenced by no config (only funnel URLs in openclaw.json); tailscale cert regenerates on demand
2026-06-12  Manifest fail-closed roots include .gemini and .ai-agents-skills state home — adversarial review found both unclassified; .claude/skills NOT blanket-delegated (_run.sh + skill scripts are user-owned)
2026-06-12  ELF binaries never public-copied (sync refuses by magic bytes); reinstalled per-arch — agy/deepseek/deepseek-tui are aarch64-only
```
