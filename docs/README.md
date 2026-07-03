# Documentation index

Project overview, quickstart, routine use, and the target matrix live in the
[root README](../README.md) — this folder holds the detailed documents only,
so the two never drift.

- [INSTALL.md](INSTALL.md) — phase-by-phase install, SKIP_* toggles, degraded mode
- [SECRETS.md](SECRETS.md) — every secret: where to get it, where it lives, what breaks
- [ARCHITECTURE.md](ARCHITECTURE.md) — surfaces, manifest semantics, delegation boundaries
- [BACKUP-RESTORE.md](BACKUP-RESTORE.md) — runbooks, zip rotation, restore drills
- [CODESPACES.md](CODESPACES.md) — live interactive replica in a GitHub Codespace
- [github-actions-experiment-runner-plan.md](github-actions-experiment-runner-plan.md) — the `research_compute` GitHub Actions / Modal compute broker: design + the GHA compute lane (day-to-day routing/usage is the installed `github-actions-offload-routing` instruction, delivered by ai-agents-skills)
- [CI.md](CI.md) — GitHub Actions rehearsal (no-secrets + key live-tests)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — known post-install fixes
- [../DECISIONS.md](../DECISIONS.md) — append-only decision log
