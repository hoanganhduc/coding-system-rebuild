# Coding System Rebuild

Backup/restore system for a complete multi-agent coding/research machine:
**Claude Code, Codex, GitHub Copilot CLI, OpenCode, CodeWhale + DeepSeek CLI,
Gemini/AntiGravity CLI, and OpenClaw**, plus the system layer they run on
(npm globals, Python environments, Docker images, systemd user services, cron,
shell environment, TeX Live, Calibre, Lean/elan, Rust/Bun toolchains).

```
                ┌──────────────────────────────┐   ┌──────────────────────────┐
                │ PUBLIC repo (this)           │   │ PRIVATE secrets zip      │
                │  configs (sanitized),        │   │  AES-256, single file    │
                │  skills, scripts, Makefile,  │   │  every key/token/cred +  │
                │  manifests, docs             │   │  small personal state    │
                └──────────────┬───────────────┘   └─────────────┬────────────┘
                               │        make install SECRETS=…   │
                               ▼                                 ▼
                        ┌─────────────────────────────────────────────┐
                        │           fresh Ubuntu 24.04 machine        │
                        │              (amd64 or arm64)               │
                        └─────────────────────────────────────────────┘
```

Two existing repositories are orchestrated as **pinned components**
(`components.lock`), not duplicated:

| Component | Role |
|---|---|
| [`openclaw-bot`](https://github.com/hoanganhduc/openclaw-bot) | OpenClaw slice: sanitized config templates, workspace skills, lifecycle scripts |
| [`ai-agents-skills`](https://github.com/hoanganhduc/ai-agents-skills) | Cross-agent skill installer (canonical skill bodies, per-agent targets) |

## Quickstart (fresh machine)

```bash
sudo apt-get install -y git make 7zip
git clone https://github.com/hoanganhduc/coding-system-rebuild
cd coding-system-rebuild
make doctor                                   # preflight
make install SECRETS=/path/to/coding-system-secrets-<stamp>.zip
make test                                     # verify everything
```

Without the secrets zip, `make install` still completes in **degraded mode**
and prints exactly which feature each missing secret disables
(see `make verify-secrets --degraded` and [SECRETS.md](SECRETS.md)).

## Routine use (source machine)

```bash
make backup    # refresh state → sanitize-capture → leak-scan → local commit → new zip
git show       # review what changed
make push      # leak-scans again, then publishes (always manual)
```

## Target matrix

| | amd64 | arm64 (origin) |
|---|---|---|
| Agents + skills + services | ✅ | ✅ |
| SageMath docker image | ❌ skipped (image is arm64-only) | ✅ |
| `agy`/`deepseek` local binaries | reinstall per-arch | ✅ |

## Documents

- [INSTALL.md](INSTALL.md) — phase-by-phase install, SKIP_* toggles, degraded mode
- [SECRETS.md](SECRETS.md) — every secret: where to get it, where it lives, what breaks
- [ARCHITECTURE.md](ARCHITECTURE.md) — surfaces, manifest semantics, delegation boundaries
- [BACKUP-RESTORE.md](BACKUP-RESTORE.md) — runbooks, zip rotation, restore drills
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — known post-install fixes
- [../DECISIONS.md](../DECISIONS.md) — append-only decision log
