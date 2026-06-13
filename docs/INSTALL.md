# INSTALL — fresh Ubuntu 24.04 (amd64 / arm64)

## 0. What you need

1. This repo (public).
2. The secrets zip + its password (see [SECRETS.md](SECRETS.md)). Optional —
   without it the install completes in **degraded mode**.
3. A user with sudo. Examples assume user `ubuntu`; any user works — every
   captured path is `{{ HOME }}`-templated and rendered at install time.

## 1. Bootstrap

```bash
sudo apt-get update && sudo apt-get install -y git make 7zip
git clone https://github.com/hoanganhduc/coding-system-rebuild
cd coding-system-rebuild
make doctor
```

`doctor` hard-fails on: no network, missing git/make/python3/python3-yaml, no
7-Zip CLI. It warns on: <60GB free disk, missing linger, non-24.04, amd64
(SageMath image is arm64-only).

## 2. Full install

```bash
make install SECRETS=/path/to/coding-system-secrets-<stamp>.zip
# password read from CSR_SECRETS_PASSWORD or prompted
```

Phases (each gated; resume after a failure with `PHASE=<n> bin/install.sh`):

| # | Phase | Gate |
|---|---|---|
| 1 | doctor + dirs | doctor exit 0 |
| 2 | prepare: apt, xtradeb PPA (chromium/calibre), texlive-full, tailscale, NodeSource node 22, npm prefix, npm globals (pinned), pipx, rustup, bun, elan, modal, docker, images | binaries respond |
| 3 | restore secrets + chmod fixups (+ `tailscale up --authkey` if provided) | required entries present |
| 5 | components: clone openclaw-bot → `external/`, ai-agents-skills → `~/ai-agents-skills` (single source of truth), at locked SHAs | HEAD == lock |
| 6 | render configs/scripts/symlinks into $HOME | no unresolved `{{ HOME }}` |
| 7 | OpenClaw slice via openclaw-bot (`--skip-docker --skip-services`); npm install channel plugins | secrets untouched; no dangling refs |
| 8 | `research_compute` broker installed from `~/ai-agents-skills` (`install --apply --real-system --backup-replace --skills modal-research-compute`) + `verify` | broker runs via the `_run.sh` shim |
| 8b| re-overlay zip secrets; `_run.sh` sha check | verify-secrets OK |
| 9 | python envs from pip freezes (workspace-local target dir, ~/.venvs, docling-venv, lean-explore) | import smokes |
| 10| docker images re-check (arch-conditional) | images present |
| 11| systemd units rendered + per-unit enable state applied; linger; crontab marker block | states match `units.state` |
| 12| post-install notes + `make verify` | verify green / green-with-degraded |

### SKIP_* toggles (sizes)

| Toggle | Skips | Approx size/time |
|---|---|---|
| `SKIP_LATEX=1` | texlive-full | ~5.5GB |
| `SKIP_DOCKER_IMAGES=1` | sandbox 8.5GB + sage 4.6GB (arm64) + translation-server 2GB | ~15GB |
| `SKIP_LEAN=1` | elan (toolchains lazy-install per project anyway) | ~1–3GB on first use |
| `SKIP_RUST=1` / `SKIP_BUN=1` | rust / bun (only needed to build qmd) | ~1.2GB / ~0.5GB |
| `SKIP_CALIBRE=1` / `SKIP_CHROMIUM=1` | calibre / chromium+driver (xtradeb PPA) | ~1GB |
| `SKIP_TAILSCALE=1` | tailscale install | — |
| `SKIP_NPM_GLOBALS=1` | the 8 pinned agent CLIs | ~1.3GB |

Example minimal try-out: `SKIP_LATEX=1 SKIP_DOCKER_IMAGES=1 make install`

### Notes & caveats

- **docker group**: phase 2 adds your user to the `docker` group; the scripts
  use `sg docker -c` so the same session can pull images. A full re-login is
  still recommended afterwards.
- **AES zips**: stock `unzip` cannot read them — that is why `7zip` is in the
  bootstrap line. Scripts auto-detect `7zz` or `7z`.
- **Ubuntu chromium**: stock 24.04 has no chromium deb; prepare adds the
  `ppa:xtradeb/apps` PPA (matches the source machine's packages).
- **Degraded mode**: with no `SECRETS=`, phases 3/7-gateway/11-start are
  skipped or relaxed; install prints the missing-secret → broken-feature table
  at the start and end. Re-run later with
  `make restore-secrets SECRETS=… && PHASE=7 bin/install.sh`.
- **Ollama** is intentionally NOT installed (verified unused on the source
  system). If ever wanted: `curl -fsSL https://ollama.com/install.sh | sh &&
  ollama pull qwen2.5:7b` — the OpenClaw provider entries for it are inert.
- **GHA compute broker**: `~/ai-agents-skills` is the single source for skills;
  phase 8 installs the `research_compute` broker (the local→Modal→GitHub Actions
  compute router) from there to the runtime root, and the documented
  `~/.claude/skills/_run.sh skills/modal-research-compute/…` call is forwarded to
  it. One-time per machine, run the broker's `bootstrap` (generates config,
  authenticates `gh`, runs `doctor`); the per-install `[gha]` config rides the
  secrets zip. See [github-actions-experiment-runner-plan.md](github-actions-experiment-runner-plan.md) and the installed `github-actions-offload-routing` skill instruction.

## 3. Verify

```bash
make test      # doctor + verify
make smoke     # quick CLI pin checks only
```

Re-auth one-liners for session-bound credentials (they may be stale in the zip):
`claude login`, `codex login`, `gh auth login`, `modal token new`.
