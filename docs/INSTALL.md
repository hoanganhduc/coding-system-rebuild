# INSTALL — fresh Ubuntu 24.04 (amd64 / arm64)

## 0. What you need

1. This repo (public).
2. The secrets zip + its password (see [SECRETS.md](SECRETS.md)). Optional —
   without it the install completes in **degraded mode**.
3. A user with sudo. Examples assume user `ubuntu`; any user works — every
   captured path is `{{ HOME }}`-templated and rendered at install time.

## 1. Bootstrap

```bash
sudo apt-get update && sudo apt-get install -y git make 7zip python3-yaml
git clone https://github.com/hoanganhduc/coding-system-rebuild
cd coding-system-rebuild
make doctor
```

`doctor` hard-fails on: no network, missing git/make/python3/python3-yaml, no
7-Zip CLI. It warns on: <60GB free disk, missing linger, non-24.04, or an
architecture without a pinned SageMath image.

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
| 5 | components: clone openclaw-bot → `external/`; ensure the pinned ai-agents-skills object exists in the compatibility/development repository at `~/ai-agents-skills` without changing an existing worktree | exact pinned object is locally available |
| 6 | render configs/scripts/symlinks into $HOME; atomically install the immutable grok-proxy user/root release | no unresolved `{{ HOME }}`; one coherent admitted Grok release |
| 7 | OpenClaw slice via openclaw-bot (`--skip-docker --skip-services`); npm install channel plugins | secrets untouched; no dangling refs |
| 8 | bind the materializer by its recorded SHA-256 into a root-owned no-replace helper, materialize the exact pinned ai-agents-skills Git blobs at `/usr/local/libexec/coding-system/components/ai-agents-skills/<sha>`, then install `research_compute` from that stable tree under a closed environment + `verify` | helper digest/authority, blob/mode parity, immutable ownership, idempotent no-replace publication, and `_run.sh` broker smoke |
| 8b| re-overlay zip secrets; `_run.sh` sha check | verify-secrets OK |
| 9 | python envs from pip freezes (workspace-local target dir, ~/.venvs, docling-venv, lean-explore) | import smokes |
| 10| docker images re-check (arch-conditional) | images present |
| 11| systemd units rendered + per-unit enable state applied; linger; crontab marker block | states match `units.state` |
| 12| post-install notes + `make verify` | verify green / green-with-degraded |

Phase 6 treats `~/grok-proxy` as the editable Grok authoring source while
preserving its private configuration, credentials, model cache, locks, and
tunnel state. On a fresh machine it restores only the manifest-allowlisted
public source from `system/grok-proxy`. If any managed public path already
exists, the complete managed tree must match byte-for-byte (including executable
bits) or the install fails before writing source files or invoking sudo. This
prevents restore from overwriting local authoring work or creating a hybrid tree.

The editable tree is never the production execution authority. Before phase 6,
an administrative package transaction must install the native, production-keyed
`/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap`, one signed closed
dispatcher under `bootstrap-releases/`, and the root-owned `selected-release`
file. Candidate source cannot create or replace those trust-anchor artifacts.
After proving that the repository backup and canonical authoring tree match,
the renderer invokes only that native verifier and its administratively selected
signed dispatcher. The signed dispatcher stages paired root-owned immutable
user/root releases; `~/.local/bin/grok-remote` then selects the admitted user
release. Direct execution from either editable checkout refuses production use.
The native verifier independently opens the fixed root-owned selector, requires
the requested signed application ID to match, and rechecks the selector at its
final execution boundary; renderer validation is defense in depth.
`bin/render-install.sh --render-only` performs the source reconciliation but
does not invoke the verifier or change live release selectors.

To inspect the selected release from the repository checkout:

```bash
GROK_RELEASE_PATH=$(readlink -f -- /usr/local/libexec/grok-proxy/current)
GROK_RELEASE_ID=${GROK_RELEASE_PATH##*/}
[[ $GROK_RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$GROK_RELEASE_ID/install-release.py"
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" status
```

The installer path must name a concrete 64-hex release directory. The mutable
`current/install-release.py` path is rejected; if selection changes after the
path is derived, the concrete installer rechecks under the operation lock and
fails closed.

To stage and atomically select the current checkout without rerunning the
machine-wide package phases:

```bash
bash bin/render-install.sh
```

This installs the signed application named by the administrative selector; it
never executes `system/grok-proxy/install-release.py` or
`~/grok-proxy/install-release.py` as root. A missing, malformed, incorrectly
owned, or unsigned bootstrap artifact is a hard failure.

The opt-in multi-session lane remains fail-closed until the selected release
passes its fixed `load32` and `fault-recovery` qualification and each intended
route/model tuple passes the fixed real-pair canary. The installer interface is:

```bash
RELEASE_ID='replace-with-the-64-lowercase-hex-release-id'
[[ $RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$RELEASE_ID/install-release.py"
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  begin-release-qualification --release-id "$RELEASE_ID" --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  canary-exec --qualification-step load32 --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  canary-exec --qualification-step fault-recovery --apply

sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" begin-rung-canary \
  --release-id "$RELEASE_ID" \
  --rung '<rung>' --route-profile '<profile>' \
  --contract-sha256 '<contract_sha256>' \
  --grok-release-id '<grok_release_id>' --model-id '<model_id>' --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  canary-exec --qualification-step real-pair --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" promote-rung --apply
```

`PROFILE` is one of `direct`, `iphone`, `vpn`, `home:<label>`, `auto`, or
`auto-no-direct`. Promotion accepts only installer-derived fixed results; manual
canary transcripts and external evidence files are nonqualifying. Use
`abort --apply` to cancel an active qualification fence. These commands start a
release's first fixed qualification. Version 1 deliberately has no reset for an
already completed qualification directory: if the generated gates change while
the runtime release ID stays the same, stale evidence fails closed and the
release cannot be requalified through this interface. Preserve the exact
installer bytes; do not delete qualification state by hand.

### Interrupted Grok release recovery

Use `status` as the preliminary check before retrying phase 6:

```bash
GROK_RELEASE_PATH=$(readlink -f -- /usr/local/libexec/grok-proxy/current)
GROK_RELEASE_ID=${GROK_RELEASE_PATH##*/}
[[ $GROK_RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$GROK_RELEASE_ID/install-release.py"
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" status
```

For an interrupted release operation, an authorized recovery operator must also
inspect the root-owned deny record and both root/user selection records. `status`
does not expose the full deny ledger or selection phase. Once the immutable
target user/root pair has been published, resume the target named by the deny
ledger. Recovery uses immutable signed code rather than rebuilding from current
source bytes. `SIGNED_RELEASE_DIR` below must be the exact directory named by
the root-owned bootstrap selector after its ownership, mode, and closed content
have been independently validated:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- \
  resume --apply
```

Before pair publication, retry phase 6 through `bash bin/render-install.sh` or
abort to the release recorded in `from_release` through the same signed
bootstrap lane:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- abort \
  --restore-from PRIOR_RELEASE_ID \
  --apply
```

A first install has `from_release: null`; it has no prior release to abort to.
Correct the blocking condition and resume/retry the same published target.
Never start a different install while that null-source deny remains active.
In particular, a fenced phase-6 operation must use `resume`; do not use a
different `install` until the deny is cleared.

Older interrupted targets may lack the authenticated legacy-migration broker
endpoint. Current `resume` can still converge them only after root inventory
proves the fixed legacy pathname absent. If `/var/lib/grok-vpngate` still
exists, stop: do not run `resume`, and do not delete or move it ad hoc. This
guide does not define a quarantine operation, and the public warm-handoff
command is nonmutating. If a separately authorized and reviewed host-specific
procedure has already made that exact pathname absent while retaining an
independently verified root-only archive, `resume` rechecks every OpenVPN
process, broker ledger, namespace, tun, listener, multi-session fence,
workspace, reserved cgroup, and root inventory and fails closed on residue.
Retain the archive through qualification, rollback, and reinstall.

After `resume`, run `status` again and require `rollback_denied: false`, matching
target root/user release IDs, `active_release_valid: true`,
`release_access_policy_valid: true`, and exactly one ID in
`exposed_user_releases`. Separately verify
that both selection records are `READY`, their nonzero evidence digest matches
the target evidence file, and that evidence is schema 3 before qualification.

To roll back, require `rollback_eligibility_complete: true` and take a prior ID
from `rollback_eligible_releases`. Retained IDs absent from that list predate or
differ from the exact self-admission contract and cannot be selected. Archived
user releases remain mode `0500` until this validation succeeds. Then run:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
ROLLBACK_RELEASE_ID='replace-with-an-eligible-64-lowercase-hex-release-id'
[[ $ROLLBACK_RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- rollback \
  --release-id "$ROLLBACK_RELEASE_ID" \
  --apply
```

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
  system). The OpenClaw provider entries for it are inert unless Ollama is
  deliberately installed later.
- **GHA compute broker**: `~/ai-agents-skills` is the fetch/object and legacy
  compatibility repository; its HEAD, index, ignored files, and working-tree
  edits are not executable installer input. Phase 8 validates the pinned Git
  closure, transports raw blobs without checkout filters, publishes a stable
  root-owned SHA tree, and installs the `research_compute` broker (the
  local→Modal→GitHub Actions compute router) from that tree to the runtime root.
  Old SHA trees are retained because reference-mode adapters and symlink-mode
  skills bind to their exact source path. The documented
  `~/.claude/skills/_run.sh skills/modal-research-compute/…` call is forwarded to
  it. One-time per machine, run the broker's `bootstrap` (generates config,
  authenticates `gh`, runs `doctor`); the per-install `[gha]` config rides the
  secrets zip. See [github-actions-experiment-runner-plan.md](github-actions-experiment-runner-plan.md) and the installed `github-actions-offload-routing` skill instruction.

## 3. Verify

```bash
make test      # no-secrets self-tests and roundtrip
make smoke     # quick CLI pin checks only
```

Re-auth one-liners for session-bound credentials (they may be stale in the zip):
`claude login`, `codex login`, `gh auth login`, `modal token new`.
