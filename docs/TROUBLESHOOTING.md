# TROUBLESHOOTING — known fixes and verification procedures

## Google Chat threading (verify BEFORE patching)
The locked extension version (2026.7.1) may already thread correctly — older
notes about a mandatory "unthread patch" are version-sensitive. Procedure:
send a message in a Google Chat space the bot serves; reply in-thread; if the
bot's replies break threading, run
`~/.openclaw/workspace/openclaw-scripts/openclaw_googlechat_unthread.sh`
(dry-run by default, `--apply` to write), then restart the gateway.
Re-verify only when promoting a new locked OpenClaw/plugin closure; restore does
not use a mutable `npm install -g openclaw` tree.

## Remote Bridge / ARL says Codex Zulip credentials are absent

The canonical authority is host-owned
`~/.config/remote-bridge/secrets.json`, not Codex's shared
`workspace/.secrets.json`. Codex selects it through
`REMOTE_BRIDGE_SECRETS_FILE`; OpenClaw receives a generated workspace
projection. Inspect only redacted metadata:

```bash
stat -c '%a %U %n' "$HOME/.config/remote-bridge/secrets.json"
bash "$HOME/.codex/runtime/run_skill.sh" \
  skills/remote-bridge/run_remote_bridge.sh show-config
```

The authority must be a current-user-owned, single-link mode-`0600` JSON file
with complete Zulip `site`, bot `email`, and `api_key` fields. A legacy source
with all three `ZULIP_ORG_URL`, `ZULIP_EMAIL`, and `ZULIP_API_KEY` fields can be
promoted and the projections regenerated without printing them:

```bash
python3 "$HOME/coding-system-rebuild/bin/materialize-secret-projections.py" \
  --home "$HOME" \
  --migrate-remote-bridge-legacy \
  --migrate-aas-legacy
python3 "$HOME/coding-system-rebuild/bin/verify-skill-credentials.py" \
  --home "$HOME" \
  --repository "$HOME/coding-system-rebuild"
```

If neither canonical nor complete legacy fields exist, the correct status is
`NOT_CONFIGURED`; add the authority on the source host and create a new recovery
set. Restore cannot recover values absent from that set. Outbound Zulip is not
globally disabled after restore. Inbound control intentionally remains disabled
until explicit allowed-user IDs are configured.

An ARL message that **explicit user confirmation is required** is not a
credential error. Multi-agent participant launch, paid Kaggle/Hetzner actions,
and enforce-mode external egress retain their own confirmation/consent gates.
For external enforce-mode progress notifications, set
`AAS_AUTOLOOP_EXTERNAL_NOTIFY_EGRESS=allow` only after the user authorizes that
egress; having a Zulip key never grants that consent automatically.

## Zalo `net.js` shim
If gateway logs show `Cannot find module ../../../src/gateway/net.js` from the
Zalo extension: create a shim re-exporting `resolveClientIp` from
`openclaw/plugin-sdk/mattermost` (see openclaw-bot repo notes). Re-check it when
promoting a new locked OpenClaw closure; do not patch the read-only installed
closure in place.

## SageMath container permissions
Do not make a research directory world-writable. Restored OpenClaw containers
run with the host owner's UID/GID while the image's declared default user is
verified separately. If a Sage job cannot write, inspect the bind-mount owner,
the digest-selected image, and the launcher user, then rerun `make verify`;
`chmod 777` masks a broken ownership/launcher contract and is not a supported
fix.

## Moltbook curl bind-mount
Changes to `workspace-moltbook/bin/curl` (submolt enforcement wrapper) need a
container recreation: `docker rm -f openclaw-sbx-moltbook-*`, then restart the
gateway.

## AES zip won't open with `unzip`
Stock Info-ZIP `unzip` cannot read AES-256 zips. Use `7zz x` / `7z x`
(`apt install 7zip`). All repo scripts auto-detect via `7zz || 7z`.

## docker: permission denied after fresh install
Group membership applies on next login. Either re-login, or prefix with
`sg docker -c '<command>'` (the scripts already do this).

## Gateway will not start
`journalctl --user -u openclaw-gateway -n 50`. Usual suspects:
secrets not restored (degraded install), config validation errors from
unfilled `{{ DEFAULT_PRIMARY_MODEL }}` placeholders (set your models in
`openclaw.json`), or bundled-plugin load failures (ignorable warnings for
unsupported bundled plugins).

## Modal is ready but Kaggle or Hetzner is absent

These are separate authorities. Modal reads `~/.modal.toml`; Kaggle and
Hetzner read strict keys from
`~/.config/ai-agents-skills/compute.env`. Kaggle additionally receives the
derived `~/.kaggle/access_token`. Run the redacted verifier above. If Modal is
`PASS` while compute is `NOT_CONFIGURED`, no technical restore failure occurred:
configure `KAGGLE_API_TOKEN` and/or `HCLOUD_TOKEN` on the source and create a
new recovery set. Do not use a legacy `kaggle.json` username/key pair for this
contract.

If the credential check passes but a service reports exhausted quota, retain
`CREDIT_BLOCKED`; reinstalling packages or restoring the same set cannot add
credits. A native OAuth/device session rejected by its provider is instead
`REAUTH_REQUIRED` and should be renewed with that provider's login flow.

## LeanExplore credential appeared in a process command line

Rotate `LEANEXPLORE_API_KEY` at its provider and replace the value in
`~/.config/ai-agents-skills/skill.env`; command-line exposure must be treated as
credential disclosure. The managed LeanExplore 1.2.1 compatibility adapter
removes the replacement from its environment before importing the package and
runs the MCP app in-process. Restart the owning MCP client after rotation so no
process retains the superseded value. Do not paste the old or replacement key
into a diagnostic command.

## Tailscale is installed but recovery readiness is not `PASS`

The portable authority is two data files, never executable shell:
`~/.config/coding-system/tailscale-authkey` and
`~/.config/coding-system/tailscale-hostname`, both mode `0600`. The retired
`tailscale.env` is accepted only as a bounded migration source. Inspect the
redacted local state without making a network request:

```bash
python3 "$HOME/coding-system-rebuild/bin/verify-tailscale-readiness.py" \
  --home "$HOME"
```

`NOT_CONFIGURED` means the source generation had no raw authority.
`REAUTH_REQUIRED` means the restored key/session cannot establish the required
local running state. `TECHNICAL_FAIL` means the authority, binary, daemon, or
local status probe is structurally unavailable. After correcting the specific
condition, the explicit apply path is:

```bash
bash "$HOME/coding-system-rebuild/bin/apply-tailscale-authority.sh" \
  --home "$HOME"
```

That command uses `tailscale up --auth-key=file:<protected-path>`; do not paste
the raw key into a command line, environment variable, or diagnostic. The
rebuild installs the newest Tailscale release, at least 1.102.3.

## AAS file-delivery queue is `NOT_CONFIGURED`

The host queue authority is
`~/.config/ai-agents-skills/file-delivery-queue.json`; its replay token resolves
only to the owner-private
`~/.local/state/ai-agents-skills/file-delivery-replay/` continuity tree. Missing
authority is intentionally `NOT_CONFIGURED`: restore creates the private replay
directory but never invents an HMAC key or recipient allowlist. Create the
authority only with an explicit channel/target allowlist, then create a new
signed recovery set.

This AAS queue contract is not an OpenClaw delivery policy and must never be
copied into an OpenClaw workspace credential file. Likewise, an OpenClaw bot
token, Zulip identity, or conversation history does not authorize an AAS queue
target. Use the redacted credential verifier to distinguish missing authority,
invalid schema, and resolver drift without printing targets or keys.

## Full restore stops at `ARTIFACT_UNAVAILABLE`

Inspect the signed checkout's Grok bootstrap, platform, Python, and image locks.
A `pending-publication`, `pending-clean-host`, or `pending-artifacts` state is a
deliberate release gate, not a missing-secret condition. Run source-contract
tests for diagnostics, but do not replace a digest with a mutable tag or let pip
resolve online. The qualified artifact must be published/promoted for both
`amd64` and `arm64`, its lock and parent digests reviewed, and a new recovery
set bound to that commit.

## A managed CLI reports a version different from the lock
The npm CLI tree is content-addressed and read-only; in-place self-update is not
part of restore. `make verify` checks the locked package/artifact bytes and the
supported version probe. Promote a new closure instead of accepting drift.

## getscipapers
The managed entrypoint is `~/.local/bin/getscipapers`, backed by the locked
`~/.local/share/coding-system/python-closure/getscipapers` environment. On a
host without that closure the launcher runs the owner's development venv
`~/.getscipapers_venv`; `GETSCIPAPERS_VENV` overrides both.
`usr-local-bin.tsv` may expose a compatibility link to that launcher; a
floating `pip --user` installation is not the runtime authority.

## Completion and scheduler closure

If a new interactive Bash shell reports a missing OpenClaw completion file,
regenerate it from the installed CLI.  The shell block treats completion as
derived state and remains safe while the file is absent:

```bash
bash ~/coding-system-rebuild/bin/materialize-openclaw-completion.sh
bash ~/coding-system-rebuild/bin/materialize-openclaw-completion.sh --verify
```

Full restore runs this after the locked OpenClaw CLI is installed. The file is
derived state and is deliberately absent from the encrypted archive; the
managed Bash block checks readability before sourcing it, so a missing file
does not break every new shell while recovery is still in progress.

Host schedules are declared in `system/schedules/host.v1.json`.  Preview or
reconcile the managed crontab block without replacing unrelated user entries:

```bash
python3 ~/coding-system-rebuild/bin/reconcile-host-schedules.py --dry-run
python3 ~/coding-system-rebuild/bin/reconcile-host-schedules.py --verify
python3 ~/coding-system-rebuild/bin/reconcile-host-schedules.py
```

Systemd timer schedules (the RSS digest and the scheduler canary) are drop-ins
rather than crontab lines. Add `--scope systemd` to the same three commands;
`--verify` also compares the loaded timer with `systemctl --user show`, so a
timer that still runs on the component's default schedule is reported.

Phase 11 performs this reconciliation automatically in a full restore. The
commands above are for drift diagnosis or repair after an external edit.

Recorded user-unit states are activated with `enable --now` semantics.  A
degraded restore can register enablement without starting enabled services:

```bash
bash ~/coding-system-rebuild/bin/reconcile-systemd-user-units.sh --registration-only
bash ~/coding-system-rebuild/bin/reconcile-systemd-user-units.sh --verify
```

OpenClaw cron backups are logical declarations, not database copies.  Export
only after the gateway is healthy; import uses declaration keys and the CLI's
`cron.add` reconciliation path.  The adapter reads the one-time legacy file but
does not change it.  Paths below the selected `--home` are stored as portable
`{{ HOME }}` values and materialized on import.  The checked-in baseline at
`system/schedules/openclaw-cron.v2.json` declares the provider-free canary:

```bash
python3 ~/coding-system-rebuild/bin/openclaw-cron-v2.py export \
  --output ~/.local/state/coding-system/openclaw-cron.v2.json
python3 ~/coding-system-rebuild/bin/openclaw-cron-v2.py import \
  --input ~/coding-system-rebuild/system/schedules/openclaw-cron.v2.json --dry-run
python3 ~/coding-system-rebuild/bin/openclaw-cron-v2.py adapt-legacy \
  --input ~/.openclaw/cron/jobs.json.migrated \
  --output ~/.local/state/coding-system/openclaw-cron.v2.json
```

Provider-free scheduler canaries are direct command jobs and consume no model
credit.  The enabled `coding-system-scheduler-canary.timer` records systemd
evidence, while the fixed `coding-system.restore.scheduler-canary` OpenClaw
declaration records OpenClaw evidence. The restore captures a strict whole-second
boundary after scheduler activation and requires all three canaries to be both
recent and at or after that boundary. This prevents a recent file from an older
restore from satisfying the gate. `--dry-run` creates no state; production
records should use a private state directory and can be checked against an
explicit boundary when diagnosing a restore.

Every scheduled job and the shell's owner-settings loader run code through the
repository selector `~/.local/share/coding-system/repository`, never through a
working checkout. In a full restore the installer copies the verified Stage-0
generation into a sealed generation the owner owns, under
`~/.local/share/coding-system/repository-generations/`, and points the selector
at it; the root-owned Stage-0 generation serves only the restore's system steps.
Resetting or switching a checkout therefore leaves the scheduler and new shells
unaffected. To move them to a newer commit, without root:

```bash
bin/publish-repository-generation.sh --repository ~/coding-system-rebuild --commit origin/main
```

It publishes only committed content, re-hashes every blob, and repoints the
selector. Run `reconcile-host-schedules.py` afterwards when the commit changed
scheduled jobs.

```bash
activation_boundary_unix=$(( $(date +%s) + 1 ))
REPOSITORY=~/.local/share/coding-system/repository
python3 "$REPOSITORY/bin/scheduler-canary.py" record \
  --scheduler openclaw --state-dir ~/.local/state/coding-system/scheduler-canaries --dry-run
python3 "$REPOSITORY/bin/scheduler-canary.py" verify \
  --scheduler openclaw --state-dir ~/.local/state/coding-system/scheduler-canaries \
  --not-before-unix "$activation_boundary_unix"
python3 "$REPOSITORY/bin/scheduler-canary.py" verify \
  --scheduler systemd --state-dir ~/.local/state/coding-system/scheduler-canaries \
  --not-before-unix "$activation_boundary_unix"
```
