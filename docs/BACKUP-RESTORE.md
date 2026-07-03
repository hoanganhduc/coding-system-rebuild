# BACKUP & RESTORE runbooks

## Routine backup (source machine, recommended weekly)

```bash
cd ~/coding-system-rebuild
make backup        # gates → refresh state → sync --apply → leak-scan → commit → new zip
git show --stat    # REVIEW the diff before publishing
make push          # re-scans, then pushes (manual by design)
```

Pre-backup gates hard-fail unless `make init-private` has run on this machine
(7-Zip present, bashrc markers, denylist, units.state, zip password file).

The weekly cron (`bin/auto-backup.sh`, Mon 05:26 UTC) runs the same capture
unattended, plus the owner-data snapshot and the passphrase-escrow ensure; it
commits locally but does **not** publish unless `CSR_AUTO_PUSH=1` is set.

The off-machine copy is automatic: `make backup` uploads the new AES-256 zip
to `dropbox:Misc/coding-system-backups` via rclone (ciphertext only;
`CSR_NO_OFFSITE=1` skips). Extra copies on an encrypted USB or another cloud
remain a good idea, not a requirement. The zip password is
`~/.config/coding-system/zip-password.txt` (one passphrase for zip + GPG
snapshots), escrowed 2-of-N off-machine — see
[SECRETS.md](SECRETS.md#backup-password-file).

Zip rotation: local and offsite pruning keep the 3 newest plus the newest
snapshot per month.

## Full restore drill (fresh machine)

See [INSTALL.md](INSTALL.md). Proof sequence:

```bash
make doctor
make install SECRETS=…
make test
# live checks: send one Telegram message via the gateway; zotero doctor
```

## Partial restores

- **Secrets only**: `make restore-secrets SECRETS=…` (idempotent, chmod fixups).
- **One agent's configs**: `bash bin/render-install.sh` is idempotent; or copy
  the `agents/<agent>/` subtree manually (strip `.template` suffixes, replace
  `{{ HOME }}`).
- **Services only**: `PHASE=11 bash bin/install.sh`.

## research_compute broker (installer-owned)

The `research_compute` GHA/Modal compute broker is **not** captured by the backup — it's
delegated to the ai-agents-skills installer (phase 8 installs it from `~/ai-agents-skills` to
the runtime root; the `_run.sh` shim forwards the documented call to it). Only its
**per-install config** (`research-compute.toml`, with the `[gha]` repo targets — no tokens)
rides the secrets zip. After a restore without the zip, run the broker's `bootstrap` once to
regenerate config and authenticate `gh`. See
[github-actions-experiment-runner-plan.md](github-actions-experiment-runner-plan.md).

## OpenClaw data backup (separate concern)

This repo's zip carries OpenClaw **secrets/config only**. Research data,
sessions, memory, and the workspace git history are the domain of
`openclaw-bot/backup.sh` (GPG tar.gz, ~600MB–1GB). Since 2026-07-03 the weekly
`bin/auto-backup.sh` cron runs it automatically after a successful `make
backup`: age-gated (at most one snapshot per 6 days), guarded by a 5GB
free-disk check, refreshed via `make components` so the pinned copy is
current, encrypted non-interactively with the same passphrase file as the zip
(`~/.config/coding-system/zip-password.txt`, via
`OPENCLAW_BACKUP_PASSPHRASE_FILE`), verified by decrypt+list, and pruned to
the newest 2 archives under `~/openclaw-backups/`. Manual run:

```bash
OPENCLAW_BACKUP_PASSPHRASE_FILE=~/.config/coding-system/zip-password.txt \
  external/openclaw-bot/backup.sh --output ~/openclaw-backups --verify
```

Machine-loss recovery of the passphrase itself: fetch any two escrow shares
(Dropbox `escrow/passphrase-share-dropbox.txt`, private GitHub repo
`key-escrow`, Google Drive when connected) and run
`bin/escrow-passphrase.sh recover <share> <share>` — proven by a live
disaster drill on 2026-07-03.

Restore a snapshot with `gpg --decrypt <archive> | tar -xzf - -C ~/.openclaw`
(prompted, or batch with the same passphrase-file mechanism). Archives created
before 2026-07-03 used an interactively entered password and the older
`*-openclaw-backup.tar.gz` naming; the current chain is
`openclaw-private-<stamp>.tar.gz.gpg`.

## Optional: restoring the DeepSeek plugin in OpenClaw (decision 10)

The sanitized OpenClaw template keeps bundled provider/plugin wiring, including
DeepSeek entries, while removing owner-local checkout paths such as
`openclaw-src` and templating secrets. If a recaptured template still contains
`{{ DEFAULT_PRIMARY_MODEL }}` placeholders, set the desired model primaries in
`openclaw.json` and restart the gateway. The DeepSeek CLI agents
(`~/.codewhale`, `~/.deepseek`) are separate surfaces.

## Roundtrip self-test (no system mutation)

```bash
make roundtrip   # 5 steps in /tmp: capture → render → fixture-secrets → re-sync → canaries
```
