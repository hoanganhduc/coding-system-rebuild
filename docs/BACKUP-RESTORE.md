# BACKUP & RESTORE runbooks

## Routine backup (source machine, recommended weekly)

```bash
cd ~/coding-system-rebuild
make backup        # gates → refresh state → sync --apply → leak-scan → commit → new zip
git show --stat    # REVIEW the diff before publishing
make push          # re-scans, then pushes (manual by design)
```

Pre-backup gates hard-fail unless `make init-private` has run on this machine
(7-Zip present, bashrc markers, denylist, units.state).

Copy the newest `~/secrets-out/coding-system-secrets-<stamp>.zip` somewhere
**off this machine** (encrypted USB, private cloud). The zip is AES-256; its
password lives only in your password manager
(bootstrap copy: `~/.config/coding-system/zip-password.txt` — rotate it).

Zip rotation: keep the 3 newest + one monthly; prune the rest manually.

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

## OpenClaw data backup (separate concern)

This repo's zip carries OpenClaw **secrets/config only**. Research data,
sessions, memory, and the workspace git history are the domain of
`openclaw-bot/backup.sh` (GPG tar.gz, ~600MB–1GB) — run it separately if you
want owner-data snapshots:

```bash
external/openclaw-bot/backup.sh --output ~/openclaw-backups
```

## Optional: restoring the DeepSeek plugin in OpenClaw (decision 10)

The rebuilt openclaw.json has the personal deepseek plugin/provider stripped
and model primaries as `{{ DEFAULT_PRIMARY_MODEL }}` placeholders. To restore
the old setup: clone `https://github.com/openclaw/openclaw`, build/keep
`extensions/deepseek`, add its path to `plugins.load.paths`, re-add `deepseek`
to `plugins.allow` + `plugins.entries`, restore a `deepseek` provider block
under `models.providers`, set the primaries, and restart the gateway. The
DeepSeek CLI agents (`~/.codewhale`, `~/.deepseek`) need none of this.

## Roundtrip self-test (no system mutation)

```bash
make roundtrip   # 5 steps in /tmp: capture → render → fixture-secrets → re-sync → canaries
```
