# VNU eOffice Restore Specification

## Goal

Restore the OpenClaw VNU eOffice workflow after a secrets-based machine rebuild.

## Scope

- Materialize the pinned `vnu-eoffice` checkout at
  `~/.openclaw/workspace/vnueoffice_repo`.
- Derive the sandbox-only VNU credential file from the authoritative restored
  `~/.claude/secrets.json` without printing secret values.
- Back up that derived credential file when present.
- Make host and sandbox launchers use the same workspace checkout.

## Exclusions

- OpenClaw channels, model configuration, and unrelated cron jobs.
- Telegram file delivery or VNU attachment downloads.

## Acceptance Criteria

- The checkout is pinned to an exact commit and importable from the launcher.
- The bridge file contains the two VNU credential keys and has mode `0600`.
- `doctor --network` queries both `den` and `di` successfully.
- `monitor --no-notify --limit 60 --pages 2` exits successfully.
- Focused unit, manifest, and launcher regression checks pass.
