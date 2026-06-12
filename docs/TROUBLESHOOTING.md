# TROUBLESHOOTING — known fixes and verification procedures

## Google Chat threading (verify BEFORE patching)
The live extension version (2026.6.x) may already thread correctly — older
notes about a mandatory "unthread patch" are version-sensitive. Procedure:
send a message in a Google Chat space the bot serves; reply in-thread; if the
bot's replies break threading, run
`~/.openclaw/workspace/openclaw-scripts/openclaw_googlechat_unthread.sh`
(dry-run by default, `--apply` to write), then restart the gateway.
Re-verify after every `npm install -g openclaw`.

## Zulip channel (disabled by default — matches source system since 2026-06-05)
Re-enable runbook:
1. enable the channel in `openclaw.json`;
2. `ln -s ~/.npm-global/lib/node_modules/openclaw \
   ~/.openclaw/extensions/zulip/node_modules/openclaw`
   (plugin-sdk is a devDependency upstream — absent from production installs);
3. clear the jiti cache: `rm -rf /tmp/jiti`;
4. restart: `systemctl --user restart openclaw-gateway`.

## Zalo `net.js` shim
If gateway logs show `Cannot find module ../../../src/gateway/net.js` from the
Zalo extension: create a shim re-exporting `resolveClientIp` from
`openclaw/plugin-sdk/mattermost` (see openclaw-bot repo notes). Must be
re-created after every `npm install -g openclaw`.

## SageMath container permissions
If sage jobs fail writing to the mounted workdir: `chmod 777` the job dir
(container uid 1000 vs host uid mismatch). `make verify` runs a sage smoke.

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

## Self-updating CLIs report different versions than the npm pins
`copilot`/`codewhale` self-update in place; `make verify` therefore checks the
npm-installed version (authoritative), not CLI `--version` output.

## getscipapers
The real entrypoint is `~/.local/bin/getscipapers` (pip --user). The old
`/usr/local/bin/getscipapers` symlink on the source machine pointed to a
removed venv; this repo's `usr-local-bin.tsv` records the corrected target.
