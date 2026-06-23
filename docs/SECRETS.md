# SECRETS — what's in the zip, where to obtain each key, what breaks without it

The single AES-256 zip (`make backup` regenerates it) holds **every** credential
plus small personal state, with `$HOME`-relative paths. Authoritative inventory:
[`secrets/secrets-manifest.yaml`](../secrets/secrets-manifest.yaml).
`make verify-secrets` prints a live OK/MISSING table;
`make verify-secrets SECRETS=<zip>` checks an archive;
`bin/secrets-verify.sh --degraded` prints the missing → broken-feature table.

**Password policy:** the zip password exists nowhere on disk except (optionally)
`~/.config/coding-system/zip-password.txt` on the source machine. Keep it in a
password manager. Losing it makes the archive unrecoverable — there is no reset.

## Key-by-key: `~/.claude/secrets.json` (16 keys, shared design with `~/.openclaw/secrets.json`)

| Key | Used by | Obtain |
|---|---|---|
| `TAPHOAAPI_API_KEY` | primary Claude-model reseller provider | taphoaapi.com account |
| `LAOZHANG_API_KEY` | fallback Claude-model reseller | laozhang.ai account |
| `GROQ_API_KEY` | Groq fallback models | console.groq.com |
| `PERPLEXITY_API_KEY` | (currently unreferenced — legacy) | perplexity.ai |
| `ZOTERO_API_KEY` | Zotero library skill (`/zotero`) | zotero.org/settings/keys |
| `WEBDAV_PASSWORD` | Zotero attachment WebDAV sync | your WebDAV provider |
| `GDRIVE_CREDENTIALS` | Calibre/Drive skills (JSON-in-JSON service account) | GCP console → service account key |
| `TELEGRAM_BOT_TOKEN` | file delivery, digests, notifications | @BotFather |
| `ZALO_BOT_TOKEN` | Zalo channel | Zalo OA console |
| `ZULIP_API_KEY` / `ZULIP_EMAIL` / `ZULIP_ORG_URL` | Zulip channel + send_file | your Zulip org settings |
| `GATEWAY_AUTH_TOKEN` | OpenClaw gateway auth | generate any strong token |
| `MOLTBOOK_API_KEY` | moltbook agent | moltbook account |
| `VNU_EOFFICE_USERNAME` / `VNU_EOFFICE_PASSWORD` | VNU eOffice skill | VNU account |

## Shell env file `~/.secrets.env` (sourced by the managed bashrc block)

| Var | Feature |
|---|---|
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | shell-side Telegram delivery |
| `OCRSPACE_API_KEY` | OCR fallback (ocr.space) |
| `LEANEXPLORE_API_KEY` | lean-explore MCP (leanexplore.com) |
| `MOLTBOOK_*`, `MOLBOOK_AGENT_ID` | moltbook agent configuration (personal) |

## ai-agents-skills runtime secrets (`<runtime_root>/workspace/.secrets.json`)

Skills run via the managed runner read `AAS_SECRETS_FILE` =
`<runtime_root>/workspace/.secrets.json` (e.g. `~/.codex/runtime/workspace/` and
`~/.local/share/ai-agents-skills/runtime/workspace/`). The `send-email` skill
keeps its SMTP credentials and sender identity here, in an `smtp` object (one
profile, or several named profiles). Only `user`/`password` are sensitive.

| Key | Feature | Obtain |
|---|---|---|
| `smtp.host`, `smtp.port`, `smtp.security` | SMTP server endpoint | your mail provider (e.g. smtp.gmail.com 587 starttls) |
| `smtp.user`, `smtp.password` | SMTP authentication | provider app password (revocable; not the account password) |
| `smtp.from`, `smtp.from_name`, `smtp.reply_to`, `smtp.signature*` | sender identity (not secret) | per the send-email SKILL.md |

Send-email also keeps an **address book** of saved recipients at
`<runtime_root>/workspace/.address-book.json` (personal state, not credentials);
it is backed up so saved contacts survive a rebuild.

To serve every install target from one config, this machine uses the shared file
`~/.config/send-email/secrets.json` (option 1): `.secrets.env` exports
`AAS_ALLOW_EXTERNAL_SECRETS_FILE=1` and `AAS_SECRETS_FILE` pointing there, so all
runners read it. That file is backed up too.

The OpenClaw sandbox cannot read `~/.config`, so it gets its own copy at
`~/.openclaw/workspace/.config/send-email/secrets.json` (mounted at
`/workspace/.config/...`; `.config` is `.stignore`'d so it never syncs); it is
backed up. PGP-signed sends from the OpenClaw sandbox are routed to a host signing
queue because the sandbox has no `gpg` or private key — the host signs with the
`.gnupg` keyring (see Infrastructure), so that keyring must be backed up for
signing to survive a rebuild.

## Per-agent auth files

| File | Agent | Re-auth alternative |
|---|---|---|
| `.claude/.credentials.json` | Claude Code OAuth | `claude login` |
| `.codex/auth.json` (`OPENAI_API_KEY`, tokens) | Codex | `codex login` |
| `.copilot/mcp-config.json` | Copilot MCP servers | re-create MCP config |
| `.codewhale/config.toml` + `.codewhale/secrets/` | CodeWhale (DeepSeek key inline) | platform.deepseek.com |
| `.deepseek/config.toml` + `.deepseek/secrets/` | DeepSeek CLI | platform.deepseek.com |
| `.gemini/antigravity-cli/antigravity-oauth-token` | Gemini/AntiGravity | its login flow |
| `.openclaw/secrets.json`, `credentials/`, `identity/`, `agents/*/agent/auth-profiles.json`, `moltbook.env`, `workspace/.secrets.json` | OpenClaw gateway/channels/providers | re-pair channels, re-enter keys |
| `.config/openclaw/google-chat/*.json` | Google Chat service account | GCP console |

## Infrastructure

| File | Feature | Obtain |
|---|---|---|
| `.ssh/*` | git push, host identities | existing keys / `ssh-keygen` + GitHub |
| `.gnupg/` | GnuPG keyring — PGP private key for `send-email` signing (also used by the OpenClaw host signing queue) | import your existing secret key, or `gpg --full-generate-key` |
| `.gitconfig`, `.config/gh/hosts.yml` | git identity, gh auth | `gh auth login` |
| `.docker/config.json` | private registry pulls (absent on source machine — optional) | `docker login ghcr.io` |
| `.config/rclone/rclone.conf` | rclone remotes | `rclone config` |
| `.modal.toml` | modal research compute | `modal token new` |
| `.config/coding-system/tailscale.env` (`TS_AUTHKEY=`) | unattended `tailscale up` | tailscale admin → auth keys |
| `.config/getscipapers/<service>/credentials.json` (8 services) | paper retrieval — each degrades individually | per-service account |
| `.config/moltbook/credentials.json`, `.config/course/mat1204/credentials.json`, `.config/deepseek/settings.toml` | tool-specific | respective platforms |

## Personal state (not credentials, still private)

`.claude/projects/-home-ubuntu/memory/` (agent memory),
`.claude/learnings/`, `.deepseek/memory/`, `.deepseek/.learnings/`,
`.openclaw/workspace/data/writing-style.md`,
skill `config.json` files with personal IDs (zotero/calibre, both homes),
`.config/coding-system/leak-denylist.txt` (the leak scanner's personal-ID list).

## Rotation

Rotate a key → update the live file → `make backup` (new zip). Old zips remain
valid for their snapshot date; prune them manually from `~/secrets-out/`.
