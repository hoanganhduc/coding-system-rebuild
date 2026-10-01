# Secret authorities, sessions, projections, and private state

The public authority for what is backed up is
[`secrets/secrets-manifest.yaml`](../secrets/secrets-manifest.yaml). It contains
paths and behavior metadata only—never credential values. The manifest uses
`coding-system.secrets-manifest.v2` and validates four classifications:

| Classification | Meaning | Archived? |
|---|---|---|
| `authority` | The one canonical, portable source for a credential or private configuration | Yes when `backup: true` |
| `session` | OAuth/device/channel state that may expire or be machine-bound | Yes when `backup: true`, then probed or reauthenticated |
| `projection` | A generated target/sandbox copy of an authority | Never; regenerated after restore |
| `private-state` | Owner data needed for behavior but not normally an authentication authority | Yes when `backup: true` |

Each entry also records a stable authority identity, mode, portability,
required/optional status, affected feature, and a re-obtainment path. A
projection must reference an existing authority, use `portability:
regenerated`, and set `backup: false`. This prevents two stale copies from
silently becoming competing credential sources.

Historical ZIP import has an additional, narrow contract. A required archived
entry may be absent only when it declares `legacy_import`. `generated` means the
importer must deterministically create the entry from bounded staging inputs;
`destination-authority` means it must securely capture an existing destination
authority and prove it against a public trust root. Both policies fail closed
before a recovery set is created. They are not general missing-secret waivers.
Currently they cover only the metadata-only credential source contract and the
repository-pinned recovery signing authority, respectively.

Validate the contract or inspect the current machine without printing values:

```bash
python3 bin/lib/recovery_tool.py manifest-check \
  --manifest secrets/secrets-manifest.yaml

bin/secrets-verify.sh
bin/secrets-verify.sh --degraded
```

A live credential restore authenticates and decrypt-validates the complete
recovery set before changing process state. It then stops the OpenClaw gateway
and host queue worker, and refuses to replace native session stores while Codex,
Claude, Copilot,
OpenCode, Kimi, Gemini/Antigravity, Grok, DeepSeek, CodeWhale, or another
declared session-owning CLI is running. Run the one-command restore from an
ordinary shell after those interactive clients have exited; the installer can
be resumed safely after this gate.

## Agent and infrastructure coverage

| Surface | Backed authority/session | Reauthentication or recreation |
|---|---|---|
| GitHub and Git | `~/.ssh/`, `~/.gnupg/`, `~/.gitconfig`, `~/.config/gh/hosts.yml` | `ssh-keygen`, key import, or `gh auth login` |
| Docker/GHCR | `~/.docker/config.json` | `docker login`; private pulls must use `--password-stdin` |
| Cloudflare Wrangler | `~/.config/.wrangler/config/default.toml` OAuth session only; `~/.config/.wrangler/logs/` is excluded | `wrangler login` if the restored refresh session is rejected |
| Forms local development | `~/forms/apps/classroom50-runner/.env`, `~/forms/apps/api/.dev.vars`, and `~/forms/apps/web/.env.local` | Exact Git-ignored local authorities/settings are encrypted and source-contracted; GitHub Actions and Cloudflare protected secrets remain remote provider state and are not exportable host files |
| rclone and Modal | `~/.config/rclone/rclone.conf`, `~/.modal.toml` | Native setup/login commands |
| Tailscale | Raw key authority `~/.config/coding-system/tailscale-authkey` plus the non-secret `tailscale-hostname`; the retired executable `tailscale.env` is migration input only | `bin/apply-tailscale-authority.sh --home "$HOME"` uses `--auth-key=file:<path>` so the key never enters shell text or argv; readiness is `PASS`, `NOT_CONFIGURED`, `REAUTH_REQUIRED`, or `TECHNICAL_FAIL` |
| OpenClaw owner-data archive | `~/.config/coding-system/openclaw-owner-backup-passphrase.txt` | Generated once by `make init-private`; the encrypted large archive is retained separately |
| Claude | `~/.claude/secrets.json` and its OAuth session | `claude login` if a separate provider-native check rejects the restored session |
| Codex | `~/.codex/auth.json` | `codex login` |
| Copilot | Target-scoped projection of `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_PROVIDER_API_KEY`, or `COPILOT_PROVIDER_BEARER_TOKEN` from the dedicated `~/.config/ai-agents-skills/providers/copilot.env`; an optional native credential-store session remains separate | `copilot login` only when neither the portable projection nor a native session is available; BYOK additionally needs its non-secret provider/model configuration |
| Kimi | `~/.kimi-code/config.toml`; optional ARL fallback in `providers.env` | Kimi login/provider configuration |
| OpenCode | `~/.local/share/opencode/auth.json` | `opencode auth login` |
| CodeWhale and DeepSeek | Their protected config and secret-store paths | Provider API-key setup |
| Gemini CLI | `~/.gemini/oauth_creds.json` | Gemini login |
| Antigravity | `~/.gemini/antigravity-cli/antigravity-oauth-token` | Antigravity login; this is not Gemini CLI authority |
| Grok | `~/.grok/auth.json` and protected proxy identity/state | Grok browser login or proxy re-enrollment |
| OpenClaw | Provider/channel secrets, credentials, identities, and the native `agents/<agentId>/agent/openclaw-agent.sqlite` backup snapshot; legacy `auth-profiles.json` is import input only | The pinned `openclaw doctor --fix` migrates legacy JSON, then the offline auth-closure gate rejects missing-in-use, noncanonical, or structurally invalid authentication; cooldown/credit bookkeeping is recorded but is not a technical restore failure; provider login remains an owner-input fallback |
| OpenClaw paired devices | `~/.openclaw/devices/` (`paired.json` contains durable approvals and operator tokens; `pending.json` is short-lived state) | Re-pair and approve devices with `openclaw devices` if machine-bound tokens are rejected |
| VNU eOffice | `~/.config/vnu-eoffice/secrets.json` | VNU account credentials |
| Google Chat | `~/.config/openclaw/google-chat/*.json`, always restored as `0600` | New GCP service-account key |
| Research/delivery skills | Zotero, Calibre, GetSciPapers, Send Email, Moltbook, course, and research-compute authorities | Per-service account setup |

Full verification writes the metadata-only OpenClaw runtime result to the
owner-private
`~/.local/state/coding-system/restore/openclaw-runtime-verification.json`.
The target-state verifier accepts it only as a fresh `0600`, owner-owned,
single-link regular file and binds the report's passing agent records to the
exact `.openclaw/agents/*/agent/openclaw-agent.sqlite` files. It never parses a
SQLite authority as text and never performs a model-provider call for this
authentication check.

## Dedicated skill credential authorities

Restore does not pour every key into one `.secrets.json`. Each reader gets a
bounded authority with a different schema, and only declared projections are
copied into runtimes or the OpenClaw workspace:

| Authority | Exact responsibility | Generated consumers |
|---|---|---|
| `~/.config/ai-agents-skills/secrets.json` | Shared JSON only: `CALIBRE_GDRIVE_FOLDER_ID`, `GDRIVE_CREDENTIALS`, `TELEGRAM_BOT_TOKEN`, `WEBDAV_PASSWORD`, `ZOTERO_API_KEY` | Codex/shared `workspace/.secrets.json` plus exact host Calibre and Zotero projections. The broad OpenClaw shared projection is retired; OpenClaw receives only separately declared narrow views |
| `~/.config/ai-agents-skills/calibre-secrets.json` | Generated host Calibre view containing only `CALIBRE_GDRIVE_FOLDER_ID` and `GDRIVE_CREDENTIALS` | Native Calibre selector and the separately regenerated narrow OpenClaw Calibre view |
| `~/.config/ai-agents-skills/zotero-secrets.json` | Generated host Zotero view containing only Zotero, WebDAV, Drive, and optional Semantic Scholar fields | Native Zotero selector and the separately regenerated narrow OpenClaw Zotero view |
| `~/.config/ai-agents-skills/file-delivery-queue.json` | AAS-native queue authority with exactly version 1, a 64-lowercase-hex HMAC key, a nonempty explicit channel/target map, bounded age/media/replay settings, and replay token `aas-host-state:file-delivery-replay` | Host queue only through `AAS_FILE_DELIVERY_SECRETS_FILE`; it is never copied into OpenClaw policy or workspace credentials. Absence is `NOT_CONFIGURED`, never implicit generation |
| `~/.local/state/ai-agents-skills/file-delivery-replay/` | Owner-private `0700` replay-continuity state resolved from the fixed queue token, outside agent workspaces | Host queue replay defense; it is backed up as private state and restored independently of the authority |
| `~/.config/ai-agents-skills/skill.env` | Strict per-skill env keys: `AXLE_API_KEY`, `LEANEXPLORE_API_KEY`, the four accepted OCR Space spellings, `OPENCLAW_S2_API_KEY`, `SEMANTIC_SCHOLAR_API_KEY`, `UNPAYWALL_EMAIL`, `ZENODO_TOKEN` | `AAS_SKILL_SECRETS_FILE` on native targets; OpenClaw receives only narrow Axiom, LeanExplore, research-digest, submission-venue, and Zotero projections at wrapper-owned defaults |
| `~/.config/ai-agents-skills/providers.env` | Strict child-provider fallbacks: Anthropic/Claude keys or OAuth token, DeepSeek, Gemini/Google, Grok/xAI, **Kimi/Moonshot**, OpenAI, and OpenCode | `AAS_PROVIDER_SECRETS_FILE` on Codex/shared targets and the OpenClaw main agent |
| `~/.config/ai-agents-skills/providers/copilot.env` | The five native Copilot credential names only: `COPILOT_GITHUB_TOKEN`, `COPILOT_PROVIDER_API_KEY`, `COPILOT_PROVIDER_BEARER_TOKEN`, `GH_TOKEN`, and `GITHUB_TOKEN` | The installed native Copilot launcher and its bounded OpenClaw projection |
| `~/.config/ai-agents-skills/compute.env` | `HCLOUD_TOKEN`, optional `HCLOUD_SSH_KEYS`, `KAGGLE_API_TOKEN`, optional `KAGGLE_CONFIG_DIR` | `AAS_COMPUTE_SECRETS_FILE`, the OpenClaw main-agent projection, and `~/.kaggle/access_token` derived from the Kaggle token |
| `~/.config/remote-bridge/secrets.json` | Dedicated Remote Bridge Zulip (`site`, bot `email`, `api_key`) and optional dedicated Telegram channel; inbound allowlists remain explicit | Codex selects this host path; the OpenClaw main agent gets `/workspace/.config/remote-bridge/secrets.json` |
| `~/.config/send-email/secrets.json` | SMTP/account profiles only | `SEND_EMAIL_SECRETS_FILE` and the OpenClaw Send Email projection |
| `~/.openclaw/workspace/.address-book.json` | OpenClaw Send Email saved-recipient state, not credentials | Archived directly as portable private state so contacts created in the sandbox survive restore |
| `~/.modal.toml` | Modal token ID/secret profiles | Native Modal CLI/broker and `/workspace/.modal.toml` |
| `~/.config/vnu-eoffice/secrets.json` | `VNU_EOFFICE_USERNAME`, `VNU_EOFFICE_PASSWORD`, optional `VNU_STATE_HMAC_KEY`, and optional VNU delivery bot/chat | `/workspace/secrets/vnu-eoffice/secrets.json` |
| `~/.config/course/google-classroom/credentials.json` and `token.pickle` | Google OAuth client plus refresh/session token | neutral native selector and OpenClaw projections |
| `~/.config/course/` | The rest of the course tree: per-course CLI configs, OAuth clients and tokens, and the Google Classroom token store `google-classroom/tokens/`; files with their own row are captured by that row | Read directly by the course CLI |
| `~/.config/course/canvas/config.json` | Canvas `CANVAS_LMS_API_URL`, `CANVAS_LMS_API_KEY`, and optional `CANVAS_LMS_COURSE_ID` | `CANVAS_CONFIG_PATH` on native targets and `/workspace/.config/course/canvas/config.json` in OpenClaw |
| `~/.config/getscipapers/` | The complete declared private service tree: credentials/config/proxies, Telegram session, and login/cache state | Strict allowlisted mirror at `/workspace/.config/getscipapers/` |
| Native agent homes | Claude, Codex, Copilot, Kimi, OpenCode, CodeWhale/DeepSeek, Gemini/Antigravity, Grok, GitHub, and OpenClaw session files | Read directly by each native CLI; never merged into AAS JSON |

The four OCR aliases accepted in `skill.env` are `OCR_SPACE_API_KEY`,
`OCR_SPACE_KEY`, `OCRSPACE_API_KEY`, and `OCRSPACE_KEY`. The provider allowlist
is deliberately exact: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
`CLAUDE_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `DEEPSEEK_API_KEY`,
`GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GROK_API_KEY`, `KIMI_API_KEY`,
`MOONSHOT_API_KEY`, `OPENAI_API_KEY`, `OPENCODE_API_KEY`, and `XAI_API_KEY`.
Copilot's five names are physically and logically separate. A legacy mixed
provider authority is split only after conflicts are preflighted, then its
Copilot fields are scrubbed from the broad authority. Unknown fields fail
validation instead of silently entering every agent process.

OpenClaw's established compute/provider and service-specific selectors are
attached only to agent `main`; they are removed from `agents.defaults` and from
auxiliary-agent overrides because Docker environment maps inherit and merge
defaults. The broad `AAS_SECRETS_FILE`, `OPENCLAW_SECRETS_FILE`, and
`AAS_SKILL_SECRETS_FILE` selectors are retired from the ambient sandbox, as are
the five per-skill selectors and `AAS_FILE_DELIVERY_SECRETS_FILE`. Axiom,
LeanExplore, research-digest, submission-venue, Zotero, and file-delivery
wrappers select their own owner-private `0600` default only when it exists, and
their loader constructs the skill environment from an exact allowlist.
Auxiliary agents restore with an explicit empty skill allowlist and no raw
credential selectors; adding a future credentialed auxiliary skill requires
its own owner-private workspace projection and wrapper boundary.

Those OpenClaw defaults are `/workspace/.config/ai-agents-skills/axiom-axle.env`,
`lean-explore.env`, `research-digest.env`, `submission-venue.env`, and
`zotero-secrets.json`, plus
`/workspace/.config/file-delivery/secrets.json`. The first four are strict
`KEY=value` subsets; Zotero and file delivery are exact JSON subsets. Restore
deletes the retired `/workspace/.config/ai-agents-skills/skill.env` mirror.

`~/.openclaw/secrets.json` is a host-only authority for gateway, provider,
channel, and Moltbook SecretRefs. It is never copied to
`~/.openclaw/workspace/.secrets.json` and no sandbox receives an
`OPENCLAW_SECRETS_FILE` selector. Projection convergence removes that retired
catch-all workspace file if an earlier restore created it.

In particular, Zulip does not belong in the Codex runtime's shared
`.secrets.json`. Codex's rendered environment selects the host-owned Remote
Bridge authority through `REMOTE_BRIDGE_SECRETS_FILE`; OpenClaw main uses the
regenerated workspace copy. A legacy bundle is promoted only when all three
`ZULIP_ORG_URL`, `ZULIP_EMAIL`, and `ZULIP_API_KEY` fields are complete. The
result enables configured outbound notification, while inbound control remains
fail-closed until allowed user IDs are explicitly added. Configured outbound
Zulip is therefore active after restore.

Likewise, Modal being ready says nothing about Kaggle. Kaggle is independently
`NOT_CONFIGURED` until `KAGGLE_API_TOKEN` exists in `compute.env`; materialize
then creates the supported token-file projection. Hetzner is independently
configured by `HCLOUD_TOKEN`. Credits or quota are measured separately from
these credential/resolver checks.

`CLASSROOM50_ORG_ALLOWLIST` is non-secret configuration stored with private
owner settings in the encrypted `~/.secrets.env` recovery authority. An absent
value is reported as `NOT_CONFIGURED`. API keys and bot tokens are forbidden in
that shell file after migration; they live in the bounded authorities below.
`CLASSROOM50_SERVICE_TOKEN` is deliberately not a global recovery authority and
is never restored by this repository.

The owner-settings file is data, not shell program text. The managed Bash block
opens it through the strict allowlist parser and exports only accepted literal
values; it never uses `source`, `.`, `eval`, or command substitution. Prepack
first migrates exact owner settings from the live `.bashrc`/`.profile` and their
managed pre-install copies, sanitizes any retained rollback copy to mode `0600`,
and promotes an exact historical `.npmrc.pre-coding-system` only when it is the
unambiguous canonical npm authority. Conflicts stop capture instead of choosing
the newest copy.

Personal schedules and storage locations are owner settings as well, so the
public tree carries no default for them. `CSR_OWNER_TIMEZONE` and
`CSR_RSS_DIGEST_ONCALENDAR` fill the `${...}` placeholders in
`system/schedules/host.v1.json`; a full install stops right after restoring
secrets when either is missing. A systemd timer schedule is written as the
drop-in `~/.config/systemd/user/<timer>.d/90-coding-system-schedule.conf`
(mode `0600`), which the component installer leaves alone when it rewrites the
timer unit, and which capture never copies. `CSR_RCLONE_DEST`, `CSR_OWNER_RCLONE_DEST`,
`CSR_ESCROW_GDRIVE` and `CSR_ESCROW_GH_REPO` name the offsite and escrow
locations. A value may contain spaces (a calendar expression does), which is
one more reason the file is never sourced: `bin/migrate-owner-settings.py`
removes the old `. ~/.secrets.env` loader lines and refuses any other form.

The canonical GitHub CLI files remain `~/.config/gh/hosts.yml` and optional
`config.yml`. Restore materializes private mode-`0600` copies below
`~/.openclaw/workspace/.config/gh/`, where GitHub CLI sees them as
`/workspace/.config/gh` inside the sandbox. The live OpenClaw configuration
receives only the validated organization allowlist value and the projected
config directory; token contents are never placed in command arguments, logs,
or the public repository. The offline verifier can prove the file and projection
but cannot determine token expiry. A separate `gh auth status` result may be
recorded as `REAUTH_REQUIRED`; expiry is not a technical package failure.

The VNU eOffice authority is no longer the OpenClaw workspace copy. The
workspace path is a projection generated from
`~/.config/vnu-eoffice/secrets.json`. Likewise, OpenClaw workspace secrets,
Send Email runtime copies, GitHub CLI files, and OpenClaw Zotero/Calibre
configurations are projections rather than independently backed files.

The older VNU keys inside `~/.claude/secrets.json` remain a migration source
only. Move them into the canonical VNU file, rotate the password if it was
exposed in diagnostics, then create a new recovery set.

## Migration and new recovery generations

`make secrets-pack` and full restore run the same bounded materializer. It can
promote allowlisted fields from historical `~/.claude/secrets.json`, literal
assignments in `~/.secrets.env`, historical `~/.openclaw/secrets.json`, and
legacy Zotero/Calibre configs. Successfully
promoted credential assignments are removed atomically from `.secrets.env`,
which remains only a private owner-settings data file parsed through the exact
allowlist and is never sourced or evaluated. A lowercase
`semantic_scholar_api_key` in an old Zotero config is promoted to the private
`skill.env` authority before it is scrubbed from every mode-`0644` config. It
also extracts one unambiguous Canvas field set
from historical `~/.config/course/*/config.json` files; divergent candidates
require an explicit canonical Canvas authority. It never evaluates shell code,
merges unknown keys, or logs values. Conflicting legacy and canonical data is a
verification failure rather than a last-writer-wins merge.

`make secrets-pack` automatically runs the redacted, offline
authority/projection/resolver check after bounded migration and before it
publishes a new recovery generation. It archives a metadata-only source
capability contract (IDs, statuses, and counts, never values or digests). Full
restore must make every capability that was configured at backup time
resolver-reachable again; an optional service cannot silently degrade from
`PASS` to `NOT_CONFIGURED`. You can also run the same gate directly:

```bash
python3 bin/verify-skill-credentials.py \
  --home "$HOME" \
  --repository "$HOME/coding-system-rebuild"
```

This command prints statuses, counts, and reason codes but not values, digests,
account identifiers, or service-specific exception text. If an old archive did
not contain a credential, materialization cannot invent it. Configure the
canonical authority on the source host and create a new signed recovery set;
copying a new projection into an already-created set is not supported.

New recovery generations emit source-capability contract schema v3. The reader
also accepts archived v2 contracts for backward compatibility, but v2 cannot
assert the two runtime-authority rows introduced by v3. Compatibility never
upgrades an absent historical claim into `PASS`.

## Legacy Claude/OpenClaw bundles

The legacy provider bundles can contain keys such as `TAPHOAAPI_API_KEY`,
`LAOZHANG_API_KEY`, `GROQ_API_KEY`, `ZOTERO_API_KEY`, `WEBDAV_PASSWORD`,
`GDRIVE_CREDENTIALS`, channel tokens, `GATEWAY_AUTH_TOKEN`, Moltbook keys, and
VNU migration keys. The manifest never enumerates or reads their values during
documentation or discovery. Drift between a neutral authority and a generated
target copy is a restore failure, not a reason to choose whichever copy is
newer.

These legacy files remain archived where a native Claude/OpenClaw reader still
needs them or where the migration contract explicitly names them. They are not
the canonical source for Remote Bridge, Send Email, compute, per-skill,
provider, VNU, Classroom, or target-neutral Zotero/Calibre credentials after
promotion.

## Session portability

Restoring bytes does not prove an OAuth/device session remains usable. The
mandatory verifier is deliberately offline: it checks structure, permissions,
projections, and selectors without spending credits. When an explicitly run
provider-native check supplies additional evidence, report outcomes as:

- `PASS`: offline closure passes, or a separately identified live probe accepts the session.
- `AUTH_INVALID`: restored credential is rejected.
- `REAUTH_REQUIRED`: the session was intentionally not portable, expired, or
  requires browser/MFA/device approval.
- `CREDIT_BLOCKED`: authentication works but provider quota is exhausted; this
  is not a restoration defect.
- `NOT_CONFIGURED`: an optional account was not present in the source set.

ARL/user-approval gates are ephemeral noncredential state. Configured Zulip or
Telegram delivery, Kaggle access, and Hetzner access prove only that their
bounded authorities resolve; they do not prove quota, credits, recipient
authorization, or consent for a new operation. A credential-complete loop can
still exit 2 until the user confirms a multi-agent panel, a gated Kaggle or
Hetzner action receives its exact per-operation confirmation, or enforce-mode
external notification egress is explicitly allowed. Restore must not convert
credential possession into operational consent.

Never put token values in shell command arguments, unit files, loop ledgers, or
documentation. Select the protected authority file; the bounded launcher may
inject allowlisted values into the immediate child process environment without
printing them. Recovery tooling accepts master/share/password **file paths**
only, and GnuPG receives passphrases on an inherited file descriptor.

## Crash-consistent file replacement

Restore file replacement is a durable transaction, not an exception-only
rollback. Before any declared destination file is changed, the restore engine
preflights the complete path plan and writes verified same-filesystem backups
below:

```text
~/.local/state/coding-system/recovery-transactions/
```

That state root and every transaction/backup are owner-only. The journal is
`0600` and contains metadata only (paths, sizes, hashes, modes, ownership, and
the `prepared`, `applying`, or `committed` state); plaintext file contents are
never embedded in it. Backups are regular `0600`, single-link files. Journal,
backup, file-replacement, and parent-directory transitions are fsynced before
the next state can be published.

Every restore first takes the transaction lock. The staged plan includes the
authenticated archive files, generated authorities/projections, bounded legacy
promotions and scrubs, and explicit deletions, so no migration can commit ahead
of the authority it depends on. A prior `prepared` or `applying` transaction is
rolled back to the exact pre-restore bytes and modes before the new restore
begins. A prior `committed` transaction is already durable and only its
backup/journal directory is removed. Recovery is idempotent even if the process
dies again during rollback. Symlinks, hard-linked files, foreign ownership,
cross-filesystem targets, writable shared ancestors, malformed journals, and
concurrent path changes are refused rather than overwritten.

For a live-home restore, process exit alone is not evidence of which side of
the commit boundary ran. The lifecycle therefore recovers the journal, checks
the resulting stable files against the restored source-capability contract
(v3 for current generations; archived v2 remains backward-compatible), and
resumes only the supported services recorded active before quiescence.
Recovery or verification failure leaves those services stopped and retains the
owner-private service-state record for operator inspection.

## File permissions and discovery

Credential directories are `0700`; credential files are `0600` unless the
manifest explicitly marks public or non-secret owner state. Capture validates
the live owner and single-link status before reading any selected file and
repeats the metadata check at the archive read boundary. It also refuses a file
whose group or other permission bits go beyond the manifest mode, counted only
for the classes that can traverse the home directory: an owner-only home hides
every file below it, so umask-default modes such as `0664` do not stop capture
there. Archives always carry the manifest mode, which restore applies. Capture
refuses symlinks, special files, source mutations during reading, undeclared
archive members, and newly discovered credential candidates that have not been
classified.

Metadata-only discovery also covers common agent-facing credential locations
such as legacy Kaggle JSON, Git credential-store files, PyPI configuration, and
Hugging Face token files. They are not silently added to a recovery set: an
unclassified file stops capture until it is deliberately migrated, declared,
or removed. The supported Kaggle path remains the generated
`~/.kaggle/access_token` projection from `compute.env`. Discovery opens only
undeclared files: a path that a manifest entry declares is already classified,
whatever its size or schema. An empty SQLite file is an empty database, so it
has no schema to report.

Before publishing a new generation:

```bash
python3 bin/lib/recovery_tool.py manifest-check \
  --manifest secrets/secrets-manifest.yaml
bin/secrets-verify.sh
bin/leak-scan.sh
```

Do not weaken permissions merely to make a probe pass. Kimi configuration and
Google Chat service-account JSON that previously used group/world-readable
modes must be corrected to `0600`, and affected credentials should be rotated
before the first closure-complete generation.

## What is not in the secret archive

Program binaries, npm packages, Git repositories, Docker image layers, and
generated completion files are restored from locked public identities. The
recovery set carries only the credentials/configuration required to obtain and
use them. Docker images are pulled by platform digest; only registry authority
is secret.

OpenClaw cron jobs are exported as encrypted logical declarations in private
state, not by copying the version-specific SQLite database. Runtime counters,
last-run logs, and next-wake timestamps are derived state.

Some declared paths stay outside the recovery set (`backup: false`):

- component checkouts under `~/.local/share/coding-system/components/` and the
  OpenClaw delivery projections, which restore regenerates;
- Codex log and thread-history databases, which exceed the per-file bound;
- QMD index caches, Go telemetry, Zotero staging copies, and Codex runtime code
  installed by ai-agents-skills;
- Syncthing state, kept out by owner decision, so a restored machine joins as a
  new device.

OpenClaw research data under `~/.openclaw/workspace/data/` travels in the
separate owner-data archive. Claude and Codex conversation transcripts are not
captured.

See [BACKUP-RESTORE.md](BACKUP-RESTORE.md) for recovery-set and 2-of-4 escrow
operations.
