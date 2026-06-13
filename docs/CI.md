# CI rehearsal (GitHub Actions as the throwaway VM)

`.github/workflows/rehearsal.yml` turns a fresh `ubuntu-24.04` Actions runner into
the rehearsal VM. Two jobs:

| Job | Secrets used | When | Proves |
|---|---|---|---|
| `rehearsal-core` | none | every push/PR + weekly | doctor, leak-scan (tree + full history), canary + field-set guards, rotation unit tests, full roundtrip — on a clean machine |
| `verify-keys` | individual repo secrets | push + manual (not fork PRs) | each configured key actually works (live API call) |
| `install-degraded` | none (no zip) | manual + weekly | the whole `make install` machinery on a fresh VM: prepare (real software), render configs, python envs, systemd unit render, verify |

## POLICY: the secrets zip is NEVER uploaded to GitHub

The encrypted `coding-system-secrets-*.zip` stays off GitHub entirely. CI tests
**only** with individual key secrets set via `gh secret set` (or repo Settings →
Secrets and variables → Actions). No Release asset, no base64 blob, no zip.

## What CI can and cannot verify about installation

`install-degraded` runs the **entire `make install` in degraded mode (no zip)** on a
fresh runner and asserts the key phases complete: software install (`prepare`), config
render, Python env rebuild, systemd unit render, and `verify`. It proves the install
*machinery* works end-to-end on a clean Ubuntu box.

It does **not** verify the live OpenClaw gateway starting, channel round-trips, or full
secret restore — those need the complete encrypted archive **and** a real systemd/DBUS
session, neither of which exists on a hosted runner (and the zip is never uploaded). That
remains the manual VM rehearsal (docs/BACKUP-RESTORE.md). To also clone the private
`openclaw-bot` / `ai-agents-skills` components in CI, add a `COMPONENTS_TOKEN` repo secret
(a fine-grained PAT with read access to those repos); without it those phases are skipped.

## Setting the key secrets

The fastest way (sources each value from its working deployed location, never
prints values, encrypts client-side):

```bash
make ci-secrets           # set them all
make ci-secrets ARGS=--dry-run    # preview the mapping first (names only)
```

Or add them by hand in **Settings → Secrets and variables → Actions → New
repository secret**:

| Repo secret | Tested as | Verifier endpoint |
|---|---|---|
| `ZOTERO_API_KEY` | `ZOTERO_API_KEY` | api.zotero.org/keys/current |
| `TELEGRAM_BOT_TOKEN` | `TELEGRAM_BOT_TOKEN` | api.telegram.org getMe |
| `GROQ_KEY` | provider `groq` (soft*) | groq /models |
| `ZAI_KEY` | provider `zai` | z.ai /models |
| `GOOGLE_KEY` | provider `google` | gemini /models |
| `DEEPSEEK_KEY` | `DEEPSEEK_API_KEY` | deepseek /models |
| `OPENROUTER_KEY` | provider `openrouter` | openrouter /models |

Unset secrets are simply `SKIP`ped. To add more: add a `probe ...` line in the
workflow's `verify-keys` job, a mapping row in `bin/lib/set_ci_secrets.py`, and a
case in `bin/lib/verify_secret.py`.

## Notes
- Each Actions secret is capped at 48 KB — fine, every key is far smaller.
- Secret values are auto-masked in logs; our scripts never print them.
- Secret-using jobs do **not** run on fork pull requests (Actions withholds
  secrets there). This repo is private with no external forks; the guard stays.
- A `FAIL` from `verify-keys` can mean a wrong key **or** a rate-limited/exhausted
  provider — re-check before assuming the key is bad.
- *Soft providers (e.g. `groq`) block GitHub's datacenter IPs, so a 403 in CI is a
  false negative; their FAIL is reported but does not fail the job. Verify them
  locally with `make verify-secret PROVIDER=groq`.
- arm64: add `ubuntu-24.04-arm` as a matrix `runs-on` to also rehearse arm64
  (may incur cost on private repos).
