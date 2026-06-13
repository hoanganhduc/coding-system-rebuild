# CI rehearsal (GitHub Actions as the throwaway VM)

`.github/workflows/rehearsal.yml` turns a fresh `ubuntu-24.04` Actions runner into
the P2 rehearsal VM. Three jobs, increasing trust + secret exposure:

| Job | Secrets used | When | Proves |
|---|---|---|---|
| `rehearsal-core` | none | every push/PR + weekly | doctor, leak-scan (tree + full history), canary + field-set guards, rotation unit tests, full roundtrip — on a clean machine |
| `verify-keys` | individual repo secrets | push + manual (not fork PRs) | each configured key actually works (live API call) |
| `install-full` | `ZIP_PASSWORD` + Release asset | manual dispatch only | end-to-end `make install` from the encrypted zip |

## The 48 KB rule (important)

Each GitHub Actions secret is capped at **48 KB**. The encrypted secrets zip is
~580 KB, so it **cannot** be a single secret. Two supported patterns:

### Pattern A — individual key secrets (recommended; what `verify-keys` uses)
Store only the keys you want CI to live-test. Each is tiny and masked. In
**Settings → Secrets and variables → Actions → New repository secret**, add any of:

| Repo secret | Tested as | Verifier |
|---|---|---|
| `ZOTERO_API_KEY` | `ZOTERO_API_KEY` | api.zotero.org/keys/current |
| `TELEGRAM_BOT_TOKEN` | `TELEGRAM_BOT_TOKEN` | api.telegram.org getMe |
| `GROQ_KEY` | provider `groq` | groq /models |
| `ZAI_KEY` | provider `zai` | z.ai /models |
| `GOOGLE_KEY` | provider `google` | gemini /models |
| `DEEPSEEK_KEY` | `DEEPSEEK_API_KEY` | deepseek /models |
| `OPENROUTER_KEY` | provider `openrouter` | openrouter /models |
| `TELEGRAM_CHAT_ID` | (optional) | enables the Telegram result message |

Unset secrets are simply `SKIP`ped. Add more rows by editing the `probe ...`
lines in the workflow + adding a case in `bin/lib/verify_secret.py`.

### Pattern B — full zip via a private Release asset (for `install-full`)
1. Create a private Release tagged `secrets-latest` and upload your encrypted
   `coding-system-secrets-*.zip` as `*.zip`:
   ```bash
   gh release create secrets-latest ~/secrets-out/coding-system-secrets-*.zip \
     --title "secrets (encrypted)" --notes "AES-256; fetched by install-full"
   ```
   (The asset is ciphertext; the repo is private. Update it after each `make backup`.)
2. Add the `ZIP_PASSWORD` repo secret (the zip password).
3. Run **Actions → rehearsal → Run workflow** with *run_full_install = true*.
   It fetches the asset with the built-in token, decrypts with `ZIP_PASSWORD`,
   and runs `make install` (docker images + texlive skipped on the small runner).

Alternative transports if you prefer not to use a Release: split the base64 zip
across several <48KB secrets and reassemble, or have CI `rclone` it from
`dropbox:Misc/coding-system-backups` (needs an rclone token secret).

## Security notes
- Secret values are auto-masked in logs; our scripts never print them.
- Secret-using jobs do **not** run on pull requests from forks (Actions withholds
  secrets there). This repo is private with no external forks, but the guard stays.
- A `FAIL` from `verify-keys` can mean a wrong key **or** a rate-limited/exhausted
  provider — re-check before assuming the key is bad.
- arm64: GitHub offers `ubuntu-24.04-arm` runners. To also rehearse arm64, add it
  as a matrix `runs-on` (note: arm runners on private repos may incur cost).
