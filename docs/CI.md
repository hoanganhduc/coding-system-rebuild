# CI rehearsal (GitHub Actions as the throwaway VM)

`.github/workflows/rehearsal.yml` runs no-secret contracts on fresh Ubuntu 24.04
runners. Its core jobs are:

| Job | Secrets used | When | Proves |
|---|---|---|---|
| `rehearsal-core` | none | every push/PR + manual | doctor, leak-scan (tree + full history), canary + field-set guards, rotation unit tests, full roundtrip — on a clean machine |
| `platform-contracts` | none | every push/PR | native amd64 + arm64 platform, npm, Python-wheelhouse, OCI, shell, and focused contract validation |
| `verify-keys` | individual repo secrets | push + manual (not fork PRs) | each configured key actually works (live API call) |
| `install-degraded` | none | manual only, amd64 + arm64 | the whole degraded `make install` machinery on a fresh VM: prepare, render, Python envs, unit render, verify |

## Native Python wheelhouse workflow

`.github/workflows/python-wheelhouse.yml` is a separate, no-secrets supply-chain
workflow.  It builds CPython 3.12 wheels natively on `ubuntu-24.04` amd64 and
`ubuntu-24.04-arm`, verifies the artifact-only filesystem, offline-installs all
seven environments, runs `pip check`, requires exact inventories, and executes
functional smokes.  Pull-request and push runs validate locally without
publishing.  Only a manual dispatch may publish the validated
architecture-scoped candidates and their multi-platform candidate digest, and
even that job does not modify restore locks or qualification state.  Review and
promotion are separate gates; see [PYTHON-CLOSURE.md](PYTHON-CLOSURE.md).

## Grok bootstrap package and promotion workflows

`.github/workflows/grok-bootstrap-build.yml` runs in the protected
`grok-bootstrap-build` environment and compiles the production-public-key native
verifier and script-free Debian package separately on Ubuntu 24.04 amd64 and
arm64. It receives no private key, emits build-provenance attestations, and
publishes only run-scoped package artifacts. The manual promotion workflow uses
separate protected verification and publication environments. It accepts a
successful build run and an exact-commit draft release containing the three
public, production-signed dispatcher files plus an offline-signed canonical
authorization request and SSHSIG. It verifies that administrative signature,
the dispatcher signature, both build attestations, Debian metadata and closed
control/payload inventories, then performs seven-asset upload/readback before
publishing and exporting a qualified lock candidate. It cannot create either
signature, does not overwrite release assets, and does not edit the checked-in
lock. The retained first-generation dispatcher is exported with
`bin/export-signed-grok-dispatcher.py`, which verifies its production signature
and emits only the three public files—never a private key. See the publication procedure in
`system/grok-proxy/bootstrap/README.md`.

## Policy: recovery media is never uploaded to GitHub

Encrypted recovery sets, escrow shares, and owner-data archives stay off GitHub
Actions entirely. CI tests **only** with individual key secrets set via `gh
secret set` (or repository Actions settings). No recovery artifact, share,
base64 blob, or legacy ZIP is accepted by a workflow.

## What CI can and cannot verify about installation

`install-degraded` runs the **entire `make install` in degraded mode (no recovery set)** on a
fresh runner and asserts the key phases complete: software install (`prepare`), config
render, Python env rebuild, systemd unit render, and `verify`. It proves the install
*machinery* works end-to-end on a clean Ubuntu box. Until a qualified Grok bootstrap
release is published, the job sets `SKIP_GROK=1`, which a real restore also needs
today: the fixture below still builds and checks the signed bootstrap, while phase 6
installs no Grok release and must report that it skipped the Grok gates.
The job first moves the runner image's own Node out of `/usr/local/bin`: a fresh
Ubuntu has none, and it would shadow the locked Node in `~/.npm-global/bin`. If the
installer fails, the job resumes it once after each failing phase, so the same run
also reports later failures; those probe logs are diagnostics only.

It does **not** verify the live OpenClaw gateway starting, channel round-trips, or full
secret restore — those need the complete encrypted archive and production-like host and
service state (and recovery media is never uploaded). The workflow starts a transient systemd
user manager only to provide the D-Bus session used by later user-unit registration. The
installer itself runs as the target UID in a bounded system-manager service whose direct
parent is delegated and whose main process is isolated in an `installer` subgroup. A
fixed-purpose preflight enables only the CPU, memory, and PID controllers, then requires
the production cgroup predicate to select that exact direct parent; fallback to an
ambient user-manager cgroup fails closed. The fresh-runner fixture also mirrors the
production package activator's persistent state anchors: a preserved empty root-owned
`release-control/operation.lock` and the root-owned `runner-scopes` journal directory.
The preflight validates both before install; the production installer remains forbidden
from creating or repairing its own operation lock. The job does not recursively delete
fixed root paths afterward: the GitHub-hosted VM is discarded, while the private signing
key is already removed by its narrowly scoped temporary-directory trap. This avoids
turning an unconditional cleanup step into authority over pre-existing host state. This is
not a live-service rehearsal. Full
installer output is capped at 4 MiB before it reaches the Actions log/artifact
path; exceeding that ceiling fails the job. The transient service limits the
launcher and cooperating descendants, but is not a sandbox for the deliberately
privileged install operations: a unit started through `sudo systemctl` has its
own systemd lifecycle. The structured post-install gates, rather than the
transient cgroup, prove those operations reached the expected state. Full
verification remains the manual VM rehearsal (docs/BACKUP-RESTORE.md). The `openclaw-bot` and
`ai-agents-skills` components are public and clone without a token. The optional
`COMPONENTS_TOKEN` repo secret (a fine-grained PAT with read access) is only for a private
component; without it such a component is unavailable in CI.

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
  secrets there). This repo is public, so the guard stays.
- A `FAIL` from `verify-keys` can mean a wrong key **or** a rate-limited/exhausted
  provider — re-check before assuming the key is bad.
- *Soft providers (e.g. `groq`) block GitHub's datacenter IPs, so a 403 in CI is a
  false negative; their FAIL is reported but does not fail the job. Verify them
  locally with `make verify-secret PROVIDER=groq`.
- `platform-contracts` runs natively on both architectures; full secret-bearing
  clean-host restoration remains an operator drill, never an Actions job.
