# Locked Ubuntu software closure

The supported host substrate is Ubuntu 24.04 on `arm64` or `amd64`. A bare host
does not need Git, Node, Docker, or an agent CLI preinstalled. Put
`restore-ubuntu.sh` with one recovery-set directory under
`~/secrets-restore-inbox`, then run:

```bash
/usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh"
```

Stage 0 hard-fails on another operating system or architecture, installs only
the signed Ubuntu bootstrap substrate, checks out the exact
`components.coding-system-rebuild.commit` from `recovery-set.json`, then
descriptor-executes the sealed `bin/restore.sh` continuation with its protected
snapshot. It never executes a network response through a shell pipeline.

The only bare-host prerequisites are the complete protected recovery inbox, an
ordinary non-root owner account whose declared privileged operations work with
`sudo -n`, and working DNS/network access to the exact declared sources.
Stage 0 supplies Git, Make, GnuPG, Python/YAML, and other bounded bootstrap
tools. Restore then installs the declared Ubuntu packages, Docker CE, Node/npm,
Rust/Bun/elan, TeX/Calibre/browser tooling, native architecture-specific
binaries, the npm CLI closure, Python environments, and per-target
ai-agents-skills runtimes. The user does not separately install Claude, Codex,
Copilot, Gemini, Kimi, Grok, OpenCode, CodeWhale, OpenClaw, `gh-teacher`, or
their runtime packages before running Stage 0.

Executable closure and credential closure remain separate. Locks obtain and
verify program bytes; the encrypted recovery set restores native agent sessions
and dedicated AAS, Remote Bridge, Send Email, Modal, VNU, Google Classroom,
Canvas LMS, GetSciPapers, GitHub, registry, and provider authorities.
Installing a CLI does not imply its account is configured, and restoring an
expired session does not change a verified binary version.

## Release locks

The platform authorities are:

- `system/software/ubuntu-24.04-arm64.lock.json`
- `system/software/ubuntu-24.04-amd64.lock.json`
- `system/software/platform-lock.schema.json`
- `system/grok-proxy/bootstrap/release.lock.json`
- `system/grok-proxy/bootstrap/release-lock.schema.json`

Each profile binds the exact package manifests by SHA-256, records standalone
artifact URLs and SHA-256 values, records the expected CLI versions, and points
at the immutable OCI lock. `system/software/lockctl.py` checks the complete
internal relationship before preparation begins.

The separate Grok bootstrap lock closes the pre-import privilege boundary that
phase 6 requires. A qualified generation contains two architecture-native,
script-free `grok-bootstrap` Debian packages; `dispatcher.pyz`; its canonical
manifest and production Ed25519 signature; and the canonical recovery-release
authorization request and SSHSIG. Every asset URL is restricted to this
repository's release namespace and is bound by exact size and SHA-256. The
package metadata also binds its architecture, version, and source Git commit;
the installed native binary must report the public key and key ID recorded in
the Stage-0-authenticated lock. The offline authorization signs the exact five
core assets (both packages and the three dispatcher files), repository,
protected workflow identity, commit, tag, architecture set, and trust anchor.
Restore refuses a pending generation before phase 1 instead of building
privileged code locally or silently using an older host package.

Release engineering is deliberately separate from restoration. The native
build workflow compiles the package on Ubuntu 24.04 amd64 and arm64 without a
private key. The first closure release reuses the source host's retained,
production-signature-verified `bc6c611f…a08e` dispatcher; signing the newer
editable source is a later release operation, not a restore prerequisite. A
maintainer combines the chosen already-signed three-file dispatcher with the
two attested native packages, creates and signs the canonical authorization
request offline, and uploads the dispatcher plus the two public authorization
files to an exact-commit draft release. The protected manual promotion workflow
verifies that authorization, the dispatcher signature, both native build
attestations, script-free Debian inventories, upload, and seven-asset remote
readback before publishing and exporting a qualified lock candidate. The
reviewed candidate replaces `release.lock.json` in a later signed recovery
generation; workflows never synthesize a digest or hold either private key.

APT packages install at the newest version from the configured signed Ubuntu,
Docker, Tailscale, or xtradeb repository. `system/packages/apt.lock.txt` gives
each one a minimum (`name>=version`, the version the reference host ran on
2026-10-01) or, for the three xtradeb packages, the PPA itself
(`name@xtradeb`). Prepare stops on a package below its minimum or not built by
its PPA, and the installed-software report records every observed version. The
xtradeb source, signing key included, is a digest-bound file in this
repository, so no restore depends on the Launchpad API. Standalone Node,
Rustup, Bun, elan, Kimi, and Grok downloads are written to protected temporary
files and SHA-256 checked before extraction or execution.

The npm CLI set is a project closure, not a sequence of global installs.
`system/software/npm-closure/package.json` contains exactly the direct versions
listed in `system/packages/npm-globals.txt`, while its package-lock v3 records
every selected direct, transitive, and optional package with an exact
`registry.npmjs.org` URL and SHA-512 integrity. Restore runs `npm ci` against
that lock with lifecycle scripts disabled, so an integrity-checked package
cannot fetch an additional mutable installer payload.

Each install is staged and validated under
`~/.npm-global/closures/`, then published at a content-addressed directory. The
directory is made read-only. `~/.npm-global/cli-current`, the declared command
links in `~/.npm-global/bin`, and compatibility package links under
`~/.npm-global/lib/node_modules` point only into that closure. The compatibility
tree exists for OpenClaw service paths; it is not an `npm install -g` authority.
An older unowned global package tree is moved once to
`~/.npm-global/legacy/` instead of being overwritten.

Claude Code and OpenCode normally use postinstall scripts to copy a platform
binary. Restore instead exposes the corresponding Linux arm64 or amd64 binary
from its integrity-locked optional npm package directly. CodeWhale is a
different case: its npm wrapper normally downloads its native release files on
first use, outside npm's package-lock. Restore keeps lifecycle scripts disabled
and obtains `codew`, `codewhale`, and `codewhale-tui` through `lockctl.py` from
the exact GitHub release URLs of the version the npm closure locks (0.10.0,
where all three are one binary). Their per-architecture SHA-256 values are
grounded in CodeWhale's official
[`codewhale-artifacts-sha256.txt`](https://github.com/Hmbown/CodeWhale/releases/download/v0.10.0/codewhale-artifacts-sha256.txt).
The builder takes the version from the platform lock, refuses a wrapper of any
other version, and injects the verified files and their version markers into
the wrapper's `bin/downloads/` directory before the installed npm tree is
hashed and made read-only. Verification rehashes all three native files against
the active arm64 or amd64 platform lock; it never invokes CodeWhale's
downloader. The wrapper and these artifacts move together: a backup never
promotes the codewhale npm package on its own.

The host's system layer is declared too. `system/host/services.v1.json` names
the system services a restore enables (Caddy, earlyoom, monit, Ollama, the forms
tmux server, Tor), their public unit templates, and the private configuration
files that restore installs under `/etc` from the owner's recovery-set copy
(`bin/export-system-private.py` refreshes that copy during backups; a root-only
file needs a prior `sudo -v`). Crontab lines the owner adds by hand are adopted
into the private schedule file `~/.config/coding-system/host-schedules.private.cron`
and restored as their own managed block, so they never reach the public
template. Image, boot and provider packages (kernel, bootloader, cloud agents)
are not restored. Neither are Python packages installed system-wide under
`/usr/local`: ai-agents-skills provisions its own user-level skill venv
(`~/.agents_skills_venv`) with the packages its skills import.

The locks follow the host. A locked version is a floor: verification passes
when a tool is at that version or newer, wherever the owner installed it, and
reports the version it observed. Each backup (`bin/refresh-state.sh`) runs
`bin/promote-installed-clis.py`, which moves an artifact-locked CLI (Node,
Rustup, Bun, elan, Kimi, Grok, Antigravity, gh-teacher) to the newer version
installed on the host by hashing that release's HTTPS download for both
architectures, and moves each newer npm global by recording the registry's
sha512 integrity and re-resolving the npm CLI closure. A restore therefore
installs what the host ran at its last backup. A release that cannot be fetched
keeps its previous entry and the backup continues; OpenClaw moves only with its
compatibility tuple. The current versions are in the two platform locks and
`system/packages/npm-globals.txt`. The gh-teacher binaries come from the
foundation50 release named in the platform lock; installation and verification
both reject a digest or reported-version mismatch with that lock.

Aider is installed and version-inventoried, but its account/provider readiness
is optional and remains `NOT_CONFIGURED` until an explicit bounded provider
authority exists. Package presence is not a live provider or credit check.
GitHub CLI must be at least 2.45.0: offline verification proves the
binary version and the protected structural shape of `~/.config/gh/hosts.yml`;
token expiry is a distinct native `gh auth status` outcome and may be
`REAUTH_REQUIRED` without invalidating the software closure.

Tailscale installs the newest release from Tailscale's signed Noble
repository, at least 1.102.3. The official [v1.98.4 CLI source](https://github.com/tailscale/tailscale/blob/v1.98.4/cmd/tailscale/cli/up.go#L95-L99)
defines the `file:` form for `--auth-key`, and its resolver reads and trims the
named file before authentication. Restore therefore passes only
`--auth-key=file:<protected-path>`, consistent with Tailscale's
[auth-key security guidance](https://tailscale.com/docs/features/access-control/auth-keys/how-to/secure-auth-keys).

Claude's direct wrappers for Zotero, Calibre, vnthuquan, and Modal delegate to
the same pinned shared ai-agents-skills runtime used by the other targets. The
installer verifies that runtime's recorded digest and provides no Claude-local
fallback. A historical Claude-local runtime copy is retired only when its bytes
exactly match a known legacy copy; divergent residue blocks convergence.

`~/.gauss/.env` is discovery-only legacy residue. Shell startup never sources
it, the software closure does not treat it as an OpenGauss credential
authority, and recovery discovery stops for explicit classification rather
than silently archiving or activating it.

Docker Engine is restored from Docker's official Ubuntu Noble repository at
the newest release, no older than the reference host's 2026-10-01 tuple
(Engine/CLI 29.7.2, containerd, Buildx, Compose, and rootless extras). The repository signing key is itself a
SHA-256-locked artifact; Docker's documented amd64 and arm64 Ubuntu support is
the platform authority.

Authoritative version/checksum sources include the
[Node distribution checksums](https://nodejs.org/dist/),
[Rust static archive](https://static.rust-lang.org/rustup/archive/),
[Bun releases](https://github.com/oven-sh/bun/releases),
[elan releases](https://github.com/leanprover/elan/releases), the
[Antigravity CLI releases](https://github.com/google-antigravity/antigravity-cli/releases),
and the vendor Kimi manifest. The xAI Grok endpoint does not publish an independent checksum;
its exact bytes are locked but explicitly marked `UNVERIFIED — assumed` until
the release pipeline mirrors and signs them.

The standalone DeepSeek executable is `NOT_APPLICABLE`: CodeWhale is the
declared and version-probed DeepSeek compatibility surface for this system.
`lockctl.py --require-complete` still fails on any future unresolved required
artifact instead of treating the host as closure-complete.

These numbers describe this signed commit, not a request to remain forever on
those releases. An existing recovery set deliberately remains reproducible if
upstream publishes newer versions: it continues to install its qualified
tuple. `make closure-drift` or `make refresh-lock` reports upstream/installed
drift but does not silently change recovery authority.

Updating software is a separate release operation: select the intended
versions, ground every URL/checksum, build a candidate lock, validate all
cross-lock hashes and compatibility contracts, exercise both native Ubuntu
24.04 clean-host profiles, and promote the whole tuple in review. For npm,
change `npm-globals.txt` and the exact dependency in
`npm-closure/package.json` together, regenerate `package-lock.json` with the
locked Node/npm pair using `npm install --package-lock-only --ignore-scripts`,
review every new registry/integrity record, and run `closurectl.py validate`.
OCI/Python/privileged artifacts additionally need their own publication and
qualification evidence. Publish the resulting repository commit and create a
new signed recovery set bound to it. Normal backup and restore never rewrite
version pins or the package-lock.

A lock can be structurally valid yet not release-ready. Full restore requires
the active platform and Python qualification states to be `qualified` and the
privileged Grok release lock to be published/qualified. In the current
checkout, those records still contain pending states; full mode therefore
stops with `ARTIFACT_UNAVAILABLE` rather than selecting whatever happens to be
latest upstream.

MCP processes are also part of the executable closure; they may not use a
floating `npx`/`uvx` launcher. The enabled, disabled, and intentionally omitted
sets and their bounded handshake gate are documented in
[MCP-CLOSURE.md](MCP-CLOSURE.md).
