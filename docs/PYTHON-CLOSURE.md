# Python Artifact Closure

## Status

Restore phase 9 is wired to a digest-selected, artifact-only OCI wheelhouse for
Ubuntu 24.04 on `amd64` and `arm64`. It installs eight isolated environments:
`workspace`, `shared`, `docling-cpu`, `lean-explore`, `getscipapers`, `aider`,
`modal`, and `course-management`.

The workspace venv lives under
`~/.openclaw/workspace/.python-closure/` so its relative `.local` projection is
valid both on the host and at `/workspace` inside the sandbox. Six shared tool
venvs live under `~/.local/share/coding-system/python-closure/`.
`course-management` is exposed as the managed `~/.course_venv` generation
link so Classroom50 never falls back to the ambient interpreter.

The production Python locks remain deliberately `pending-artifacts`, and the
OCI image lock does not yet contain a promoted `python-wheelhouse` role.
Consequently, a full restore currently stops with `ARTIFACT_UNAVAILABLE`; it
does not fall back to PyPI, Git, an sdist build, or the old freeze files. A CI
or no-recovery-set restore validates the declarations and records the runtime
artifact gate as skipped.

## Authority chain

The runtime trust chain is:

1. `system/software/images.lock.json` selects one digest-only OCI image and an
   exact platform-manifest digest.
2. `bin/extract-python-wheelhouse.py` hashes the registry manifest, confirms the
   platform descriptor and local image identity, then copies `/wheelhouse` from
   a never-started container through a bounded tar extractor.
3. Canonical root and per-environment manifests bind every wheel filename,
   distribution/version, compatible tag, byte digest, count, and total size.
4. A canonical, read-only extraction receipt binds the local wheelhouse to the
   image-lock digest, OCI index/platform digests, platform, and root manifest.
5. The architecture-specific Python lock binds that root manifest, each
   environment manifest, and the identical artifact inventories.
6. Each installed venv marker uses
   `coding-system.python-closure-install/v3` and binds the Python-lock digest,
   OCI receipt, root and environment manifests, exact distribution inventory,
   and a canonical installed-content-tree digest. The tree attestation covers
   regular-file bytes (including package modules, native modules, metadata, and
   generated entry points), all directory records, file and directory modes,
   symlink targets, and any `.pyc`/`.pyo` or `__pycache__` content. No
   bytecode/cache pathname is exempt from installed authority.

Python lock schema v2 intentionally has no per-wheel URL. Wheels come only from
the validated OCI directory, so fake, mutable, or unreachable URLs cannot be
mistaken for a qualified recovery source. Qualified records contain only
`name`, `version`, `filename`, `tags`, and `sha256`. A qualified environment
must also carry its canonical `manifestSha256`; a qualified platform must bind
the root `wheelhouseManifestSha256` and qualify all eight environments.
The reproducible build inputs pin `course-hoanganhduc` 0.4.0 to
`course_management_toolkit` commit `5e402db40db6c4a50d9c9292a5b352e62447ab04`.

`docling-cpu` rejects CUDA, NVIDIA, Triton, ROCm, and non-`+cpu` PyTorch records.
Only CPython 3.12 wheels compatible with the selected architecture are admitted.

## Restore behavior

`make restore` reaches phase 9 through `bin/install.sh`. In a full restore it:

```bash
python3 bin/extract-python-wheelhouse.py extract \
  --lock system/software/images.lock.json \
  --arch arm64 \
  --destination "$HOME/.cache/coding-system/python-wheelhouse/arm64" \
  --provenance "$HOME/.cache/coding-system/python-wheelhouse/arm64.provenance.json" \
  --replace

python3 bin/install-python-closure.py install-all \
  --lock system/python-closure/ubuntu-24.04-arm64.lock.json \
  --images-lock system/software/images.lock.json \
  --wheelhouse "$HOME/.cache/coding-system/python-wheelhouse/arm64" \
  --provenance "$HOME/.cache/coding-system/python-wheelhouse/arm64.provenance.json" \
  --replace-unmanaged
```

The installer never resolves or downloads dependencies. It creates pip-less
venvs and uses host pip only as an offline wheel unpacker with `--isolated`,
`--no-index`, `--no-deps`, and `--no-compile`. It then runs `pip check`, compares
the exact inventory, hashes the installed content tree, writes the read-only
provenance marker, and switches each logical environment symlink. Package
files are frozen to `0444`/`0555` and package directories to `0555` before
activation, so a normal import cannot create an unattested cache. The
generation root remains `0755` only for the atomic marker write; any new root
entry changes the attested tree and fails verification. Existing
target state remains in a rollback path until the activated environment passes
its post-switch verification. A failure before the switch restores that path
with an atomic rename; a failure after the switch uses Linux
`renameat2(RENAME_EXCHANGE)` to put the old file, directory, or symlink back in
one namespace operation without first deleting it. Rerunning a verified
generation returns `unchanged`. Marker schema v3 with content schema v2 covers the generation-root
mode, every installed directory mode, regular-file byte digest and mode, and
symlink target, including interpreter bytecode and cache paths.

After all eight environments install, compatibility links expose the workspace
site-packages, shared venv, Docling venv, LeanExplore venv, Aider, and Modal at
the runtime paths used by existing skills, plus Classroom50 at
`~/.course_venv`. The installed ai-agents-skills
workspace receives its own `.local` link to the shared venv, so its managed
runner resolves the restored interpreter and packages during normal execution.
The phase-9 installed-runtime smoke additionally receives the same interpreter
through `AAS_RUNTIME_PYTHON` while its code is copied to an isolated scratch
workspace. Codex separately selects `~/.codex/runtime` through its rendered
shell-environment policy. A provider-free phase-9 smoke runs that private
runner with an isolated `HOME` in which the normal shared
`~/.local/share/ai-agents-skills/runtime` route is absent. The OpenClaw
workspace `.local` link is relative and remains
entirely within the mounted workspace; no host-absolute sandbox link is created.
Replacing a pre-existing unmanaged path requires
`--replace-unmanaged`, which phase 9 supplies during a fresh-system migration.
Compatibility projections form a separate batch transaction: every replacement
is staged first, all prior paths are retained until the complete link set
verifies, and a failure rolls changed links back in reverse order before any old
state is removed. This rollback guarantee is per environment activation and for
the whole compatibility-link batch; it does not claim that `install-all` rolls
back already verified environment activations when a later environment fails.

OpenClaw sandbox execution does not reuse host venv binaries across the Ubuntu
host/Debian image boundary. The sandbox image build consumes the canonical
`docling-cpu`, `lean-explore`, and `course-management` wheelhouse inputs into
separate image-owned venvs under `/opt/coding-system/python-closure/`. Their
launchers select those paths only when both `HOME` and `OPENCLAW_WORKSPACE` are
`/workspace`. The sandbox image sets both values as part of contract v3; host
execution selects the restored host closure. The sandbox contract checks exact
manifest inventory, CPU-only PyTorch, imports, Docling, `course --help`, and
the Classroom50 agent entrypoint without contacting a package index.

Calibre metadata bootstrap remains after this gate. Services and schedulers are
started only in later phases, so no restored job can observe a partially
installed Python runtime.

## Verification

Structural validation does not claim artifact availability:

```bash
python3 bin/install-python-closure.py validate \
  --lock system/python-closure/ubuntu-24.04-arm64.lock.json
```

The release gate is stricter and intentionally fails while locks are pending:

```bash
python3 bin/install-python-closure.py validate \
  --lock system/python-closure/ubuntu-24.04-arm64.lock.json \
  --require-qualified
```

After promotion and installation, verify the extraction authority, all
installed inventories, and every marker-v3 content-tree attestation without
registry or package-index access:

```bash
python3 bin/extract-python-wheelhouse.py verify-directory \
  --directory "$HOME/.cache/coding-system/python-wheelhouse/arm64" \
  --platform linux/arm64 \
  --lock system/software/images.lock.json \
  --provenance "$HOME/.cache/coding-system/python-wheelhouse/arm64.provenance.json"

python3 bin/install-python-closure.py verify-all \
  --lock system/python-closure/ubuntu-24.04-arm64.lock.json \
  --images-lock system/software/images.lock.json \
  --wheelhouse "$HOME/.cache/coding-system/python-wheelhouse/arm64" \
  --provenance "$HOME/.cache/coding-system/python-wheelhouse/arm64.provenance.json"
```

`make verify` runs those gates in the full profile. The CI profile validates the
lock schema and explicitly skips extraction/live inventory because it has no
promoted runtime artifact or restored home.

## Build and promotion

`.github/workflows/python-wheelhouse.yml` builds both architectures on native
Ubuntu 24.04 runners. The Docker builder may resolve and build candidate wheels;
the final `scratch` image contains only `/wheelhouse`. Candidate validation
creates fresh pip-less venvs, installs exclusively with `--no-index --no-deps`,
runs exact inventory and dependency checks, and performs environment-specific
imports/CLI probes. The workflow does not edit release locks or qualification
state.

Production promotion requires a reviewed change that:

1. records exactly one multi-platform `python-wheelhouse` image in
   `images.lock.json`, using its immutable index digest and both exact platform
   digests;
2. copies each architecture's canonical root/environment manifest digests and
   artifact arrays into the matching Python lock, then marks every environment
   and the platform `qualified`;
3. records successful clean-host extraction, offline install, functional,
   rollback, tamper, and second-run idempotence evidence for both architectures;
4. updates the parent platform-lock hashes that bind the image and Python locks.

A build completion or candidate tag is not qualification. Missing artifacts,
digest disagreement, incompatible wheels, incomplete inventory, or failed
functional probes remain technical blockers.
