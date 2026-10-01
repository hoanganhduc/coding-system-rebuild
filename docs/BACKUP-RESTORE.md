# Recovery-set backup and restore

The supported private backup is an immutable recovery-set directory. A
historical AES ZIP is `legacy-incomplete` and is never accepted directly by the
restore path.

## Recovery-set layout

```text
csr-<utc>-<nonce>/
├── recovery-set.json
├── recovery-set.json.sig
├── recovery-signing-public-key.pub
├── escrow-generation.json
├── keys.json.gpg
├── secrets.tar.gpg
└── private-state.tar.gpg
```

`recovery-set.json` is public metadata and the final commit marker. It binds:

- an immutable set identity and creation time;
- the exact lowercase 40- or 64-hex `coding-system-rebuild` commit;
- the v2 secrets-manifest digest;
- the immutable escrow generation and manifest digest; and
- every ciphertext filename, size, and SHA-256 digest.

The `.sig` and `.pub` files are the bounded detached-signature/public-key pair
used by the bare-host bootstrap. They contain no secret material and must
appear together when present.

`secrets.tar.gpg` and `private-state.tar.gpg` each use a fresh random 256-bit
passphrase. Their keys and plaintext digests live in `keys.json.gpg`, which is
encrypted by the escrow master. That encrypted envelope repeats the exact
`coding-system-rebuild` commit, so changing only the public commit reference is
rejected. The master itself is never in the recovery set.

Create, validate, and restore each read the secrets manifest once into bounded
immutable bytes and use that same snapshot for parsing and hashing. When the
referenced repository commit exists in the local Git object database, its exact
`secrets/secrets-manifest.yaml` blob must have the same digest.

Schemas are published at:

- `secrets/recovery-set.schema.json`
- `secrets/escrow-generation.schema.json`
- `secrets/secrets-manifest.schema.json`

## Immutable 2-of-4 escrow generation and distribution

Configure the two rclone roots and the exact existing private GitHub repository.
The command never creates a repository. Choose new local paths; creation and
every remote write refuse overwrite:

```bash
umask 077
mkdir -p "$HOME/.config/coding-system/escrow"

generation_dir="$HOME/.config/coding-system/escrow/generation-$(date -u +%Y%m%dT%H%M%SZ)"
master_key="$HOME/.config/coding-system/recovery-master.key"

CSR_RCLONE_DEST='<dropbox-remote>:<backup-path>' \
CSR_ESCROW_GDRIVE='<gdrive-remote>:<backup-path>' \
CSR_ESCROW_GH_REPO='<owner>/<private-escrow-repository>' \
bin/escrow-passphrase.sh create-and-publish \
  "$generation_dir" \
  "$master_key"
```

The immutable mapping is:

| Index | Location | Generation objects |
|---|---|---|
| 01 | owner-only local generation directory | `escrow-generation.json`, `share-01.txt` |
| 02 | Dropbox rclone root | `generations/<generation_id>/escrow-generation.json`, `share-02.txt` |
| 03 | Google Drive rclone root | `generations/<generation_id>/escrow-generation.json`, `share-03.txt` |
| 04 | exact private GitHub repository | `generations/<generation_id>/escrow-generation.json`, `share-04.txt` |

Location 04 is the private repository named by the owner setting
`CSR_ESCROW_GH_REPO`; the three locations are owner settings with no built-in
default. Its role is deliberately narrow: it stores **one** share and the
public digest-bearing generation manifest. It is not a mirror of
`coding-system-rebuild`, does not contain `secrets.tar.gpg`, and cannot decrypt
anything by itself. The encrypted recovery-set directory is retained/uploaded
separately by `make secrets-pack` and `make offsite`; recovery combines that
set with any two matching shares from different custody locations. The restore
does not clone or execute code from the escrow repository.

The tool snapshots the source generation into owner-only tmpfs, validates every
recorded digest and all six possible 2-share pairs, and uploads only that stable
snapshot. Rclone writes use `--immutable`; GitHub creates objects without an
overwrite SHA after confirming the exact repository is private. It then reads
all six remote objects back into a new tmpfs directory, compares all three
manifests byte-for-byte, validates all four individual share hashes, and proves
all six pairs again. Only after that complete proof are `share-02.txt` through
`share-04.txt` removed from the creation directory. The local manifest and
share 01 remain. The same verified transaction atomically selects the generation
through `~/.config/coding-system/escrow/current`, which is the default authority
used by `make backup` and unattended backup jobs; a non-symlink object at that
name is never replaced.

`escrow-generation.json` contains only public metadata and digests, never share
values. Share contents are not placed in process arguments, environment
variables, or command output. A failed publication retains the local shares. If
a late failure has already created one remote object, preserve it as evidence
and create a new generation rather than deleting or overwriting it.

Read-only distribution verification is repeatable after local retirement:

```bash
bin/escrow-passphrase.sh verify-distributed "$generation_dir"
```

Never overwrite remote share names. Retain a share generation for as long as
any recovery set references it. The schema records share digests so a share
from another generation is rejected before decryption.

For a fresh host, fetch exactly two matching shares to deterministic protected
basenames. This example uses the local and Google Drive locations. The owner
settings file is not restored yet at this point, so the location of each remote
share is given in the environment; share 1 needs none:

```bash
generation_id=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["generation_id"])' \
  "$generation_dir/escrow-generation.json")
inbox="$HOME/secrets-restore-inbox/escrow/$generation_id"
install -d -m 700 "$inbox"

bin/escrow-passphrase.sh fetch-share \
  "$generation_dir/escrow-generation.json" 1 "$inbox/share-01.txt"
CSR_ESCROW_GDRIVE='<gdrive-remote>:<backup-path>' \
bin/escrow-passphrase.sh fetch-share \
  "$generation_dir/escrow-generation.json" 3 "$inbox/share-03.txt"
```

The manifest and share paths are non-secret; the helper writes each share
through an exclusive no-follow create at mode `0600` and validates its index
and digest before success. Stage0 matches those basenames against the recovery
set's embedded escrow manifest. It refuses a missing, duplicate, mismatched, or
third share rather than guessing.

To reconstruct the master, write it to a protected file; it is never printed:

```bash
bin/escrow-passphrase.sh recover-to \
  /path/to/escrow-generation.json \
  /path/to/share-01.txt \
  /path/to/share-03.txt \
  /protected/path/recovered-master.key
```

## Create a recovery set

First publish the reviewed public commit. A recovery set cannot name a dirty,
detached, differently hosted, or unpublished checkout, because Stage 0 must be
able to fetch the exact commit on a bare host. Then create and upload the set:

```bash
cd "$HOME/coding-system-rebuild"
make backup-public
git show --stat
make push
make secrets-pack
make offsite
```

`make secrets-pack` first runs the bounded credential materializer. Its
allowlisted migrations cover VNU eOffice, Remote Bridge Zulip, shared AAS,
compute, per-skill and provider fields, Zotero/Calibre, Google Classroom,
Canvas LMS, the historical lowercase Zotero Semantic Scholar key, and the
legacy GetSciPapers sandbox tree. Before those credential moves, the owner
settings migrator parses the live and managed pre-install Bash/profile copies
as data, sanitizes retained rollback files, and refuses conflicts; it never
sources or evaluates `.secrets.env`. The AAS file-delivery queue authority and
its separate replay-continuity tree are archived when present, while generated
views are excluded. It then archives
authorities rather than generated runtime copies. It also exports the current
logical OpenClaw cron declaration snapshot when OpenClaw is configured; a
configured but unhealthy gateway stops capture rather than silently producing
a backup with stale or absent jobs. Host crontab and user-systemd desired state
are public declarations in this repository.

The same credential contract includes the three exact Git-ignored Forms local
files under `~/forms/apps/`: the Classroom50 runner `.env`, API `.dev.vars`, and
web `.env.local`. The first two are local credential authorities and the third
is private endpoint state. Provider-managed GitHub Actions and Cloudflare
deployment secrets remain in those providers and are not claimed as exportable
host backup data; restored `gh` and Wrangler sessions provide access to manage
them after restore.

Promotion is key-wise and allowlisted. It does not guess values, accept shell
expressions, or turn an absent optional account into an empty credential. The
pack command runs the redacted closure gate automatically; these commands are
useful for an additional operator check and archive verification:

```bash
python3 bin/verify-skill-credentials.py \
  --home "$HOME" \
  --repository "$HOME/coding-system-rebuild"
bin/secrets-verify.sh
```

If the report says `NOT_CONFIGURED` for a service you expect to use, configure
its canonical authority before continuing. In particular, an old recovery set
that omitted Zulip, Kaggle, Kimi/provider fallback, VNU eOffice, Canvas LMS, or
another credential authority cannot be repaired in place: configure or migrate
the source authority and create a new immutable set.

The set directory is created exclusively and `recovery-set.json` is written
last. Before any archive is created, capture requires every selected live file
to be owned by the restoring user, have exactly one hard link, and match its
manifest mode. It also fails on missing required authorities, symlinks, special
files, source changes during reading, or output reuse. Credential values never
appear in process arguments, environment values, or logs.

After creation:

1. `make offsite` refuses overwrite, requires exact local/remote inventory
   equality, fetches the published tree into protected local storage, and
   re-runs the detached-signature and complete public-manifest inventory gates
   over those fetched bytes.
2. Fetch any two shares into a synthetic restore inbox and authenticate the
   downloaded set before changing the advertised recovery pointer.
3. Keep the previous known-good set and its escrow generation until the new set
   passes a clean-host restoration drill.

## Fresh-host verification and restore

Run restoration from an ordinary shell after exiting interactive agent CLIs.
The command validates the authenticated recovery set first, records which of
the OpenClaw gateway and host queue worker are active, and stops those units in
dependency order. The state record is owner-private and names only those two
exact units. A native credential client or lingering supported service process
fails the quiescence gate rather than allowing replacement beneath a live
reader.

Place one complete set and exactly two matching shares under the deterministic
inbox on a stock Ubuntu 24.04 `amd64` or `arm64` host. The owner account needs
noninteractive `sudo -n`, working DNS/network access to the declared
repositories/registries, and owner-only inbox/escrow directories; Git, `gh`,
Node/npm, Docker, and the agent CLIs need not already exist. Prepare exactly two
matching mode-`0600` shares, then run the sole trusted Stage-0 operator command:

```bash
/usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh"
```

The verifier checks public schemas/bindings, ciphertext size/digests, share
membership, GnuPG authentication, plaintext size/digests, archive bounds,
member types, canonical paths, duplicates, manifest coverage, and modes without
extracting into the destination.

Every recovery-media entry point authenticates `recovery-set.json.sig` against
the repository-pinned signing key before it can mutate restored state. Stage 0
first streams the closed recovery inventory through held no-follow descriptors
into an owner-only, read-only `/tmp/csr-recovery-snapshot.<uid>.*` directory.
The signed repository pointer, embedded Stage-0 script, and descriptor-bound
handoff to the sealed `bin/restore.sh` all use that snapshot, never the original
removable/FUSE paths.

Repository-side validation and restore independently capture key, signature,
manifest, escrow metadata, and all ciphertexts into one private snapshot. The
signature is checked over the exact manifest bytes held by that snapshot, and
artifact size/digests plus authenticated plaintext digests are checked before
destination mutation. Direct `make restore-secrets` therefore cannot verify set
A and restore a path-swapped set B. `make restore` and `bin/install.sh` are
internal Stage-0 continuations, not independent recovery trust roots; they
require its protected snapshot and signed-commit handoff. Authenticated restore
rejects the descriptor-launch repository override (which remains a degraded
CI-only path), disables Git hooks/file monitors/replacement objects, lazy
fetches, transports, and auxiliary object caches. Before any candidate Git
object is executed, Stage 0 validates local metadata and ancestor ownership,
rejects alternates, promisor storage and config includes, and runs strict full
fsck over the signed commit closure. It does not trust `.git/index` or `git
status`: a verifier read from the checked commit hashes the closed working-tree
inventory, types, and executable modes against that commit and rejects extra
paths, shared-writable ownership, and remote/FUSE storage. Security-critical Python
entry points use an empty bytecode cache prefix, so ignored repository-local
`__pycache__` files cannot replace reviewed source. GnuPG is the fixed Ubuntu
`/usr/bin/gpg`, symmetric-key caching is disabled, and each scoped agent is
terminated before its temporary homedir is removed. Missing, malformed,
differently keyed, invalid, or later path-replaced inputs cannot change the
bytes consumed by install or destination restore.

Restore decrypts only below an owner-only tmpfs root. It prefers
`$XDG_RUNTIME_DIR` or `/run/user/$UID` and can create an owner-only recovery
root on `/dev/shm`. It fails closed if none is available. A persistent staging
filesystem is admitted only when both an owner-only directory is named and the
risk is explicitly acknowledged:

```bash
install -d -m 700 "$HOME/.local/state/coding-system/recovery-tmp"
CSR_RECOVERY_TMPDIR="$HOME/.local/state/coding-system/recovery-tmp" \
CSR_RECOVERY_ALLOW_PERSISTENT_TMP=1 \
/usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh"
```

Persistent staging can leave recoverable credential bytes after a crash and is
not the normal restore path. Destination traversal uses no-follow directory
descriptors. Symlink or non-directory ancestors and non-regular targets are
refused. Identical files are idempotent; divergent files fail before mutation.
An explicitly supervised merge may set `CSR_RESTORE_REPLACE=1`. Authorities,
generated projections, bounded legacy promotions/scrubs, and declared stale
deletions are preflighted and committed in one fsynced transaction. A process
death before commit rolls every affected path back to its original bytes and
mode; death after commit preserves the complete new state and leaves only
owner-private cleanup for the next recovery pass.

The bootstrap auto-selects exactly one recovery set and exactly two matching
shares, then passes their paths into the sealed restore continuation without
placing share values in arguments or environment variables. An optional single owner-data archive
under `~/secrets-restore-inbox/owner-data/` is selected before installation.
After authorities land, install phases regenerate only non-secret runtime state
and validate offline credential structure, modes, selectors, installed resolver
reachability, and every capability recorded by the current source v3 contract.
Archived v2 contracts remain accepted for backward compatibility but cannot
assert capabilities introduced only in v3. A
nonzero restore subprocess cannot be assumed pre-commit: the live path first
recovers the durable journal, materializes runtime state, and repeats that
credential gate. Only then does it resume exactly the units recorded active.
An unresolved journal, failed materializer, failed credential gate, or failed
resume retains the state record and leaves services stopped. These checks do
not spend provider credits or claim that an OAuth session is accepted by its
remote service. Schedulers activate only after the technical closure checks
pass; exact legacy cron predecessors are adopted once, ambiguous near-matches
are refused, and enabled timers are verified active.

That one operator command restores the locked Ubuntu/native CLI substrate,
agent-specific sessions, target-neutral skill authorities, Codex and shared
skill runtimes, Docker image digests, OpenClaw completion, user-systemd state,
the managed host crontab block, and logical OpenClaw cron declarations. The
encrypted owner-data archive is optional and separate because large history,
research data, and session memory have different retention needs from the
credential recovery set.

## Legacy ZIP migration only

Historical archives reveal filenames, used a shared AES ZIP password, and may
omit current authorities. They remain evidence for migration, not accepted
restore inputs. Keep the original immutable while importing:

```bash
LEGACY_ZIP=/path/coding-system-secrets-<stamp>.zip \
LEGACY_PASSWORD_FILE=/protected/path/legacy-password.txt \
CSR_RECOVERY_MASTER_KEY_FILE=/protected/path/recovery-master.key \
CSR_ESCROW_GENERATION=/path/to/escrow-generation.json \
CSR_RECOVERY_SIGNING_KEY_FILE="$HOME/.config/coding-system/recovery-signing" \
bin/secrets-import-legacy-zip.sh \
  /path/coding-system-secrets-<stamp>.zip \
  "$HOME/secrets-out"
```

The importer first parses a bounded 7-Zip metadata stream and rejects more than
20,000 members, a member over 256 MiB, more than 2 GiB expanded data, a
compression ratio over 200:1, noncanonical/oversized paths, duplicate or
file/directory-conflicting paths, unencrypted files, links, and special files.
The archive integrity test supplies the password through a private pseudo-TTY
only after 7-Zip prompts. Extraction then starts one exact, wildcard-disabled
member at a time, sends the protected-file password through a private stdin
pipe, and streams stdout into a no-follow regular file while re-enforcing the
declared size and one whole-archive deadline. 7-Zip never creates archive paths
or file types. Plaintext staging uses the same tmpfs-only policy as normal
recovery.

Only entries with an explicit `legacy_import` strategy may be absent from the
historical listing. The metadata-only source capability contract uses
`generated`; it is produced from the converged staging home. The recovery
signing authority uses `destination-authority`: the importer requires the live
private key (default
`~/.config/coding-system/recovery-signing`) to be a bounded, caller-owned,
single-link `0600` regular file beneath no symlinked path components. It copies
one stable descriptor-held snapshot into the owner-only staging home and uses
`ssh-keygen -y` on that held file to require an exact Ed25519 identity match
with `system/recovery/recovery-signing-public-key.pub`. A missing, replaced,
mispermissioned, oversized, encrypted/unusable, or mismatched key stops import;
the importer never generates a replacement trust root.

After that trust-root gate, the importer normalizes each allowlisted member
from its private extraction mode to the current manifest mode, migrates bounded
legacy authorities in staging, converges their selectors, and runs the same
redacted offline credential gate used for a new backup. It records the
resulting metadata-only source capability contract before emitting a normal
recovery set. If a now-required authority is
absent or a configured capability is not resolver-reachable, import fails;
restore or reauthenticate that authority on the source host and create a
complete set. Never pass the legacy password with `-pPASSWORD` or through an
environment variable.

The old `escrow-passphrase.sh ensure/check/recover` commands exist only for
historical ZIP retention and emit a warning. Legacy `recover` accepts two
protected share files plus a protected output filename; it no longer accepts
literal share arguments or prints the passphrase. It must not be used in the
new flow. Legacy GitHub upload also requires the exact configured repository to
exist and be private. Repository creation requires
`CSR_ESCROW_ALLOW_GITHUB_REPO_CREATE=1`; overwriting an existing remote object
requires `CSR_ESCROW_ALLOW_GITHUB_OVERWRITE=1`. New legacy objects use
generation-scoped paths.

## Rotation and updates

- `make rotate-keys` is a fail-closed compatibility command and performs no
  mutation. The historical dynamic-name and field-target engine could update
  migration-era mirrors without proving the canonical/effective deployed
  credential, while OpenClaw provider authentication is native SQLite state.
  Rotate through the authority's reviewed native workflow, run the offline
  authority/projection/selector verifier, and only then create a new recovery
  set. A missing target, write failure, or unchanged input must never be
  reported as a successful rotation.
- Credential rotation creates a new recovery set; old sets retain the old
  snapshot and must follow the same retention/revocation policy.
- Software/version refresh is separate. `make refresh-lock` reports drift;
  reviewed release tooling promotes a new component/artifact tuple only after
  amd64/arm64 tests. A routine secret backup never advances software versions.
  Upstream package releases do not invalidate an existing recovery generation:
  it continues to name the exact qualified
  commit and artifacts it was tested with. To adopt an update, create and
  qualify a complete candidate tuple, publish its reviewed commit, then create
  a new recovery set bound to that commit.
- Docker image layers are not backed up. Restoration pulls the locked
  platform-specific digest and uses the restored registry authority if needed.
- Provider quota exhaustion is `CREDIT_BLOCKED`, not a technical restore
  failure. An optional authority absent on the source is `NOT_CONFIGURED`;
  expired or machine-bound sessions are `REAUTH_REQUIRED`. Malformed,
  partially migrated, or divergent authorities remain technical failures.
- A full restore never treats a build completion, tag, or pending lock as a
  qualified release. A signed commit that still names unpublished Grok
  bootstrap assets, pending Python wheelhouse data, or pending clean-host
  platform evidence stops with `ARTIFACT_UNAVAILABLE` until those exact
  artifacts are promoted.

Synthetic recovery tests never use live credentials:

```bash
python3 -m unittest -v \
  tests.test_recovery_tool \
  tests.test_recovery_hardening
```
