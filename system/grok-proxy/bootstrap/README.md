# Grok pre-import bootstrap

This directory contains the additive trust anchor for signed Grok release
applications.  The production binary is native code linked only to the system
OpenSSL `libcrypto`; it does not import candidate Python while deciding whether
the candidate is trusted.

## Runtime interface

```text
grok-bootstrap --release-dir /usr/local/libexec/grok-proxy/bootstrap-releases/<signed-app-id> -- [application arguments]
```

The signed application ID is the manifest `release_id` (64 lowercase
hexadecimal characters).  Its directory must be a real, root-owned mode-`0555`
directory.  The dedicated `bootstrap-releases` namespace is intentionally
disjoint from `/usr/local/libexec/grok-proxy/releases/`, which is reserved for
the existing installer-managed runtime releases.  The signed application
directory contains exactly these bootstrap artifacts, each a root-owned,
single-link, mode-`0444` regular file:

- `release-manifest.txt`
- `release-manifest.sig`
- `dispatcher.pyz`

The bootstrap verifies the exact manifest bytes with the build-time Ed25519
public key, strictly parses the closed manifest schema, copies and hashes the
bundle into a sealed memfd, rechecks path identity, then executes the sealed
descriptor with `/usr/bin/python3 -I -B -S` and a closed environment.  Every
bootstrap failure is a bounded constant diagnostic, exits `126`, and has no
mutable-source fallback.

Before its first OpenSSL operation, the native verifier removes caller
`OPENSSL_CONF`, `OPENSSL_CONF_INCLUDE`, `OPENSSL_ENGINES`, and `OPENSSL_MODULES`
values and initializes libcrypto with `OPENSSL_INIT_NO_LOAD_CONFIG`.  Caller
configuration therefore cannot activate a provider before signature
verification.

The closed environment contains only fixed `PATH`, `LANG`, `LC_ALL`, and
`PYTHONDONTWRITEBYTECODE` values plus
`GROK_BOOTSTRAP_AUTHORITY_FD=<descriptor>`.  That descriptor is the root-created,
anonymous, sealed, non-executable dispatcher memfd; `install-release.py` consumes and validates
it before granting the bootstrap lane, so directly invoking editable, user-release,
or merely extracted Python cannot gain bootstrap authority.  The production
bootstrap is root-only and is normally entered through the fixed `sudo` caller.
It requires the caller's `SUDO_UID` to be canonical decimal, nonzero, representable
as `uid_t`, and resolvable to a non-root passwd account with a nonempty absolute
home other than `/`.  It reconstructs only `SUDO_UID=<canonical>` for the signed
installer; `SUDO_USER`, `SUDO_GID`, `HOME`, Python variables, and all other
caller values remain absent.  A non-root invocation, or a root invocation
without a valid target identity, fails with exit `126` before importing the
signed application. Production admits the dynamically linked native binary
only through the fixed setuid `sudo` path, whose secure-execution (`AT_SECURE`)
boundary sanitizes loader inputs, or as a child of an already
environment-isolated activator/publisher process. Direct invocation by an
already-root process carrying hostile `LD_PRELOAD` or related loader state is
unsupported because the binary cannot clear loader inputs before its loader
starts.

The verifier remains deliberately separate from `install-release.py` and is
never installed by candidate code. `bin/lib/render_install.py` validates the
package-owned selector and verifier metadata, invokes this binary for the
signed bootstrap `install` lane, then checks `status` through the concrete
installed immutable release. Administrative package installation remains a
separate prerequisite.

The package/update transaction also owns the logical selector
`/usr/local/libexec/grok-proxy/bootstrap/selected-release`.  It is a root-owned,
single-link, mode-`0444` regular file containing exactly the selected 64-byte
lowercase signed application ID and one newline.  The native bootstrap opens
that fixed selector through the root-owned package path, validates its metadata
and closed format, requires it to name the requested signed application, and
rechecks the held directory and selector identities immediately before `execve`.
The caller performs the same validation as defense in depth, but direct native
invocation cannot select a different signed application.  Selector publication
and signed-application publication must be one reviewed package/update
transaction.  Its stable lock anchor is
`/usr/local/libexec/grok-proxy/bootstrap/update.lock`, a root-owned, single-link,
empty, mode-`0600` regular file.  The native verifier opens it through the
trusted directory, validates its identity and exact metadata, takes `LOCK_SH`
before its first selector read, and retains that lock until successful `execve`
closes the descriptor.  The administrative publisher must take `LOCK_EX` on
that same inode across complete signed-app publication, selector rename, and
durability fsyncs.  Package creation may create the lock when it is absent, but
upgrades and publishers must never replace, truncate, or unlink the lock inode.
The root-only mode prevents the unprivileged target account from acquiring a
publisher lock and denying bootstrap service.

The fixed package activator takes that lock exclusively and the release-control
`operation.lock` shared. It durably creates `package-update.pending`, installs
and validates the publisher support files, activates the native verifier last,
then removes the marker only after descriptor-based validation and directory
fsync. Both the native execution path and the publisher refuse work while the
marker exists. The marker is canonical JSON binding the exact trust anchor and
the mode, size, SHA-256 digest, and canonical generation ID of every fixed
payload artifact. Only a byte-identical generation can reconcile a pending
activation. A different payload with the same key fails closed, so recovery
cannot bless support and native files from different package generations.
Failure injection and prefix overrides exist only in the non-root test path.
The production launcher is a freestanding static no-interpreter ELF; it closes
inherited descriptors and directly executes the fixed Python/script argument
vector with a newly constructed exact environment, forwarding no arguments.

The existing dispatcher is a multi-file Bash/Python application rather than a
zipapp-native Python entry point.  `stage_dispatcher.py` turns its literal
installer declarations into a closed source tree: generated `__main__.py`, the
declared top-level runtime files, exactly one declared broker, and admitted
`grok_ms/*.py` modules.  It fails if its reviewed extraction contract and the
installer declarations drift.

The signed `__main__.py` manually validates and extracts only that closed ZIP
shape into a fresh root-owned mode-`0700` directory beneath `/run`, preserving
signed file modes as `0644` or `0755`.  It then executes the extracted signed
`install-release.py` with `runpy`; the installer's existing bootstrap default
therefore sets `--source` to that exact extracted directory.  It never executes
or imports the mutable authoring checkout.  Extraction rejects unsafe,
duplicated, unsorted, linked, special, compressed, oversized, or undeclared ZIP
members and removes the temporary tree on exit.

## Manifest v1

The signed manifest is ASCII, newline-terminated, and ordered exactly as below:

```text
schema=grok-bootstrap-manifest-v1
key_id=<build-time key id>
release_id=<sha256 of all canonical file= records>
bundle_name=dispatcher.pyz
bundle_size=<canonical decimal>
bundle_sha256=<sha256>
file_count=<canonical decimal>
file=0644:<sha256>:<safe relative path>
...
```

Paths are sorted, unique, relative, and restricted to ASCII letters, digits,
`/`, `.`, `_`, and `-`; empty, `.` and `..` components are forbidden.  A
release must contain exactly one `__main__.py`.  Source modes are normalized to
`0644` or `0755` in both the inventory and deterministic ZIP.

## Deterministic bundle construction

First stage the declared dispatcher closure outside the authoring tree:

```bash
python3 -B stage_dispatcher.py \
  --source-root /path/to/grok-proxy \
  --output /path/to/closed-dispatcher-source
```

The output path must not already exist.  The stager snapshots source files with
descriptor-relative, no-follow reads and emits deterministic bytes and modes.
Then build and sign that closed source tree:

```bash
python3 build_bundle.py \
  --source /path/to/closed-dispatcher-source \
  --output /path/to/output-root \
  --key-id production-2026-01 \
  --signing-key /secure/offline/location/ed25519-private.pem
```

The signing key is read from the supplied external path.  The builder never
generates a key and the repository must never contain a production private
key.  It emits `<output-root>/<release-id>/` and prints that path.
The package-owned root-only publisher validates that complete signed directory
against the package trust anchor, imports it without following links, seals and
durably publishes it without replacement, and then selects it atomically:

```bash
sudo /usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap-publisher \
  publish --signed-application /secure/staging/<release-id> \
  --expected-current none
```

In production the signed staging path must be absolute. Every directory from
`/` through the mode-`0555` release directory must be root-owned, must not be
group- or other-writable, and must be opened without following symlinks. The
three artifacts must be root-owned, single-link, mode-`0444` regular files.

Audited administrative reselection and rollback never remove an older signed
application:

```bash
sudo /usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap-publisher \
  select --release-id <release-id> --expected-current <current-id> \
  --reason rollback
```

Both commands use the existing package-owned `update.lock` inode.  Selector
mutation additionally holds the preserved release-control `operation.lock` in
shared mode and refuses to proceed while `rollback-deny.json`,
`canary-terminal.json`, `rung-canary.json`, or a nonempty `runner-scopes`
journal exists.  Unsafe or malformed interlock paths also block mutation.
Publishing a previously absent immutable signed application may finish while
such a state blocks its selection; the old originating dispatcher remains
selected for recovery. The singleton durable `selector-audit/pending.json`
record is reconciled under both locks: an unchanged selector aborts and removes
its exact staged selector, a
selector at the audited target is revalidated and committed, and every other
state fails closed. An incomplete `pending.tmp` is safely discarded; completed
history records are retained but are never scanned as an admission condition,
so history volume cannot wedge future updates. The publisher never signs,
never receives a private key, never executes candidate content, and never
garbage-collects signed applications.  Candidate installation does not invoke
this administrative tool.  Reselection is compare-and-swap: a stale
`--expected-current` fails without changing the selector.  On every invocation
the publisher obtains the Ed25519 key and key ID directly from the locked exact
native verifier through its constant `--describe-trust-anchor` report; no
separate trust metadata can drift from the compiled verifier. The installed
publisher launcher is a freestanding static no-interpreter ELF. It constructs
the fixed `/usr/bin/python3 -I -B -S` prefix and exact environment before
forwarding at most 64 administrative CLI arguments; a larger vector fails with
exit `126`.

### Exact orphaned-compatibility rescue

An older selected runtime can be unable to finish public recovery when it left
an exact generation-zero compatibility VPN ledger and a later supervisor died
with its fence in `RECOVERING`. Do not remove the ledger, fence, namespace, or
PID records manually. After the new signed application has been published and
selected by the package-owned publisher, invoke its closed rescue command:

```bash
sudo -n -- /usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap \
  --release-dir /usr/local/libexec/grok-proxy/bootstrap-releases/<signed-app-id> \
  -- recover-compatibility-ledger --apply
```

The command accepts no caller paths, release IDs, PIDs, identities, or force
option. It owns the package-preserved operation lock, both stable compatibility
locks, and the historical singleton; requires the selected target UID/release,
an exact dead `RECOVERING` fence, and the canonical `compat-<uid>` generation-0
port-1080 zero-contract root ledger; stages only the signed candidate root
release without selecting it; and executes only the staged candidate broker.
That broker may use the old selected immutable VPN/relay helper bytes bound by
the ledger, but it never executes the old broker implementation. The command
must report `public_recovery_required:true` and deliberately leaves the user
state and fence unchanged. Its authenticated broker success is the root commit
point; later target-user replacement of cooperative lock or fence pathnames
cannot retroactively turn committed cleanup into failure. Public handoff has no
destructive compatibility-ledger authority and can proceed only after this
root cleanup proves empty.

Then finish the old installed public transaction and only afterward run the
normal signed install:

```bash
env -u GROK_MULTI_SESSION grok-remote recover

sudo -n -- /usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap \
  --release-dir /usr/local/libexec/grok-proxy/bootstrap-releases/<signed-app-id> \
  -- install --apply
```

Any mismatch or incomplete cleanup retains the ledger/fence and fails closed.
The rescue is unavailable from an installed runtime and is not a general reset
or teardown interface.

The subsequent install also supports one bounded historical source layout: its
user manifest must match the complete identity, include direct admission, and
omit the installed installer, while its root manifest contains exactly the four
identity-bound helpers. Because older generated gates can differ from the
current generator, their root-owned mode-0555 bytes are admitted only when both
selection records, their cross-hash, promotion evidence, manifest hashes,
helper map, selectors, and release access bind the exact bytes. This is a
one-shot migration capability only. Such a release is never an eligible target;
new and rollback targets still require the full root closure, installed
installer, direct admission, and current generated gates.

## Production build and package contract

The production public key is mandatory non-root build input:

```bash
make all \
  PUBLIC_KEY_HEX=<64-lowercase-hex> \
  KEY_ID=production-2026-01
```

`PUBLIC_KEY_HEX` is the raw 32-byte Ed25519 public key.  There is no default
production key. Never invoke GNU Make as root for this package. GNU Make reads
`MAKEFLAGS`, `MAKEFILES`, included makefiles, and command-line evaluations before
any recipe can reject hostile input, so a root recipe cannot establish the
privilege boundary. The `install` target always refuses; `install-test` is an
explicit non-root-only test harness.

After `make all`, build the architecture-bound Debian artifact as the same
non-root build user. The version, exact 40-hex source commit, Debian
architecture, and reproducible source epoch are mandatory inputs, and the
output basename is fixed by the package name, version, and architecture:

```bash
python3 -I -B build_debian_package.py \
  --build-root /absolute/non-root/build \
  --output /absolute/output/grok-bootstrap_<version>_<architecture>.deb \
  --version <version> \
  --source-commit <40-lowercase-hex-commit> \
  --architecture <amd64-or-arm64> \
  --source-date-epoch <commit-epoch>
```

The builder uses only fixed `dpkg-deb`, `readelf`, and `nm` paths with closed
subprocess environments. It requires the build directory to contain exactly
the declared five single-link artifacts with the declared modes, validates
both Python sources and the host-ABI/static-launcher contracts, and creates a
deterministic root-owner archive through an atomic no-clobber publication.
The package control metadata binds the version, architecture, and source
commit. The low-level builder still emits its legacy descriptor-validating
`postinst`, but that raw artifact is never eligible for promotion. The protected
build workflow requires the raw control inventory to be exactly `control` plus
that one expected script, removes the script as an unprivileged build step,
rebuilds deterministically, and passes the script-free archive through the
same exact promotion validator before attestation.

### Repository release publication

Normal restore never compiles or signs privileged bootstrap content. The
checked-in `release.lock.json` starts in `pending-publication`, which is an
intentional hard stop. Publication is a two-workflow release operation:

1. Protect the default branch and configure the three workflow environments
   `grok-bootstrap-build`, `grok-bootstrap-verify`, and
   `grok-bootstrap-publish` for that branch (with a required reviewer and
   self-review disabled where the repository plan supports it). Run
   `grok-bootstrap-build.yml` at the exact default-branch source commit. Its
   native Ubuntu 24.04 matrix produces script-free amd64 and arm64 Debian
   packages with the public production trust anchor compiled in, then emits a
   GitHub build-provenance attestation for each exact package. It has no
   private-key input. Promotion rejects an unprotected branch, a different
   workflow/ref/commit, a self-hosted attestation, or a package without the
   exact workflow attestation.
2. Choose an already production-signed dispatcher. For the immediate restore
   baseline, the source host already retains signed application
   `bc6c611f32a1420558cf3ff4e01a813f13dfcb526800dd8d3cf211be8275a08e`.
   Its manifest and signature verify against
   `grok-dispatch-prod-2026-07-v1`, so its three public files can be exported and
   promoted without the private key. For a later code update, stage the new
   closed dispatcher with `stage_dispatcher.py` and sign it on the offline
   Ed25519 signing host as documented above. Either route exports only
   `dispatcher.pyz`, `release-manifest.txt`, and `release-manifest.sig`.
   Export and independently reverify the retained baseline into a new private
   working directory (the files are public; the directory mode merely prevents
   another local user from racing the upload):

   ```bash
   retained_id=bc6c611f32a1420558cf3ff4e01a813f13dfcb526800dd8d3cf211be8275a08e
   export_dir="$HOME/grok-bootstrap-dispatcher-$retained_id"
   python3 -I -B bin/export-signed-grok-dispatcher.py \
     --source-root "/usr/local/libexec/grok-proxy/bootstrap-releases/$retained_id" \
     --expected-release-id "$retained_id" \
     --output-dir "$export_dir"
   ```

   The exporter consumes the production public key from the checked-in lock,
   rejects an existing or symlinked destination, copies exactly the three
   public files with no-clobber writes, and verifies the copied signature and
   release ID. It never reads, requests, or exports a private key.
3. Download both attested package artifacts into a private directory alongside
   the three dispatcher files, then emit the canonical authorization request:

   ```bash
   python3 -I -B bin/promote-grok-bootstrap-release.py \
     --emit-authorization-request \
     --artifact-dir <private-five-core-assets-directory> \
     --tag <grok-bootstrap-vTAG> \
     --package-version <version-from-build> \
     --source-commit <40-hex-build-commit> \
     --output <absolute-private-path>/release-authorization.json
   ```

   On the offline administrative signing host, sign those exact canonical
   bytes with the recovery-release SSH Ed25519 authority whose public key is
   independently pinned in `release.lock.json`:

   ```bash
   ssh-keygen -Y sign \
     -f <protected-recovery-signing-private-key> \
     -n grok-bootstrap-release-authorization \
     <absolute-private-path>/release-authorization.json
   mv <absolute-private-path>/release-authorization.json.sig \
     <absolute-private-path>/release-authorization.sig
   ```

   Return only the public request and SSHSIG file as
   `release-authorization.json` and `release-authorization.sig`; never return
   the private key. The signed
   request binds the repository, protected workflow ref, source commit, tag,
   package version, both architectures, trust anchor, signed dispatcher ID,
   and size/SHA-256 of every one of the five core assets.

4. Create a draft repository release targeting the exact build commit and
   upload exactly the three dispatcher files plus the two authorization files.
   Do not upload the private key:

   ```bash
   gh release create <grok-bootstrap-vTAG> \
     --repo hoanganhduc/coding-system-rebuild \
     --target <40-hex-build-commit> \
     --draft \
     --title <grok-bootstrap-vTAG> \
     --notes "Grok bootstrap trust-anchor generation"
   gh release upload <grok-bootstrap-vTAG> \
     "$export_dir/dispatcher.pyz" \
     "$export_dir/release-manifest.txt" \
     "$export_dir/release-manifest.sig" \
     <absolute-private-path>/release-authorization.json \
     <absolute-private-path>/release-authorization.sig \
     --repo hoanganhduc/coding-system-rebuild
   ```

5. Run `grok-bootstrap-promote.yml` with that draft tag and the successful
   native build run ID. Promotion requires the draft to target the build's
   exact protected-default-branch commit and initially contain exactly the five
   dispatcher/authorization files. It verifies the administrative signature,
   dispatcher signature, build attestations, script-free exact Debian control
   and payload inventories, embedded production public key, and both Debian
   identities. It uploads without replacement, downloads all seven assets
   again, revalidates their bytes, publishes the release, and exports
   `grok-bootstrap-release.lock.candidate.json`.
6. Review that candidate and replace `release.lock.json` in a new protected
   commit, then distribute that exact commit through the signed recovery set.
   Until that later exact commit is available to restore, full
   restore continues to fail with `ARTIFACT_UNAVAILABLE`; it never falls back to
   the host's old package or to an editable build.

The two manual workflow invocations, after their workflow files are present on
the default branch, are:

```bash
gh workflow run grok-bootstrap-build.yml \
  --repo hoanganhduc/coding-system-rebuild \
  --ref <exact-source-ref>
gh workflow run grok-bootstrap-promote.yml \
  --repo hoanganhduc/coding-system-rebuild \
  --ref <ref-containing-the-promotion-workflow> \
  -f build_run_id=<successful-run-id> \
  -f release_tag=<grok-bootstrap-vTAG>
```

The promotion workflow deliberately cannot create the Ed25519 signature and
does not accept a signing-key secret. Reusing the verified retained application
closes restoration of the known generation; the fact that a newer editable
source inventory has a different release ID is tracked as a future release
update, not as a reason to make fresh-host restoration depend on an unavailable
private key.

The `.deb` is not independently authorized merely because it was built by
this script. The closure path requires both the exact protected-workflow
attestation and the offline signature over the five core assets in the
seven-asset release before
`dpkg` can run. The package control archive must contain only `control`—all
Debian maintainer scripts are rejected—and the fixed provisioner explicitly
runs the already authenticated package activator after installation. There are two production authentication paths: a separately
reviewed signed APT repository pinned with `signed-by`, or the closure restore's
Stage-0 signature-authenticated exact Git commit plus
`release.lock.json`. The latter accepts only the repository-controlled release
URL, exact size and SHA-256, package version, architecture, source commit, and
production trust anchor recorded after remote readback. The fixed provisioner
then inspects the complete Debian archive and embedded production public key
before `dpkg`, and explicitly invokes the installed fixed activator only after
the script-free package install succeeds. An arbitrary local `.deb`, a pending lock, or an unpinned URL
does not satisfy the administrative-signature requirement.

`package/grok-bootstrap-package.json` records the closed five-file build output,
ownership, modes, dependency, key-provisioning, and activation requirements.
The package manager installs the exact three-file payload at the fixed
root-owned mode-`0555` `/usr/lib/grok-bootstrap-package` root and the exact
two-file activator at fixed root-owned mode-`0555`
`/usr/libexec/grok-bootstrap-package`. Before `dpkg`, the held-descriptor archive
validator requires those exact two leaf directories and their closed
inventories and rejects links, devices, unknown control files, and every
maintainer script. After installation, the explicitly invoked activator
descriptor-walks the complete ancestry without following links, requires
root-owned fixed-mode single-link files, snapshots and hashes every file,
AST-parses both Python sources, and checks the three ELF machines. It also
requires both static launchers to have no `PT_INTERP`, `PT_DYNAMIC`,
`DT_NEEDED`, or undefined symbol and to contain each fixed argv/environment/
contract string exactly once. It rechecks every held directory and file before
descriptor-executing exactly, with no arguments:

```bash
/usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate
```

That architecture-native x86_64/AArch64 launcher has no ELF interpreter,
dynamic section, needed library, libc startup, or undefined symbol. Its raw
`_start` uses only direct Linux system calls: it closes descriptors above 2 and
executes `/usr/bin/python3 -I -B -S` with the fixed activator script, no caller
arguments, and exactly the fixed path, locale, and bytecode environment. A
failed or denied descriptor-range close exits `126` before Python; inherited
root-process descriptors are never silently retained. The administrative
signature authority (signed APT directly, or Stage-0 signed commit plus the
qualified exact package digest) and package manager's pre-execution ancestry/file
validation authorize the current launcher execution; the Python activator's
ELF and file revalidation protects subsequent use after Python has started.
The activator reopens its own fixed files and the fixed payload
descriptor-relatively without following links, snapshots them, and accepts no
production source or destination override. It sets a fixed process umask and
fchmods every newly created directory before exact validation, so a restrictive
inherited umask cannot wedge first activation. It creates or
preserves both root-owned empty mode-`0600` lock inodes:
`bootstrap/update.lock` and `release-control/operation.lock`; upgrades never
replace or truncate either inode. Production `install-release.py` opens the
existing operation lock through its verified parent, requires exact owner,
mode, link count, size, and named inode identity before and after `LOCK_EX`, and
never creates or repairs it. Only the explicitly marked non-root prefix test
activation may create its isolated fixture lock.

An existing verifier's key ID and public key must exactly match the requested
package build. In-place key rotation is deliberately unsupported and is
rejected before component activation. A future rotation requires an explicit,
bounded multi-key or new signed-application-ID migration that preserves retained
rollback applications; merely rebuilding the package with a different key is
not a rotation procedure.

Tests compile a visibly separate `GROK_BOOTSTRAP_TEST_BUILD` binary with a
runtime-generated test key.  Production builds neither accept test metadata
nor read test-hook environment variables.
