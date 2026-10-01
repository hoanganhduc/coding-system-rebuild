# INSTALL — fresh Ubuntu 24.04 (amd64 / arm64)

## 0. What you need

1. A stock Ubuntu 24.04 host on `amd64` or `arm64`, with working DNS and network
   access to the exact repositories, registries, and artifact URLs in the
   signed locks.
2. A trusted, independently reviewed copy of `restore-ubuntu.sh` retained with
   the recovery media. It is the Stage-0 trust root and pins the recovery
   signing key.
3. Exactly one complete signed recovery-set directory.
4. Exactly two matching protected shares from that set's embedded escrow
   generation, stored as
   `~/secrets-restore-inbox/escrow/<generation-id>/share-XX.txt`.
5. Optionally, exactly one separately encrypted
   `openclaw-private-*.tar.gz.gpg` under
   `~/secrets-restore-inbox/owner-data/` when prior large workspace history and
   owner data must survive. Its passphrase authority is inside the recovery set.
6. An ordinary non-root user with noninteractive `sudo -n` authority for the
   declared apt and root-owned installation operations. Examples use `ubuntu`,
   but every captured path is `{{ HOME }}`-templated. Confirm `sudo -n true`
   succeeds before starting; the restore does not pause for a sudo password.
7. An owner-only `~/secrets-restore-inbox`, owner-only escrow/generation
   directories, and exactly two mode-`0600` share files. Extra, mismatched,
   linked, or broadly readable shares are rejected rather than guessed.

A stock supported host does **not** need Git, `gh`, Node/npm, Docker, Python
venvs, Claude, Codex, Copilot, Gemini, Kimi, Grok, OpenCode, CodeWhale, or
OpenClaw preinstalled. Stage 0 installs the minimal bootstrap; later gated
phases install and verify the locked native/software closure for the detected
architecture.

## 1. Bootstrap

After preparing the protected inbox described above, the complete fresh-host
operator command is exactly:

```bash
/usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh"
```

This is the only command required on a stock supported host. Stage 0 rejects
root execution, non-Ubuntu-24.04 hosts, unsupported architectures, ambiguous
sets, and unsigned or differently signed repository pointers. It installs the
minimal signed Ubuntu bootstrap packages, fetches the exact signed commit, and
descriptor-executes its sealed `bin/restore.sh` continuation. Do not obtain the Stage-0 script from the same untrusted
location as both escrow shares without an independent hash/review.

Before authenticating recovery metadata, Stage 0 copies the exact closed media
inventory through no-follow descriptors into an owner-only, read-only snapshot.
All signature, bootstrap-digest, repository-pointer, and downstream restore
reads use that snapshot. The original USB/FUSE/download path may disappear or
change after the copy without changing what is authenticated and restored.
Stage 0 resets `PATH` to Ubuntu system directories for its trust gate, checks
the ciphertext and escrow-manifest digests from the signed manifest, and
requires exactly two owner-only matching share files before package or checkout
changes. Its Git probe disables hooks, file monitoring, replacement objects,
ambient configuration, lazy object fetching, auxiliary object caches, and all
Git transports during inspection. Before reading an object, a fixed Stage-0
preflight rejects unsafe ancestors, metadata ownership, alternates, partial
clones, config includes, and remote/FUSE storage; strict full `git fsck` then
authenticates the signed commit closure. An index-independent verifier loaded
from that checked commit hashes every working-tree file directly against the
commit tree, checks executable modes and ownership, and rejects extra paths;
index flags such as `skip-worktree` cannot hide changed code.

For a non-mutating media preflight:

```bash
/usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh" --check-only
```

This verifies the signature, signed Stage-0 binding, complete artifact
inventory/digests, and two share records. It explicitly does not decrypt the
payload; authenticated decryption is performed by the sealed restore continuation.

## 2. Internal repository handoff and degraded development mode

`make restore` and `bin/install.sh` are internal continuations of the Stage-0
process. They deliberately require its protected snapshot and verified-commit
handoff and are not standalone authenticated entry points. Start or resume a
real recovery by rerunning the trusted Stage-0 command; do not reconstruct its
environment variables manually. `make install` without a recovery set is
retained for CI/development; it reports degraded checks and is not a complete
restoration.

Phases (each gated; resume after a failure through the same trust root):

```bash
PHASE=<n> /usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh"
```

| # | Phase | Gate |
|---|---|---|
| 1 | doctor + dirs | doctor exit 0 |
| pre-phase gate | provision and verify the production-keyed Grok bootstrap package and signed dispatcher before any phase runs | published Grok release lock, hashes, signatures, and dispatcher identity |
| 2 | prepare: locked apt packages (minimum versions, xtradeb PPA builds), locked Node/npm transitive CLI tree, Rust, Bun, elan, native agent binaries, and Docker CE; image pulling is deferred until registry credentials land | platform release lock, hashes, and versions |
| 3 | restore encrypted authorities/sessions + chmod fixups; materialize bounded credential views; migrate retired `tailscale.env` into raw `tailscale-authkey` and `tailscale-hostname` files, then apply with `--auth-key=file:<path>` when configured | required entries present; dedicated authorities are owner-private; Tailscale reports `PASS`, `NOT_CONFIGURED`, `REAUTH_REQUIRED`, or a technical failure without exposing the key in shell text or argv |
| 4 | pull architecture-selected OCI images after Docker/GHCR authority restoration | immutable index/platform digests; no mutable-tag or backup-tar fallback |
| 5 | components: clone openclaw-bot and course_management_toolkit → `external/`; ensure the pinned ai-agents-skills object exists at `~/ai-agents-skills`; clone the pinned VNU eOffice package → `~/.openclaw/workspace/vnueoffice_repo` and retain a `~/vnueoffice` compatibility symlink for older host launchers | exact pinned objects are locally available |
| 6 | render configs/scripts/symlinks into $HOME, converge the existing Codex selector table without replacing unrelated settings, and atomically install the immutable grok-proxy user/root release | no unresolved `{{ HOME }}`; Codex selects every restored authority; one coherent admitted Grok release |
| 7 | restore owner data as the older overlay; converge the OpenClaw slice without downgrading the CLI; migrate exact owner settings from live and managed pre-install shell copies without sourcing them; sanitize retained rollback copies; promote bounded legacy fields into dedicated VNU, Remote Bridge, shared AAS, compute, per-skill, and provider authorities; derive bounded views; install exact plugin locks and integrity records; materialize installed-version Bash completion | owner state preserved without rolling runtime files backward; `.secrets.env` remains data-only; authority values never logged; no dangling refs; config validates; plugin doctor and completion checks pass |
| 8 | bind the materializer by its recorded SHA-256 into a read-only no-replace helper owned by the user, materialize the exact pinned ai-agents-skills Git blobs under `~/.local/share/coding-system/components/` without root, restore the complete skill profile to eight normal agent targets, install Codex's private runtime and select both `AAS_RUNTIME_ROOT=~/.codex/runtime` and the phase-9 managed Python path, retire historical Claude-local runtime copies only when they exactly match known legacy bytes, then apply every pinned non-runtime OpenClaw skill file through the v2 probe → dry-run manifest → approval → real-system gate while OpenClaw is quiescent, then install the pinned third-party skills of `system/software/vendor-skills.lock.json` where they are missing | helper digest/authority, blob/mode parity, immutable ownership, shared-runtime digest verification, divergent Claude-local residue rejected, all six currently declared OpenClaw skill files receipt-bound (with Classroom50 present on all nine supported targets), and an executable/config-selected `~/.codex/runtime/run_skill.sh`; phase 9 proves the selected Python closure |
| 8b| re-overlay recovery authorities and deterministically regenerate Codex/shared and narrow service-specific views: host Calibre/Zotero, AAS queue state, OpenClaw compute/provider/service selectors, Modal, Remote Bridge, Send Email, Google Classroom, Canvas, GetSciPapers, GitHub CLI, and the locked teacher extension under `/workspace/.local-data`; retire broad OpenClaw shared/skill mirrors and ambient selectors; `_run.sh` SHA-256 check | secret and skill-credential closure OK; AAS queue authority remains distinct from OpenClaw delivery policy; Classroom50 projection digest/version/help probes pass without colliding with the managed `/workspace/.local` Python link |
| 9 | eight exact offline Python wheel environments from the platform wheelhouse, including `~/.course_venv`; bounded Calibre `metadata.db` bootstrap | complete inventory, `pip check`, Classroom50 import/`course --help` smokes, an isolated Codex private-runtime smoke with the shared runtime path absent, SQLite quick-check and `books` table |
| 10| content-addressed sandbox images re-check (arch-conditional) | locked image present, contract-v3 course runtime passes, and compatibility tuple agrees |
| 11| user-systemd reconciliation, gateway readiness, sandbox recreation, host schedule reconciliation, logical OpenClaw cron import, and provider-free canaries | exact declarations, enabled/active timers, gateway health, and cron/systemd/OpenClaw evidence emitted after this restore's activation boundary |
| 12| explicit-profile verification and atomic restore report | `full` proves installed software, Python/Node closure, MCP, targets, schedulers, images, secrets, dedicated skill credentials/resolvers, OpenClaw, and Classroom50; optional absence, reauthentication, and quota exhaustion are classified separately from technical failure |

The dedicated credential authorities are not interchangeable. Shared
Zotero/Calibre/Drive/Telegram JSON, strict per-skill env keys, ARL child-provider
fallbacks (including Kimi), Kaggle/Hetzner compute keys, Remote Bridge Zulip,
Send Email, Modal, VNU eOffice (including its optional state-HMAC), Google
Classroom OAuth, Canvas LMS, and the GetSciPapers private tree each retain a
separate resolver contract. Native agent login/session files are also restored
under their native homes. See [SECRETS.md](SECRETS.md) for the exact paths and
allowlists.

`NOT_CONFIGURED` means an optional authority did not exist in the source
generation; it is not a package or restore failure. `REAUTH_REQUIRED` means
the bytes were restored but the native session needs login/MFA/device renewal.
`CREDIT_BLOCKED` means authentication is present but provider quota is
exhausted and is likewise nontechnical. A malformed, partially migrated, stale,
or resolver-divergent credential is a technical failure.

Autonomous Research Loop safety confirmation is independent of restoration.
Restoring provider, Remote Bridge, or compute credentials does not authorize a
new multi-agent panel, paid resource, or external egress. The workflow still
requires the user confirmation and exact egress/`--confirm` gates declared by
the selected ARL/panel/compute skill. An exit status 2 for missing confirmation
is therefore intentional even on a credential-complete host.

When resuming at `PHASE=12`, the installer establishes a fresh run
boundary and waits for all three schedulers again before final verification.

Final verification loads `system/software/mcp-policy.json` and performs a
bounded `initialize` plus `tools/list` exchange with every enabled restored MCP.
Optional MCPs without reviewed artifacts are explicitly disabled or omitted;
see [MCP-CLOSURE.md](MCP-CLOSURE.md). Phase 8 records these live checks as
deferred because Python runtimes and schedulers are completed in later phases.

Source-contract tests are not an artifact-availability claim. A full restore
also requires the selected architecture's platform and Python locks to be
`qualified` and privileged release locks to be published/qualified. If the
signed commit names `pending-clean-host`, `pending-artifacts`, or
`pending-publication`, the corresponding phase stops with
`ARTIFACT_UNAVAILABLE`; it never substitutes a floating package, online pip
install, mutable image tag, or locally built privileged binary. In this
checkout, the Grok bootstrap lock and Python/platform qualification records
still carry pending states, so they remain release gates until promoted.

Phase 6 treats `~/grok-proxy` as the editable Grok authoring source while
preserving its private configuration, credentials, model cache, locks, and
tunnel state. On a fresh machine it restores only the manifest-allowlisted
public source from `system/grok-proxy`. If any managed public path already
exists, the complete managed tree must match byte-for-byte (including executable
bits) or the install fails before writing source files or invoking sudo. This
prevents restore from overwriting local authoring work or creating a hybrid tree.

The editable tree is never the production execution authority. Phase 2 uses
`system/grok-proxy/bootstrap/release.lock.json` to install the native,
production-keyed `/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap`,
publish one production-signed closed dispatcher under `bootstrap-releases/`,
and atomically select it. The provisioner accepts only a `qualified` lock whose
five repository-release assets have real sizes and SHA-256 values; a
`pending-publication` lock stops full restore as `ARTIFACT_UNAVAILABLE`. It
validates the Debian version, architecture, source commit, installed trust
anchor, signed manifest, immutable root metadata, and remote-byte digests.
Phase 6 re-verifies that exact installed state before rendering. Candidate
source cannot create or replace those trust-anchor artifacts.
After proving that the repository backup and canonical authoring tree match,
the renderer invokes only that native verifier and its administratively selected
signed dispatcher. The signed dispatcher stages paired root-owned immutable
user/root releases; `~/.local/bin/grok-remote` then selects the admitted user
release. Direct execution from either editable checkout refuses production use.
The native verifier independently opens the fixed root-owned selector, requires
the requested signed application ID to match, and rechecks the selector at its
final execution boundary; renderer validation is defense in depth.
`bin/render-install.sh --render-only` performs the source reconciliation but
does not invoke the verifier or change live release selectors.

To inspect the selected release from the repository checkout:

```bash
GROK_RELEASE_PATH=$(readlink -f -- /usr/local/libexec/grok-proxy/current)
GROK_RELEASE_ID=${GROK_RELEASE_PATH##*/}
[[ $GROK_RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$GROK_RELEASE_ID/install-release.py"
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" status
```

The installer path must name a concrete 64-hex release directory. The mutable
`current/install-release.py` path is rejected; if selection changes after the
path is derived, the concrete installer rechecks under the operation lock and
fails closed.

To stage and atomically select the current checkout without rerunning the
machine-wide package phases:

```bash
bash bin/render-install.sh
```

This installs the signed application named by the administrative selector; it
never executes `system/grok-proxy/install-release.py` or
`~/grok-proxy/install-release.py` as root. A missing, malformed, incorrectly
owned, or unsigned bootstrap artifact is a hard failure.

The opt-in multi-session lane remains fail-closed until the selected release
passes its fixed `load32` and `fault-recovery` qualification and each intended
route/model tuple passes the fixed real-pair canary. The installer interface is:

```bash
RELEASE_ID='replace-with-the-64-lowercase-hex-release-id'
[[ $RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$RELEASE_ID/install-release.py"
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  begin-release-qualification --release-id "$RELEASE_ID" --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  canary-exec --qualification-step load32 --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  canary-exec --qualification-step fault-recovery --apply

sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" begin-rung-canary \
  --release-id "$RELEASE_ID" \
  --rung '<rung>' --route-profile '<profile>' \
  --contract-sha256 '<contract_sha256>' \
  --grok-release-id '<grok_release_id>' --model-id '<model_id>' --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" \
  canary-exec --qualification-step real-pair --apply
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" promote-rung --apply
```

`PROFILE` is one of `direct`, `iphone`, `vpn`, `home:<label>`, `auto`, or
`auto-no-direct`. Promotion accepts only installer-derived fixed results; manual
canary transcripts and external evidence files are nonqualifying. Use
`abort --apply` to cancel an active qualification fence. These commands start a
release's first fixed qualification. Version 1 deliberately has no reset for an
already completed qualification directory: if the generated gates change while
the runtime release ID stays the same, stale evidence fails closed and the
release cannot be requalified through this interface. Preserve the exact
installer bytes; do not delete qualification state by hand.

### Interrupted Grok release recovery

Use `status` as the preliminary check before retrying phase 6:

```bash
GROK_RELEASE_PATH=$(readlink -f -- /usr/local/libexec/grok-proxy/current)
GROK_RELEASE_ID=${GROK_RELEASE_PATH##*/}
[[ $GROK_RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$GROK_RELEASE_ID/install-release.py"
sudo -n -- /usr/bin/python3 -I -B "$GROK_INSTALLER" status
```

For an interrupted release operation, an authorized recovery operator must also
inspect the root-owned deny record and both root/user selection records. `status`
does not expose the full deny ledger or selection phase. Once the immutable
target user/root pair has been published, resume the target named by the deny
ledger. Recovery uses immutable signed code rather than rebuilding from current
source bytes. `SIGNED_RELEASE_DIR` below must be the exact directory named by
the root-owned bootstrap selector after its ownership, mode, and closed content
have been independently validated:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- \
  resume --apply
```

Before pair publication, retry phase 6 through `bash bin/render-install.sh` or
abort to the release recorded in `from_release` through the same signed
bootstrap lane:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- abort \
  --restore-from PRIOR_RELEASE_ID \
  --apply
```

A first install has `from_release: null`; it has no prior release to abort to.
Correct the blocking condition and resume/retry the same published target.
Never start a different install while that null-source deny remains active.
In particular, a fenced phase-6 operation must use `resume`; do not use a
different `install` until the deny is cleared.

Older interrupted targets may lack the authenticated legacy-migration broker
endpoint. Current `resume` can still converge them only after root inventory
proves the fixed legacy pathname absent. If `/var/lib/grok-vpngate` still
exists with an exact canonical compatibility ledger and a dead selected-release
`RECOVERING` fence, do not delete or move it ad hoc. Use only the selected
signed application's parameter-free rescue:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- \
  recover-compatibility-ledger --apply
```

Require `public_recovery_required:true`, unchanged root/user selectors, and an
unchanged fence. The rescue stages only the signed candidate root release and
retires only the exact target user's generation-zero compatibility root ledger;
the authenticated broker result is its root commit point. Public handoff has no
destructive ledger authority, and target-user pathname replacement after that
commit cannot turn completed cleanup into a reported failure. The rescue has no
force option and cannot be invoked from an installed release. Next
run `env -u GROK_MULTI_SESSION grok-remote recover` so the old selected public
transaction clears its own user state and fence. Only after that succeeds may
the same signed application run `install --apply`. Any other residue still
requires manual investigation rather than deletion. Release recovery rechecks
every OpenVPN process, broker ledger, namespace, tun, listener, multi-session
fence, workspace, reserved cgroup, and root inventory and fails closed on
ambiguity.

During that install, an exact historical helper-only root manifest can be used
only as the one-shot migration source. The paired user manifest must match its
full identity, contain direct admission, and omit the installed installer; the
root manifest must contain exactly the four identity-bound helpers. Historical
gate bytes must remain root-owned mode `0555` and match the cross-bound
selection records and promotion evidence. This compatibility does not make the
historical release selectable: every target still needs the full root closure,
installed installer, direct admission, and current generated gates.

After `resume`, run `status` again and require `rollback_denied: false`, matching
target root/user release IDs, `active_release_valid: true`,
`release_access_policy_valid: true`, and exactly one ID in
`exposed_user_releases`. Separately verify
that both selection records are `READY`, their nonzero evidence digest matches
the target evidence file, and that evidence is schema 3 before qualification.

To roll back, require `rollback_eligibility_complete: true` and take a prior ID
from `rollback_eligible_releases`. Retained IDs absent from that list predate or
differ from the exact self-admission contract and cannot be selected. Archived
user releases remain mode `0500` until this validation succeeds. Then run:

```bash
GROK_BOOTSTRAP=/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap
ROLLBACK_RELEASE_ID='replace-with-an-eligible-64-lowercase-hex-release-id'
[[ $ROLLBACK_RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
sudo -n -- "$GROK_BOOTSTRAP" --release-dir "$SIGNED_RELEASE_DIR" -- rollback \
  --release-id "$ROLLBACK_RELEASE_ID" \
  --apply
```

### SKIP_* toggles (sizes)

| Toggle | Skips | Approx size/time |
|---|---|---|
| `SKIP_LATEX=1` | texlive-full | ~5.5GB |
| `SKIP_DOCKER_IMAGES=1` | sandbox 8.5GB + sage 4.6GB (arm64) + translation-server 2GB | ~15GB |
| `SKIP_LEAN=1` | elan (toolchains lazy-install per project anyway) | ~1–3GB on first use |
| `SKIP_RUST=1` / `SKIP_BUN=1` | rust / bun (only needed to build qmd) | ~1.2GB / ~0.5GB |
| `SKIP_CALIBRE=1` / `SKIP_CHROMIUM=1` | calibre / chromium+driver (xtradeb PPA) | ~1GB |
| `SKIP_TAILSCALE=1` | tailscale install | — |
| `SKIP_NPM_GLOBALS=1` | the pinned npm CLI/tool closure | ~1.3GB |
| `SKIP_CADDY=1` | the Caddy web server from its locked Cloudsmith source | — |
| `SKIP_OLLAMA=1` | Ollama from its locked release | ~1.3–1.8GB |
| `SKIP_GPROLOG=1` | GNU Prolog, built from its locked source tarball | — |
| `SKIP_VERACRYPT=1` | the VeraCrypt console package | — |
| `SKIP_GROK=1` | the Grok CLI, its bootstrap release and their gates; `lockctl validate --require-complete` then treats `grok-artifact` as optional. Grok is not restored. | — |

Example minimal try-out: `SKIP_LATEX=1 SKIP_DOCKER_IMAGES=1 make install`

### Notes & caveats

- **docker group**: phase 2 adds your user to the `docker` group; the scripts
  use `sg docker -c` so the same session can pull images. A full re-login is
  still recommended afterwards.
- **Legacy AES ZIPs**: 7-Zip exists only for the bounded one-time importer;
  normal signed recovery sets use GnuPG ciphertexts and do not expose member
  names.
- **Ubuntu chromium**: stock 24.04 has no chromium deb; prepare installs the
  repository's locked deb822 source for the `ppa:xtradeb/apps` PPA, signing key
  included.
- **Degraded mode**: with no `RECOVERY_SET`, phases 3/7-gateway/11-start are
  skipped or relaxed; install prints the missing-secret → broken-feature table
  at the start and end. Put a complete signed set and exactly two shares in the
  standard inbox, then rerun the trusted `restore-ubuntu.sh`; do not splice a
  partial degraded run into a claimed full restore.
- **Ollama** is intentionally NOT installed (verified unused on the source
  system). The OpenClaw provider entries for it are inert unless Ollama is
  deliberately installed later.
- **GHA compute broker**: `~/ai-agents-skills` is the fetch/object and legacy
  compatibility repository; its HEAD, index, ignored files, and working-tree
  edits are not executable installer input. Phase 8 validates the pinned Git
  closure, transports raw blobs without checkout filters, publishes a stable
  SHA tree owned by the user (never root), and installs the `research_compute` broker (the
  local→Modal→GitHub Actions compute router) from that tree to the runtime root.
  Old SHA trees are retained because reference-mode adapters and symlink-mode
  skills bind to their exact source path. The documented
  `~/.claude/skills/_run.sh skills/modal-research-compute/…` call is forwarded to
  it. A complete recovery restores the private `[gha]` config and native `gh`
  session; run the broker's `bootstrap` only when that optional authority was
  `NOT_CONFIGURED` on the source or `gh` reports `REAUTH_REQUIRED`. See the
  installed `github-actions-offload-routing` skill instruction.

## 3. Verify

```bash
make test      # no-secrets self-tests and roundtrip
make smoke     # quick CLI pin checks only
make verify    # installed full-profile checks and redacted status reports
```

Use the restore report rather than blanket reauthentication. Run `claude
login`, `codex login`, `gh auth login`, or `modal token new` only for the native
session/authority specifically classified `REAUTH_REQUIRED` or
`NOT_CONFIGURED`; quota-only `CREDIT_BLOCKED` results do not require a restore
or package change.
