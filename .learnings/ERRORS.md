## [ERR-20260712-001] make-test-manifest-drift

**Logged**: 2026-07-12T14:59:54Z
**Priority**: medium
**Status**: resolved

### Summary

The full repository test failed because a live grok-proxy runtime file was not classified by the fail-closed backup manifest.

### Error

    ERROR: unclassified paths (fail-closed):
        grok-proxy/known_hosts

### Context

- `make test` reached the round-trip sync dry-run after all focused Grok proxy tests passed.
- `known_hosts` is persistent private topology/host-key state, not generated cache data.

### Suggested Fix

Classify every new or newly observed runtime artifact in both `MANIFEST.yaml` and, for private archives, `secrets/secrets-manifest.yaml`; run `bin/sync.sh --dry-run` before the full round-trip gate.

### Canonical Integration Plan

- Related Skills: self-improving-agent
- Related Settings Or Artifacts: manifest, tests
- Affected Install Targets: not_applicable
- Affected OS/Substrates: linux
- Canonical Repo Change: `MANIFEST.yaml`, `secrets/secrets-manifest.yaml`
- Docs And Generated Outputs: not needed
- Verification Plan: `bash bin/sync.sh --dry-run`, then `make test`
- Blocked Or Unsupported Targets: non-Linux substrates uninspected

### Metadata

- Reproducible: yes
- Related Files: `MANIFEST.yaml`, `secrets/secrets-manifest.yaml`, `bin/test-roundtrip.sh`

---

## [ERR-20260717-042] assumed-low-level-broker-status-cli

**Logged**: 2026-07-17T05:42:24Z
**Priority**: low
**Status**: resolved

### Summary

The final residue audit invoked `vpn-broker status` as if it were a standalone
positional command.  The broker intentionally exposes only a closed,
owner-bound option schema, so argparse rejected the call before inspection.

### Response

Stopped the gate, acknowledged the protocol violation, read `vpn-broker
--help`, and restarted with the supported aggregate `install-release.py status`
plus independent OS listener/process/netns/cgroup inventories.

### Prevention

Do not infer a public CLI from an internal operation name.  Check `--help` for
each low-level privileged helper and prefer the documented aggregate diagnostic
when ownership credentials are intentionally unavailable.

### Metadata

- Reproducible: yes; the mistaken read-only invocation exited at argparse
- Related Files: `system/grok-proxy/vpn-broker`, `docs/INSTALL.md`

---

## [ERR-20260717-041] watchdog-probe-forked-before-private-umask

**Logged**: 2026-07-17T05:08:00Z
**Priority**: high
**Status**: resolved

### Summary

The first cache-permission correction applied `umask 077` only after the
compatibility watchdog had been forked.  A later watchdog `models_via` deep
probe could therefore delete and recreate Grok's shared cache under the
operator's original `umask 002`, restoring unsafe mode `0664`.

### Response

A fresh-context reviewer traced the fork order.  Added a red fake-Grok
regression that invokes `models_via` under `umask 002`, then applied the private
mask at the probe boundary itself while retaining the launch boundary mask.

### Prevention

For shared mutable state, enumerate every producer process rather than securing
only the primary process.  Fork ordering matters: a child created before a
security-context change retains the old context even when a later sibling is
correctly constrained.

### Metadata

- Reproducible: yes; the new focused regression failed before the correction
  and passed afterward
- Related Files: `system/grok-proxy/egress.sh`,
  `system/grok-proxy/grok-remote`,
  `system/grok-proxy/tests/test_proxy_env.sh`

---

## [ERR-20260717-043] parallel-roundtrip-shared-staging-race

**Logged**: 2026-07-17T01:30:03Z
**Priority**: low
**Status**: resolved

### Summary

Two `bin/test-roundtrip.sh` checks were launched in parallel to cover the live
home and an empty CI home. Both sync paths use the repository's shared
`.staging` workspace, so the concurrent runs interfered and the live-home run
reported a false sync failure. The same live sync passed when rerun alone.

### Response

Treat repository sync and roundtrip helpers as serial verification gates. Run
independent read-only syntax and environment probes in parallel, but do not
parallelize commands that render through the shared staging directory.

### Prevention

Before parallelizing repo-level test helpers, inspect whether they share a
staging, cache, journal, port, or generated-output path. A helper described as
non-mutating toward the live system may still mutate repository-local scratch
state.

### Canonical Integration Plan

- Related Skills: none
- Related Settings Or Artifacts: local verification workflow
- Affected Install Targets: codex
- Affected OS/Substrates: linux
- Canonical Repo Change: not needed; preserve as project-local command discipline
- Docs And Generated Outputs: not needed
- Verification Plan: rerun each roundtrip branch sequentially
- Blocked Or Unsupported Targets: other agents and operating systems unverified

### Metadata

- Reproducible: yes
- Related Files: `bin/test-roundtrip.sh`, `.staging`

---

## [ERR-20260717-044] leak-scan-explicit-dot-bypassed-default-scope

**Logged**: 2026-07-17T01:30:03Z
**Priority**: low
**Status**: resolved

### Summary

The final leak check invoked `bin/leak-scan.sh .` instead of the documented
`make leak-scan` gate. Supplying `.` bypassed the script's default exclusions
and flagged deliberate secret-shaped canaries in the vendored `external/`
test fixtures.

### Response

Read the Makefile target and reran its exact no-argument invocation. The
documented working-tree gate passed with 1,702 files scanned.

### Prevention

Use repository-defined verification targets before composing direct helper
arguments. An explicit path can change a scanner's scope and exclusion policy.

### Canonical Integration Plan

- Related Skills: none
- Related Settings Or Artifacts: local verification workflow
- Affected Install Targets: codex
- Affected OS/Substrates: linux
- Canonical Repo Change: not needed; the Makefile already exposes the correct gate
- Docs And Generated Outputs: not needed
- Verification Plan: `make leak-scan`
- Blocked Or Unsupported Targets: other agents and operating systems unverified

### Metadata

- Reproducible: yes
- Related Files: `Makefile`, `bin/leak-scan.sh`, `external/`

---

## [ERR-20260717-045] installer-fixture-depended-on-production-lock

**Logged**: 2026-07-17T01:58:10Z
**Priority**: high
**Status**: resolved

### Summary

After delegated cgroup setup let GitHub Actions reach the installer suite, 98
cases failed because the fake `grok-remote` embedded the production
self-admission block and tried to open the live production install lock. The
development host already had that lock, masking the fresh-runner dependency.

### Error

    compatibility-matrix: exit 78
    /var/lib/grok-proxy/release-control/install.lock: No such file or directory

### Response

Keep the exact production admission-marker bytes in the fixture, but mark the
fake payload as already admitted by the generated gate under test. Production
admission and evidence validation remain unchanged. A clean container without
the production lock now passes the exact formerly failing install case.

### Prevention

Fixtures that embed production boundary code must explicitly neutralize live
host dependencies outside the boundary being tested. Validate them once in an
environment without existing installation state; a green development host is
not fresh-host evidence.

### Canonical Integration Plan

- Related Skills: none
- Related Settings Or Artifacts: installer regression tests, GitHub Actions
- Affected Install Targets: not_applicable
- Affected OS/Substrates: linux
- Canonical Repo Change: `system/grok-proxy/tests/test_release_installer.py`
- Docs And Generated Outputs: not needed
- Verification Plan: clean-container focused test, delegated local installer suite, hosted rehearsal
- Blocked Or Unsupported Targets: non-Linux substrates unverified

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_release_installer.py`,
  `system/grok-proxy/install-release.py`

---

## [ERR-20260717-042] empty-pgrep-aborted-clean-residue-probe

**Logged**: 2026-07-17T00:24:00Z
**Priority**: low
**Status**: resolved

### Summary

The final residue probe used `set -e -o pipefail` with `pgrep | wc -l`.
`pgrep` correctly returned 1 for no matching process, but pipefail converted the
desired empty state into an early command failure before the summary printed.

### Response

Reran the read-only probe with no-match handled explicitly before counting.

### Prevention

Process-absence checks must treat `pgrep` status 1 as data, not an error; capture
its optional output with `|| true` and count afterward.

### Metadata

- Reproducible: yes
- Related Files: final live verification command only

---

## [ERR-20260717-041] backup-parity-check-ignored-mode-normalization

**Logged**: 2026-07-17T00:20:00Z
**Priority**: low
**Status**: resolved

### Summary

An independent Grok source/backup parity check required identical numeric modes.
The canonical collaborative source is `0664`/`0775`, while public capture
intentionally normalizes files to `0644`/`0755`, so the check falsely reported
54 mismatches despite exact bytes and executable semantics.

### Response

Changed the independent oracle to require exact bytes, no symlinks, and the
documented normalized public mode selected from the source executable bits.

### Prevention

For sanitized public-copy parity, compare bytes exactly but validate modes
against capture normalization, not the authoring tree's collaborative umask.

### Metadata

- Reproducible: yes
- Related Files: `bin/lib/manifest_sync.py`, `system/grok-proxy`

---

## [ERR-20260717-040] scoped-manifest-inside-staging-was-cleaned-before-read

**Logged**: 2026-07-17T00:16:00Z
**Priority**: low
**Status**: resolved

### Summary

A Grok-only sync manifest was placed inside `.staging/`. The sync engine clears
that directory before opening the requested manifest, so the dry run failed
with `FileNotFoundError` before capture began.

### Response

Recreated the same temporary manifest at the repository root, outside the
engine-owned staging directory, and kept the failed run read-only.

### Prevention

Never place sync inputs beneath `.staging/`; it is output scratch space owned by
the capture engine. Use a repository-root temporary manifest and remove it after
the scoped apply.

### Metadata

- Reproducible: yes
- Related Files: `bin/sync.sh`, `bin/lib/manifest_sync.py`

---

## [ERR-20260716-052] live-recovery-fence-contaminated-home-bound-tests

**Logged**: 2026-07-16T14:34:00Z
**Priority**: medium
**Status**: resolved

### Summary

The full VPN broker suite initially reported eight failures because an earlier
real-route canary had left a production recovery fence active in the real home.
Fifty tests passed, but compatibility-home cases correctly refused to run
through that live fail-closed state.

### Response

Audit and recover the exact dead canary epoch, complete the supported installer
abort, and rerun the unchanged suite.  All 58 broker tests then passed.

### Prevention

Before any test suite that can resolve the real home, assert that production has
no deny, canary, recovery fence, or runtime residue.  Prefer temporary homes for
all cases that do not explicitly test the live integration boundary.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260716-053] recovery-bridge-postcheck-retained-prestate-expectation

**Logged**: 2026-07-16T14:34:00Z
**Priority**: medium
**Status**: resolved

### Summary

The narrowly reviewed one-shot recovery bridge removed the exact dead recovery
fence successfully, but its inline postcondition helper reused a snapshot
assertion that still required the pre-recovery fence to exist.  The helper
therefore raised after the intended mutation.

### Response

Reinspect the fence, deny, terminal, processes, listeners, namespaces, journals,
and broker state independently.  Only the expected fence had disappeared; the
supported installer `abort` then restored a valid active release.

### Prevention

Encode recovery bridge preconditions and postconditions as distinct schemas.
The postcondition must compare an explicit allowed delta instead of rerunning a
prestate assertion after mutation.

### Metadata

- Reproducible: yes
- Related Files: live release recovery state only; no bridge was persisted

---

## [ERR-20260716-054] qualification-status-probe-timeout-aborted-readiness-window

**Logged**: 2026-07-16T14:34:00Z
**Priority**: high
**Status**: resolved

### Summary

Two release `load32` attempts failed at the first readiness sample because one
five-second `grok-remote status` probe timed out under sustained four-core host
load.  `wait_status()` had a 60-second outer budget, but `status()` propagated
the nested `TimeoutExpired`, aborting the whole window and leaving cleanup
without captured epoch authority.

### Response

Normalize only `subprocess.TimeoutExpired` to an unavailable status sample.
Polling retries within the existing global deadline, while cleanup and fault
paths continue to reject an unavailable sample before destructive action.
Add timeout, retry, deadline, and cleanup-authority regressions.  `strace` was
not installed, so the exact exception was obtained with a non-persisted,
in-memory diagnostic wrapper around the immutable verifier.

### Prevention

Nested probes inside a larger bounded readiness loop must report transient
unavailability rather than escape the outer budget.  Do not broaden the catch
to integrity, execution, or generic subprocess failures.

### Metadata

- Reproducible: yes; both attempts had the same closed error digest
- Related Files: `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260716-055] repeated-wrong-unittest-class-selector

**Logged**: 2026-07-16T14:34:00Z
**Priority**: low
**Status**: resolved

### Summary

A focused command selected `LiveVerificationTests`, although the inspected file
defines `LiveVerifierHelperTests`.  Unittest produced four loader errors and ran
no test bodies.  This repeated the selector discipline problem already noted in
ERR-20260716-051.

### Response

Use `rg '^class '` as a separate discovery step, then rerun the four exact tests
under `LiveVerifierHelperTests`; all passed.

### Prevention

Do not combine class-name discovery and an assumed selector in one shell call.
Resolve the class first, inspect the output, and only then construct the focused
unittest command.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260716-050] nested-compatibility-handoff-lost-public-recovery-admission

**Logged**: 2026-07-16T13:08:03Z
**Priority**: high
**Status**: resolved

### Summary

A failed real-route canary left the exact recovery fence and canary terminal
durably active.  The public `grok-remote recover` wrapper admitted itself under
deny, but its contained standalone `egress.sh compatibility-handoff` child
performed ordinary self-admission and exited 78 before any cleanup proof.

### Response

Forward the exact egress argv into self-admission and request
`--public-recovery` only for literal handoff mode with the single exact
`compatibility-handoff` command.  Preserve all later fence-owner, release, and
port checks; retain the prior reviewed egress hash for rollback; add both argv
and top-level immutable-release regressions.

### Prevention

Recovery admission must be tested at every nested executable boundary, not
only at the public wrapper.  A test that disables warm handoff cannot establish
that the production recovery chain remains reachable under durable deny.

### Metadata

- Reproducible: yes; installed admission returned 78 normally and 0 with the
  missing `--public-recovery` flag
- Related Files: `system/grok-proxy/egress.sh`,
  `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/test_release_installer.py`,
  `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260716-051] focused-admission-test-used-synthetic-runtime-fixture

**Logged**: 2026-07-16T13:08:03Z
**Priority**: low
**Status**: resolved

### Summary

The first focused regression used `make_installer()`, whose runtime files are
deliberate stubs, so its egress `status` returned success instead of exercising
production self-admission.  The first isolated command also combined `-I` with
package-style unittest names, removing the local test package from `sys.path`.

### Response

Use the file-based unittest invocation documented by the suite and construct
the regression with `_default_runtime_files(ROOT)` in a prefix layout.  The
corrected test now proves ordinary egress remains denied while the exact
handoff reaches its post-admission owner validation.

### Prevention

Security-boundary tests must name whether they exercise synthesized fixtures
or actual runtime bytes.  Use file-based test selection when isolated Python
intentionally excludes the working directory.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_release_installer.py`,
  `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260716-044] retained-user-releases-remained-directly-executable

**Logged**: 2026-07-16T12:36:09Z
**Priority**: high
**Status**: resolved

### Summary

The initial immutable-release design left every retained user release at mode
`0555`. Releases created before payload self-admission could therefore remain
directly executable even though only the current selector was intended to run.

### Response

Keep only the selected user release at `0555`, archive every inactive user
release at `0500`, retain root helper releases at `0555` for deny-safe recovery,
and require the exact reviewed production admission bytes before re-exposure.

### Prevention

Treat retained-code readability as part of selection state, not merely storage.
Exercise distinct-UID execution after every install, rollback, and recovery.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/test_release_installer.py`

---

## [ERR-20260716-045] mixed-selector-recovery-was-expected-to-succeed

**Logged**: 2026-07-16T12:36:09Z
**Priority**: medium
**Status**: resolved

### Summary

An early fault-matrix assertion expected public recovery to succeed at every
selector publication checkpoint. Five checkpoints intentionally contain mixed
selector or metadata state, where admitting the payload would be unsafe.

### Response

Require public recovery to return 78 at mixed checkpoints and succeed only once
the published selector/metadata set is coherent enough to authenticate.

### Prevention

Classify crash points by externally coherent state before assigning recovery
expectations; fail-closed recovery is a valid and required outcome.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_release_installer.py`

---

## [ERR-20260716-046] access-quarantine-ran-before-durable-deny

**Logged**: 2026-07-16T12:36:09Z
**Priority**: high
**Status**: resolved

### Summary

The first access-convergence implementation archived inactive user releases
before publishing the durable deny. An `fchmod` or `fsync` failure could leave
access drift while the active gate remained runnable.

### Response

Publish and fsync the deny first, converge access behind that fence, and clear
the deny only after the exact access policy and selection are proven. Added a
failure/retry regression for the idempotent repair path.

### Prevention

Every operation that can discover unsafe executable state must establish its
fail-closed fence before attempting repair.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/test_release_installer.py`

---

## [ERR-20260716-047] client-test-inherited-canonical-private-model-choice

**Logged**: 2026-07-16T12:36:09Z
**Priority**: medium
**Status**: resolved

### Summary

A client unit test passed the canonical `~/grok-proxy` source as a pretend
release. Once the preserved private `.model.choice` existed there, production
compatibility routing persisted to that directory instead of the test's
temporary home, causing an environment-dependent failure.

### Response

Give the test a dedicated empty temporary release directory. Stress-repeat the
focused case before rerunning the project suite.

### Prevention

Tests of release behavior must never use the mutable canonical authoring tree as
a fixture when private/generated state can legitimately coexist there.

### Metadata

- Reproducible: yes when canonical `.model.choice` exists
- Related Files: `system/grok-proxy/tests/test_grok_ms_client.py`

---

## [ERR-20260716-048] canonical-test-assumed-nested-repository-layout

**Logged**: 2026-07-16T12:36:09Z
**Priority**: medium
**Status**: resolved

### Summary

The pipeline tests derived the rebuild repository solely from the backup copy's
three-level nesting. Running the same authoritative tests from canonical
`~/grok-proxy` therefore resolved helper modules below `/home/bin` and failed.

### Response

Support both inspected layouts: the nested repository root and the canonical
source's sibling `coding-system-rebuild` root, accepting only a candidate that
contains the exact helper under test.

### Prevention

Tests mirrored between canonical source and repository backup must either be
self-contained or explicitly resolve and verify both supported install layouts.

### Metadata

- Reproducible: yes from canonical `tests/run.sh`
- Related Files: `system/grok-proxy/tests/test_install_pipeline.py`,
  `system/grok-proxy/tests/test_source_backup_pipeline.py`

---

## [ERR-20260716-049] sourced-provider-test-overwrote-private-host-config

**Logged**: 2026-07-16T12:36:09Z
**Priority**: high
**Status**: resolved

### Summary

The provider mutation test sourced canonical `egress.sh`. Because a real
source-local `hosts.conf` existed, its compatibility preference over the test
HOME redirected the fixture's hostile-host rewrite into the user's private
configuration.

### Response

Bind the fixture `CONF` explicitly to its temporary HOME before mutation,
restore the private file only from independently inspected encrypted backup,
and rerun the test with a before/after digest guard.

### Prevention

Any sourced shell test that mutates a derived path must assert that the final
path is below its temporary root; environment overrides alone are insufficient
when source-local compatibility files can take precedence.

### Metadata

- Reproducible: yes when canonical `hosts.conf` exists
- Related Files: `system/grok-proxy/tests/test_multi_gate.sh`, `grok-proxy/hosts.conf`

---

## [ERR-20260716-041] source-execution-guard-invalidated-cli-test-fixtures

**Logged**: 2026-07-16T12:20:00Z
**Priority**: medium
**Status**: resolved

### Summary

Several shell regressions still executed copied or editable `grok-remote` and
`egress.sh` files with `GROK_TESTING=1`. The new release self-admission guard
correctly rejected those calls before the intended compatibility behavior was
reached, so their assertions reported misleading functional failures.

### Response

Converted function-level compatibility checks to source the script and invoke
the intended function explicitly. The multi-session dispatch check now builds
and invokes a real prefix-installed immutable release instead of reinstating a
test-only source-execution bypass.

### Prevention

Keep security-boundary tests on an installed fixture and keep pure behavior
tests on explicit function/module seams. An environment variable must not turn
an editable runtime tree into an admitted production release.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_p0_baseline.sh`,
  `system/grok-proxy/tests/test_session_lock.sh`,
  `system/grok-proxy/tests/test_multi_gate.sh`,
  `system/grok-proxy/tests/test_diagnostic_safety.sh`

---

## [ERR-20260716-042] immutable-prefix-fixture-needs-explicit-cleanup-mode

**Logged**: 2026-07-16T12:25:00Z
**Priority**: low
**Status**: resolved

### Summary

A manual prefix-install probe succeeded, but its ordinary `rm -rf` cleanup
could not remove the deliberately immutable `0555` release directories.

### Response

Removed the known temporary probe after making only that temporary tree
user-writable. The reusable shell fixture now performs the same scoped mode
adjustment in its exit trap.

### Prevention

Test fixtures that intentionally create immutable directory trees must own an
explicit, path-scoped teardown step; do not weaken production release modes to
make generic temporary-directory cleanup work.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_multi_gate.sh`,
  `system/grok-proxy/install-release.py`

---

## [ERR-20260716-043] global-process-scans-make-broker-installer-suites-nonparallel

**Logged**: 2026-07-16T12:45:00Z
**Priority**: medium
**Status**: resolved

### Summary

Running the VPN broker and release-installer suites concurrently caused one
installer case to report a legacy OpenVPN process from the broker suite. The
installer deliberately scans global process state before switching releases,
so these integration suites are not isolation-safe peers.

### Response

Reran the affected installer test after the broker suite ended; it passed.
The final comprehensive verification schedules global process/network suites
sequentially.

### Prevention

Parallelize hermetic unit suites only. Any test that scans global PIDs,
listeners, namespaces, cgroups, or release selectors must be serialized with
other tests that create matching resources.

### Metadata

- Reproducible: yes when the suites overlap; isolated rerun passed
- Related Files: `system/grok-proxy/tests/test_release_installer.py`,
  `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260716-040] exec-redirection-silenced-admission-diagnostics

**Logged**: 2026-07-16T11:35:00Z
**Priority**: medium
**Status**: resolved

### Summary

The first self-admission guard opened its persistent Bash descriptor with
`exec {fd}<path 2>/dev/null`. Because `exec` had no external command, that
redirection changed the current shell's stderr for the rest of the wrapper.
Rejection still returned 78, but all diagnostics disappeared.

### Response

Removed the persistent stderr redirection and reran the direct-source,
test-variable, and import-shadow refusal cases.

### Prevention

Treat redirections on the no-command form of Bash `exec` as persistent shell
state. Suppress an expected open error in a subshell or retain the diagnostic;
never attach `2>/dev/null` to a persistent descriptor declaration.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/grok-remote`,
  `system/grok-proxy/egress.sh`,
  `system/grok-proxy/tests/test_source_backup_pipeline.py`

---

## [ERR-20260715-033] focused-unittest-used-uninspected-class-name

**Logged**: 2026-07-15T18:30:00Z
**Priority**: low
**Status**: resolved

### Summary

A focused VPN broker regression command named `VpnBrokerTests`, but the test
module's inspected class is `BrokerTests`. Unittest therefore reported two
loader errors and ran no test bodies.

### Response

Confirmed the class declaration with `rg`, preserved the failed output as
non-evidence, and reran the same focused cases under `BrokerTests`.

### Prevention

Resolve the exact unittest class and method names from the target module before
composing dotted selectors; do not infer a class name from the filename.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260714-019] assumed-installer-verb-action-contract

**Logged**: 2026-07-14T21:34:44Z
**Priority**: low
**Status**: resolved

### Summary

After safely staging the reviewed installer, I first invoked a nonexistent
`release-id` verb and then incorrectly added `--dry-run` to the intrinsically
read-only `plan` verb. Both parser checks rejected the commands before any live
mutation.

### Response

Confirmed the staged installer hash/ownership were intact, inspected the
verb-specific validation, and switched to plain `plan` for release-ID
inspection.

### Prevention

Before composing an installer command, inspect that exact staged helper's
command list and verb-specific action validation; do not infer verbs or attach
generic action flags to intrinsically read-only commands.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`

---

## [ERR-20260714-020] assumed-installed-manifest-filename

**Logged**: 2026-07-14T21:37:41Z
**Priority**: low
**Status**: resolved

### Summary

A read-only post-install validator assumed the immutable manifest was named
`manifest.json`; the deployed layout and installer contract name it
`release.json`. The script stopped after validating selector shapes and made no
state change.

### Response

Enumerated the exact deployed release layout, confirmed owner/mode invariants,
and rebuilt the validator around the discovered `release.json` paths.

### Prevention

Derive deployed artifact paths from the installer layout or enumerate the
exact immutable release directory before writing an independent validation
script; do not infer conventional filenames.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`

---

## [ERR-20260714-021] concurrent-exec-disrupted-live-qualification

**Logged**: 2026-07-14T22:10:00Z
**Priority**: high
**Status**: resolved

### Summary

Starting a second execution cell to inspect an in-flight `load32`
qualification disrupted the verifier process. The installer rejected the
empty/non-JSON result and retained its authenticated crash-pending intent;
31 fixture barrier markers and one temporary directory remained.

### Response

Stopped concurrent inspection, inventoried the exact pending state without
reading private data, and used the installer's authenticated `abort` path to
clear the fence and incomplete evidence. The candidate selectors and boot
inventory returned to valid READY state.

### Prevention

Do not assume separate execution cells are isolation-safe observers of a live
qualification process group. Run live installer-owned qualification in one
uninterrupted execution cell. For additional diagnostics, use reviewed closed
checkpoint codes emitted by the verifier rather than concurrent process or
temporary-directory inspection.

### Metadata

- Reproducible: unknown; observed once during concurrent execution
- Related Files: `system/grok-proxy/install-release.py`, `system/grok-proxy/grok_ms/qualification_verifier.py`

---

## [ERR-20260714-022] unparsed-inline-preflight-script

**Logged**: 2026-07-14T23:05:00Z
**Priority**: low
**Status**: resolved

### Summary

A read-only inline Python preflight had one missing closing parenthesis, so its
process and temporary-directory inventory did not run. Independent status,
netns, and release-plan commands in the same shell continued and remained
read-only.

### Response

Reran the omitted sampler as a separate bounded command and confirmed zero
Grok, release-runtime, qualification, and broker processes, zero qualification
temporary directories, zero Grok cgroups, and no fixed listeners.

### Prevention

Keep inline preflight probes short and syntax-check them separately before
combining them with other evidence commands.

### Metadata

- Reproducible: yes
- Related Files: orchestration only; no product file was involved

---

## [ERR-20260714-014] external-time-binary-assumed

**Logged**: 2026-07-14T14:00:53Z
**Priority**: low
**Status**: resolved

### Summary

The first unchanged-tree aggregate attempt assumed `/usr/bin/time` existed;
this host has Bash's timing keyword but no external `time` binary. The test
runner did not start and no source or runtime state changed.

### Response

Switched elapsed-time collection to Bash's portable `TIMEFORMAT` plus the
shell `time` keyword, while retaining the pre/post source digest gate.

### Prevention

Check helper availability before using absolute utility paths. For Bash test
runners, prefer the built-in timing keyword when no machine-readable external
`time` contract is required.

### Metadata

- Reproducible: yes
- Related Files: orchestration only; no product file was involved

---

## [ERR-20260714-004] unsupported-help-ran-full-installer

**Logged**: 2026-07-14T01:59:30Z
**Priority**: high
**Status**: mitigated

### Summary

Invoking a shell installer with `--help` was assumed to be read-only even
though that script has no argument parser; it began the complete restore and
upgraded Chromium before its exact process group was stopped.

### Error

    bash bin/install.sh --help
    # bin/install.sh ignores positional arguments and starts phase 1

### Impact

- `chromium`, `chromium-common`, `chromium-driver`, and `chromium-sandbox`
  changed from `149.0.7827.114-1xtradeb1.2404.1` to
  `150.0.7871.114-1xtradeb1.2404.1`.
- The Grok deployment selector and runtime files were not reached or changed.
- `dpkg --audit` is clean.  The prior Chromium packages are no longer in the
  configured repository or apt cache, so an immediate exact downgrade is not
  available.

### Prevention

Read a shell helper's prologue/argument parser before trying `--help`.  Only
invoke `--help` after confirming the helper implements it, or run the helper in
an isolated test root when its behavior is unknown.  For a multi-command probe,
do not append an unverified helper after known-safe commands.

### Metadata

- Reproducible: yes
- Related Files: `bin/install.sh`, `bin/prepare.sh`

---

## [ERR-20260714-005] pdeathsig-creator-thread-exited

**Logged**: 2026-07-14T02:45:00Z
**Priority**: high
**Status**: resolved

### Summary

A provider process was created with `PR_SET_PDEATHSIG` by a short-lived Python
worker thread.  Linux treats that creating thread as the parent for this
contract, so the kernel killed the provider when the worker thread exited even
though the main supervisor process remained alive and had committed the
provider generation.

### Symptom

The control plane reported two ready leases and a committed provider PID, but
the private SOCKS listener disappeared immediately after generation setup.

### Resolution

Keep the generation worker thread alive for the entire provider epoch.  Notify
waiting registrations after commit, then wait on the supervisor stop event so
the creator-thread lifetime matches the child lifetime.

### Prevention

Whenever `PR_SET_PDEATHSIG` is installed from a multithreaded parent, make the
creator-thread lifetime an explicit part of the ownership design.  Regression
tests must exercise the real post-commit data path, not only the control-plane
READY response or recorded PID.

### Metadata

- Reproducible: yes
- Inspected substrate: Linux 6.8, Python 3.12
- Unverified substrates: other kernels and non-Linux systems
- Related Files: `system/grok-proxy/grok_ms/supervisor.py`, `system/grok-proxy/tests/test_multi_feature_e2e.py`

---

## [ERR-20260714-003] parallel-broker-test-interface-drift

**Logged**: 2026-07-14T01:06:35Z
**Priority**: medium
**Status**: unresolved

### Summary

Broker integration tests retained older private constructor/helper contracts
while the concurrently developed broker changed them, breaking combined gates
after focused suites had previously passed independently.

### Error

    AttributeError: 'Broker' object has no attribute '_helper'. Did you mean: '_helpers'?
    TypeError: Request.__init__() missing 1 required positional argument: 'listen_port'

### Suggested Fix

Treat cross-module fixtures as explicit handoff contracts during parallel
implementation: rerun all consumer tests after the producer handoff, and prefer
a stable public validation method over a private helper in integration tests.

### Progress

The broker handoff restored the compatibility helper, after which all 14
release-installer tests passed. The aggregate run then exposed the stale
`Request` fixture; resolution remains with the in-flight broker handoff.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/vpn-broker`, `system/grok-proxy/tests/test_release_installer.py`, `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260714-002] sourced-initializer-status-ignored

**Logged**: 2026-07-14T00:00:00Z
**Priority**: high
**Status**: resolved

### Summary

A Bash wrapper sourced a fail-closed initializer without checking the `.` command's status, so a rejected security-sensitive environment override was logged but execution continued.

### Error

    [egress] GROK_VPNGATE is not supported; the VPN broker path is fixed
    fake-grok:inspect
    exit status: 0

### Context

- An exact feature-gate regression compared `GROK_MULTI_SESSION=1` with a similar non-enabling value.
- `egress.sh` correctly returned nonzero, but `grok-remote` used plain `. "$DIR/egress.sh"` under `set -uo pipefail` (without `set -e`) and continued.

### Suggested Fix

Treat sourced security initializers as explicit gates (`if ! . file; then exit 1; fi`) and add a test proving both the error text and final nonzero status.

### Canonical Integration Plan

- Related Skills: self-improving-agent, adversarial-boundary-gate
- Related Settings Or Artifacts: tests
- Affected Install Targets: codex, claude, deepseek, copilot
- Affected OS/Substrates: linux, macos, wsl, git-bash-msys
- Canonical Repo Change: add this check to shell-wrapper review guidance and a focused fixture under `tests/`
- Docs And Generated Outputs: update generated docs only if guidance is promoted
- Verification Plan: shell regression with a sourced initializer that returns nonzero; ShellCheck where available
- Blocked Or Unsupported Targets: native Windows PowerShell/CMD is a different sourcing model and remains unverified; OpenClaw is outside the current install-target claim

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/grok-remote`, `system/grok-proxy/tests/test_multi_gate.sh`

---

## [ERR-20260714-006] codewhale-readonly-adapter-wrote-config-artifact

**Logged**: 2026-07-14T08:34:00Z
**Priority**: high
**Status**: mitigated

### Summary

The CodeWhale read-only review adapter passed reasoning effort through
`--config reasoning_effort=max`. CodeWhale 0.8.66 interpreted that value as a
workspace file target, created `reasoning_effort=max`, and reported that it had
written recovered credential material there despite `--sandbox-mode read-only`.

### Response

- The file was deleted immediately without reading it.
- The CodeWhale process was interrupted and its partial output was rejected as
  evidence.
- A scoped status check confirmed that the unexpected path no longer exists.

### Prevention

Treat the current CodeWhale adapter command shape as mutation-capable. Do not
reuse it until a fake-workspace regression proves zero filesystem delta and the
CLI's supported reasoning option is passed without overloading `--config`.
Read-only claims must be verified by before/after workspace inventory, not by
sandbox flags alone.

### Canonical Integration Plan

- Related Skills: cross-agent-delegation, agent-group-discuss
- Affected Install Targets: codex, claude, deepseek
- Affected OS/Substrates: Linux inspected; macOS, WSL, and Windows unverified
- Canonical Repo Change: fix the CodeWhale adapter argument mapping and add a
  fake-workspace zero-delta smoke test before external review dispatch
- Verification Plan: run the adapter against a disposable workspace with a
  synthetic credential provider, then compare an exact pre/post tree manifest
- Blocked Limits: do not claim read-only CodeWhale review until that regression
  passes on the installed CodeWhale version

### Metadata

- Reproducible: yes
- Related Files: external CodeWhale read-only adapter

---

## [ERR-20260714-007] failed-e2e-left-empty-cgroup-scopes

**Logged**: 2026-07-14T09:53:36Z
**Priority**: high
**Status**: resolved

### Summary

Four user-owned `grok-ms-*` cgroup-v2 scopes remained after earlier failed
multi-session E2E attempts. All were empty and unpopulated, but the installer
correctly treated their presence as release-switch residue.

### Response

- Verified every exact name, owner, mode, empty `cgroup.procs`, and
  `populated 0` state.
- Verified that no user/root authority record referenced any scope.
- Removed only those four exact empty directories and proved a zero-scope
  inventory afterward.
- Re-ran the corrected E2E and installer suites; both ended with zero reserved
  cgroup residue.

### Prevention

Always inventory reserved cgroups after a killed or failed process-scope test.
Treat empty orphan cleanup as an explicit, identity-checked recovery action;
never recursively delete or remove populated/unrecognized cgroups.

### Metadata

- Reproducible: observed; the specific earlier failing run that created each
  scope is inferred rather than individually traced
- Related Files: `system/grok-proxy/grok_ms/process_scope.py`,
  `system/grok-proxy/tests/test_multi_feature_e2e.py`

---

## [ERR-20260714-008] strace-not-installed-during-lock-diagnosis

**Logged**: 2026-07-14T09:53:36Z
**Priority**: low
**Status**: resolved

### Summary

A lock-wait diagnosis assumed `strace` was installed. It was not available on
this host, and installing packages was outside the acceptance workflow.

### Response

Used existing `/proc` process relationships, wait channels, `lslocks`, and
source inspection instead. Those identified the exclusive installer parent and
the broker child waiting for a shared lock on the same inode.

### Prevention

Check diagnostic-tool availability before composing a trace. Prefer the
already-installed `/proc` and `lslocks` path for bounded lock ownership checks;
do not add packages during live release verification.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`,
  `system/grok-proxy/vpn-broker`

---

## [ERR-20260714-009] external-time-command-not-installed

**Logged**: 2026-07-14T10:21:00Z
**Priority**: low
**Status**: resolved

### Summary

A verification command assumed GNU `time` existed at `/usr/bin/time`. This
host provides only Bash's `time` keyword, so the test process did not start.

### Response

Confirmed the missing executable before retrying. Use Bash's `TIMEFORMAT` and
`time` keyword for elapsed-duration evidence on this host.

### Prevention

Check `command -v /usr/bin/time` before using external timing flags. Prefer the
shell keyword when only elapsed wall time is required.

### Metadata

- Reproducible: yes
- Related Files: verification command only; no product file was involved

---

## [ERR-20260714-010] assumed-component-makefile

**Logged**: 2026-07-14T10:25:00Z
**Priority**: low
**Status**: resolved

### Summary

A verification-inspection command tried to read `system/grok-proxy/Makefile`,
but this component has no Makefile. Its documented aggregate entrypoint is
`system/grok-proxy/tests/run.sh`.

### Response

Kept the successful status/diff/test-runner inspection and stopped relying on
an inferred build file. Use `rg --files` before addressing optional component
helpers by name.

### Prevention

Discover component build and verification entrypoints before assuming a common
filename exists.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/run.sh`

---

## [ERR-20260714-011] security-review-model-capacity

**Logged**: 2026-07-14T10:42:00Z
**Priority**: medium
**Status**: resolved

### Summary

The fresh adversarial security-review subagent completed source tracing but
failed before its final disposition because its selected model was at capacity.
Its incomplete turn is not review evidence.

### Response

Retried the same bounded, read-only review and retained the completed local
tests and other independent reviews as separate evidence.

### Prevention

Treat capacity failures as failed review attempts, not partial passes. Retry a
fresh turn and require a complete findings-first disposition before closing the
security gate.

### Metadata

- Reproducible: external capacity state is transient
- Related Files: orchestration only; no product file was involved

---

## [ERR-20260714-012] openvpn-sanitizer-preserved-nul-suffix

**Logged**: 2026-07-14T11:08:00Z
**Priority**: high
**Status**: resolved

### Summary

The new adversarial OpenVPN corpus showed that `sanitize.awk` could emit an
allowlisted directive containing an embedded NUL and hostile-looking suffix.
OpenVPN's C parser and awk need not interpret bytes after that NUL identically.

### Response

Added a seen-to-fail regression and made any embedded NUL a hard sanitizer
error. The caller already discards every nonzero sanitizer result before an
OpenVPN config is published.

### Prevention

Security-boundary parsers must reject bytes that make producer and consumer
line/token views ambiguous, even when the observed consumer would probably
truncate to a safe prefix. Keep the quote/backslash/VT/FF/CR/block/NUL corpus
in the aggregate VPN input test.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/sanitize.awk`,
  `system/grok-proxy/tests/test_vpngate_input.sh`

---

## [ERR-20260714-013] sanitizer-review-classifier-block

**Logged**: 2026-07-14T11:12:00Z
**Priority**: low
**Status**: resolved

### Summary

A delegated read-only OpenVPN sanitizer bypass review was blocked by a generic
cybersecurity classifier before returning evidence.

### Response

Excluded the blocked subreview from the evidence set. The parent instead used
the completed static security review, a local adversarial corpus, a reproduced
NUL ambiguity, the resulting fix, and the passing aggregate VPN test.

### Prevention

Keep defensive parser reviews narrowly phrased around local regression cases,
and never count a policy-blocked review as a pass or a finding.

### Metadata

- Reproducible: policy-dependent
- Related Files: orchestration only; no product file was involved

---

## [ERR-20260714-015] pid-marker-existence-race

**Logged**: 2026-07-14T15:20:00Z
**Priority**: medium
**Status**: resolved

### Summary

The first final aggregate loop caught a test race: a child PID marker existed
after `open(O_TRUNC)` but before its decimal payload was visible, so immediate
`int(read_text())` raised on an empty string.

### Response

Replaced existence-only waits at both descendant-marker call sites with one
bounded helper that waits for a nonempty decimal payload before parsing it.
The product cancellation and recovery paths were unchanged.

### Prevention

For asynchronously written readiness or identity markers, wait for the complete
validated payload contract rather than treating pathname existence as content
readiness. Reuse the bounded helper for equivalent test fixtures.

### Metadata

- Reproducible: timing-dependent; observed once in the aggregate suite
- Related Files: `system/grok-proxy/tests/test_grok_ms_supervisor.py`

---

## [ERR-20260714-016] status-rejects-action-flags

**Logged**: 2026-07-14T16:05:00Z
**Priority**: low
**Status**: resolved

### Summary

The pinned release installer rejected `status --dry-run`; `status` is already
read-only and deliberately accepts neither action nor fault flags.

### Response

Confirmed the rejection happened before mutation and reran the inspection with
plain `status`. Reserved `--dry-run` and `--apply` for verbs that advertise an
action mode.

### Prevention

Check verb-specific help or parser validation before appending generic action
flags to an otherwise read-only command.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`

---

## [ERR-20260714-017] qualification-hashed-release-payload-as-public-gate

**Logged**: 2026-07-14T16:18:00Z
**Priority**: high
**Status**: resolved

### Summary

The first live `load32` qualification blocked before workload launch because
the verifier compared the selector's public-gate digest with the intentionally
different `grok-remote` payload inside the immutable release.

### Response

Confirmed every installed manifest, selector, evidence record, and gate hash
independently. Changed qualification launches to use the passwd-home public
gate, which revalidates and then execs the selected payload, and added a test
whose public gate and release payload have deliberately different hashes.

### Prevention

Qualification must exercise the same installed admission path whose digest is
recorded in selection metadata. Keep at least one installed-layout regression
where gate bytes and selected payload bytes differ by design.

### Metadata

- Reproducible: yes; reproduced on release `428ff68e...`
- Related Files: `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260714-018] fake-release-gate-inherited-production-country-block

**Logged**: 2026-07-14T17:02:00Z
**Priority**: high
**Status**: resolved

### Summary

After the entrypoint fix, live `load32` reached the real direct provider but
could not start because this host's DE exit is in the production blocked-country
set. That made the fake-Grok release resource gate depend on route geography.

### Response

Reproduced the exact provider error with one authenticated fake-Grok client.
Made only the fixed fake load/fault environment use an empty blocked-country
set; the separate real-pair environment retains normal production policy.

### Prevention

Keep release implementation/resource qualification deterministic and distinct
from route/model qualification. Tests must prove hostile ambient country policy
cannot enter fake load/fault contracts and cannot be weakened for real pairs.

### Metadata

- Reproducible: yes; direct exit observed as DE
- Related Files: `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260714-023] quarantined-installer-status-omitted-source

**Logged**: 2026-07-14T23:35:00Z
**Priority**: low
**Status**: resolved

### Summary

A read-only `status` call through the quarantined root-staged installer omitted
`--source`, so the copied script looked for its declared runtime beside the
quarantine path and failed before inspecting release state.

### Response

Confirmed the failure was pre-mutation and retained the reviewed component
source path for every staged-installer verb, including `status`.

### Prevention

Treat a quarantined installer copy as code-only: always pass the exact reviewed
`--source` payload root even for read-only verbs whose validation loads the
declared runtime inventory.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`

---

## [ERR-20260715-024] fault-verifier-waited-for-descendant-pipe-before-recovery

**Logged**: 2026-07-15T00:05:00Z
**Priority**: high
**Status**: resolved

### Summary

Live fault qualification timed out after killing the supervisor because
`Popen.communicate()` waited for stdout/stderr EOF from the intentionally
escaped descendant, while offline recovery that kills that descendant was
sequenced only after `communicate()` returned.

### Response

Changed the proof order to wait only for wrapper process exit, validate and run
offline recovery, prove the descendant absent, and then drain the closed pipes.
Added an explicit pipe-barrier regression plus source-order assertions.

### Prevention

When a fault fixture deliberately leaves descendants alive, distinguish
process termination from inherited-descriptor EOF. Use deterministic barriers
in tests and place output draining after the authority that closes descendants.

### Metadata

- Reproducible: yes; live failure duration included the 10-second timeout
- Related Files: `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260715-025] process-inventory-printed-unrelated-command-secrets

**Logged**: 2026-07-15T00:50:00Z
**Priority**: high
**Status**: resolved

### Summary

A host-load diagnostic printed full command arguments for unrelated processes;
one unrelated integration had placed a credential in its argv, so the tool
output exposed it to the session transcript.

### Response

Stopped using full argv for host-wide resource checks and switched to bounded
PID/user/state/CPU/memory/thread/elapsed/command-name columns only.

### Prevention

Treat `/proc/*/cmdline` and `ps ... args` as secret-bearing. For broad process
inventory, omit argv unless a narrowly identified process requires it; redact
known credential flags before any displayed output.

### Metadata

- Reproducible: yes
- Related Files: host diagnostic workflow (no product source file)

---

## [ERR-20260715-026] cleanup-bind-probe-misclassified-time-wait

**Logged**: 2026-07-15T01:05:00Z
**Priority**: high
**Status**: resolved

### Summary

Live load qualification proved no listening rows but timed out its cleanup gate
because a bare bind probe treated TCP `TIME_WAIT` on a recently closed product
port as active listener residue.

### Response

Matched the product listeners' pre-bind `SO_REUSEADDR` setting and required the
probe to reach `listen()`. Added a real-kernel regression that rejects an
active listener, creates server-side `TIME_WAIT`, confirms a bare bind fails,
and confirms the restartability probe succeeds.

### Prevention

Cleanup probes should test the product's actual restart contract, not a stricter
socket configuration. Pair restartability with independent listener inventory
so reusable closed connections are distinguished from live ownership.

### Metadata

- Reproducible: yes; exact error hash decoded to an empty occupied-port list
- Related Files: `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260715-027] literal-ip-trace-failed-through-working-ssh-socks

**Logged**: 2026-07-15T01:35:00Z
**Priority**: high
**Status**: resolved

### Summary

The Windows route established successfully, but the initial exit-identity
probe against `https://1.1.1.1/cdn-cgi/trace` failed with curl TLS error 35.
The hostname endpoint succeeded through the same pinned SSH SOCKS tunnel.

### Response

Switched initial qualification and watchdog identity probes to
`https://www.cloudflare.com/cdn-cgi/trace` and added tests that assert the
actual probe argument. The diagnostic tunnel was authenticated, torn down, and
its local port independently proved reusable.

### Prevention

Use a hostname when TLS endpoint behavior depends on SNI, even when SOCKS5
performs remote DNS. Verify both setup and teardown through the exact transport
before attributing a TLS failure to the route.

### Metadata

- Reproducible: yes; literal-IP failure and hostname success were observed
  consecutively through one SSH tunnel
- Related Files: `system/grok-proxy/grok_ms/supervisor.py`,
  `system/grok-proxy/tests/test_grok_ms_supervisor.py`

---

## [ERR-20260715-028] provider-up-collapsed-live-failures-to-status-one

**Logged**: 2026-07-15T02:05:00Z
**Priority**: high
**Status**: resolved

### Summary

An integrated home-provider canary failed before qualification, but the shell
adapter discarded stderr and every provider-up boundary returned status 1.
Exact SSH and isolated provider-mode diagnostics passed, leaving the failing
production boundary unidentifiable from closed evidence.

### Response

Kept provider stderr suppressed and assigned fixed nonzero stage codes for
context, rung, frozen input, direct misuse, occupied port, state cleanup,
tunnel startup, tunnel liveness, and inventory publication. The Python adapter
normalizes pre-dispatch, parent-guard, exec, signal, and spawn failures to the
closed infrastructure code 29. Regressions exercise every shell code, the
internal-rung branch, exact cleanup order/failure, the real guard/process
boundary, unexpected statuses, signals, and spawn failure.

### Prevention

When untrusted diagnostics must stay suppressed, return a closed semantic code
at each material boundary so live failures remain actionable without replaying
external text.

### Metadata

- Reproducible: yes; both live wrappers returned the same opaque status 1
- Related Files: `system/grok-proxy/egress.sh`,
  `system/grok-proxy/tests/test_p0_baseline.sh`

---

## [ERR-20260715-029] root-only-staged-installer-read-without-sudo

**Logged**: 2026-07-15T02:40:13Z
**Priority**: low
**Status**: resolved

### Summary

A read-only staged-installer verification chained an unprivileged `sha256sum`
before the intended status command. The installer is deliberately root-owned
and mode 0400, so the metadata read failed and short-circuiting prevented the
status command from running.

### Response

Confirmed that no installer action ran. Root-only staged artifacts are now
hashed and inspected with `sudo -n` before invoking their separately reviewed
read-only or mutating commands.

### Prevention

Match the privilege level of metadata verification to the protected artifact;
do not put an expected-to-fail unprivileged read before an authorized command
in an `&&` chain.

### Metadata

- Reproducible: yes; the staged file is root-owned mode 0400
- Related Files: `system/grok-proxy/install-release.py`

---

## [ERR-20260715-030] legacy-provider-descendant-escaped-before-first-artifact

**Logged**: 2026-07-15T05:20:00Z
**Priority**: critical
**Status**: resolved

### Summary

The legacy provider adapter protected and cancelled only its direct guarded
shell. A `setsid` descendant created before any PID file, listener, inventory,
or workspace artifact could survive supervisor death while offline recovery
incorrectly proved the generation empty.

### Response

Every legacy shell verb now starts behind a release barrier, records
`PREPARED`, `SCOPE_CREATED`, and `ATTACHED` cgroup-v2 authority in the central
recovery journal, and releases the barrier only after durable attachment.
Successful `provider-up` atomically promotes the same exact scope to provider
lifetime; all other commands reconcile synchronously. Cancellation, all three
durable phases, post-promotion failure, normal stop, and both command-role and
provider-role offline recovery are permanent real-cgroup regressions.

### Prevention

Do not infer descendant ownership from a parent-death signal, process group,
listener, PID file, or later inventory. Block executable effects until exact
durable process-scope authority exists, and retain that authority for every
daemonized backend until teardown proves the cgroup empty.

### Metadata

- Reproducible: yes; a TERM/HUP-ignoring `setsid` child produced a delayed effect after recovery returned clean
- Related Files: `system/grok-proxy/grok_ms/providers.py`,
  `system/grok-proxy/grok_ms/supervisor.py`,
  `system/grok-proxy/tests/test_grok_ms_providers.py`

---

## [ERR-20260715-031] parallel-recovery-journals-bound-only-subset-of-request

**Logged**: 2026-07-15T05:25:00Z
**Priority**: high
**Status**: resolved

### Summary

The main provider recovery record did not require its release ID to equal the
frozen request release, and the live verifier compared a retained provider
scope to the applied provider using only epoch, generation, rung, and
transition. A different release contract or private port could therefore be
accepted by one evidence path even though another recovery journal rejected
it.

### Response

Provider recovery construction and decoding now require exact release
equality. Offline recovery rejects mismatches before invoking an adapter. The
verifier binds the complete `ProviderRequest`, release, scope inode, process
membership, and record filename, while installer/client quiescence inventories
include the new provider-scope journal.

### Prevention

When two durable records describe one effect, compare their complete canonical
authority objects at every reader. Do not duplicate a hand-selected subset of
identity fields in recovery, verification, switching, or cleanup gates.

### Metadata

- Reproducible: yes; both cross-release recovery and cross-port verifier counterexamples were accepted before the fix
- Related Files: `system/grok-proxy/grok_ms/supervisor.py`,
  `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/install-release.py`

---

## [ERR-20260715-032] one-off-watchdog-test-connection-reset

**Logged**: 2026-07-15T05:30:00Z
**Priority**: low
**Status**: resolved

### Summary

One complete-suite run saw the watchdog ladder-exhaustion test lose its control
connection during initial registration. The isolated test and two complete
supervisor-suite runs passed without a source change, and the final complete
repository gate passed uninterrupted.

### Response

Paused the broad gate, reran the exact failing test, reran all supervisor tests,
then required a new full repository run after all later changes. No functional
failure or residue reproduced.

### Prevention

Do not dismiss a timing-only failure immediately. Recheck the narrow case, its
containing suite, and a final uninterrupted broad gate before classifying it as
a transient host-load event.

### Metadata

- Reproducible: no; one occurrence followed by repeated passes
- Related Files: `system/grok-proxy/tests/test_grok_ms_supervisor.py`

---

## [ERR-20260715-034] shebang-holder-proc-read-raced-second-exec

**Logged**: 2026-07-15T18:35:00Z
**Priority**: low
**Status**: resolved

### Summary

The first real-`/proc` argv regression used an `env` shebang holder. `Popen`
returned after the interpreter handoff began, and the immediate cmdline read
observed the transient empty record during the second exec.

### Response

Replaced the two-stage shebang holder with an explicit Python interpreter
process, keeping the real `/proc` and empty-argument coverage without the
interpreter-resolution race.

### Prevention

For immediate `/proc/<pid>/cmdline` assertions, launch the final interpreter
directly or wait for an exact stable identity before sampling a shebang chain.

### Metadata

- Reproducible: timing-sensitive
- Related Files: `system/grok-proxy/tests/test_vpn_broker.py`

---

## [ERR-20260716-035] preserved-directory-metadata-copied-before-children

**Logged**: 2026-07-16T09:55:50Z
**Priority**: low
**Status**: resolved

### Summary

The first real authoritative Grok capture preserved repository-local
`.planning` and `.learnings` contents but changed their directory mtimes.
`copy_real_tree` applied `copystat` before recursively creating children, so
those child writes immediately invalidated the copied directory metadata.

### Response

Move directory `copystat` after the recursive child copy and cover preserved
file and directory metadata in the authoritative-capture regression.

### Prevention

When cloning a directory tree with metadata fidelity, copy children first and
apply directory metadata last. Verify file and directory modes/timestamps, not
only bytes, when a path is described as preserved.

### Metadata

- Reproducible: yes; detected by the first live Grok-only authoritative apply
- Related Files: `bin/lib/manifest_sync.py`,
  `system/grok-proxy/tests/test_source_backup_pipeline.py`

---

## [ERR-20260716-036] authoritative-capture-inherited-group-writable-umask

**Logged**: 2026-07-16T10:00:32Z
**Priority**: high
**Status**: resolved

### Summary

Authoritative capture wrote public text with the process umask and then ORed
execute bits, turning safe executable fixtures into mode `0775`. The complete
installed-feature suite correctly rejected the group-writable fake OpenVPN
prerequisite before creating an install fence; the following `resume` therefore
also failed with no interrupted operation.

### Response

Normalize every authoritative public output to `0755` when the source is
executable and `0644` otherwise, for both text and binary paths. Add exact mode
assertions to the source/backup regression and rerun the two failed end-to-end
tests before resuming the broad suite.

### Prevention

Security-sensitive snapshots must assign an explicit final mode instead of
deriving it from `open()` defaults plus the ambient umask. When one test failure
is a downstream recovery error, inspect the first operation's stderr before
debugging the recovery path independently.

### Metadata

- Reproducible: yes; both feature-on failures shared the same unsafe fixture mode
- Related Files: `bin/lib/manifest_sync.py`,
  `system/grok-proxy/tests/test_source_backup_pipeline.py`,
  `system/grok-proxy/tests/test_multi_feature_e2e.py`

---

## [ERR-20260716-037] release-plan-rejects-explicit-dry-run-flag

**Logged**: 2026-07-16T10:09:02Z
**Priority**: low
**Status**: resolved

### Summary

The live release preflight initially invoked `plan --dry-run`. The CLI rejects
all action flags for `plan` because that subcommand is inherently read-only.

### Response

Reran the same command without `--dry-run`; it returned the expected immutable
release plan and no state changed before the subsequent explicit install.

### Prevention

Use `install-release.py plan --source ... --home ...` without an action flag.
Reserve `--apply`/`--dry-run` for subcommands whose parser accepts an action.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/install-release.py`, `docs/INSTALL.md`

---

## [ERR-20260716-038] scoped-capture-overwrote-global-symlink-observation

**Logged**: 2026-07-16T10:11:33Z
**Priority**: medium
**Status**: resolved

### Summary

A Grok-only custom-manifest apply correctly updated the Grok snapshot but also
replaced the repository's global `.staging-symlinks-observed.tsv` with an empty
partial view. The final worktree audit caught the unrelated 126-line deletion.

### Response

Restored the exact pre-task global report. Custom-manifest applies now write
their partial observation under `.staging/symlinks-observed.tsv`; only the
default repository manifest may update the global tracked observation. Added a
regression proving scoped apply leaves the global report unchanged.

### Prevention

Diagnostic outputs that summarize global state must be scoped to the same input
universe as the operation. A filtered manifest must never publish its partial
inventory at a global path.

### Metadata

- Reproducible: yes
- Related Files: `bin/lib/manifest_sync.py`,
  `system/grok-proxy/tests/test_source_backup_pipeline.py`,
  `.staging-symlinks-observed.tsv`

---

## [ERR-20260716-039] preserved-repository-notes-blocked-leak-scan

**Logged**: 2026-07-16T10:13:32Z
**Priority**: medium
**Status**: resolved

### Summary

The full leak scan found three literal home paths in repository-local Grok
learning notes. Authoritative capture correctly preserved those notes rather
than importing them from the authoring tree, but the preserved content still
belongs to the public worktree and blocked backup publication.

### Response

Replaced only the three host-specific prefixes with `~` forms and reran the
full leak scan. Runtime source, private state, and capture ownership were
unchanged.

### Prevention

Preserved repository-local paths are outside source mirroring, not outside leak
scanning. Include preserve trees in the final public leak gate and keep their
diagnostic paths topology-generic.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/.learnings/ERRORS.md`, `bin/leak-scan.sh`

---

## [ERR-20260717-040] compatibility-grok-cache-inherited-cooperative-umask

**Logged**: 2026-07-17T04:43:40Z
**Priority**: high
**Status**: resolved

### Summary

A successful live compatibility invocation removed and let Grok recreate its
shared model cache under the operator shell's `umask 002`, producing mode
`0664`. The fixed multi-session real-pair verifier then failed its baseline
before transport because group-writable cache input is outside its trust
boundary.

### Response

Matched the verifier's error hash to its exact source literal, confirmed the
live file identity, added a red fake-Grok regression under `umask 002`, and made
the compatibility launch apply `umask 077` before Grok recreates the cache.

### Prevention

When one lane creates mutable state later consumed by a stricter lane, set an
explicit creation mask at the producer boundary and test the resulting mode;
do not rely on the interactive shell's ambient umask or repair one file ad hoc.

### Metadata

- Reproducible: yes; two real-pair attempts returned the same baseline error hash
- Related Files: `system/grok-proxy/grok-remote`,
  `system/grok-proxy/tests/test_proxy_env.sh`,
  `system/grok-proxy/grok_ms/qualification_verifier.py`

---

## [ERR-20260720-046] installed-admin-counted-as-release-residue

**Logged**: 2026-07-20T04:20:00Z
**Priority**: high
**Status**: resolved

### Summary

The first live `begin-release-qualification` on a newly installed release
failed because the release-bound process inventory counted the documented
Python installer process and its immediate `sudo` monitor as stale consumers.

### Response

Add an installed-lane-only exemption for the exact epoch-bound administrative
pair. Bind the Python argv slot, complete child/parent argv relationship,
executable identity, and full UID/GID vectors; retain any additional bound
cwd, executable, argument, wrapper, or unrelated process as a blocker.

The focused regressions, complete isolated suite, and a live installed
`begin-release-qualification` using the exact `sudo` to `/usr/bin/python3 -I
-B` pair all passed after this correction.

### Prevention

Any quiescence scanner that examines command arguments must test the real
administrative invocation that calls it. Hermetic inventories must include the
scanner process and privilege wrapper, not only unrelated residue fixtures.

### Metadata

- Reproducible: yes; two live attempts returned only transient self/parent PIDs
- Related Files: `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/test_release_installer.py`

---

## [ERR-20260720-047] isolated-candidate-inherited-group-write-mode

**Logged**: 2026-07-20T04:52:54Z
**Priority**: medium
**Status**: resolved

### Summary

An isolated regression candidate extracted under the caller's `0002` umask
materialized Git executable entries as `0775`. The E2E prerequisite check
correctly rejected the group-writable OpenVPN fixture.

### Response

Extract normalized Git archives under an explicit `0022` umask and pass
`tar --no-same-permissions`; GNU tar otherwise preserves Git archive `0775`
entries despite the caller umask. Verify a representative executable is `0755`
before applying the reviewed working-tree patch.

### Prevention

Candidate construction must pin its extraction umask and verify a representative
executable is `0755` before launching the full isolated gate.

### Metadata

- Reproducible: yes; two partial ledgers failed at the same E2E prerequisite
- Related Files: `system/grok-proxy/tests/run-isolated.sh`

---

## [ERR-20260720-048] release-builder-required-precreated-output-root

**Logged**: 2026-07-20T09:10:00Z
**Priority**: low
**Status**: resolved

### Summary

The first read-only-to-output release build attempt failed because the builder
requires both source and output roots to exist, while its short usage guidance
did not state that precondition.

### Response

Created a task-specific temporary directory with the required output child,
then reran the same deterministic build. No release selector or production
state changed on the failed attempt.

### Prevention

Inspect the builder implementation as well as its usage text, create and
validate task-specific source/output roots before invocation, and retain the
explicit `umask 0022` archive rule.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/bootstrap/build_bundle.py`

---

## [ERR-20260720-049] guessed-helper-and-test-selectors

**Logged**: 2026-07-20T10:05:00Z
**Priority**: low
**Status**: resolved

### Summary

Two nonmutating commands guessed a helper path and a unittest method name that
do not exist in this repository.

### Response

Located the exact entrypoints with `rg --files` and method definitions with
`rg`, then reran the intended checks successfully. No source or runtime state
was changed by either failed selector.

### Prevention

Resolve helper paths and test selectors from the current tree before invoking
them; do not infer either from a related module name or nearby test wording.

### Metadata

- Reproducible: yes
- Related Files: `bin/sync.sh`, `bin/lib/manifest_sync.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260720-050] e2e-echo-wait-used-absolute-count

**Logged**: 2026-07-20T10:24:00Z
**Priority**: medium
**Status**: resolved

### Summary

The isolated full gate exposed a timing race in the installed two-wrapper E2E
fixture: its wait loop stopped at an absolute two accepted echo connections,
while earlier release canaries had already contributed four connections.

### Error

    AssertionError: 5 not greater than or equal to 6

### Response

Changed only the wait predicate to use the same relative threshold as the
assertion, `canary_accepts + 2`. The failed partial ledger was retained as the
seen-to-fail proof before rerunning the isolated gate.

### Prevention

When one long E2E fixture reuses a cumulative counter across phases, every wait
and assertion must be relative to the phase baseline; never mix an absolute
readiness threshold with a delta assertion.

### Metadata

- Reproducible: timing-dependent; observed in the mandatory isolated gate
- Related Files: `system/grok-proxy/tests/test_multi_feature_e2e.py`

---

## [ERR-20260720-051] changed-egress-missed-self-admission-bundle

**Logged**: 2026-07-20T10:42:00Z
**Priority**: high
**Status**: resolved

### Summary

The first isolated run after the country-policy edit reached the production
self-admission test and correctly rejected the changed `egress.sh` bytes
because the reviewed three-file bundle had not been extended.

### Response

Computed the exact current `grok-remote`, `egress.sh`, and
`grok_ms/release_admission.py` hashes, appended them as one inseparable bundle,
and retained prior tuples for rollback without admitting component hybrids.

### Prevention

Treat any byte change to a direct-admission path as a required bundle update;
run the exact production-contract test before the full isolated gate.

### Metadata

- Reproducible: yes; fail-closed in the mandatory isolated suite
- Related Files: `system/grok-proxy/egress.sh`,
  `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/test_release_installer.py`

---

## [ERR-20260720-052] candidate-patch-escaped-normalizing-umask

**Logged**: 2026-07-20T11:20:00Z
**Priority**: medium
**Status**: resolved

### Summary

The first replacement candidate extracted its Git archive under `umask 0022`
but applied the working-tree patch after leaving that subshell.  Modified files
therefore inherited the interactive `0002` umask and became `0664` or `0775`.

### Response

Discarded that candidate before verification, rebuilt from a fresh temporary
root with one `umask 0022` scope around both archive extraction and `git apply`,
and required a whole-tree check proving that no regular file was group- or
world-writable.

### Prevention

The normalized-candidate recipe must keep every file-creating step inside the
same restrictive umask, including patch application.  Verify representative
`0755` and `0644` paths plus a whole-tree writable-file scan before launching
the isolated gate.

### Metadata

- Reproducible: yes
- Related Files: `system/grok-proxy/tests/run-isolated.sh`

---

## [ERR-20260720-053] source-reconcile-must-preserve-excluded-descendants

**Logged**: 2026-07-20T12:05:00Z
**Priority**: high
**Status**: resolved

### Summary

The first dry-run-only authoring reconciliation helper proposed exchanging
whole manifest match roots.  Review caught that doing so would remove generated
or excluded descendants nested inside managed directories, and that its custom
transaction marker had no supported crash rollback path.  No real source file
was changed by that version.

### Response

Replaced the helper before apply with a forward-resumable per-managed-file
transaction: complete classification first, copied single-link byte backups,
a mode-0700 inode-bound transaction journal, the renderer's genuine restore
marker, no-replace quarantine, pinned manifest/renderer bytes, and an exact
private/generated identity fingerprint.  Publication writes a private pending
inode, fsyncs it, and uses `linkat(AT_EMPTY_PATH)` from the still-open descriptor
so a pathname substitution cannot publish an unsynced replacement.

Fresh review caught and fake tests reproduced four additional pre-apply crash
or resume defects: torn final backup/READY writes, rejection of the valid
`target=new` resume state, reuse of an exact-but-not-proven-durable pending
inode, and a post-fsync pathname swap.  Each was fixed and re-reviewed before
the one real apply.  Normal apply, pre-marker failure, post-quarantine failure,
first-restore publication, repeated-fsync failure, and pathname-substitution
fixtures converged or failed closed.  The real canonical tree then matched all
82 expected public files, the compatible marker was absent, and the unmanaged
fingerprint and worktree binary diff were unchanged.

The fixture also caught that `Path("/proc/self/fd/N")` is itself a symlink for a
root scan and cannot be reopened with `O_NOFOLLOW`.  Root scans now use the
reviewed `/proc/self/fd/N/.` form, while root-directory fsync duplicates the
already pinned descriptor.

### Prevention

Never replace a manifest match directory when exclusions may live below it.
For reverse authoring reconciliation, mutate only classified managed files,
make every pre-marker record atomically publishable and forward-resumable,
bind publication to the fsynced inode rather than its pathname, and do not
touch the real tree until fault injection and fresh-context review both pass.

### Metadata

- Reproducible: yes; caught before real `--apply`
- Related Files: `MANIFEST.yaml`, `bin/lib/render_install.py`,
  `bin/lib/manifest_sync.py`

---

## [ERR-20260720-054] linked-worktree-control-file-tripped-leak-scan

**Logged**: 2026-07-20T14:20:00Z
**Priority**: low
**Status**: resolved

### Summary

Running the repository leak scanner directly in a Git linked worktree reported
the worktree's `.git` control file because it contains the absolute path of the
primary repository.  That control file is Git metadata, not a tracked or
publishable artifact.

### Response

Kept the scanner policy unchanged and reran the same scanner on the normalized
`git archive` plus reviewed binary patch candidate.  The actual 1,694-file
publishable tree passed cleanly.

### Prevention

For release evidence from a linked worktree, scan the normalized publishable
candidate.  Treat a `.git` control-file-only finding as worktree plumbing, but
never suppress findings from tracked files or weaken the repository scanner.

### Metadata

- Reproducible: yes
- Related Files: `bin/leak-scan.sh`

---

## [ERR-20260720-055] direct-real-pair-expected-provider-readiness

**Logged**: 2026-07-20T08:55:00Z
**Priority**: high
**Status**: resolved

### Summary

The first production `direct` rung real-pair canary reached two live leases but
failed closed at `real-pair-authority`.  The verifier required a
`provider_canary_nonce` field in `supervisor.ready` for every rung, while the
client intentionally closes a direct-rung canary capability before supervisor
bootstrap and publishes that field only for provider-backed rungs.

### Response

Made the verifier derive readiness nonce expectations from the same rung
boundary as the client: `direct` expects the base exact schema, and every
provider-backed rung expects the authenticated nonce.  Added regression
coverage for both sides and kept the exact-schema rejection intact.

### Prevention

Whenever an authenticated capability is consumed at different lifecycle
boundaries by different route classes, test every durable schema consumer for
both capability-present and intentionally capability-absent cases.

### Metadata

- Reproducible: yes; production gate failed closed before promotion
- Related Files: `system/grok-proxy/grok_ms/client.py`,
  `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260720-056] first-direct-rung-cleanup-required-a-promoted-rung

**Logged**: 2026-07-20T09:35:00Z
**Priority**: high
**Status**: resolved

### Summary

The first profile-bound direct real-pair reached its authenticated repair and
two-session completion path, but cleanup recovery was allowed to suppress
compatibility routing only for the older fixed-release canary shape. With the
new policy intentionally invalidating all prior rung evidence, compatibility
had no promoted rung and the otherwise valid canary failed closed at cleanup.

### Response

Extended strict direct recovery to exact FD-authenticated direct rung canaries
(`direct` and direct-capable `auto`) while retaining the fixed-release path.
The recovery implementation still forbids compatibility handoff and rejects
every non-direct provider record. Added seen-to-fail client and verifier
regressions plus negative non-direct and malformed cases.

### Prevention

When a workflow invalidates all prior authorization evidence, test the first
new authorization from a genuinely empty catalog. Bootstrap cleanup must not
depend on the permission that the same workflow is trying to create.

### Metadata

- Reproducible: yes; the new focused regressions failed before the correction
- Related Files: `system/grok-proxy/grok_ms/client.py`,
  `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/tests/test_grok_ms_client.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`

---

## [ERR-20260720-057] guessed-supervisor-test-class-name

**Logged**: 2026-07-20T09:45:00Z
**Priority**: low
**Status**: resolved

### Summary

A focused unittest command guessed `SupervisorTests` instead of inspecting the
module's actual `SupervisorRecoveryTests` declaration. The loader failed before
running any test.

### Response

Read the class declarations with `rg`, reran the same three exact test methods
under `SupervisorRecoveryTests`, and obtained three passes.

### Prevention

Resolve unittest class and method selectors from source before composing a
fully qualified focused command.

### Metadata

- Reproducible: yes; loader-only failure, no runtime or deployment mutation
- Related Files: `system/grok-proxy/tests/test_grok_ms_supervisor.py`

---

## [ERR-20260720-058] scheduled-install-lacked-delegated-cgroup-context

**Logged**: 2026-07-20T10:20:00Z
**Priority**: high
**Status**: resolved

### Summary

The weekly `install-degraded` job reached the signed Grok bootstrap but failed
the fresh release install. The normal push lane stayed green because the heavy
install job runs only for schedules and manual dispatches. The live-layout
installer requires a target-owned delegated cgroup-v2 ancestor for its bounded
smoke runners, while the workflow launched `bin/install.sh` directly from the
hosted runner service.

### Response

The first attempted correction moved the installer into a transient user
service, but the hosted run failed identically. Reinspection proved that unit
had no direct `user.delegate` marker; the local predicate had silently selected
the host's already-delegated `user@UID.service` fallback. The replacement uses
a target-UID system-manager service with `Delegate=yes`, a fixed `installer`
subgroup, and bounded CPU/memory/PID resources. A fixed-purpose launcher enables
only those three controllers, closes the environment, and rejects the run
unless the production predicate selects the transient service's exact direct
parent. The existing pipeline ledger still preserves the child exit.

The exact hosted rerun proved this direct-parent preflight passed. The same
178-byte phase-6 fingerprint then recurred before any runner scope was created,
so this was a necessary production-precondition correction but not the cause
of that fingerprint; see ERR-20260720-064.

### Prevention

Exercise schedule/manual-only jobs after changing production-only installer
preconditions. A cgroup probe must assert the selected parent identity, not
only that *some* ancestor passes. Keep static workflow coverage for the system
manager, target identity, delegated subgroup, finite limits, four-value
environment allowlist, exact-parent preflight, and exit ledger. Do not infer
that a passed cgroup preflight explains an earlier opaque child error.

### Metadata

- Reproducible: scheduled-only on the fresh GitHub runner; exact corrected
  service preflight reproduced locally
- Related Files: `.github/workflows/rehearsal.yml`,
  `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/ci_delegated_install.py`,
  `system/grok-proxy/tests/test_bootstrap.py`,
  `system/grok-proxy/tests/test_ci_delegated_install.py`

---

## [ERR-20260720-059] e2e-openvpn-fixture-depended-on-checkout-mode

**Logged**: 2026-07-20T15:05:00Z
**Priority**: medium
**Status**: resolved

### Summary

The full clean-candidate gate failed two installed-feature E2E tests because
they reused the repository's fake `curl` executable as the test OpenVPN
prerequisite. A group-writable candidate checkout correctly failed the
installer's owner-only prerequisite policy, even though the same tests passed
from a checkout whose executable modes happened to be stricter.

### Response

Kept production prerequisite validation unchanged. Each E2E test now creates a
dedicated owner-only fake OpenVPN executable and passes it explicitly to every
install command and in-process test layout.

### Prevention

Security-sensitive executable fixtures must declare their own mode and owner
inside the test's private directory. Do not reuse an unrelated tracked helper
whose effective checkout permissions vary across runners or shared clones.

### Metadata

- Reproducible: yes; the normalized group-writable candidate failed both E2E
  tests before this correction
- Related Files: `system/grok-proxy/tests/test_multi_feature_e2e.py`

---

## [ERR-20260720-060] delegated-launcher-probe-executed-real-installer

**Logged**: 2026-07-20T11:01:51Z
**Priority**: high
**Status**: resolved

### Summary

An integration probe for the replacement system-manager launcher invoked the
fixed-purpose helper without substituting a harmless terminal command. The
helper passed its cgroup preflight and therefore executed the real degraded
`bin/install.sh` on the production host.

### Response

No signal, stop, or kill was sent. The transient unit exited naturally with
`Result=success`. Read-only reconciliation found no repository changes and no
change to the Grok bootstrap selector, active user/root release selectors,
canary/deny records, or their pre-incident timestamps. The install may have
idempotently rendered or verified non-Grok assets; those cannot be proven
unchanged without a before-snapshot. Subsequent helper tests mock `execve` or
use filesystem fixtures instead of launching an integration command.

### Prevention

Never live-probe a fixed-purpose exec helper until its terminal action is
injectable and replaced with an inert identity/exit stub, or the entire target
filesystem is disposable. Confirm the captured execution handle before a
long-running command yields. Treat a successful preflight as authority to run
the terminal action, not as a dry run.

### Metadata

- Reproducible: yes; caused by the explicit local probe
- Related Files: `system/grok-proxy/tests/ci_delegated_install.py`,
  `.github/workflows/rehearsal.yml`

---

## [ERR-20260720-061] combined-unittest-file-and-module-selectors

**Logged**: 2026-07-20T11:04:00Z
**Priority**: low
**Status**: resolved

### Summary

A focused command passed both the test file and an unqualified class selector
to `python -m unittest`. The file's 31 tests passed, then unittest treated the
class token as a second top-level module and returned a loader error.

### Response

Reran the inspected test file as its sole selector; all 31 tests passed. The
failure was command composition only and did not exercise a product failure.

### Prevention

Use exactly one selector style per unittest command: either a file path for the
whole module, or one fully qualified dotted test name. Never append a class or
method token after a file selector.

### Metadata

- Reproducible: yes; loader-only failure after the real tests passed
- Related Files: `system/grok-proxy/tests/test_bootstrap.py`

---

## [ERR-20260720-062] ledger-list-subcommand-required-kind

**Logged**: 2026-07-20T11:15:00Z
**Priority**: low
**Status**: resolved

### Summary

After reading only the verification ledger's top-level help, a check invoked
`list` without its required `--kind` option. The ledger self-test passed, but
the chained command stopped before the focused tests.

### Response

Reran `list --kind unittest`, confirmed the new launcher case was present, and
then ran the focused launcher and bootstrap suites successfully.

### Prevention

For CLIs with subcommands, inspect the selected subcommand's help before
composing it, even when top-level help has already been read.

### Metadata

- Reproducible: yes; argument-validation failure only
- Related Files: `system/grok-proxy/tests/verification_ledger.py`

---

## [ERR-20260720-063] isolated-launcher-has-no-help-mode

**Logged**: 2026-07-20T11:42:19Z
**Priority**: low
**Status**: resolved

### Summary

A documentation check invoked `run-isolated.sh --help`, but this fixed-purpose
launcher accepts only its explicit launch protocol and rejected the unknown
mode before doing any substantive work.

### Response

Inspected the launcher source and retained the repository-required `--launch`
invocation for the normalized full gate. No test, installer, signal, or host
mutation occurred during the rejected help call.

### Prevention

Inspect this fixed-purpose launcher's source-defined dispatch before invoking
it; do not assume conventional `--help` support when no help contract is
documented.

### Metadata

- Reproducible: yes; mode-validation failure only
- Related Files: `system/grok-proxy/tests/run-isolated.sh`

---

## [ERR-20260720-064] degraded-fixture-omitted-package-operation-lock

**Logged**: 2026-07-20T12:20:00Z
**Priority**: high
**Status**: testing

### Summary

The ephemeral signed-bootstrap fixture installed the native verifier, signed
application, selector, and bootstrap update lock, but did not mirror the
production package activator's distinct release-control state anchors. The
live installer intentionally refuses to create or repair the stable
`/var/lib/grok-proxy/release-control/operation.lock` inode.

### Response

The exact current error line, including its newline, is 178 bytes with SHA-256
`e4c82359b8159fa41c7ceac62679311a68b6120e508e46ddaf36e9cb1ddf6fdc`,
matching the hosted artifact byte for byte. The workflow now first proves the
entire disposable state root is absent, then mirrors the package-owned
root:root state: mode-0755 release control, an empty single-link mode-0600
operation lock, and a mode-0700 runner-scope journal. Its preflight validates
those identities before invoking the installer. The hosted VM is disposable,
so the workflow performs no recursive deletion of those fixed root paths; the
private signing key remains covered by its separate temporary-directory trap.

### Prevention

A production bootstrap rehearsal must reproduce both executable trust
artifacts and package-owned persistent lock/journal anchors. Never weaken the
installer to auto-create a missing production lock, and never replace or
truncate an existing lock inode. Keep the hosted gate in testing until the
exact manual full-install job passes.

### Metadata

- Reproducible: yes; exact error bytes and digest matched the hosted artifact
- Related Files: `.github/workflows/rehearsal.yml`,
  `system/grok-proxy/bootstrap/activate_package.py`,
  `system/grok-proxy/tests/test_bootstrap.py`,
  `system/grok-proxy/tests/test_release_installer.py`

---

## [ERR-20260720-065] verification-overlay-copied-worktree-git-pointer

**Logged**: 2026-07-20T12:28:00Z
**Priority**: low
**Status**: resolved

### Summary

The first clean-candidate overlay excluded `.git/` as a directory only. The
source was a linked worktree whose `.git` is a regular pointer file, so rsync
copied that pointer over the disposable clone's ordinary `.git` directory and
the leak gate correctly rejected its absolute home path.

### Response

No product test ran or failed. Recreate the disposable clone and exclude the
name `.git` regardless of file type before rerunning the unchanged gate.

### Prevention

When normalizing from a possible linked worktree, use an exclusion that matches
both `.git` files and `.git` directories, then assert the candidate `.git` is a
directory before verification.

### Metadata

- Reproducible: yes; verification-fixture construction only
- Related Files: `.git`, `Makefile`

---

## [ERR-20260720-066] cleanup-marker-did-not-bind-created-root-inodes

**Logged**: 2026-07-20T12:42:00Z
**Priority**: high
**Status**: resolved

### Summary

An attempted guard for the workflow's unconditional root cleanup proved that
the job intended to create a fixture, but did not bind later deletion to the
exact directory inodes created by that run. A privileged race, root swap, or
nested mount could therefore make pathname-based recursive cleanup exceed its
ownership proof.

### Response

Removed the recursive fixed-root cleanup entirely. GitHub-hosted runners are
discarded after the job, the fixed fixture contains no private signing key,
and the key's private temporary directory already has its own scoped trap.
Static coverage now rejects reintroduction of the root cleanup step and its
`rm -rf` command.

### Prevention

An intent marker is not an inode authority. Destructive cleanup must either
retain descriptor-bound identity for every target and reject nested mounts, or
be omitted when disposable infrastructure makes deletion unnecessary.

### Metadata

- Reproducible: review finding; no destructive local command was run
- Related Files: `.github/workflows/rehearsal.yml`,
  `system/grok-proxy/tests/test_bootstrap.py`, `docs/CI.md`

---

## [ERR-20260720-067] real-pair-cleanup-misreported-natural-exit

**Logged**: 2026-07-20T13:15:00Z
**Priority**: high
**Status**: testing

### Summary

The live direct real-pair qualification completed its authenticated provider
fault and repair, then reported `real-pair-cleanup-after-primary` even though
the final host inventory was empty. Besides the already-covered status/pidfd
exit races, a guarded session could begin draining before the verifier renewed
its exact two-lease destructive authority, causing cleanup to return before its
passive clean proof. Wrapper TERM/KILL wait errors could likewise remain stale
after a later wait proved the exact child exited. The combined failure code also
discarded the closed primary checkpoint needed to diagnose the live failure.

### Response

Retain exact destructive recovery at its existing liveness boundaries. When
authority renewal instead observes the same epoch draining, close the failed
qualification pause, retain the captured epoch only for validation, and permit
nonmutating passive convergence: exact wrapper stop, same/absent-fence checks,
the exhaustive clean checkpoint, and a separate bounded absence proof for the
captured supervisor. Reject replacement or malformed fences without supervisor
signaling or recovery. Defer wrapper signal/wait diagnostics and suppress them
only after `Popen` proves exit. Publish a finite stage-specific
`real-pair-cleanup-after-*` code while continuing to hash all dynamic detail.

### Prevention

Process-exit races are convergence only when identity, ownership, and terminal
state are all independently proved. Cover same, missing, replacement, and
malformed fences; a still-live versus delayed-exit captured supervisor; wrapper
TERM/KILL signal and wait ordering; every granular primary/cleanup code mapping;
pause-close-before-passive-cleanup; and the generated selected-gate exact-fence
recovery composition. Do not promote or push until the patched signed release
passes a real-pair canary and two simultaneous real sessions locally.

### Metadata

- Reproducible: yes; live qualification plus deterministic regressions
- Related Files: `system/grok-proxy/grok_ms/qualification_verifier.py`,
  `system/grok-proxy/install-release.py`,
  `system/grok-proxy/tests/test_live_multi_verify.py`,
  `system/grok-proxy/tests/test_release_installer.py`

---
