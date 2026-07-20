# Specification — Grok Remote Same-Contract Multi-Session v1

## Goal

Allow multiple simultaneous `grok-remote` processes to share one qualified
egress when, and only when, they use the same concrete model and canonical
routing contract. Preserve the existing feature-off command behavior while
adding crash-safe exclusion, bounded routing, deterministic recovery, atomic
deployment, and fail-closed live transitions.

The normative design is the reviewed 2026-07-13 consolidated plan at:

`~/.local/share/ai-agents-skills/runs/agent_group_discuss/grok-multisession-adversarial-review-20260713-01/final/revised_plan.md`

## Scope

### In scope

- Managed-default dispatch: bare `grok-remote` uses the current
  installer-attested profile, `GROK_MULTI_SESSION=0` selects the supported
  compatibility escape, and exact `GROK_MULTI_SESSION=1` remains a
  qualification/migration input when no current activation exists. Any other
  present value retains literal legacy compatibility behavior and never causes
  managed activation or managed boot-state inspection.
- One per-user supervisor, one public SOCKS endpoint, one watchdog/transition
  writer, and multiple same-contract leases.
- Concrete model pinning and typed canonical contract comparison before route
  mutation.
- Private direct, home SSH, iPhone-sidecar, and VPN backends.
- Linux `SOCK_SEQPACKET` control IPC with peer credentials and bounded messages.
- Grok child pre-exec ownership barrier, two exact execution units, signal/TTY/exit
  propagation, and fail-closed supervisor-loss behavior. Optional Grok leader
  mode must either publish one exact socket per unit or be proved disabled for
  both independently owned Grok children.
- Durable compatibility fence, exact cleanup, idempotent recovery, and
  feature-off rollback.
- Fixed root-owned VPN broker and release-specific root helpers.
- Immutable user/root releases and an atomic user-visible selector.
- One-way source ownership: `~/grok-proxy` is the editable/capture authority,
  `system/grok-proxy` is its sanitized public backup, and only a root-owned
  immutable release may execute in production.
- Deterministic fault/load/security tests and bounded real two-session canaries.

### Out of scope

- Concurrent different concrete models or different routing contracts.
- Multiple VPN namespaces, multiple phone identities, or pooled cross-contract
  physical backends.
- Re-adopting a Grok process after supervisor failure.
- Protection from a deliberately malicious process already running as the same
  Unix user, or from a user who deliberately restores an archived pre-interlock
  executable.
- Isolation from another local UID that can connect to loopback TCP. The v1
  public SOCKS endpoint is not a cross-user authentication boundary.
- Thirty-two paid live Grok sessions; the 32-client gate is deterministic
  control/data-plane load, supplemented by two live Grok sessions per rung.

## Assumptions

- Linux provides Unix `SOCK_SEQPACKET`, `SO_PEERCRED`, `/proc` start identities,
  `flock`, writable delegated cgroup v2, Python 3.12+, OpenSSH, Tailscale,
  OpenVPN, `ip`, `ss`, and `sudo`. Feature-on fails closed when cgroup-v2
  descendant containment is unavailable; it has no process-group fallback.
- The scheduled/manual degraded-install rehearsal must place the installer in
  the fixed `installer` subgroup of a bounded system-manager transient service
  delegated to the target UID. Its preflight may enable only `cpu`, `memory`,
  and `pids`, and must prove the production runner-parent predicate selects the
  transient service's exact direct parent. An ambient user-manager fallback is
  not valid rehearsal evidence. CI output is byte-capped and an overflow fails
  the job. The transient resource envelope is not a sandbox for privileged
  systemd units deliberately started by the installer; structured post-install
  state gates remain the evidence for those effects.
- iPhone and home-PC peers are already enrolled/configured; setup remains an
  explicit maintenance operation.
- Provider availability is external. An unavailable provider blocks its live
  canary rather than weakening the gate.
- The public endpoint remains loopback-only. The supported deployment is a
  single-tenant host: every local UID able to connect to loopback is trusted,
  and one cooperative Unix account owns the supervisor and Grok sessions.
- Fixed qualification state binds the exact generated user and broker gate
  digests. A changed installer that produces different gates cannot reuse prior
  load/fault qualification even when runtime bytes yield the same release ID.
  The live rollback exercise nevertheless freezes one installer byte sequence
  for reproducibility.
- Fixed `load32` and `fault-recovery` qualification run in one root-retained
  accounting cgroup. Cleanup kills that outer scope, reconciles the still-named
  user-owned durable runtime, publishes `RECOVERED`, revokes delegation, kills
  again, removes nested topology, publishes `CONTAINED`, and only then removes
  the parent and root journal. `DELEGATING` is durable before the first chown.
  Missing `DELEGATED`, `RUNNING`, or `RECOVERED` scopes fail closed; only a
  missing `PREPARED` or `CONTAINED` scope is self-finalizing. The authenticated
  fixed direct canary suppresses warm legacy handoff so strict recovery cannot
  inherit a compatibility effect.
- Diagnostic commands and route-specific `real-pair` qualification do not use
  the accounting parent: they are parent-death/session contained while their
  supervisor-owned durable cgroups remain named for ordinary recovery.

## Interfaces

- Managed default: `grok-remote [existing arguments]` when the selected release
  has a valid active profile; the immutable release payload makes the same
  decision even when invoked directly.
- Compatibility escape: `GROK_MULTI_SESSION=0 grok-remote [existing arguments]`.
- Qualification/migration compatibility input:
  `GROK_MULTI_SESSION=1 grok-remote [existing arguments]`.
- Recovery and read-only status: `grok-remote recover` and
  `grok-remote status` under a current managed activation.
- Emergency recovery: exact one-argument `recover` remains public for an
  absent or exact `0`/`1` mode so dead state can be reconciled during a durable
  install/rollback deny. A present nonliteral mode remains compatibility and
  receives neither managed recovery nor deny-bypass authority.
- Orphaned compatibility VPN recovery: only the authenticated signed-bootstrap
  package may retire a root ledger, while it owns the root operation lock, both
  stable user exclusion locks, and the historical singleton lock by exact
  inherited descriptors. The immutable candidate broker independently binds an
  exact dead `RECOVERING` fence to the selected release and target UID, and the
  ledger must be the canonical `compat-<uid>` generation-zero, port-1080,
  zero-contract compatibility owner. Cleanup identities come only from that
  root-owned ledger and the selected immutable helper manifest. Any live,
  mismatched, malformed, supervisor-owned, or incompletely cleaned state keeps
  both ledger and fence and fails closed. Public `grok-remote recover` remains
  root-nonmutating and can finish only after the signed bootstrap has committed
  root cleanup; there is no force option.
- Control socket: bounded JSON records over mode-`0600` Unix
  `SOCK_SEQPACKET` in a verified mode-`0700` runtime directory.
- Stable production state: the passwd account home at
  `~/.local/state/grok-proxy/control/`; caller `HOME` and `XDG_STATE_HOME`
  overrides cannot split the user and privileged interlocks. Isolated tests
  have an explicit feature-on-only seam.
- Authoring source: `~/grok-proxy`. Public allowlisted source is mirrored
  one-way into `system/grok-proxy`; private credentials/topology enter only the
  encrypted archive, and generated runtime state is excluded.
- Restore source: `system/grok-proxy` repopulates an absent public authoring
  tree without replacing private/generated files. A divergent existing public
  source fails closed instead of being silently overwritten.
- Execution source: root-owned content-addressed release trees. Root helper
  trees remain mode `0555`; exactly the selected user release is mode `0555`
  and every retained inactive user release is mode `0500`. Running
  `~/grok-proxy/grok-remote` or another unfrozen source copy directly is
  unsupported and must refuse production execution.
- Pre-import update authority: a separately packaged native verifier at
  `/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap`, compiled with the
  production Ed25519 public key. It accepts only a closed signed dispatcher
  beneath `/usr/local/libexec/grok-proxy/bootstrap-releases/<signed-app-id>`.
  The administrative package transaction owns the root-only trust-anchor
  update, signed application publication, and exact `selected-release` file;
  the native verifier itself requires the requested ID to equal that selector
  and rechecks its descriptor-bound identity at the final exec boundary. Native
  execution holds a shared lock on the inode-stable root-only
  `bootstrap/update.lock` file through `execve`; the administrative publisher
  holds the matching exclusive lock on that same inode through publication,
  selector rename, and fsync. Before changing the selector it also holds the
  package-preserved `release-control/operation.lock` in shared mode and blocks
  on any install/rollback deny, canary terminal, rung canary, or nonempty runner
  journal. Immutable application publication may finish while selection is
  blocked, preserving the originating dispatcher for recovery. Audited
  compare-and-swap reselection and rollback retain every older signed
  application. A singleton durable pending selector audit reconciles an
  unchanged old selector as aborted and an already-renamed, revalidated target
  as committed; every other state fails closed. Partial audit staging is safely
  discarded, and retained history is not scanned as an update admission
  condition. The publisher obtains the key ID and public key directly
  from the exact locked native binary's constant trust-anchor report and runs
  through a host-ABI freestanding static launcher that constructs a fixed
  isolated-Python prefix and exact environment before forwarding a bounded
  administrative argument vector. Neither lock file is ever replaced or
  truncated. The dynamically linked native verifier is admitted only through
  fixed setuid `sudo` secure execution (`AT_SECURE`) or as a child of an already
  environment-isolated activator/publisher process; direct already-root
  invocation with a hostile loader environment is unsupported.
  Production signed staging is an absolute root-owned path whose complete
  ancestry from `/` is opened without following symlinks and is never group- or
  other-writable. GNU Make is never invoked as root because its pre-recipe
  `MAKEFLAGS`, `MAKEFILES`, include, and evaluation processing cannot establish
  a privilege boundary. The package manager installs a closed three-file
  payload at `/usr/lib/grok-bootstrap-package` and a closed two-file activator at
  `/usr/libexec/grok-bootstrap-package`, verifies their root-owned non-writable
  ancestry and exact single-link file metadata as one authenticated five-file
  generation, then invokes the fixed zero-argument activator launcher directly.
  That host-ABI x86_64/AArch64 launcher has no interpreter, dynamic section,
  needed library, libc startup, or undefined symbol; its raw `_start` closes
  inherited descriptors and directly executes the fixed isolated-Python argv
  and newly constructed exact envp without reading or forwarding caller
  arguments. A failed or denied descriptor-range close exits `126` before
  Python. The activator descriptor-opens and snapshots its own fixed files
  and payload, fixes its umask and newly-created directory modes, takes update
  `LOCK_EX` then operation `LOCK_SH`, and activates validated support files
  before the native verifier. Its durable `package-update.pending` canonical
  JSON binds the trust anchor and every payload artifact mode, size, digest, and
  canonical generation ID; native execution and publisher work fail closed
  until only that byte-identical generation completes the native-last
  transaction and removes the marker. A different same-key generation cannot
  reconcile the marker. Existing key-ID or public-key changes are rejected:
  in-place rotation is unsupported until an explicit bounded multi-key/new-ID
  migration is implemented.
  Candidate source and ordinary release installation cannot replace them.
- Installer lanes: signed bootstrap applications may plan/install/rollback,
  recover release publication, and run the closed parameter-free one-time
  `recover-compatibility-ledger --apply` rescue. The rescue owns the
  package-preserved operation lock and both compatibility singleton locks,
  proves an exact dead `RECOVERING` fence, publishes only the signed
  candidate's immutable root release without selecting it, and invokes that
  candidate broker through inherited descriptor authorities. The candidate
  broker may use the old selected immutable helper bytes bound by the old
  ledger, but never executes the old broker implementation. It removes only
  exact root compatibility resources and deliberately leaves user state and
  the fence for the installed public `grok-remote recover` transaction. It
  treats the authenticated broker's successful cleanup result as the root
  commit point: target-user replacement of cooperative lock or fence pathnames
  afterward cannot convert committed cleanup into a reported failure. Public
  handoff has no destructive compatibility-ledger operation and therefore
  cannot exploit a replacement lock domain. It accepts no caller paths,
  release IDs, PIDs, resource identities, or force
  controls and is unavailable from the installed lane. One historical
  migration source shape is recognized narrowly: the user manifest must equal
  its full runtime identity, include direct admission, and lack the installed
  installer, while the root manifest must be exactly the four identity-bound
  helper files. Its existing root-owned mode-0555 gates are usable only inside
  the one-shot migration capability when both selection records, their
  cross-hash, manifest/evidence digests, helper map, selectors, and access
  policy bind those exact gate hashes. This shape is never target-eligible;
  every selectable target still requires the full root runtime closure,
  installed installer, direct admission, and current generated gates.
  Post-install qualification, promotion, profile
  activation, and read-only status run only from the concrete root-selected
  immutable release. Installed commands reject caller `--source`, `--home`, and
  `--prefix`; prefix tests use only their inherited descriptor-bound proc
  fixture. Bootstrap commands require the native verifier's root-owned sealed
  memfd authority; direct editable, user-release, or extracted Python is
  rejected before source discovery. No privileged lane imports or executes
  editable source.
- Root broker: fixed `/usr/local/libexec/grok-proxy/vpn-broker`, selecting only
  root-owned `/usr/local/libexec/grok-proxy/releases/<release-id>/` helpers.
- Atomic user releases: root-owned
  `~/.local/lib/grok-proxy/releases/<release-id>/` trees plus a renamed
  `current` selector and `~/.local/bin/grok-remote` convenience entrypoint.
  The selected tree is target-user-readable but never writable; inactive trees
  are root-only until the installer revalidates and atomically selects one.
- Promotion evidence: fixed root-owned
  `/var/lib/grok-proxy/release-control/evidence/<release-id>.json` records
  (rebased only by the prefix test layout). These records are durable,
  host-bound release evidence and deliberately do not attest the current boot
  or any external route. Final selection metadata binds the exact record digest
  and target helper map. A transient `CANARY` selection is executable only
  through the installer's inherited fixed authorization FD.
- Boot inventory: fixed root-owned
  `/var/lib/grok-proxy/release-control/boot-inventory/<release-id>.json`, bound
  to the host and current boot. Feature-off admission does not require it;
  feature-on admission and privileged broker mutation do. The installer
  `revalidate --apply` command re-runs complete quiescence inventory after a
  boot before feature-on can launch.
- Rung qualification: normal feature-on routing admits only exact
  `(rung, route profile, original RouteContract digest, Grok release identity,
  concrete model)` records listed in the selected release. Each record binds a
  fixed root-owned closed-schema evidence file under
  `rung-evidence/<release-id>/`. Missing, malformed, failed, deleted, or
  nonmatching evidence removes the rung; an empty ladder fails closed.
- Route profiles form a closed set: `direct`, `iphone`, `vpn`, `home:<label>`,
  `auto`, and `auto-no-direct`. A forced profile must name its exact rung. AUTO
  profiles bind the digest of the full original ladder; each canary filters the
  runtime ladder to its authorized rung while retaining all frozen inputs, so
  the supervisor can reconstruct and re-check the original digest. Multiple
  promoted AUTO rungs may therefore share one original contract digest.
- Controlled qualification has two fences. First,
  `begin-release-qualification --release-id ID --apply` is followed by the
  installer-owned fixed `load32` and `fault-recovery` steps. Then
  `begin-rung-canary --release-id ID --rung RUNG --profile-sha256 DIGEST
  --apply` derives the route, full contract, projected contract, Grok, and model
  bindings from one exact private profile and authorizes one fixed `real-pair`
  step. The explicit binding form remains only for controlled legacy
  qualification. `promote-rung --apply` derives evidence only from those
  root-owned results; external evidence is rejected. Free-form
  `canary-exec --canary-arg ...` runs are diagnostic transcripts and never
  qualify promotion. `abort --apply` cancels either fence.
- The durable deny remains active throughout rung qualification. A VPN canary
  begins only after an exclusive selection-lock recheck, so every command
  admitted under the prior READY state has released its shared lock before the
  canary deny is published. A VPN canary
  may cross it only for broker `up`/`next` in supervisor mode, and only when
  both the generated root gate and immutable broker independently validate the
  root-owned rung-canary record against the current host, READY release, VPN
  rung, route profile, and exact request contract digest. Cleanup operations
  remain deny-safe; compatibility, install/rollback, reset, and mismatched
  requests remain fenced.
- An FD-authenticated direct rung canary may use strict direct recovery for its
  own exact dead epoch. This recovery forbids compatibility handoff and any
  non-direct provider record, so a fresh profile can qualify its first direct
  rung without depending on already-promoted rung evidence.
- A rung canary's authenticated provider-fault marker is one-use evidence.
  Any exact marker, including a `PREPARED` or malformed record, blocks another
  `real-pair` launch before intent publication; the operator must abort and
  begin a fresh canary instead of replaying a destructive fault nonce.
- The broker CLI disables long-option abbreviation and rejects every duplicate
  option. The generated gate accepts the VPN exception only after parsing a
  closed set of exact full option names, so both privileged boundaries agree
  on the request being authorized.
- Real-pair qualification adds one transient supervisor-owned admission fence.
  The authenticated verifier binds the fence to the exact two registered
  wrapper/lease/child tuples, then freezes their complete lease cgroups before
  the provider fault. Registration is closed while the fence exists. After
  repair, the verifier thaws and re-freezes each scope separately and requires
  a new committed-frontend acceptance from that scope before moving to the
  other. Control EOF or the fixed deadline thaws every scope automatically;
  an uncertain thaw drains and reconciles the exact epoch instead of reopening
  admission. This qualification-only fence does not alter the promoted route
  contract's normal session capacity.
- Fixed qualification result schema 5 exposes only installer-validated,
  step/status-specific failure codes plus a hash of suppressed detail. Dynamic
  exception text, provider stderr, paths, and process identities are never
  returned. Cleanup uncertainty overrides any earlier stage code, and failed or
  blocked results remain nonpersistent while the canary fence stays active.
- Real-pair cleanup may treat the already-captured supervisor's natural exit
  between an exact-live sample and status/pidfd revalidation as convergence,
  but only while the recovery fence still names that exact epoch (or has already
  been removed by it), the captured process identity is absent, and the normal
  exhaustive clean checkpoint subsequently succeeds. A malformed or replacement
  fence remains fatal and grants no signal or recovery authority. Wrapper signal
  errors are likewise ignored only when waiting on that exact child proves exit.
- The cgroup PID contract counts Linux tasks, including threads. Load
  qualification budgets six tasks per held client (wrapper, Grok child,
  supervisor control, frontend stream, provider stream, and verifier echo)
  plus a fixed 48-task allowance for accept/watchdog/status/overload/cleanup
  transients. The load32 ceiling is therefore 240; an observed peak above it
  fails qualification.
- Qualification, promotion, and abort write a closed root-owned terminal record
  before unlinking canary authorization. An interruption between canary unlink
  and deny removal is resumed only when that record, the exact selected release,
  quiescent inventories, and the absence of pending execution residue agree.
  `resume --apply` and `abort --apply [--restore-from ID]` recover durable
  interruptions without the original target source tree once the immutable
  user/root target pair has been published. Before target publication, recovery
  must retry the byte-identical frozen source or abort to the recorded prior
  release; `resume` does not reconstruct unpublished source bytes.
- Rung-canary schema 6 binds the profile digest, qualification-result schema 5
  binds the projected contract digest, and terminal rung-evidence schema 9 is
  the live per-rung authorization. Promotion transcripts remain audit records;
  deleting one cannot revoke a promoted rung. Removing or invalidating one
  terminal evidence object revokes only its exact selected rung.
- Legacy-root migration is an install-only internal broker operation. It is
  authorized only by coherent root/user `CANARY` selectors whose operation is
  exactly `install` and whose deny ledger names the same source and target.
  Upgrades also require passing closed schema-2 or schema-3 evidence for the
  exact prior release on the current host; schema 2 is admitted only for a
  pre-migration release and still binds its exact root manifest, helper bytes,
  and complete five-criterion pass. A first install requires an explicit null
  source. Only
  an inactive, root-owned, mode-bounded, regular-file allowlist under
  `/var/lib/grok-vpngate` may be removed. FIFOs, links, nested entries, mount-ID
  changes, active or ambiguous namespaces/tun/listeners/cgroups, and any
  OpenVPN process fail closed. Removal is idempotent, but operators retain an
  independent root-only archive until qualification and rollback complete.
  The public compatibility-handoff verb is nonmutating at the root boundary: it
  proves the legacy root tree absent and fails closed if any artifact remains.

## Hard Acceptance Criteria

- Feature-off/no-fence behavior passes the frozen compatibility matrix.
- Feature-off mutation refuses any live or uncertain multi-session fence.
- Equivalent typed contracts join; one-field differences reject before effects.
- No client byte reaches an uncommitted, rejected, canceled, or revoked backend.
- Relay output is byte-identical under fragmentation, partial writes, repeated
  `EAGAIN`, slow readers, silence, cancellation, and the documented half-close
  policy.
- The last live/provisional interest linearizes to draining once, cancels all
  work, proves empty residue, clears the fence, and exits.
- Supervisor loss terminates Grok children; recovery is idempotent and never
  re-adopts them.
- Provider transition commands, persistent legacy backends, qualification
  probes, and watchdog probes execute in durably recorded cgroup-v2 scopes.
  A barrier prevents provider effects before the command child is attached and
  its exact scope phase is durable. Successful `provider-up` retains that
  scope until stop/recovery; every other command reconciles its scope before
  returning. Cancellation, timeout, supervisor loss, and offline recovery
  reconcile the whole descendant scope before any empty proof can succeed.
- Provider startup exposes only closed numeric stages. Codes 20–28 identify
  common validation/start/inventory stages, 29 is the adapter's infrastructure
  collapse, and VPN-only codes 31–34 identify broker invocation,
  namespace/TUN/VPN proof, relay proof, and active-state publication. The
  adapter preserves 31–34 only for VPN `provider-up`; every
  other verb, rung, helper status, signal, and output remains normalized or
  discarded. Failed atomic active-state publication removes its exact
  temporary file before provider cleanup.
- A fixed qualification accounting parent is never removed ahead of its nested
  ownership graph. Root cleanup preserves topology through strict direct
  recovery, durably distinguishes recovered from fully contained state, and
  rejects a nominal verifier pass if the terminal sweep still had to repair
  runtime residue.
- No live environment variable selects privileged executable code. Every root
  mutation is owned by one release/UID/epoch/generation ledger entry.
- Runtime routing never invokes a package manager. OpenVPN is an installer
  prerequisite and remains a broker-owned, non-daemonized process with a
  durably recorded operation identity.
- The VPN relay binds in the host namespace, enters `grokvpn`, drops to the
  exact requesting non-root UID/GID, fsyncs and closes the broker-owned pidfile
  descriptor, disables core dumps, and only then restores checked same-UID
  descriptor visibility before `listen()`. This permits the unchanged
  unprivileged verifier to bind the listener inode to the exact relay process;
  any credential, `prctl`, readback, or ordering failure prevents readiness.
- VPN Gate data cannot introduce executable directives, plugins, hooks, remote
  private addresses, arbitrary paths, namespaces, or arguments.
- Install/rollback publishes a durable deny before draining active work;
  interruption exposes a complete old release or complete new release, and
  any uncertain drain/helper/release state remains denied and fail closed.
- Deny remains active through exact gate/wrapper help, safe wrapper version,
  inactive status, broker-gate helper-map/status, and empty-inventory canaries.
  Failed target evidence reselects and smokes the prior release; failed restore
  evidence leaves the deny durable. Installer-local evidence claims no live
  home, iPhone, or VPN rung result.
- The compatibility promotion criterion sources the selected `egress.sh` and
  exercises the real command classifier, direct/home/iPhone/VPN transport
  fixture hooks, and teardown snapshot in an installer-owned hermetic
  directory. A help/version early exit is not compatibility evidence.
- Release switching proves the broker ledger and authenticated root inventory,
  multi-session fences/workspaces, release-bound `/proc` identities, fixed
  listeners, and production cgroup-v2 names are empty. Inventory is read-only;
  expected OS/subprocess promotion failures either restore and re-prove the
  prior release or leave the durable deny in place.
- The release-bound inventory excludes only the epoch-bound installed Python
  command and its exact immediate `/usr/bin/sudo [ -n ] --` monitor. The
  concrete installer must occupy the fixed argv slot, both processes must be
  observed in the same inventory pass, full credential vectors and complete
  argv must match, and any additional bound cwd, executable, argv, wrapper,
  descendant, or unrelated consumer still fails closed. A wrapper between
  `sudo` and Python breaks the pair. An outer invoker is not classified from an
  opaque command-string substring alone: selection-lock exclusion plus durable
  deny publication linearizes any process it starts, while concrete descendant
  path observations remain blockers.
- A same-release install never treats legacy root residue as idempotent success.
  Cross-release migration binds selection operation, prior release, current
  host, evidence digest, directory/file mount identity, and inactive process
  inventory before unlinking any allowlisted file.
- Deterministic 2/32-client, crash, replay, stale-result, overload, cleanup, and
  rollback gates pass before live promotion.
- Two live same-contract Grok sessions share one route and distinct execution
  units. If Grok leader mode is active, each unit has a distinct exact leader
  socket; if it is inactive, both independently owned Grok child processes and
  absence of shared/per-session leader sockets are proved instead.
  each establish a post-repair stream through the repaired generation within
  the measured reconnect window, return resources to baseline, and preserve
  output/exit semantics.

## Verification

- Record pre-fix failures for each P0 defect before implementation.
- Run shell/Python syntax and the complete offline regression/fault/load suite.
- Run source/deployed/release parity and manifest/hash checks.
- Prove authoritative capture propagates public-source deletions, cannot retain
  a mixed old/new backup tree, and never captures or mutates private/generated
  state.
- Prove fresh restore recreates the public authoring tree, divergent existing
  source fails closed, and direct source execution cannot bypass the installed
  admission gate.
- Run live home, iPhone, and VPN canaries only when each dependency qualifies.
- Measure Grok retry/cache/leader behavior, provider and transition timings,
  host resource deltas, crash cleanup, installer switching, canary abort, and
  rollback restoration.
- Obtain fresh-context code, test, and security review; repair valid findings
  and rerun affected gates.

## Compatibility forced-iPhone acceptance correction

An explicit compatibility invocation with `--iphone` expresses route intent,
not a request to rerun the automatic ladder's baseline-delta policy.  A fresh
or reusable phone route is acceptable when its pinned identity is healthy, its
country passes policy, the model API is reachable, and it offers the effective
session model.  Effective model precedence is explicit `-m`/`--model`, an
existing `GROK_REQUIRE_MODEL` pin, then a valid nonempty remembered choice.  A
missing or intentionally empty choice remains unpinned and does not silently
become Grok's configured default.  Without an explicit/environment pin,
model-listing subcommands and `--pick-model` remain preference-neutral and may
expose the complete valid phone catalog; an environment pin continues to bound
`--pick-model` as it did before this correction.

The correction must not change automatic selection, demotion ordering, direct
fallback, fail-closed cleanup, or watchdog model pinning.  A missing concrete
target, blocked country, unreachable API, wrong phone identity, or failed
teardown still fails closed.  Compatibility model-choice files remain written
only by the existing model-selection path; qualification probes do not persist
preferences.  Forced-phone intent remains bound through watchdog confirmation:
an unpinned equal catalog is revalidated with the forced predicate, and a
failed phone is torn down and retried without entering the automatic/VPN
ladder.  Automatic sessions retain their existing repair and demotion order.
Because both compatibility probes and the interactive launch remove and let
Grok recreate its shared model cache, every such Grok child (including a
watchdog deep probe) must inherit `umask 077`; an ambient cooperative umask must
not produce cache state rejected by the multi-session trust boundary.

Acceptance requires seen-to-fail coverage for equal direct/phone catalogs,
fresh and reused forced routes, explicit-model precedence, absent target model,
`--pick-model`, model-listing subcommands, blocked country, unchanged automatic
selection, private model-cache creation by launch and watchdog probes, and
exact post-session cleanup.
Production changes are installed
only through a new immutable release; selected-release parity and existing
qualified route behavior must be re-established before delivery.

## Compatibility forced-home acceptance correction

An explicit compatibility invocation with `--host LABEL` expresses exact
route intent just as `--iphone` does.  The named host need not add a model
beyond the direct baseline, but it must be the configured endpoint for
`LABEL`, establish its SSH/SOCKS route, pass country policy, reach the model
API, and offer the effective session model.  Effective-model precedence and
preference-neutral listing/picker behavior are identical to forced-iPhone
selection: explicit CLI model, environment pin, valid nonempty remembered
choice, then an unpinned complete catalog.

The exact host request remains binding after initial admission.  Reuse must
re-probe the route instead of trusting only its listener, repair must validate
the effective model, terminal failure must tear the route down, and empty-state
reacquisition must retry only the same `local:LABEL` rung.  A forced-host
session must never silently demote to another home PC, iPhone, VPN, or direct.
If exact host/iPhone teardown reports that a control master, listener, or other
provider may remain, the route ownership record must be retained: admission
exits, watchdog repair does not raise a replacement, and empty-state
reacquisition cannot begin until exact cleanup succeeds. Compatibility
teardown is one aggregate transaction across local, phone, and VPN cleanup:
the validated owner is reconciled first, all paths are attempted, and a bounded
second pass decides the final empty proof after shared-port cross-provider
listeners have disappeared. State becomes empty only when that proof succeeds.
Automatic selection, repair, demotion, stale-route replacement, `ip`, the
standalone selector, forced-VPN failure cleanup, and `stop` must enter selection
only from that proved-empty state. Successful automatic/stop behavior and the
forced-VPN selection policy remain unchanged.
A fixed-content, owner-only compatibility recovery marker durably covers every
transition window in which route state alone cannot identify whether effects
remain.  Startup reconciles all provider residue before raising a route; a
pending marker makes watchdog and subsequent commands cleanup-only until the
aggregate transaction succeeds.  State is accepted only as one exact regular
mode-0600 record, and local SSH liveness/cleanup may consume `DEST` only when
that validated record names a `local:*` rung.  A rejected repair clears state
before removing its marker, while cleanup uncertainty retains the marker and
prevents later repair, demotion, or reacquisition.
Home-host startup publishes its validated rung, destination, and SSH port
before creating the control master.  A publication failure therefore has no
network effect; an interrupted or uncertain SSH startup remains recoverable
through the persisted destination, and startup never unlinks an unexplained
control path. Automatic selection treats retained ownership or failed
post-probe teardown as terminal instead of overwriting it with another rung or
direct fallback; `select_egress` independently rejects any nonempty ownership
state as a final caller-safety boundary.
`iphone-setup` is an owned maintenance transaction: it publishes recovery
intent and phone ownership before starting the sidecar, and reports success
only after final aggregate teardown proves empty. A valid selected route is
refused with an explicit stop requirement; pending or malformed ownership is
recovered instead. Compatibility-to-supervisor handoff consumes any valid
pending compatibility marker under the legacy lock only after the broker
admits migration; a fenced live legacy VPN ledger and an invalid marker both
fail closed and are never silently discarded.

Automatic home-PC selection remains baseline-delta-based, and forced VPN
semantics remain unchanged.  Acceptance requires seen-to-fail coverage for a
fresh equal-catalog host, reused-route model mismatch, explicit-model
precedence, blocked country, preference-neutral model listing, exact watchdog
repair/reacquisition/no-demotion, failed-teardown ownership retention, and
automatic equal-catalog host rejection.
The corrected source must be captured into the sanitized mirror and installed
only as a newly admitted immutable release before live Windows and iPhone
regression checks.

## Compatibility automatic preferred-route correction

A bare compatibility invocation selects the first usable remote route in the
configured ladder order. A route is usable only after exact startup and
ownership publication, known-country policy, a reachable nonempty Grok model
catalog, and any explicit or environment-pinned model requirement all pass.
The route does not need to add a model beyond the direct catalog. In
particular, a healthy `local:windows` route with the same `grok-4.5` catalog as
direct is selected immediately instead of being torn down while slower or
unavailable phone and VPN rungs are explored.

The direct catalog remains measured as a diagnostic and as the qualification
source for direct fallback. Direct is selected only after every configured
remote route is unavailable or unusable, and only when its catalog is nonempty
and contains any concrete required model. `--no-direct` continues to prohibit
that fallback. A previously selected direct route is not sticky: a later bare
invocation re-walks the preferred remote ladder so a newly available home host
can recover priority.

Initial selection, phone/VPN revalidation, same-rung repair, and downward-only
demotion use the same usable-catalog predicate. After launch chooses a model,
repair and demotion remain pinned to that exact model and never demote to
direct. An unpinned route retains its complete valid catalog for the existing
picker; blocked countries, unreachable/empty model APIs, failed startup, and
uncertain teardown remain fail-closed. Explicit host/iPhone exact-route
semantics and the transactional ownership/recovery rules remain unchanged.

Acceptance requires a seen-to-fail ordered-selector regression for equal
direct/Windows catalogs; proof that no later phone, VPN, or direct effect is
attempted after Windows qualifies; unavailable-first-host, missing-model,
blocked-country, VPN stability, direct/no-direct fallback, revalidation,
watchdog, and cleanup regressions; canonical/backup parity; a newly admitted
immutable release; and a live bare Windows selection with exact post-test
cleanup.

## Risks

- Grok, iOS, Tailscale, residential peers, and volunteer VPN servers can change
  independently of the implementation.
- VPN Gate servers remain privacy/availability risks despite strict parsing;
  application TLS is mandatory.
- Same-user loopback and control isolation is cooperative, not a sandbox.
- Installer-generated gate identity is selection- and qualification-bound but
  is not part of runtime release identity. A changed gate set fails closed and
  requires fresh qualification; automatic reset/migration of old completed
  qualification state is not provided in v1.
- A prior-boot uncertain installer-runner journal remains fail closed: cgroup
  inodes are boot-scoped, and v1 does not automatically discard a persistent
  `DELEGATED`, `RUNNING`, or `RECOVERED` record whose scope vanished across a
  reboot. Such a state requires audited operator recovery; it is not treated as
  proof of cleanup.
- Live destructive tests must remain inside the dedicated sidecar/netns and
  restore the original feature-off state.

## Multi-device iOS routing

### Goal and interfaces

Register each iPhone or iPad once, retain every exact Tailscale stable node ID,
and expand the phone position in the routing ladder into ordered typed
`ios:<key>` candidates.  `grok-remote --iphone` is an iOS-family request,
`grok-remote --ios KEY` is an exact-device request, and a bare invocation keeps
the order `home:*`, registered iOS devices, VPN, then the existing qualified
direct fallback.

The maintenance interface is:

- `iphone-setup [SELECTOR] [--label KEY]`: resolve, select, verify, and register
  one exact iOS exit node without replacing earlier devices;
- `iphone-list`: show ordered keys and current availability/qualification;
- `iphone-remove KEY`: remove one registered key while routing is quiescent;
- `iphone-reorder KEY...`: replace priority with one exact permutation.

Automatically derived keys use a unique Tailscale DNS short name and the
closed grammar `[a-z0-9][a-z0-9._-]{0,63}`.  A caller-supplied label uses the
same grammar.  Alias, DNS, and IP values are setup-only selectors; runtime
authority is always the verified stable node ID.

### Registry and migration

The owner-only canonical registry is
`~/.local/state/grok-proxy/iphone/devices.json`, schema 1, with no more than 16
ordered `{key, stable_node_id}` records.  Duplicate keys or IDs, key rebinding,
unsafe ownership/mode/link state, oversized input, and unknown fields fail
before mutation.  Writers use the existing maintenance exclusion plus a
mode-0600 same-directory temporary file, canonical JSON, file fsync, atomic
rename, and directory fsync.

A successful setup commits only after exact sidecar teardown proves empty.
Repeating setup for the same stable ID is an order-preserving no-op.  A valid
legacy `exit-node`/`ready` pair is imported once without requiring live device
access; both files and `tailscaled.state` remain intact for old-release
rollback.  On a fresh installation the first registered device is also
projected into the legacy pair using readiness-last publication.  The registry
is encrypted private backup data and never enters the public mirror.

### Routing and ownership

Every compatibility and multi-session device is an independent `ios:<key>`
rung.  Compatibility ownership records `RUNG=ios:<key>` and the frozen stable
ID in `DEST`; legacy `RUNG=iphone` is accepted only for recovery.  The same
sidecar identity may select different devices sequentially, but only after the
prior provider is stopped and exact port/process absence is proved.

`--ios KEY` contains exactly one device and never substitutes another device,
home route, VPN, or direct.  `--iphone` contains all registered devices in
registry order but no non-iOS rung.  Automatic modes repair the current device
in place within the existing repair budget, then treat A-to-B as a downward
candidate transition with a new provider generation.  Cleanup uses the
persisted request rather than the current registry.  A failed or uncertain A
cleanup prevents B from starting.

Live Tailscale qualification showed that a usable iOS sidecar can spend about
eight seconds starting before the Grok model probe begins.  Each exact-device
selection therefore has a 30-second envelope, and the iOS family shares a
120-second cap inside the existing cumulative transition deadline.  These
bounds leave time for a real model probe without allowing offline devices to
consume the outer transition and cleanup budgets.

### Multi-session and qualification

Contract schema 2 replaces `phone_node_id` with ordered immutable iOS endpoint
records and an optional exact key.  Protocol version 2 carries the typed rung,
key, and stable ID.  The ordered mapping is part of the canonical contract
digest; a registry identity or order change rejects a join before provider
effects.  Existing rung plus canonical-contract evidence binding is the route
authority; no duplicative route-binding digest is added.

Provider startup, inventory validation, liveness, repair, and qualification
must all prove `ExitNodeStatus.ID` equals the stable ID mapped by the frozen
contract.  Evidence and ordinary diagnostics expose the key and a stable-ID
digest rather than raw private topology.  Legacy `iphone` evidence never
authorizes `ios:<key>`, and every multi-session device requires its own live
real-pair promotion.  Compatibility routing retains its existing behavior of
using a successfully registered device without an external promotion record.

### Acceptance

Acceptance requires seen-to-fail coverage for two devices sharing HostName,
idempotent setup, append/reorder/remove, unsafe registry state, legacy import,
exact readback mismatch, offline A to online B, exact A no-substitution,
same-device repair, cross-device generation transition, evidence replay,
registry-change join rejection, cleanup after registry mutation, installer
rollback, private backup/restore, and unchanged Windows/VPN/direct behavior.
Production multi-device qualification additionally requires two simultaneously
available devices, two same-contract Grok clients, one authenticated active-
device fault, bounded failover, surviving clients, and empty final residue.

## Managed default multi-session profile and reusable rung qualification

### Scope and correction

Bare `grok-remote` shall use multi-session mode through one installer-attested,
owner-only default profile.  Callers shall not need to set
`GROK_MULTI_SESSION=1`, select a VPN rung, or reconstruct release-sensitive
configuration.  `GROK_MULTI_SESSION=0` remains an explicit compatibility
escape hatch, and the feature-on environment remains accepted for immutable
release qualification and migration.

The full `RouteContract` remains the exact supervisor-sharing boundary.  A
second, versioned `RungQualificationContract` is the promotion boundary.  Its
projection contains every common behavior, security, timeout, stability,
helper, Grok-identity, resource, and selected-endpoint field that can affect
the requested rung; it removes only route-selection state and endpoints for
other rungs.  Every `RouteContract` field must be explicitly classified, and
an unclassified future field fails closed.  Evidence binds both the original
full contract digest and the projected rung-qualification digest.  Evidence
from the prior schema is never silently upgraded.

### Profile authority and atomicity

The managed profile is canonical JSON, schema-versioned, content-addressed,
mode 0600, and owned by the target user.  It freezes the full contract plus an
absolute versioned Grok executable path and executable identity.  A separate
root-owned, mode-0444 activation record contains no private endpoints and
attests the profile digest, selected immutable proxy release, contract digest,
model, and Grok identity.  Activation publishes the immutable user profile
before atomically replacing the root pointer under the release-selection lock.
That pointer rename is the activation commit point.  Its per-release rollback
archive is written afterward; an archive-write failure reports
`activated-history-degraded`, and a post-rename directory-fsync failure reports
`activated-durability-uncertain` instead of falsely reporting a pre-commit
failure.  The next release switch must re-snapshot the exact active binding or
fail before publishing another release.  Any missing, unsafe, inconsistent, or
mutable authority component fails closed; an already-attested profile remains
the last-known-good profile after an interrupted candidate write.
Privileged activation validates the pinned executable against the explicit
set `{root UID, target-user UID}` and retains that set for descriptor
revalidation; ordinary client loading retains its narrower `{root UID,
current UID}` policy.  Thus `sudo` activation accepts the intended
target-user-owned pinned binary without accepting an unrelated owner's file.

Explicit route flags may select a rung already represented by the frozen
profile but may not import ambient routing configuration or change the model,
Grok executable, helper identity, or security policy.  Updating those values
requires a new candidate profile, qualification of every required projected
rung not covered by matching evidence, and atomic activation.  Before switching
away, the installer snapshots the selected release's exact terminal rung set
and active profile into root-owned, per-release catalogs.  A later upgrade or
rollback revalidates both catalogs against the current host, immutable private
profile, pinned Grok bytes, and terminal evidence before restoring them.
Missing or invalid rung records are removed independently.  On rollback, an
already-exact dormant active pointer is revalidated and may rebuild missing
history; otherwise missing or invalid profile history produces a closed
`profile_transition` result and leaves bare use in compatibility.  A canonical
active pointer for a different selected proxy release is dormant: it cannot
force the managed lane or break a bare command.  `doctor --json` remains
nonzero until the selected release has a valid current activation.  Release
recovery commands expose the same transition result as install and rollback.

### Readiness interface

`grok-remote doctor --json` emits schema
`grok-remote.profile-status.v1` with only public readiness metadata: status,
profile name/digest, proxy release, Grok identity, model, eligible rungs,
missing rungs, and a closed reason code.  It exposes no endpoint, stable node
ID, port, or private configuration.  Exit status is zero only when the managed
profile satisfies its minimum readiness policy; blocked, unsafe, stale, and
unconfigured states are nonzero.

### Acceptance and migration

Acceptance requires deterministic seen-to-fail coverage for cross-ladder
evidence reuse, relevant-field invalidation, unclassified-field rejection,
old-evidence rejection, unsafe profile files, activation interruption, stale
release/Grok identity, mutable-symlink drift, explicit compatibility escape,
bare managed dispatch, doctor redaction, route-neutral delegation, and real
split root/target-UID activation of a target-user-owned pinned binary.  The
first release with this schema requires one deliberate requalification of each
desired rung.  Old immutable releases and their existing selection/evidence
schemas remain rollback-readable; no live promotion or production activation
is part of source-level implementation verification.

## Default country-policy refresh — 2026-07-20

The built-in `GROK_BLOCKED_CC` policy shall default exactly to
`CN IR KP TM VE`.  It remains a frozen contract field enforced for direct,
home, iOS, and VPN rungs; an explicit operator override is not weakened or
reinterpreted by route type.  VPN rungs additionally remain constrained to
their frozen country allowlist.

This is a data correction, not a relaxation of the country-policy boundary.
The prior EU-wide default contradicted current first-party availability
documentation and a fresh route-scoped Grok 4.5 catalogue plus inference from
the production host's `DE` exit.  Managed configuration, the release
qualification verifier, the compatibility dispatcher, and the privileged VPN
helper must carry one identical default so no lane can construct a different
contract or candidate set.

Because the country policy contributes to every rung projection and contract
digest, no existing profile or rung evidence may be reused across this change.
Acceptance requires cross-source default parity, explicit-block preservation,
fresh model-probe admission for a nonblocked `DE` route, retained rejection of
the five default-blocked countries, isolated full verification, a new immutable
release and profile, direct real-pair promotion, and two simultaneous real Grok
sessions sharing one qualified generation.
