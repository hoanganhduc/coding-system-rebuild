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

- Exact `GROK_MULTI_SESSION=1` opt-in; every other value follows the
  compatibility lane.
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

- Compatibility: `grok-remote [existing arguments]`.
- Opt-in: `GROK_MULTI_SESSION=1 grok-remote [existing arguments]`.
- Recovery: `GROK_MULTI_SESSION=1 grok-remote recover`.
- Read-only status: `GROK_MULTI_SESSION=1 grok-remote status`.
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
  `begin-rung-canary --release-id ID --rung RUNG --route-profile PROFILE
  --contract-sha256 DIGEST --grok-release-id IDENTITY --model-id MODEL --apply`
  authorizes one fixed `real-pair` step. `promote-rung --apply` derives evidence
  only from those root-owned results; external evidence is rejected. Free-form
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
- Fixed qualification result schema 3 exposes only installer-validated,
  step/status-specific failure codes plus a hash of suppressed detail. Dynamic
  exception text, provider stderr, paths, and process identities are never
  returned. Cleanup uncertainty overrides any earlier stage code, and failed or
  blocked results remain nonpersistent while the canary fence stays active.
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
