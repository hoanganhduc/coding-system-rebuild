# Tasks — Grok Remote Multi-Session v1

## Preflight and lifecycle

- [x] Read repository, project, lifecycle, skill, and normative-plan guidance.
- [x] Confirm canonical commit, clean source subtree, and deployed public parity.
- [x] Record CPU/memory/disk/process/network limits and safe test parallelism.
- [x] Run the existing regression and syntax baseline.
- [x] Replace stale iPhone-only lifecycle documents with this v1 contract.

## P0 / P1

- [x] Add seen-to-fail namespace, VPN stability, relay, privilege-path,
  teardown, and durable-fence regressions.
- [x] Correct namespace/tunable handling and same-exit stability semantics.
- [x] Replace nonblocking `sendall` with bounded write-readiness relay logic.
- [x] Remove live `GROK_VPNGATE` privileged path selection and add test-only seam.
- [x] Make teardown synchronous, exact-owner, and error-reporting.
- [x] Implement stable lock/fence and pure command-classification matrix.
- [x] Qualify peer credentials and `SOCK_SEQPACKET` size/truncation behavior.
- [x] Implement typed canonical contract and one-field-delta tests.

## P2–P4

- [ ] Measure Grok version, leaders, cache overlap, retry, TTY/signals, output,
  session/resume, connections, and exit status.
- [x] Implement supervisor, bounded IPC, leases, child barrier, intent journal,
  recovery, diagnostics, and zero-interest drain.
- [x] Implement committed frontend and private direct/home backends.
- [x] Add replay, stale epoch, crash, descriptor, relay, overload, deadline,
  2-client, and seeded 32-client tests.

## P5–P7

- [x] Integrate the private iPhone adapter and deterministic qualification seams.
- [x] Implement fixed root broker and hostile VPN-data reconstruction.
- [x] Implement immutable root/user releases and atomic selector/rollback.
- [x] Test release skew, switch crashes, continuous launches, canary abort, and
  exact user/root residue.
- [x] Replace early-exit promotion smoke with the hermetic classifier,
  selected-egress, transport-fixture, and teardown compatibility matrix.
- [x] Separate durable host-bound release evidence from current-boot inventory;
  require explicit boot revalidation before feature-on admission.
- [x] Add closed exact-rung evidence ingest, deny-fenced canary execution,
  promotion, runtime filtering, and fail-closed empty-ladder behavior.
- [x] Add ledger-driven `resume` and `abort` recovery independent of the
  original target source tree after immutable pair publication, and document
  exact-source retry/abort for pre-publication interruption.
- [x] Add authenticated nonmutating broker inventory plus release-bound process,
  fixed listener, cgroup-v2, and multi-session residue checks to switch
  quiescence.
- [x] Add install-bound, host/evidence-authenticated migration of inactive
  legacy root artifacts, including FIFO, mount-identity, same-release residue,
  and ambiguous OpenVPN-process rejection.
- [x] Remove destructive root migration authority from public warm handoff;
  require it to prove installer-owned legacy migration already left no residue.
- [x] Pass the 50-case broker and two-case real gate-to-broker migration suites.
- [x] Preserve authenticated schema-2-to-schema-3 upgrade compatibility and
  cover it through the destructive bootstrap boundary.
- [x] Pass the 53-case release-installer and 28-case client unit suites after
  the evidence/recovery redesign.
- [x] Correct the live-derived load32 cgroup task contract from an undercounted
  four to six tasks per client, and add closed schema-2 failure-stage codes with
  parent-guard/process normalization, cleanup-order coverage, and second-lock
  installer fence revalidation.
- [x] Close the legacy-provider pre-artifact crash window with a barriered,
  durably recorded cgroup-v2 command scope; retain successful provider-up
  descendants through stop/recovery and prove every ephemeral command scope
  empty before returning.
- [x] Normalize provider resource-graph process identities into the verifier's
  exact identity type before listener, metrics, and cleanup proofs; cover the
  runtime/verifier interface with a regression test.
- [x] Bind recovery evidence to exact writer schema/record versions and
  filename identities, and anchor real process/listener inventories with
  pidfds plus post-read identity checks.
- [x] Match the writer's exact probe nonce grammar and revalidate attributed
  listener socket inodes plus the target listener table around ownership scans.
- [x] Preserve canonical listener bind addresses from `/proc/net` and require
  exact loopback/provider endpoints so wildcard listeners cannot qualify.
- [x] Reuse the pidfd-anchored peak supervisor record after load cleanup rather
  than reopening the deliberately retired process identity.
- [x] Separate wrapper exit from inherited pipe EOF in fault qualification:
  wait for wrapper failure, recover the escaped descendant, then drain output.
- [x] Make cleanup listener restart probes match production `SO_REUSEADDR`
  semantics and require a successful `listen()` so TCP `TIME_WAIT` is not
  mistaken for active listener residue.
- [x] Use the hostname Cloudflare trace endpoint for initial and watchdog exit
  probes; its literal-IP form fails TLS on a confirmed working Windows SOCKS
  route.
- [x] Preserve fail-closed provider startup while returning closed stage exit
  codes for context, port, tunnel, liveness, and inventory failures.
- [x] Split VPN provider-up status 26 into closed VPN-only stages 31–34,
  normalize spoofed/cross-rung exits, and remove atomic state temporaries after
  publication failure.
- [x] Restore same-UID `/proc/<pid>/fd` visibility only after the root VPN
  relay has dropped all UID/GID authority and closed its broker pidfile
  descriptor; force core limits to zero, verify `PR_SET_DUMPABLE`, and keep
  exact listener-inode attribution unchanged.
- [x] Replace verifier-local PID stopping with a supervisor-owned authenticated
  admission fence and exact cgroup freeze/thaw lifecycle.
- [x] Bind real-pair authority to the two launched wrapper/lease/child tuples
  and prove one repaired-generation frontend acceptance from each scope.
- [x] Replace substring model-list evidence and source-order tests with exact
  model-record parsing and behavior-level pause/reconnect/death tests.
- [x] Admit supervisor VPN `up`/`next` through the canary deny only when both
  root gates bind the request to the exact host/release/VPN-rung/contract
  authorization; keep every mismatched or non-canary mutation fenced.
- [x] Replace the unconditional real-Grok leader-socket assumption with closed
  evidence for two distinct execution units and explicit leader-enabled or
  leader-disabled behavior.
- [x] Linearize release/rung qualification and boot revalidation against every
  already-admitted shared selection lock before publishing authority.
- [x] Reject abbreviated, unknown, and duplicate VPN broker options consistently
  at the generated gate and immutable parser boundaries.
- [x] Separate fixed load/fault accounting from real-pair/manual containment;
  order outer-cgroup kill, strict direct runtime recovery, delegation revocation,
  second kill, nested removal, and terminal parent removal through durable v2
  `DELEGATING`/`RECOVERED`/`CONTAINED` runner phases.
- [x] Suppress warm compatibility handoff only after exact FD-backed fixed
  release/direct canary authentication, and keep the authorization marker out
  of ordinary status/control and Grok child environments.

## Verification and delivery

### P8 — source/backup ownership convergence

- [ ] Add seen-to-fail regressions for stale-file retention, missing required
  source roots, direct source execution, safe fresh restore, and divergent
  restore conflicts.
- [ ] Make `~/grok-proxy` the exact public authoring/capture authority while
  keeping credentials/topology encrypted-private and runtime state excluded.
- [ ] Restore absent public source files from `system/grok-proxy` without
  changing private/generated files or silently replacing divergent source.
- [ ] Refuse production execution outside a root-owned immutable release.
- [ ] Merge the reviewed public implementation into `~/grok-proxy` through an
  explicit allowlist and prove private/generated files are unchanged.
- [ ] Run focused pipeline tests, the complete Grok regression suite, source /
  backup / release parity, leak scan, and a fresh security/rollback review.

### P9 — signed pre-import bootstrap

- [ ] Build the production native verifier only with an explicit offline
  Ed25519 public key; never generate or store a production private key here.
- [ ] Stage only the installer-declared public runtime closure, sign its
  deterministic dispatcher, and prove unreadable private/unrelated paths are
  never opened.
- [ ] Make the administrative package transaction own the verifier, signed
  application store, and exact root-owned selector; candidate install must not
  create or replace any of them.
- [x] Add deterministic non-root Debian package construction for the exact
  root-owner five-file generation, with source/version/architecture binding,
  atomic output, and an authenticated post-install ancestry, inventory,
  hash/snapshot, Python, and static-ELF gate before zero-argument activation.
- [x] Add signed-bootstrap-only, owner-bound recovery for an orphaned
  generation-zero compatibility ledger, followed by a root-nonmutating public
  recovery that clears user state/fence, breaking old-broker deployment
  circularity without a force path.
- [x] Add the package-owned signed-application publisher with native compiled-key
  introspection, inode-stable update/release-operation locking, crash-reconciled
  selector audits, compare-and-swap reselection/rollback, and no signed-release
  garbage collection.
- [x] Move privileged package activation out of GNU Make into a fixed
  zero-argument freestanding static raw-syscall launcher and activator;
  descriptor-validate its closed package-owned self/payload roots, make exact
  directory modes independent of inherited umask, preserve lock inodes,
  activate native last, and permit crash recovery only for the exact generation
  bound by the durable pending marker. Use the same launcher source for the
  bounded-argument administrative publisher so neither boundary loads a shell,
  `env`, or caller-selected library before environment isolation.
- [ ] Route phase-6 installation only through the selected signed dispatcher,
  and route qualification/promotion/profile commands only through the concrete
  selected immutable release with no caller source/home override.
- [ ] Pass native tamper/path/identity tests, invocation-lane matrices, the
  isolated complete Grok gate, CI, fresh security review, staging audit, and
  exact remote-head verification.

- [x] Run complete deterministic suite and repository-level checks.
- [x] Deploy atomically and prove canonical/deployed/release parity.
- [x] Run live same-contract direct/home, iPhone, and VPN canaries where usable.
- [x] Exercise real failure/retry/cache/leader/provider timing and resource return.
- [x] Exercise live crash, load, canary abort, installer switch, and rollback.
- [x] Bind both generated gate digests into schema-2 fixed qualification state
  and reject stale load/fault reuse before fixed real-pair qualification
  execution or promotion. Free-form manual canaries remain nonqualifying.
- [ ] Add an explicit safe reset/migration workflow before supporting a changed
  gate generator for an already-qualified identical runtime release ID.
- [x] Restore feature-off state and prove no unexpected processes/listeners/netns.
- [x] Obtain fresh code, test, and security reviews; repair and rerun.
- [x] Record exact passed, failed, blocked, and residual evidence.
- [x] Pass the expanded privileged runner creation/recovery crash matrices and
  live fixed load/fault terminal-recovery exercise on the installed release.

## Final live evidence — 2026-07-16

- Selected immutable release:
  `284a4cd22a1b582643bfc6d24cbf204ece1f0baf967172c771196a508559cd38`.
  Installer dry-run reports `would_change:false`; final status is valid on both
  selectors, boot inventory is valid, deny is absent, and
  `qualified_rungs:[]` restores feature-off state.
- Fixed `load32` passed in 6,066 ms: 32/32 clients, overload rejected, exact
  byte path and shared contract/generation/owner proved. Peak observations were
  66 processes, 165 threads, 715 FDs, 1,353,132 KiB RSS, 198 cgroup tasks, and
  752,812,032 bytes of cgroup memory high-water delta; event deltas were zero
  and cleanup proved empty.
- Fixed forced-supervisor-loss recovery passed in 4,639 ms: wrapper failed
  closed, the escaped descendant was contained, first recovery applied, second
  recovery was a no-op, resource limits passed, and cleanup proved empty.
- VPN `real-pair` passed in 133,024 ms (transport 132,657 ms; reconnect 4,976
  ms). OpenVPN/netns/relay used the exact supervisor/broker path; 2/2 distinct
  sessions and Grok execution units shared one contract/generation/owner,
  leader mode was disabled with zero leader sockets, cache snapshots were safe,
  one authenticated provider fault caused exactly one repair, both clients
  survived, outputs were valid, and cleanup proved empty.
- `home:windows` `real-pair` passed in 84,531 ms (transport 84,173 ms;
  reconnect 4,168 ms) with the same two-session, cache, fault, single-repair,
  output, leader-disabled, and cleanup proofs over real OpenSSH.
- Direct remained policy-blocked: the current exit country is `DE`, which the
  frozen contract denies. The failed canary was diagnostic-only and aborted.
- iPhone remained externally blocked: `iphone-xr` resolved to its saved peer,
  but Tailscale reported that it was not advertising an approved exit node.
  No alternate peer was selected; the failed canary was aborted.
- Rollback from `284a4cd2...cd38` to known-good
  `f2464aa6...367d`, status validation, and reinstall back to
  `284a4cd2...cd38` all passed. Final inventory found no target listeners,
  Grok/OpenVPN/relay/sidecar processes, `grokvpn` namespace, `tun-grok`, broker
  ledger/artifacts beyond the stable lock, active canary/deny records, or
  `grok-ms-*` cgroups.

## Forced-iPhone equal-catalog correction — 2026-07-17

- [x] Add red regressions for fresh/reused forced phone acceptance when direct
  and phone offer the same model.
- [x] Prove explicit-model precedence, missing-model rejection,
  `--pick-model`/model-listing neutrality, blocked-country rejection, and
  unchanged automatic selection.
- [x] Implement a forced-phone model-offer predicate without changing
  automatic discovery/demotion, cleanup, or watchdog pinning.
- [x] Preserve forced route intent through watchdog repair/reacquisition and
  enforce a private Grok model-cache creation mask.
- [x] Extend that private mask to watchdog/deep `models_via` probes after a
  fresh review reproduced cache mode `0664` under caller `umask 002`.
- [x] Run focused tests, shell syntax, complete Grok regressions, source mirror
  checks, and leak scan.
- [x] Install the new immutable release, re-establish intended existing rung
  qualifications, and pass a real iPhone model query and inference.
- [x] Complete fresh-context review and prove source/release parity plus empty
  runtime residue.

### Final correction evidence — 2026-07-17

- Selected immutable release:
  `cc0aa2946151f9ec9edda6176c55e449a7982e37283458c960774346519e0893`.
  Root/user selectors, boot inventory, access policy, and rollback eligibility
  validate; deny is absent.
- The exact equal-catalog `grok-remote --iphone models` command passed repeatedly
  through the Vietnam phone exit, and a real pinned inference returned
  `IPHONE_ROUTE_OK`.  Under caller `umask 002`, both probe- and launch-created
  `~/.grok/models_cache.json` remained mode `0600`.
- The complete deterministic suite passed, including 104 installer tests (five
  explicit root-cgroup harness skips), install/source-backup pipelines, source
  parity, diff checks, and the 1,687-file leak scan.
- Fixed `load32` and forced-loss recovery passed.  Real two-session/fault/repair
  canaries passed and were promoted for `home:windows` and VPN, including a
  second pass after successful rollback to `370267b6...` and reinstall.
- iPhone multi-session promotion remains withheld: two same-rung fault canaries
  reached the guarded pair but reproduced `real-pair-cleanup` hash
  `bc1ce0f5...`; an intervening attempt was transiently unable to list the
  authorized model.  Exact recovery and canary abort converged each time, and
  the public forced-phone query continued to pass.  This does not revert or
  weaken the compatibility equal-catalog fix.
- Final residue inventory is empty for ports 1080/11080/11081, Grok/provider
  processes, `grokvpn`, `tun-grok`, and Grok cgroups.  Only stable empty control
  directories, mode-0600 locks, and the bounded supervisor log remain.

## Forced-home equal-catalog correction — 2026-07-17

- [x] Reproduce the selected-release failure with the real Windows route and
  prove transport/API success precedes baseline-delta rejection.
- [x] Add a deterministic fresh-host equal-catalog regression and observe it
  fail before the implementation change.
- [x] Generalize exact compatibility route intent across forced host and phone.
- [x] Cover reused-route model mismatch, precedence, listing neutrality,
  blocked country, watchdog exact-route retention, and unchanged automatic
  selection.
- [x] Resolve fresh review findings: retain exact host/iPhone ownership when
  teardown fails, suppress replacement repair/reacquisition, make route
  assertions non-vacuous, and cover successful and failed repair cycles.
- [x] Resolve follow-up review: publish home-route ownership before OpenSSH,
  retain it on uncertain startup cleanup, and directly test both exact cleanup
  helpers' state-deletion success paths.
- [x] Resolve final ownership review: make uncertain automatic startup and
  failed post-probe cleanup terminal, and preserve selected-route identity
  across stale replacement and `stop` teardown failures.
- [x] Resolve second-round caller review: make aggregate teardown transactional,
  gate automatic watchdog repair/demotion plus `ip` and standalone selection on
  proved cleanup, retain failed VPN candidate ownership, and refuse unexplained
  SSH control-path replacement.
- [x] Add exact mode/shape state validation plus a durable recovery marker;
  reconcile ownerless residue before startup and make pending watchdog cycles
  cleanup-only.
- [x] Bind OpenSSH cleanup to validated local ownership, make rejected-repair
  rollback publish empty state, and cover marker publication/clear/end failure.
- [x] Make `iphone-setup` a pre-effect owned transaction whose success requires
  exact final teardown, and consume pending recovery during warm handoff.
- [x] Reconcile the validated provider first and use a bounded second pass for
  shared-port absence, covering active/ownerless phone cleanup and permanently
  ambiguous listeners without false first-stop failure.
- [x] Run focused and full deterministic verification plus source parity and
  leak checks.
- [x] Install a newly admitted immutable release and prove live Windows success,
  rollback eligibility, and empty runtime residue.
- [ ] Repeat the live iPhone real-pair qualification when `iphone-xr` is online
  and advertising its approved exit-node role; deterministic phone regressions
  pass, but the 2026-07-17 live peer was externally unavailable.
- [x] Obtain fresh-context code/test review and resolve every valid finding.

### Final forced-home evidence — 2026-07-17

- Canonical `tests/run.sh` passed every shell and Python suite, including 104
  installer tests (five explicitly authorized root-cgroup cases skipped), 60
  broker tests, 33 provider tests, 77 supervisor tests, 64 live-verifier tests,
  and both install/backup pipelines.  A follow-up production-adapter regression
  raised the provider total to 34 and proved VPN-next publication loss remains
  residue across two fresh recovery processes; all 34 provider and all 77
  supervisor tests passed again.
- `~/grok-proxy` and `coding-system-rebuild/system/grok-proxy` have identical
  reviewed public bytes.  Repository `diff --check`, the 18-test source-backup
  pipeline, and the leak scan of 1,688 files passed.  Both trees plan immutable
  release `ca1e592d...dfbd`; installed `grok-remote` and `egress.sh` hashes match
  the canonical source.
- Fixed `load32` passed in 7,671 ms: 32/32 clients completed, overload was
  rejected, the resource gate passed, and cleanup was empty.  Peak observations
  were 66 processes, 165 threads, 715 FDs, 1,353,728 KiB RSS, 201 cgroup tasks,
  and 754,769,920 bytes of cgroup memory high-water delta, with zero memory/PID
  event deltas.
- Forced-supervisor-loss recovery passed in 4,634 ms: the wrapper failed closed,
  the escaped descendant was contained, the first recovery applied, the second
  was a no-op, the resource gate passed, and cleanup was empty.
- The selected-release compatibility command `grok-remote --host windows models`
  twice accepted the equal catalog, selected `local:windows`, reached Grok
  through the Windows exit, and listed `grok-4.5`.  The final `home:windows`
  real-pair passed in 67,233 ms (transport 66,871 ms; reconnect 4,117 ms): two
  independent sessions shared one contract/generation/owner, leader mode stayed
  disabled with zero leader sockets, cache snapshots stayed identity-safe, one
  authenticated provider fault caused exactly one repair, both clients survived,
  outputs and exit codes were valid, and cleanup was empty.
- The final VPN `real-pair` passed on its bounded retry in 164,429 ms
  (real OpenVPN/netns/relay transport 164,041 ms; reconnect 5,930 ms), with the
  same two-session, cache, leader-disabled, authenticated-fault, single-repair,
  client-survival, output, and empty-cleanup proofs.  The first attempt failed
  closed at `real-pair-old-generation`; authenticated abort and boot
  revalidation removed its canary and all route residue before the passing run.
- The live phone checks were not misreported as passing: Tailscale reported
  `iphone-xr` offline and not advertising an exit node.  Compatibility selection
  failed cleanly, fixed real-pair stopped at model refresh, and authenticated
  abort restored READY without listeners, state, marker, or sidecar residue.
- Rollback to `e54b3e84...c876a1`, selector/status validation, reinstall of
  `ca1e592d...dfbd`, a second Windows real-pair, promotion, and boot revalidation
  all passed.  Final status has coherent valid user/root selectors, valid boot
  inventory and access policy, no deny, complete rollback eligibility, only the
  target exposed, and exactly the qualified `home:windows` and `vpn` rungs.
  Final inventory found no listeners on 1080/11080/11081, owned provider
  processes, `grokvpn`, `tun-grok`, Grok cgroups, compatibility state, or
  recovery marker.

## Automatic preferred-route correction — 2026-07-18

- [x] Reproduce bare equal-catalog Windows rejection and prove live explicit
  Windows transport/model access succeeds.
- [x] Add and observe a failing ordered-selector regression for equal catalogs.
- [x] Admit the first healthy policy-compliant route with a usable catalog,
  while preserving concrete-model, VPN-stability, ownership, and cleanup gates.
- [x] Re-walk a prior direct fallback and qualify direct before using it.
- [x] Cover unavailable/missing-model/blocked-country/no-direct/reuse/watchdog
  behavior and keep forced host/iPhone regressions green.
- [x] Bind the reviewed automatic-route entrypoints into the exact production
  self-admission bundle while retaining hybrid rejection.
- [x] Run focused and complete deterministic verification plus source parity
  and leak checks.
- [x] Install and qualify a new immutable release; prove live bare Windows
  selection and exact final cleanup.

### Final automatic preferred-route evidence — 2026-07-18

- Immutable release `34bf9e56...21850` is selected and valid with no deny,
  complete rollback eligibility, and exact installed/source wrapper hashes.
- Bare `grok-remote models` accepted equal-catalog `local:windows` as the first
  rung, exited in VN, listed `grok-4.5`, and did not touch later rungs.
- Fixed `load32`, forced-loss recovery, and the real two-session Windows canary
  passed. `home:windows` is promoted for contract `3a4cef65...b445`, and an
  actual feature-on Windows model query passed.
- Focused ladder tests, all 104 installer tests (five explicit root-cgroup
  harness skips), the 18-test source-backup pipeline, source parity, diff
  checks, and the 1,704-file leak scan passed. Final listeners, owned
  processes, netns/tun, compatibility state/marker, and Grok cgroups are empty.

## Multi-device iOS routing

- [x] Confirm two-round architecture/security/test review and resolve the
  `--iphone` product decision as ordered iOS-family selection.
- [x] Add seen-to-fail registry, setup, typed-rung, failover, evidence, backup,
  and rollback regressions.
- [x] Implement secure `devices.json` parsing, migration, atomic mutation, and
  list/remove/reorder management.
- [x] Make `iphone-setup` additive and idempotent with exact stable-ID readback
  and commit-after-cleanup behavior.
- [x] Add `--ios KEY`, redefine `--iphone` as the iOS family, and expand bare
  automatic routing into ordered `ios:<key>` rungs.
- [x] Upgrade contracts/providers/supervisor/qualification to typed per-device
  identities without a redundant route-binding hash.
- [x] Update generated gates, installer schemas, fixtures, backup manifest,
  README, command help, and lifecycle documentation (no wrapper-specific shell
  completion layer exists in the current system).
- [x] Run focused and full deterministic tests, fault/load/resource gates,
  public-source parity, leak scan, and restore tests.
- [x] Install a new immutable release and verify live iPhone XR, Windows, VPN,
  two-session same-rung repair, canary promotion, rollback/reinstall, and empty
  supervisor/provider residue.
- [ ] Verify live iPad and ordered cross-device iOS failover.  The registered
  iPhone path passes, but the configured iPad peer is externally offline in the
  dedicated sidecar and therefore cannot be committed or qualified yet.

### Final multi-device iOS evidence — 2026-07-18

- Immutable release `f1474a17...d68b4` is selected and valid.  User/root
  selectors agree, deny is absent, rollback eligibility is complete, and the
  exact `home:windows`, `ios:iphone-xr`, and VPN contracts are promoted for
  Grok release `sha256:3e5e6f7f...189aba`.
- `iphone-setup iphone-xr` committed stable Tailscale ID
  `<redacted-private-node-id>` once and a repeated setup left the mode-0600 registry
  byte-for-byte unchanged.  Exact `--ios iphone-xr`, compatibility Windows,
  VPN, and bare automatic Windows model queries all reached Grok and listed
  `grok-4.5`.
- The final real-pair qualifications passed for `ios:iphone-xr` in 59,102 ms
  (reconnect 4,115 ms), `home:windows` in 71,134 ms (reconnect 4,629 ms), and
  VPN in 145,125 ms (reconnect 5,919 ms).  Each proved two independent Grok
  sessions, one shared contract/generation/owner, identity-safe cache state,
  exactly one authenticated provider repair, both clients surviving, valid
  outputs, leader mode disabled, and cleanup complete.
- Fixed 32-client load passed in 11,682 ms with 32 unique clients, shared
  generation/contract, overload rejection, 759,033,856 bytes peak cgroup
  memory delta, 199 peak cgroup PIDs, and zero post-owned processes.  Forced
  supervisor-loss recovery passed in 4,990 ms with the escaped descendant
  contained, the second recovery a no-op, and all resource gates passing.
- The full deterministic suite passed, including 80 supervisor, 64 verifier,
  60 VPN-broker, 104 installer tests (five explicit root-cgroup integration
  skips), feature-on end-to-end tests, and the source/backup install pipeline.
  Round-trip restore and the 1,691-file leak scan passed.
- Rollback from `f1474a17...d68b4` to `7607502f...caff`, status validation, and
  reinstall of `f1474a17...d68b4` passed.  The mode-0600 device registry
  survived unchanged and all three usable rungs were requalified.
- The iPad advertised stable ID `<redacted-private-node-id>` in primary Tailscale state,
  but two exact dedicated-sidecar setup attempts reported the selected peer
  offline.  Commit-after-cleanup correctly withheld it from the registry, so a
  live iPad route and iPhone-to-iPad failover remain externally blocked rather
  than being inferred from deterministic tests.

## Managed default multi-session profile and reusable rung qualification

- [x] Add an exhaustive, versioned `RungQualificationContract` projection and
  seen-to-fail invalidation/reuse tests.
- [x] Bind qualification records and installer validation to the projected
  digest while retaining the original full-contract audit digest.
- [x] Add strict content-addressed managed-profile parsing, pinned Grok
  executable identity, and atomic root activation metadata.
- [x] Route bare invocations through an active managed profile, preserve the
  explicit compatibility escape, and prohibit ambient authority drift.
- [x] Make the directly invoked immutable payload enforce the same activation,
  boot-inventory, and compatibility decisions as the installed entrypoint.
- [x] Make schema-9 terminal evidence the live independently revocable rung
  authority; retain qualification transcripts as audit-only records.
- [x] Persist and revalidate per-release qualified-rung and profile-activation
  catalogs so A/B upgrade and rollback restore a valid managed state.
- [x] Treat the active-profile pointer as the activation commit point and expose
  post-commit history-write degradation without a false activation failure.
- [x] Implement the redacted `grok-remote doctor --json` readiness interface
  and focused malformed/stale/unsafe-state tests.
- [x] Update canonical downstream delegation to stop injecting feature and VPN
  policy, and consume the readiness contract where appropriate.
- [x] Run focused and composite full deterministic verification, inspect all
  scoped diffs, and complete a fresh-context adversarial boundary review.
- [ ] Repeat the unmodified listener-sensitive end-to-end run and real
  distinct-UID/root-cgroup checks after the live port-1080 session is gone;
  isolated/component equivalents pass, but the active session was not touched.
- [ ] Separately, after operational authorization, install the new immutable
  release, perform the one-time live requalification, activate the profile,
  and verify rollback and final residue.
