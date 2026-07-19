# Task Plan — Grok Remote Multi-Session v1

## Context

The compatibility implementation began as a verified singleton. The original
opt-in v1 supplied a typed same-contract supervisor, committed frontend, exact
process scopes, generation-specific providers, fixed root broker, and coherent
release installer. The managed-default correction now makes an exact active
profile the bare-command authority while retaining an explicit compatibility
escape. Promotion remains gated on the full deterministic suite and
current-host live evidence; unavailable external peers are reported as
blocked, never inferred healthy.

## Steps and Gates

1. **P0 / G0 — qualify and correct the singleton baseline.** Add seen-to-fail
   regressions, fix tunable/namespace validation, implement buffered relay I/O,
   remove privileged path selection, and make cleanup failures visible.
2. **P1 / G1 — compatibility floor.** Freeze a pure command classifier, move
   locks/fences to stable state, make every mutation interlock-aware, qualify
   `SOCK_SEQPACKET`, and add typed-contract/provider/clock/effect seams.
3. **P2 / G2 — live Grok boundary.** Measure two exact execution units,
   optional leader-mode state, cache overlap, retry, connection schedule,
   TTY/signals, resume/session behavior, output, and exit.
4. **P3 / G3 — supervisor/recovery.** Implement bounded IPC, leases, child
   barrier, durable intents, stable ownership, last-interest drain, replay and
   crash recovery; prove deterministic 2/32-client schedules.
5. **P4 / G4 — frontend/direct/home.** Implement the generation-fenced relay
   and private direct/home backends; qualify DNS, bytes, FIN, deadlines,
   overload, warm handoff, and resource return.
6. **P5 / G5 — iPhone.** Integrate the existing isolated sidecar behind private
   generation state; test identity changes, cancel/crash/teardown, then run a
   bounded two-session canary.
7. **P6 / G6 — VPN broker.** Install fixed root-owned release helpers and a
   closed-schema broker; reconstruct hostile configs safely; prove owner
   arbitration and empty root residue before a live VPN canary.
8. **P7 / G7 — atomic release and rollback.** Stage immutable user/root releases,
   atomically select them, test old/new matrices and switch crashes, separate
   durable release evidence from current-boot inventory, qualify each exact
   rung through a deny-fenced live canary, then restore feature-off state.
9. **P8 / G8 — source/backup ownership convergence.** Merge the reviewed public
   implementation into `~/grok-proxy` without touching private/generated state;
   make its allowlisted public tree an exact one-way capture source, restore it
   safely from the repository snapshot, refuse direct source execution, and
   retain immutable releases as the only production execution authority.
10. **P9 / G9 — signed pre-import bootstrap.** Package a native verifier with
    the production public key, sign a closed installer dispatcher outside the
    candidate tree, make the administrative selector the only update authority,
    separate bootstrap and installed CLI lanes, and prove no editable Python is
    imported or executed across the privilege boundary.
11. **Delivery gate.** Fresh-context code/test/security reviews, remediation,
   full affected reruns, artifact leak scan, and explicit remaining gaps.

Provider and Grok probes are part of the same durable ownership graph as Grok
children: they run behind a parent-death/attach barrier in recorded cgroup-v2
scopes. Runtime VPN selection never installs packages; the installer validates
the fixed OpenVPN prerequisite before promotion. Release switching publishes a
deny before bounded exact drain, and a failed or interrupted drain leaves the
deny in place for an explicit resume or rollback.

## Decisions

| Decision | Rationale | Status |
|---|---|---|
| Managed default with exact compatibility escape | Bare use consumes only a current root-attested profile; `GROK_MULTI_SESSION=0` selects compatibility and exact `1` remains for qualification/migration | Accepted |
| One supervisor and one public frontend | Preserves port 1080 while sharing one contract | Accepted |
| Require a concrete model | Prevents unprovable cross-session model drift | Accepted |
| `SOCK_SEQPACKET` with explicit fallback gate | Preserves message boundaries and bounded parsing | Accepted |
| Private SOCKS backend for every route, including direct | Prevents commit-gate bypass | Accepted |
| Stable durable fence plus live `flock` | Survives supervisor death and blocks old lane | Accepted |
| No Grok re-adoption in v1 | Makes supervisor-loss ownership deterministic | Accepted |
| Fixed root broker and immutable releases | Removes user-selected privileged code and skew | Accepted |
| Writable delegated cgroup v2 is mandatory | Gives descendants one exact crash-recoverable owner | Accepted |
| Deny-before-drain release switching | Serializes new launches against active epoch teardown | Accepted |
| Evidence-bound CANARY→READY selection | Keeps deny through exact-release smoke and makes missing/failed evidence non-runnable | Accepted |
| Closed per-rung evidence in selection | Prevents installer-local smoke from claiming live direct/home/iPhone/VPN behavior | Accepted |
| Two-fence qualification | Fixed release load/fault gates must pass before any route-specific real Grok pair can be promoted | Accepted |
| Closed route profile bound to the original contract | Allows one AUTO contract to qualify individual rungs without weakening immutable configuration binding | Accepted |
| Installer-derived evidence only | Manual canary transcripts and external all-true JSON cannot qualify a rung | Accepted |
| Durable terminal canary record | Makes the canary-unlink/deny-clear crash window recoverable without guessing intent | Accepted |
| Separate boot inventory | Preserves durable release evidence while requiring root-state revalidation before first feature-on launch after boot | Accepted |
| Ledger-driven resume and abort | Recovers without the original source tree after the immutable target pair is published; a pre-publication interruption must retry the exact frozen source or abort to the prior release | Accepted |
| Root-selected read-only broker inventory | Keeps residue inspection available through deny, missing evidence, and interrupted mixed user selectors | Accepted |
| Authenticated one-time legacy-root migration | Removes only an inactive allowlisted `/var/lib/grok-vpngate` tree during an install-bound CANARY, with current-host prior evidence required for upgrades | Accepted |
| Nonmutating public warm handoff | The compatibility verb proves legacy root inactivity and absence; only installer bootstrap may delete root artifacts | Accepted |
| Gate-bound fixed qualification | Schema-2 qualification state binds the exact generated user/broker gate digests, so stale load/fault results cannot authorize a changed gate set | Accepted |
| Deterministic 32 clients, two live Grok clients | Covers load without unnecessary provider cost | Accepted |
| Six-task/client cgroup PID contract and closed stage diagnostics | Matches Linux thread accounting observed live while exposing no dynamic failure detail | Accepted |
| VPN-only provider-up substages | Preserve fixed codes 31–34 only for VPN startup while discarding helper output and normalizing every cross-rung or arbitrary exit | Accepted |
| Supervisor-owned qualification freeze and admission fence | Binds the two real wrappers to exact lease cgroups, prevents foreign admission, auto-thaws on verifier loss, and makes per-scope post-repair reconnects observable | Accepted |
| Nested Grok default plus atomic explicit choice | Matches `[models].default`, preserves `-m` memory, and keeps qualification preference-neutral | Accepted |
| Admission/repair model qualification in the managed lane | Periodic checks prove process/exit identity; unchanged-IP catalog drift remains a documented residual | Accepted |
| Single-tenant loopback trust boundary | Raw loopback SOCKS is not cross-UID authenticated; all local loopback-capable UIDs must be trusted | Accepted residual |
| Reject ambiguous OpenVPN bytes before root execution | Unterminated blocks and embedded NUL input fail closed; adversarial tokenization corpus is permanent | Accepted |
| Exact VPN rung-canary deny exception | Generated gate and immutable broker independently admit only supervisor `up`/`next` bound to the root canary's host/release/rung/profile/contract | Accepted |
| Optional Grok leader evidence | Require exact distinct leader sockets only when leader mode is active; otherwise prove two distinct owned Grok children and no shared leader | Accepted |
| Selection-linearized canary start | Wait for all shared admission locks, re-check quiescence, then publish the deny while exclusive | Accepted |
| Exact nonduplicated broker CLI | Disable argparse abbreviation and reject unknown/duplicate canary-gate options at the outer boundary | Accepted |
| Ordered fixed-qualification parent cleanup | Keep load/fault resource accounting while killing the outer scope before strict runtime recovery and removing it only after durable `RECOVERED`/`CONTAINED` proofs | Accepted |
| No accounting parent for real-pair/manual diagnostics | Preserve recoverable supervisor/provider cgroup topology while bounding the invoking verifier with parent-death and session ownership | Accepted |
| Direct-only fixed qualification bootstrap | Authenticated release/direct canaries suppress warm compatibility handoff; terminal recovery rejects every non-direct record | Accepted |
| Post-demotion VPN relay FD visibility | After the broker pid descriptor closes, require the relay's real/effective/saved UID/GID to equal the requested non-root account, set core limits to zero, and restore checked same-UID `/proc/<pid>/fd` visibility so strict listener-inode attribution remains possible | Accepted |
| Prior-boot runner uncertainty fails closed | Persistent delegated/running runner journals are not auto-discarded when boot-scoped cgroup identity has vanished | Accepted residual |
| Home authoring source, immutable execution | `~/grok-proxy` remains the backup system's editable/capture authority, while root-owned content-addressed releases preserve atomicity, privilege separation, qualification binding, and rollback | Accepted |
| Exact one-way Grok source mirror | Missing/deleted public source cannot leave a hybrid repository backup; private/generated paths remain separately classified and untouched | Accepted |
| Direct source execution refused | Prevents the editable tree from bypassing the generated release gate and invalidating release-bound evidence | Accepted |
| Selected-only user release exposure | Keep exactly the selected user release at `0555`, archive every inactive user release at `0500`, and validate the exact production self-admission bytes before re-exposure | Accepted |
| Native signed pre-import bootstrap | A separately packaged Ed25519 verifier and administrative selector admit a closed dispatcher before candidate Python can run; production private keys remain offline and candidate installation cannot replace the anchor | Accepted |

## Verification Plan

| Gate | Method | Expected result |
|---|---|---|
| G0 | Existing + new P0 regressions | Seen-to-fail proofs then all pass |
| G1 | Parser/interlock/IPC/contract matrices | Literal no-fence compatibility; fail-busy unsafe state |
| G2 | Instrumented real Grok pair | Distinct execution units, explicit leader-mode evidence, safe cache policy, measured retry/TTY/exit |
| G3 | Seeded scheduler and fault injection | Prefix invariants and idempotent recovery pass |
| G4 | Relay transcripts and 2/32 clients | No probation bytes; bounded resources; exact bytes |
| G5 | Mocked plus live sidecar | Exact phone identity and two-session canary |
| G6 | Malicious inputs/partial root effects/live VPN, FIFO and mount substitution, unrelated OpenVPN process scan, authenticated legacy-root migration | One owner, no hooks, no ambiguous process or mount state, empty root residue |
| G7 | Switch-crash matrix, hermetic compatibility matrix, process/listener/cgroup/root inventory, boot revalidation, exact-rung canary/promotion, resume/abort, rollback | Old or new only; release and boot evidence remain distinct; unqualified rungs are unroutable; failed target/restore smoke rolls back or remains denied |
| G8 | Seen-to-fail source-mirror, restore-conflict, private-preservation, and direct-execution regressions; one-time source merge inventory | Exact public parity; deletions propagate; private/generated identities stay unchanged; only installed gate executes production |
| G9 | Native bootstrap unit/integration tests, signed-bundle tamper matrix, selector/ownership checks, installed-lane invocation matrix, and private-source sentinel | Only the administratively selected signed closure reaches root; editable/private input is never opened or executed; installed maintenance revalidates the selected release under lock |

Promotion stops at the first failed gate. A skipped or externally blocked live
check is recorded as blocked, never converted into a pass.

## Post-v1 correction — forced iPhone with a globally available model

1. Add deterministic regressions proving that equal direct/iPhone catalogs
   fail before the correction while automatic selection still rejects the
   no-value tunnel.
2. Separate explicit phone acceptance from baseline-delta discovery, resolve
   the effective model without persisting a preference, and apply the forced
   predicate to fresh, reused, and watchdog-revalidated phone routes while
   retaining the forced route across teardown/retry.
3. Verify explicit-model rejection, menu/listing neutrality, country policy,
   watchdog pinning, private Grok cache creation by both launch and later
   watchdog probes, teardown, syntax, and the complete deterministic suite.
4. Capture the canonical public source into the sanitized backup, install a
   new immutable release, re-establish intended existing route qualifications,
   and run a real iPhone model query and inference.
5. Obtain fresh-context test/code review, audit release and source parity, and
   leave no listener, provider, supervisor, namespace, tun, or recovery residue.

Historical phase boundary, superseded for default dispatch by the managed-
profile phase below: changing automatic ladder policy or supporting
simultaneous different-route contracts remains out of scope.

## Post-v1 correction — forced home host with a globally available model

1. Reproduce `--host windows` against the selected immutable release and add a
   deterministic equal-catalog regression that fails on the current branch.
2. Generalize compatibility exact-route state from iPhone-only to a concrete
   forced rung, resolve the effective model for host and phone, and apply the
   forced offer predicate to fresh/reused host admission.
3. Preserve the exact host through watchdog confirmation, repair, teardown,
   and same-rung reacquisition; prohibit automatic demotion from a forced host.
   A failed exact teardown retains its ownership record and blocks replacement
   admission/reacquisition. Make compatibility teardown an aggregate
   transaction: reconcile the validated owner first, attempt every provider,
   then use a bounded second pass as the shared-port empty proof; clear state
   only after it succeeds, and require proved-empty ownership before automatic selection,
   watchdog repair/demotion, `ip`, standalone selection, forced-VPN failure
   cleanup, or `stop` can replace a route.
   Cover transition gaps with a durable owner-only recovery marker, reconcile
   every provider before fresh startup, and keep later watchdog cycles
   cleanup-only until marker, state, and effects converge. Bind SSH DEST use to
   a validated local rung; make rejected-repair rollback clear state before the
   marker; run `iphone-setup` as an owned transaction; and consume pending
   compatibility recovery under the warm-handoff lock.
   Persist the validated home cleanup destination before starting OpenSSH so a
   state-publication failure is effect-free and uncertain startup is recoverable;
   never unlink an unexplained control path, and never overwrite retained
   ownership with another rung or direct.
4. Prove missing-model and blocked-country failure, listing neutrality, and
   unchanged automatic equal-catalog rejection; run focused and full suites.
5. Synchronize the canonical and sanitized source, install and admit a new
   immutable release, then verify live Windows success and iPhone non-regression
   with exact post-test cleanup and a fresh-context review.

Historical phase boundary, superseded for default dispatch by the managed-
profile phase below: altering automatic ladder value policy, forced-VPN
selection policy, or same-contract sharing semantics remains out of scope.

## Post-v1 correction — automatic preferred-route admission

1. Reproduce bare selection against the installed release and separately prove
   that explicit Windows transport, country policy, and Grok model API access
   are healthy.
2. Add a seen-to-fail selector regression in which direct and Windows expose
   the same catalog; require the first configured healthy Windows route to win
   without touching later phone, VPN, or direct rungs.
3. Replace baseline-delta admission in compatibility ladder selection with a
   first-usable ordered predicate. Preserve concrete model requirements,
   country/API checks, VPN stability, transactional startup/teardown, and
   downward-only no-direct demotion. Re-walk rather than reuse a prior direct
   fallback.
4. Cover unavailable and invalid earlier rungs, direct/no-direct fallback,
   forced-route non-regression, reuse, watchdog repair/demotion, and cleanup
   uncertainty; run focused and complete deterministic suites.
5. Capture the canonical source into the sanitized mirror, install a new
   immutable release, and prove a live bare invocation selects Windows and
   leaves no route residue after stop.

Historical phase boundary, superseded for default dispatch by the managed-
profile phase below: remotely enabling an offline or non-advertising iOS exit
node, or weakening immutable-release qualification, remains out of scope.

## Multi-device iOS routing

1. Add failing registry, setup, classifier, ladder, contract, provider,
   supervisor, qualification, backup, and rollback tests for the approved
   semantics in `SPEC.md`.
2. Implement one strict registry helper and transactional maintenance commands;
   import the legacy stable ID without deleting rollback state.
3. Replace logical `iphone` routing with typed `ios:<key>` candidates in the
   compatibility dispatcher and schema-2 multi-session contract.  Preserve
   exact-device fail-closed behavior and make cross-device failover a new
   generation rather than same-rung repair.
4. Update every closed rung/profile parser, provider environment/inventory,
   qualification verifier, generated installer gate, private backup class,
   documentation, completion, and fake Tailscale seam.
5. Run focused and complete deterministic tests, fixed fault/load gates,
   source/mirror parity and leak scans, then install a new immutable release.
   Requalify intended routes and run live exact-device, two-session failover,
   Windows, VPN, canary, rollback, reinstall, and residue checks.  An offline
   second device is recorded as a blocked live promotion gate, never a pass.

Historical phase boundary, superseded for default dispatch by the managed-
profile phase below: concurrent different-contract supervisors, automatic
Tailscale admin approval, and modifying Grok itself remain out of scope.

## Managed default multi-session profile and reusable rung qualification

1. Define a versioned, exhaustive per-rung projection of `RouteContract`; keep
   full-contract equality for supervisor sharing and bind new evidence to both
   digests.
2. Add a strict content-addressed user profile and root activation record with
   pinned Grok path/identity, safe ownership and mode checks, atomic
   publication, release-selection-lock serialization, and an explicit
   root/target-user executable-owner set across privileged descriptor
   validation and revalidation.
3. Make bare `grok-remote` enter the managed client by default when an active
   profile exists, retain explicit compatibility and qualification paths, and
   ensure profile-backed requests never rebuild authority from ambient state.
   Treat a canonical activation for another selected release as dormant so an
   upgrade or rollback keeps bare compatibility available until activation.
4. Add a redacted `doctor --json` readiness contract and installer-side
   candidate validation/activation that reuses only matching projected rung
   evidence and reports missing qualification without weakening the gate.
5. Make terminal schema-9 evidence the independently revocable live rung
   authority, persist exact per-release rung/profile catalogs, and restore them
   only after host/profile/Grok/readiness revalidation. Revalidate an exact
   dormant pointer when rebuilding missing rollback history. Treat the active-
   pointer rename as the activation commit and distinguish later archive or
   directory-fsync uncertainty from a pre-commit failure.
6. Apply the same activation and current-boot-inventory decision inside a
   directly invoked immutable payload so bypassing the outer selector cannot
   bypass managed admission.
7. Remove provider and route injection from downstream delegation, then run
   focused/full deterministic tests, source checks, and a fresh-context trust-
   boundary review.  Leave production install, live canaries, activation,
   commit, and push to a separately authorized operational step.
