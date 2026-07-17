# Task Plan — Grok Remote Multi-Session v1

## Context

The compatibility implementation began as a verified singleton. The opt-in v1
implementation now supplies a typed same-contract supervisor, committed
frontend, exact process scopes, generation-specific providers, fixed root
broker, and coherent release installer. Promotion remains gated on the full
deterministic suite and current-host live evidence; unavailable external peers
are reported as blocked, never inferred healthy.

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
10. **Delivery gate.** Fresh-context code/test/security reviews, remediation,
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
| Exact opt-in value `GROK_MULTI_SESSION=1` | Keeps compatibility default literal | Accepted |
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
| Admission/repair model qualification in opt-in v1 | Periodic checks prove process/exit identity; unchanged-IP catalog drift remains a documented residual | Accepted |
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

Promotion stops at the first failed gate. A skipped or externally blocked live
check is recorded as blocked, never converted into a pass.
