# Closure-Complete Restore Tasks

- [x] Confirm Ubuntu 24.04 `arm64`/`amd64` scope and network-assisted artifact
  policy.
- [x] Inspect current bootstrap, software, credential, OCI, completion, and
  scheduler closure.
- [ ] Add Stage-0 bootstrap, platform software locks, OCI digest puller, and
  native CLI producers.
- [ ] Replace the legacy secret/archive contract with authority/projection
  metadata, safe recovery-set handling, and immutable escrow generations.
- [ ] Add generated-state materializers, OpenClaw cron export/import, and
  declarative host schedules.
- [ ] Integrate `make restore`, ordered activation, closure scanning, status
  reporting, and documentation.
- [ ] Run focused tests and full repository tests.
- [ ] Run clean-host/architecture rehearsals or record the exact blocked gates.
- [ ] Obtain fresh-context code, test, and security reviews; fix valid findings.
- [ ] Commit and push authorized default branches after all applicable gates.

## Implemented hardening closure

- [x] Commit authorities, projections, legacy scrubs, and stale deletions in one
  crash-consistent restore transaction.
- [x] Quiesce the live gateway and queue worker with an owner-private record of
  the exact prior active set; recover ambiguous transaction exits and revalidate
  the restored v3 capability contract before resuming that set; archived v2
  contracts remain compatibility input only.
- [x] Split native Copilot credentials from the broad provider fallback vault
  and probe both installed resolver paths independently.
- [x] Reconcile exact legacy cron predecessors without deleting unrelated jobs,
  and require enabled timers to be active.
- [x] Require exact offsite inventory equality plus authenticated private
  readback, and pin third-party workflow actions to immutable commits with
  job-scoped write permissions.
- [x] Qualify recovery releases in a closed Git environment and keep the legacy
  7-Zip parser/extractor on fixed system executables.
- [x] Capture and source-contract the exact Git-ignored Forms runner/API/web
  local files; keep provider-managed GitHub Actions and Cloudflare deployment
  secrets outside the host recovery-set claim.
