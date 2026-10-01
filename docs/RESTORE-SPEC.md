# Closure-Complete Restore Specification

## Goal

Restore this research/coding environment on a stock Ubuntu 24.04 LTS host with
one user command.  The supported platforms are `arm64` and `amd64`; the origin
profile is Ubuntu 24.04.4 on `arm64`.  A successful full restore installs the
locked software, restores authoritative credentials and private state,
materializes every derived runtime, pulls and verifies required OCI images,
reconciles schedulers, activates services, and emits an evidence-backed report.

## Scope

- In scope:
  - A signed, auditable bare-host Bash entry point and an internal `make restore`
    target.
  - Exact Ubuntu 24.04 `arm64`/`amd64` software and component locks.
  - Agent CLIs, target adapters, skills, MCP servers, Python/Node/toolchain
    runtimes, Docker, and required OCI images.
  - Encrypted authoritative credentials, portable private state, projection
    materialization, key escrow integration, and legacy archive migration.
  - Classic cron migration, user systemd timers, and OpenClaw logical cron jobs.
  - Clean-host, idempotency, security, and target-local verification.
- Out of scope:
  - Cloud VM creation, disk encryption, firewall ownership, and SSH-server
    policy.
  - Bundling Docker image tarballs or other public software artifacts inside the
    encrypted recovery set.
  - Treating expired OAuth sessions or exhausted provider credit as technical
    installation failures.

## Assumptions

- The host has stock Bash, `apt-get`, systemd, a normal user with a writable
  home, working sudo, a correct clock, outbound DNS/TLS, and enough disk.
- The operator places one recovery set, two matching escrow share files, and the
  published bootstrap script below `~/secrets-restore-inbox/`.
- Public artifacts may be downloaded.  Volatile artifacts have immutable remote
  mirrors, but are not copied into the secrets backup.
- The private escrow repository (`CSR_ESCROW_GH_REPO`) is a share-storage target.  Reusable escrow
  implementation and schemas live in this repository; live shares are never
  printed or copied into public source.

## Interfaces

- Bare host: `/usr/bin/bash -p ~/secrets-restore-inbox/restore-ubuntu.sh`
- Repository: internal Stage-0 handoff `make restore`; operator-facing
  `make backup`, `make verify`,
  `make verify-schedulers`, `make scheduler-status`, `make recovery-drill`, and
  `make refresh-lock`.
- Versioned contracts: recovery-set v1, secrets-manifest v2, software-lock v1,
  target-state v3, schedules v1, OpenClaw-cron v2, and restore-report v1.
- Status vocabulary: `PASS`, `TECHNICAL_FAIL`, `AUTH_INVALID`,
  `REAUTH_REQUIRED`, `CREDIT_BLOCKED`, `NOT_CONFIGURED`, `NOT_APPLICABLE`, and
  `ARTIFACT_UNAVAILABLE`.

## Acceptance Criteria

- A minimal Ubuntu 24.04 `arm64` or `amd64` VM needs no preinstalled Git, Node,
  npm, GitHub CLI, Docker, or agent CLI.
- The bootstrap validates the platform, installs only the recovery substrate,
  verifies the pinned repository release, and transfers control to
  `make restore` without using `curl | sh`.
- Stage 0 binds signature
  verification, the signed repository/bootstrap records, ciphertext digests,
  and restore consumption to one descriptor-copied private snapshot; pathname
  replacement after authentication cannot change restored bytes.
- Stage 0 uses only fixed Ubuntu trust-gate tools. Authenticated installation
  runs from an exact checkout with no tracked, untracked, or ignored additions,
  verified directly against the commit tree without trusting the Git index.
  Before any candidate object is executed, Stage 0 checks metadata and ancestor
  ownership, rejects external/promisor object storage and config includes,
  disables transports and auxiliary object caches, and verifies the signed
  commit closure with strict full fsck; remote/FUSE checkout storage,
  shared-writable paths, and repository-local Python bytecode are excluded.
  Recovery GnuPG
  never resolves through user PATH or retains a scoped symmetric-key agent
  after the operation.
- All installed programs and OCI images match the active platform lock by
  version and immutable digest.  No runtime image uses `latest`.
- Claude, Codex, Copilot, Gemini, Antigravity, Grok, Kimi, OpenCode, CodeWhale,
  OpenClaw, and supported DeepSeek surfaces receive their declared software,
  configuration, credential authority/projection, skills, and native probes.
- Managed-skill visibility is receipt-bound. For normal targets, each selected
  skill file must match its owner-private `ai-agents-skills` state record, the
  corresponding per-run receipt, and the canonical source path and digest in
  the exact pinned AAS tree; the receipts must cover every target-supported
  member of the pinned `complete-restore` inventory. OpenClaw's skill-file
  gate covers every target-supported non-runtime member (runtime-backed skills
  are proved by the separate runtime closure) and must match its dedicated
  target-state record and a completed transaction that
  binds the canonical source digest, rendered-content digest, and exact
  installed file identity. A resumed restore may safely attest byte-identical
  pre-existing OpenClaw content without rewriting or taking deletion ownership.
  An arbitrary
  `*/skills/<name>/SKILL.md` file and the deprecated shallow restricted-target
  evidence shape cannot satisfy this gate.
- Classroom50 restores the exact gh-teacher 1.25.1 binary, the pinned
  course-management component and `~/.course_venv`, and its skill on all nine
  supported targets. OpenClaw receives the skill only through its separately
  approved v2 real-system target gate. Its sandbox contract v3 contains the
  course runtime, while restore projects the locked teacher binary and private
  GitHub CLI configuration into `/workspace` and injects the validated
  organization allowlist. Missing GitHub authentication is `REAUTH_REQUIRED`;
  a missing organization allowlist is `NOT_CONFIGURED`.
- OpenClaw Bash completion is generated and safe when absent.  Every configured
  MCP server completes an initialize handshake.
- OpenClaw's DB-first per-agent authentication is backed up through a native
  consistent snapshot. A fresh private metadata report must bind every safe
  canonical SQLite store to a passing agent record at the locked runtime
  version; legacy JSON is migration input only, and the binding performs no
  model-provider call.
- Managed host jobs occur exactly once, enabled timers are active, and restored
  OpenClaw declarations match their encrypted logical snapshot.  Provider-free
  canaries prove cron, timer, and OpenClaw scheduler execution after the current
  restore's scheduler-activation boundary; evidence from an earlier run cannot
  satisfy the restore gate merely because it is recent.
- Host-cron reconciliation adopts only exact declared legacy lines, removes
  exact duplicate predecessors, preserves unrelated bytes, and rejects command
  or repository-path near-matches instead of guessing ownership. Every timer
  declared enabled in `system/systemd/units.state` must also be declared active.
- A second restore is byte/state idempotent.  Unsafe archives, mixed shares,
  missing closure edges, and conflicting live credentials fail without partial
  secret replacement.
- Restored authorities, regenerated projections, bounded legacy promotions and
  scrubs, and declared stale-file deletions commit in one durable transaction.
  Process death before commit rolls the whole set back; process death after
  commit preserves the whole new set and leaves only owner-private cleanup.
- A live credential restore records the exact supported services that were
  active before quiescence. No recorded service resumes until any ambiguous
  transaction outcome has been recovered and the installed credential
  resolvers satisfy the restored v3 source-capability contract. Archived v2
  contracts remain readable for backward compatibility but cannot represent
  the current queue/policy authority split. If recovery or
  revalidation fails, the services remain stopped and the state record remains.
- Offsite publication proves exact remote inventory equality, fetches the
  published bytes into protected local storage, and authenticates their
  detached signature and complete manifest inventory before reporting success.
- The final report contains no unresolved technical failure before a recovery
  generation is called complete.

## Verification

- Repository unit and integration tests, shell syntax/static scans, leak scans,
  encrypted fixture round trips, scheduler/completion regressions, and
  target-local no-credit smokes.
- Clean Ubuntu 24.04 `arm64` and `amd64` rehearsals, including reboot/linger and
  Docker platform checks.
- Fresh-context code, test, and security reviews before commit/push.
- Phase 12 creates a cryptographically random restore-run ID before verification.
  The final report accepts only private, owner-controlled evidence for that exact
  run, repository commit, profile, and architecture, observed no more than five
  minutes earlier. The target-state and Classroom50 sidecars must be private
  regular files created after that run's verification boundary; their exact
  digest, size, mode, owner, timestamp, status, and matching gate label are
  captured in the accepted evidence and rechecked before report publication.
  Gate labels are unique, counts are recomputed, and a passing
  evidence file must cover the complete versioned gate inventory for its
  profile. Source/CI verification can report technical `PASS`, but it can never
  set `releaseReady`; only a full profile with no omitted gates and qualified
  platform and Python locks can do so.

## Risks

- Vendor artifacts for Kimi, Grok, Antigravity, or legacy DeepSeek may not have
  stable dual-architecture distribution.  A full target is blocked until a
  checksummed artifact or reproducible source build exists.
- OAuth/session files may expire or be machine-bound; restoration must enter a
  resumable reauthentication queue rather than claim success.
- Remote share ACLs, mirror retention, and both-architecture execution require
  live drills; fixture-only success is insufficient.
