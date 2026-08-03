# OpenClaw Restoration Closure Plan

## Context

The current verifier reports success while the real OpenClaw sandbox lacks
required binaries and Python stacks, several skills have registration/runtime
defects, restored per-install config is not bridged into the workspace, and the
installed OpenClaw version is newer than the pinned component snapshot. This
plan first repairs deterministic defects, then closes the restoration graph.

## Immediate Repair Steps

1. Add regression tests for the confirmed Sage path, skill metadata, TikZ
   runtime path/reference, browser template, and research-compute bridge defects.
2. Patch the owning OpenClaw component and umbrella installer sources.
3. Deploy only affected public artifacts, materialize the derived config, set
   the live browser profile, and recreate the affected sandbox if needed.
4. Prove the repaired behaviors in the real sandbox and run repository tests.

## Closure Implementation Phases

1. **Compatibility contract.** Record one tested tuple of OpenClaw package
   version, `openclaw-bot` commit, config schema, and per-architecture sandbox
   image digest. Reject untested tuples during install.
2. **Dependency closure manifest.** Give every skill a machine-readable record
   of host dependencies, sandbox dependencies, secrets, owner-data, generated
   state, external repositories, doctor command, and optional/required status.
3. **Hermetic sandbox supply.** Build and publish a multi-architecture sandbox
   image from a checked-in Dockerfile. Pin OS packages, Node/Python tools, TeX
   and media dependencies, emit an SBOM, and verify declared binaries at build
   time. Produce locked, cached wheels for expensive architecture-specific
   Python closures such as GetSciPapers, and replace or explicitly approve its
   currently yanked upstream pins before publication. Keep privileged host
   commands behind narrow queue bridges.
4. **Convergent materialization.** Stage owned files, compare before replace,
   atomically activate them, and fail on drift outside explicit preserve zones.
   Eliminate silent pip failures and unresolved `.new` files.
5. **Restore and migrate.** Restore secrets/owner-data, validate manifests,
   generate derived configs, clone pinned external repositories, migrate auth
   and state schemas, install exact channel-plugin versions before gateway
   startup, repair permissions, restart services with a bounded readiness poll,
   and recreate sandboxes in dependency order. Restore the Codex runtime runner
   and its vendored skill copies as declared runtime artifacts rather than
   assuming that metadata-only skill installation is sufficient.
   Move the shared Sage/send/Manim/email queue consumer out of
   `skills/zotero/` into neutral runtime infrastructure, with a compatibility
   launcher during migration.
   Treat Calibre's remote metadata bootstrap as an owner-data operation with
   explicit request timeouts, bounded retries, and a resumable/cacheable result.
6. **Fail-closed verification.** Discover the effective skill registry, verify
   declared sandbox commands, run required doctors/smokes, validate browser and
   job-queue bridges, and emit both JSON and human summaries. Required failures
   make installation fail.
7. **Restoration rehearsal.** Test a disposable Ubuntu host on amd64 and arm64
   with a synthetic encrypted archive; rerun installation and require zero
   behavior drift. Schedule a periodic real restore drill.
8. **Security gate.** Apply channel allowlists and least-privilege tool policy
   only after confirming required access paths, then rerun the deep audit.

## Decisions

| Decision | Rationale | Status |
|---|---|---|
| Keep `make install` as the single entry point | Preserves the documented operator contract | Accepted |
| Define closure as resolved-or-explicitly-disabled | Optional integrations must not make a valid restore impossible | Accepted |
| Verify from the effective sandbox | Host-only checks caused the current false green | Accepted |
| Pin the sandbox by digest | A mutable `latest` tag is not reproducible | Accepted |
| Use narrow host bridges for privileged actions | Avoids granting the sandbox a general OpenClaw control plane | Accepted |
| Keep owner-data as a manifest-linked encrypted input | Large personal state has a different lifecycle from credentials | Accepted |
| Move the shared queue consumer behind a compatibility launcher | Removes the misleading Sage-to-Zotero dependency without breaking existing services | Accepted |
| Lock and install channel plugins before gateway startup | Plugin state is required runtime closure, not incidental startup repair | Accepted |
| Keep backup observation separate from release promotion | Prevents a routine capture from silently creating an untested mixed tuple | Accepted |
| Pin GetSciPapers source and lock its full wheel closure in the image phase | The source commit and every runtime wheel are bound into the tested multi-architecture image | Accepted / implemented |

## Closure Results

- OpenClaw `2026.7.1-2`, component commit `8dd852a`, plugin locks, config
  schema, and the public multi-architecture sandbox index form one enforced
  compatibility tuple.
- The sandbox image contains the exact Modal SDK/CLI and GetSciPapers wheel
  closure; restored credentials are projected into the workspace with private
  modes and without logging their contents.
- Calibre bootstrap is bounded by request and overall timeouts, validates the
  SQLite database before atomic activation, and the live metadata cache passes
  `quick_check`.
- The Codex runtime runner and declared vendored runtime files are installed
  from the pinned immutable `ai-agents-skills` object and verified.
- The machine-readable closure classifies all required and optional skills;
  full verification runs from the effective sandbox and fails on required
  gaps.
- A link-free encrypted owner-data baseline now exists and is copied offsite.
  Historical owner data absent from every supplied archive remains explicitly
  unreconstructable.
- Least-privilege sandbox, channel, and execution policy is migrated before
  gateway startup; the deep audit reports no critical or warning findings.

## Verification Plan

| Check | Command or method | Expected result |
|---|---|---|
| Component unit tests | `python3 -m unittest discover -s tests` in `openclaw-bot` | All pass |
| Component roundtrip | `./test-roundtrip.sh --quick` | Clean temporary install/deploy cycle |
| Umbrella tests | `make test` | All no-secrets regression tests pass |
| Skill registry | `openclaw skills check --json` | Expected skills registered; no malformed metadata |
| Sandbox dependency audit | Execute declared bins in main sandbox | No missing required executable |
| Runtime doctors | Run required doctors in main sandbox | Required skills pass; optional skills explicitly disabled |
| Idempotency | Run install twice and compare manifests | No behavior-affecting second-run drift |

## Explicitly Excluded

- Destructive cleanup of legacy or untracked workspace data.
- Reconstruction of owner history that was absent from all supplied archives;
  a new encrypted baseline is created instead.
