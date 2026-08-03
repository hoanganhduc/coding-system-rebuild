# OpenClaw Restoration Closure Tasks

## Immediate repair

- [x] Inspect live host, effective sandbox, skill registry, doctors, source
  ownership, install scripts, verifier, component pins, and backup manifests.
- [x] Add focused regression tests.
- [x] Fix Sage container path and narrow its container mount to the queue.
- [x] Fix Calibre, annotated-review, and VNU skill metadata.
- [x] Fix TikZ workspace Python path and local reference links.
- [x] Fix the public and live browser default profile.
- [x] Materialize restored research-compute config and GetSciPapers credential
  view into the OpenClaw workspace.
- [x] Deploy affected files and recreate the Sage worker sandbox.
- [x] Restore GetSciPapers from a pinned source commit into a
  workspace-portable venv and verify it from the live sandbox.
- [x] Run targeted sandbox checks and repository tests.

## Closure implementation

- [x] Add and enforce the OpenClaw/component/image compatibility lock.
- [x] Define the machine-readable skill dependency closure manifest.
- [x] Build and publish pinned multi-architecture sandbox images.
- [x] Lock the full GetSciPapers transitive closure, cache amd64/arm64 wheels,
  and resolve its yanked aiohttp/protobuf pins before image publication.
- [x] Make all required environment installation failures fatal.
- [x] Replace preserve-and-write-`.new` behavior with convergent ownership rules.
- [x] Add auth/state migration and derived-artifact phases after secret restore.
- [x] Lock, restore, and verify exact OpenClaw channel-plugin installations
  before the gateway is started; replace startup-time repair with a bounded
  migration and readiness check.
- [x] Restore and verify `~/.codex/runtime/run_skill.sh` plus declared vendored
  runtime skill copies; fail when skill metadata has no runnable closure.
- [x] Relocate the shared queue worker from `skills/zotero/` to neutral runtime
  infrastructure and migrate its systemd/caller paths compatibly.
- [x] Add timeouts, bounded retries, and resumable/cacheable owner-data
  bootstrap for Calibre metadata instead of allowing an unbounded first sync.
- [x] Replace host-only verification with fail-closed sandbox verification.
- [x] Add encrypted-fixture, idempotency, amd64, and arm64 restore rehearsals.
- [x] Decide and apply the least-privilege OpenClaw access policy.
- [x] Document and test owner-data restore alongside the secrets archive.
- [x] Keep backup refresh observation-only and add a separate drift report so
  release locks cannot advance without complete candidate qualification.
