# OpenClaw Restoration Closure Specification

## Goal

Make `make install SECRETS=/path/to/archive.zip` restore a working OpenClaw
skill environment on a supported fresh Ubuntu host. The restoration is
closure-complete when every declared skill dependency is installed, restored,
derived, migrated, or explicitly classified as unavailable, and the installer
proves the resulting state from inside the actual OpenClaw sandbox.

## Scope

- In scope:
  - Repair confirmed deterministic defects in the current live installation.
  - Pin a compatible OpenClaw CLI, `openclaw-bot` component, and sandbox image.
  - Account for host packages, sandbox binaries, Python environments, browser
    profiles, external repositories, secrets, owner-data, derived configs, and
    service/sandbox restart steps.
  - Make installation convergent and fail closed on required dependency or
    verification failures.
  - Separate observational backup refreshes from deliberate, fully qualified
    promotion of a new compatibility tuple.
  - Verify registered skills and representative runtime commands from the main
    agent sandbox on amd64 and arm64.
- Out of scope for the immediate repair pass:
  - Changing channel allowlists or elevated-tool policy without an explicit
    access-policy decision.
  - Publishing a new GHCR sandbox image without an explicit publication step.
  - Reconstructing owner-data that was absent from every supplied backup.

## Assumptions

- Ubuntu 24.04 on amd64 or arm64 remains the supported host contract.
- The public repository and pinned public components contain no secrets.
- The encrypted secrets archive remains the authority for credentials and
  small private state; larger owner-data may be a separately encrypted input.
- Optional integrations may finish in a declared `disabled` state, but must not
  be reported as working or silently skipped.
- Privileged host actions remain outside the sandbox and use narrow bridges.

## Interfaces

- Entry point: `make install SECRETS=/absolute/path/to/archive.zip`.
- Public dependency locks: `components.lock` and package/image manifests under
  `system/packages/`.
- OpenClaw source component: `external/openclaw-bot/`.
- Secret/state manifests and restore scripts under `bin/` and `secrets/`.
- Post-install contract: `make verify` plus sandbox-native skill verification.

## Acceptance Criteria

- A fresh supported host needs one documented install command after the initial
  repository clone and secrets archive download.
- A second identical install makes no behavior-affecting changes and leaves no
  unresolved `.new` files.
- No required package/environment installation failure is suppressed.
- OpenClaw CLI, component template schema, and sandbox image are validated as a
  compatible version set and the image is pinned by digest.
- Every registered skill is classified as `ready`, `disabled-optional`, or
  `failed-required`, with evidence from its effective sandbox.
- Every eligible skill's declared executable requirements exist in the sandbox,
  and required doctor/smoke commands pass.
- Restored inputs are followed automatically by derived-config generation,
  auth/state migration, permission repair, service restart, and sandbox
  recreation where required.
- `make verify` exits nonzero for any required failure and cannot report green
  while the audited sandbox skill environment is broken.
- CI performs a no-secrets installer rehearsal and encrypted fixture restore;
  convergence has focused idempotency regressions, and the complete sandbox
  dependency contract is built and exercised natively on amd64 and arm64.
- Routine backup records installed/upstream drift but cannot modify release
  locks; an update advances OpenClaw, component, plugins, schema, and image
  evidence together only after their complete qualification gates pass.

## Verification

- Focused unit tests for every repaired defect.
- Component roundtrip and umbrella `make test`.
- OpenClaw skill registration check and declared-binary audit.
- Targeted doctors and a Sage queue job inside the main sandbox.
- Disposable-host restoration rehearsal plus focused second-run convergence
  checks for component, derived-config, and owner-data materialization.

## Risks

- Installing the OpenClaw CLI in a sandbox would widen its authority; privileged
  operations should use narrow host bridges instead.
- Mutable image tags and unpinned transitive packages defeat reproducibility.
- Exact private-config restoration across OpenClaw schema versions may require
  explicit migrations rather than byte-for-byte copying.
- Owner-data and secrets have different size, sensitivity, and lifecycle needs;
  treating them as one undifferentiated archive can make restores fragile.
