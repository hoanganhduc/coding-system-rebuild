## [ERR-20260712-001] make-test-manifest-drift

**Logged**: 2026-07-12T14:59:54Z
**Priority**: medium
**Status**: resolved

### Summary

The full repository test failed because a live grok-proxy runtime file was not classified by the fail-closed backup manifest.

### Error

    ERROR: unclassified paths (fail-closed):
        grok-proxy/known_hosts

### Context

- `make test` reached the round-trip sync dry-run after all focused Grok proxy tests passed.
- `known_hosts` is persistent private topology/host-key state, not generated cache data.

### Suggested Fix

Classify every new or newly observed runtime artifact in both `MANIFEST.yaml` and, for private archives, `secrets/secrets-manifest.yaml`; run `bin/sync.sh --dry-run` before the full round-trip gate.

### Canonical Integration Plan

- Related Skills: self-improving-agent
- Related Settings Or Artifacts: manifest, tests
- Affected Install Targets: not_applicable
- Affected OS/Substrates: linux
- Canonical Repo Change: `MANIFEST.yaml`, `secrets/secrets-manifest.yaml`
- Docs And Generated Outputs: not needed
- Verification Plan: `bash bin/sync.sh --dry-run`, then `make test`
- Blocked Or Unsupported Targets: non-Linux substrates uninspected

### Metadata

- Reproducible: yes
- Related Files: `MANIFEST.yaml`, `secrets/secrets-manifest.yaml`, `bin/test-roundtrip.sh`

---
