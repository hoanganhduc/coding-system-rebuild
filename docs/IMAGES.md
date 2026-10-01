# Docker and immutable OCI images

Docker image layers are not part of the secrets or private-state backup. The
repository stores only immutable registry references and their architecture
manifest digests. A restore pulls the required layers again from the registry.
It does not create, upload, or restore Docker image tarballs. Registry
credentials, when a locked image is private, are restored first from
`~/.docker/config.json`; the image bytes remain registry artifacts.

Preview the exact pull commands without contacting Docker:

```bash
python3 system/software/pull-locked-images.py --dry-run
```

Pull and verify the currently qualified runtime images selected for the current
architecture:

```bash
python3 system/software/pull-locked-images.py
```

The helper pulls every architecture-compatible entry admitted by the image lock
and rejects missing or duplicate runtime roles. The currently promoted runtime
roles are:

| Role | amd64 | arm64 |
|---|---|---|
| OpenClaw sandbox | repository-owned multi-platform image | repository-owned multi-platform image |
| SageMath | official SageMath 10.8 image | owner-built SageMath 10.8 image |
| Zotero Translation Server | owner-built image | official Zotero image |

The Python closure has a separate artifact-only OCI candidate pipeline described
in [PYTHON-CLOSURE.md](PYTHON-CLOSURE.md).  It is intentionally absent from the
current image lock until native amd64 and arm64 offline-install gates pass and a
reviewer promotes the resulting multi-platform digest.  Its image contains no
runtime or package manager and is extracted with `docker create`/`docker cp`; it
is never run.  Candidate image layers and wheels are not part of the secrets
backup, and the workflow never mutates the image lock automatically. Once
promoted, the same pull helper admits the additional `python-wheelhouse` role;
it does not assume a fixed image count.

The OpenClaw sandbox contract is version 3. It includes isolated, CPU-only
Docling and LeanExplore environments plus the course-management environment under
`/opt/coding-system/python-closure/`, built from the same canonical wheelhouse
inputs used by host restoration. Contract v3 additionally runs the Classroom50
adapter help probe. The current compatibility and image locks select the same
multi-platform contract-v3 digest. The compatibility verifier checks the image
label independently before it executes the image contract; launchers never
bootstrap packages at runtime.

The image's build-time default user is recorded separately from the runtime
identity. OpenClaw launches the sandbox as the restored host owner's UID/GID so
bind-mounted workspaces remain writable without `chmod 777`, while the
contract probe uses the declared image identity for isolated image tests.

`system/software/images.lock.json` records the OCI index digest and resolved
platform-manifest digest for every selection. The compatibility lock, the
machine-readable image lock, and `system/packages/docker-images.txt` must agree.
Mutable tags, including `latest`, are rejected.

Docker documents that [pulling by digest selects an immutable image
version](https://docs.docker.com/reference/cli/docker/image/pull/). The Zotero
project documents the Translation Server container and its `/web`, `/search`,
`/export`, and `/import` endpoints in its
[official repository](https://github.com/zotero/translation-server).

After a pull, full verification must additionally run the OpenClaw sandbox
contract, a bounded SageMath calculation, and a deterministic Translation
Server request. Registry authentication is restored before private GHCR pulls.
If the selected locked digest cannot be pulled from its declared registry,
restoration fails; this checkout has no mirror fallback. It never falls back to
a mutable tag or an image tarball from the backup.

## Updating an image lock

An upstream tag moving or a new image release does not change an existing
recovery set. To adopt an update, build/resolve the candidate for both
`linux/amd64` and `linux/arm64`, record the immutable index plus platform
manifest digests, run the role-specific offline and functional contracts, and
review the compatibility lock and every parent platform-lock hash that binds
it. Only a reviewed promotion changes `images.lock.json`; workflows may publish
candidates but never rewrite the production lock automatically. Publish that
repository commit and create a new recovery set after qualification.

Image qualification does not override other artifact gates. A contract-v3
sandbox digest can be correctly locked while the platform, Python wheelhouse,
or privileged Grok artifacts remain pending; full restore reports their
`ARTIFACT_UNAVAILABLE` state instead of claiming the whole machine is ready.
