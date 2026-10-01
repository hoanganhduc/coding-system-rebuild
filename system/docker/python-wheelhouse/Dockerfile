# syntax=docker/dockerfile:1.7

# The builder base is the Docker Official Image index observed on 2026-08-04.
# Refreshing it is a reviewed build-input change; wheelhouse release locks are
# never updated by the build workflow itself.
ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
FROM ${UBUNTU_IMAGE} AS builder

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_INPUT=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates git python3 python3-dev python3-pip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY system/packages/requirements/ /src/system/packages/requirements/
COPY system/docker/python-wheelhouse/ /src/system/docker/python-wheelhouse/

RUN test "$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" = 3.12 \
 && test "$(dpkg --print-architecture)" = "${TARGETARCH}" \
 && python3 /src/system/docker/python-wheelhouse/build-wheelhouse.py \
      --source-root /src \
      --output /out/wheelhouse \
      --platform "linux/${TARGETARCH}"

# Deliberately no shell, Python, pip, package manager, certificates, or source.
# The final filesystem contains only /wheelhouse and its canonical manifests.
FROM scratch AS artifact
LABEL org.opencontainers.image.title="coding-system-rebuild Python wheelhouse" \
      org.opencontainers.image.description="Artifact-only CPython 3.12 wheels; never execute this image"
COPY --from=builder /out/wheelhouse /wheelhouse
