# syntax=docker/dockerfile:1.7
ARG PYTHON_BASE=python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
ARG DEBIAN_SNAPSHOT=20260727T000000Z

FROM ${PYTHON_BASE} AS wheelhouse
ARG DEBIAN_SNAPSHOT
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends build-essential git libqpdf-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY system/packages/requirements/getscipapers-sources.txt /locks/getscipapers-sources.txt
COPY system/packages/requirements/getscipapers-runtime.txt /locks/getscipapers-runtime.txt
COPY system/packages/requirements/workspace-local.txt /locks/workspace-local.txt
RUN python -m pip wheel --disable-pip-version-check --no-cache-dir --no-deps \
      --wheel-dir /wheelhouse -r /locks/getscipapers-sources.txt \
    && python -m pip wheel --disable-pip-version-check --no-cache-dir --no-deps \
      --wheel-dir /wheelhouse --find-links /wheelhouse \
      -r /locks/getscipapers-runtime.txt -r /locks/workspace-local.txt

FROM ${PYTHON_BASE}
ARG TARGETARCH
ARG NODE_VERSION=22.23.2
ARG NODE_SHA256_AMD64=d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307
ARG NODE_SHA256_ARM64=fff4078c5def658577f92c88db7db3bc0072924bfb93fe52c1e744a54e94abb8
ARG DEBIAN_SNAPSHOT

LABEL org.opencontainers.image.source="https://github.com/hoanganhduc/coding-system-rebuild" \
      org.opencontainers.image.description="Closure-complete OpenClaw skill sandbox" \
      io.hoanganhduc.openclaw-sandbox.contract="1"

RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates calibre chromium chromium-driver curl dvisvgm ffmpeg git gh gnupg jq \
      latexmk openssh-client pandoc poppler-utils p7zip-full rclone texlive-fonts-recommended \
      texlive-latex-base texlive-latex-extra texlive-pictures tmux unzip \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
      amd64) node_arch=x64; expected="$NODE_SHA256_AMD64" ;; \
      arm64) node_arch=arm64; expected="$NODE_SHA256_ARM64" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 2 ;; \
    esac \
    && archive="node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      --output "/tmp/${archive}" "https://nodejs.org/dist/v${NODE_VERSION}/${archive}" \
    && printf '%s  %s\n' "$expected" "/tmp/${archive}" | sha256sum --check --strict \
    && mkdir /tmp/node-release \
    && python -c 'import sys, tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2], filter="data")' \
      "/tmp/${archive}" /tmp/node-release \
    && cp -a "/tmp/node-release/node-v${NODE_VERSION}-linux-${node_arch}/." /usr/local/ \
    && rm -rf "/tmp/${archive}" /tmp/node-release \
    && node --version | grep -Fx "v${NODE_VERSION}"

COPY --from=wheelhouse /wheelhouse /wheelhouse
COPY system/packages/requirements/getscipapers-runtime.txt /locks/getscipapers-runtime.txt
COPY system/packages/requirements/workspace-local.txt /locks/workspace-local.txt
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
      --no-index --find-links /wheelhouse --no-deps \
      -r /locks/getscipapers-runtime.txt -r /locks/workspace-local.txt \
    && python -m pip check \
    && rm -rf /wheelhouse

COPY system/docker/openclaw-sandbox/verify.sh /usr/local/bin/verify-openclaw-sandbox
RUN chmod 0755 /usr/local/bin/verify-openclaw-sandbox \
    && useradd --create-home --uid 1001 --shell /bin/bash sandbox \
    && mkdir -p /workspace \
    && chown 1001:1001 /workspace \
    && /usr/local/bin/verify-openclaw-sandbox --build

USER 1001:1001
WORKDIR /workspace
ENV HOME=/workspace PYTHONUNBUFFERED=1
CMD ["bash"]
