# syntax=docker/dockerfile:1
# Workload image for the real-Claude-Code lane of the OpenShell live smoke
# (#528): the REAL, version-pinned Claude Code executable inside a real
# OpenShell v0.1.3 sandbox. The image carries NO credential: OpenShell injects
# the provider key after Talon's PRE_CREDENTIALS decision, and the sandbox
# never holds a Talon agent key, a reviewer credential or a provider key.
#
# The binary is Anthropic's native release build (glibc-linked, needs only
# libc/libm/libdl/libpthread/librt), fetched from the official release
# bucket at an EXACT version and verified against the sha256 of that
# version's manifest (downloads.claude.ai/claude-code-releases/<v>/manifest.json,
# platform linux-x64) before it is installed. The same two values are what
# the harness records in its run facts; a different version is a different
# pin, never a drop-in.
#
# Debian is used (not alpine) because the release binary is glibc-linked;
# curl stays in the image for the harness's in-sandbox fixture precondition
# and for the direct-bypass probe (it is NOT admitted to the provider by the
# sandbox network policy — only /usr/local/bin/claude is).
FROM debian:bookworm-slim
ARG CLAUDE_CODE_VERSION=2.1.319
ARG CLAUDE_CODE_SHA256=dabafec82ca1319fa43d8be36a10fc61b1d11821cb98ad5df04ad95e199b8eed
ARG CLAUDE_CODE_PLATFORM=linux-x64
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL --retry 3 -o /usr/local/bin/claude \
      "https://downloads.claude.ai/claude-code-releases/${CLAUDE_CODE_VERSION}/${CLAUDE_CODE_PLATFORM}/claude" && \
    echo "${CLAUDE_CODE_SHA256}  /usr/local/bin/claude" | sha256sum -c - && \
    chmod 0755 /usr/local/bin/claude && \
    useradd --uid 1000 --create-home --home-dir /home/agent --shell /bin/sh agent
USER agent
WORKDIR /home/agent
# Sanity: the pinned binary runs on this base image and reports its version.
RUN [ "$(/usr/local/bin/claude --version | cut -d' ' -f1)" = "${CLAUDE_CODE_VERSION}" ]
LABEL org.opencontainers.image.title="talon-openshell-claude-code" \
      org.opencontainers.image.source="https://github.com/dativo-io/talon" \
      org.opencontainers.image.description="Pinned real Claude Code executable for the Talon x NVIDIA OpenShell conformance lane (no credentials inside)" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/bin/sleep", "2147483647"]
