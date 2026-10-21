# syntax=docker/dockerfile:1
# Sandbox image for the Talon ↔ OpenShell tool-using reference agent.
# The agent is a static Go binary; the image is deliberately tiny and
# carries NO credential: Talon's hop, OpenShell's credential injection and
# the host-side reviewer are what give it authority. busybox stays for the
# sandbox entrypoint (sleep) and for OpenShell's proxy-mode baseline.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/support-agent .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 agent
COPY --from=build /out/support-agent /usr/local/bin/support-agent
USER agent
WORKDIR /home/agent
LABEL org.opencontainers.image.title="talon-openshell-agent" \
      org.opencontainers.image.source="https://github.com/dativo-io/talon" \
      org.opencontainers.image.description="Tool-using reference agent for the Talon x NVIDIA OpenShell composition (no credentials inside)" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/bin/sleep", "2147483647"]
