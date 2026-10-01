#!/usr/bin/env bash
# Regenerates the Go types for the pinned OpenShell supervisor-middleware
# wire contract (internal/openshell/proto/v0.1.2/*.proto, upstream tag
# v0.1.2). buf runs as a Go tool, so no protoc installation is required.
# Generated code is checked in; run this only when the pinned protos change.
set -euo pipefail
cd "$(dirname "$0")/../internal/openshell/proto"
export BUF_CACHE_DIR="${BUF_CACHE_DIR:-${TMPDIR:-/tmp}/talon-buf-cache}"
mkdir -p "$BUF_CACHE_DIR"
go run github.com/bufbuild/buf/cmd/buf@v1.57.2 generate
echo "generated: $(find gen -name '*.pb.go' | sort | tr '\n' ' ')"
