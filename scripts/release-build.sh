#!/usr/bin/env bash
# The GoReleaser build of a Talon release, in the goreleaser-cross image.
#
#   scripts/release-build.sh release     # release.yml: draft release + version-tagged images
#   scripts/release-build.sh snapshot    # same build and packaging, nothing published
#
# One command for both, so the snapshot rehearsal (release-build-snapshot.yml)
# exercises the build a tag will run.
#
# The image carries the newest goreleaser-cross Go of this line (C
# toolchains, goreleaser, Docker client). The Go toolchain that compiles the
# release is the one go.mod names: a security patch release can be newer than
# any published image, and GOTOOLCHAIN makes the image's go command fetch and
# run exactly that version. What compiled an executable is then read from
# the executable (scripts/release-toolchain-check.sh), not assumed from here.
#
# Environment (release mode): GITHUB_TOKEN, GORELEASER_CURRENT_TAG,
# GORELEASER_PREVIOUS_TAG.
set -euo pipefail

GORELEASER_CROSS_IMAGE="ghcr.io/goreleaser/goreleaser-cross:v1.26.10"

mode="${1:?usage: release-build.sh release|snapshot}"
case "$mode" in
  release) args=(release --clean) ;;
  snapshot) args=(release --clean --snapshot) ;;
  *) echo "release-build: unknown mode '$mode' (release|snapshot)" >&2; exit 2 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."
go_version="$(sed -n 's/^go \([0-9][0-9.]*\)[[:space:]]*$/\1/p' go.mod | head -n1)"
[[ "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-build: go.mod does not name a full Go version" >&2; exit 1; }
echo "release-build: mode=$mode image=$GORELEASER_CROSS_IMAGE toolchain=go$go_version"

mkdir -p "$HOME/.docker"
exec docker run --rm --privileged \
  -v "$PWD:/work" -w /work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.docker:/root/.docker" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN:-}" \
  -e CGO_ENABLED=1 \
  -e GOTOOLCHAIN="go$go_version" \
  -e GORELEASER_CURRENT_TAG="${GORELEASER_CURRENT_TAG:-}" \
  -e GORELEASER_PREVIOUS_TAG="${GORELEASER_PREVIOUS_TAG:-}" \
  "$GORELEASER_CROSS_IMAGE" \
  "${args[@]}"
