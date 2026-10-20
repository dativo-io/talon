#!/usr/bin/env bash
# Build the versioned OpenShell showcase bundle (#482, #462/#463/#464): the
# canonical runner, its library and contract test, the helper binaries the
# runner needs (mock provider, protected service, describe probe, the
# sandbox agent for operators who build their own image) and a manifest
# with the sha256 of every binary plus the pinned agent image reference. The
# customer path consumes this bundle with a published Talon release and
# never needs a source checkout or a Go toolchain; the runner refuses any
# binary whose digest is not in the manifest (TALON_SHOWCASE_RELEASE_MANIFEST).
#
#   scripts/build-showcase-bundle.sh <version> <out-dir> [agent-image-ref]
set -euo pipefail
VERSION="${1:?version (e.g. 1.11.0)}"
OUT="${2:?output directory}"
AGENT_IMAGE="${3:-ghcr.io/dativo-io/talon-openshell-agent:${VERSION}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOOS="${GOOS:-linux}"; GOARCH="${GOARCH:-amd64}"
NAME="talon-openshell-showcase_${VERSION}_${GOOS}_${GOARCH}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/showcase-bundle.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME/bin" "$OUT"
cp "$ROOT/examples/openshell/showcase/demo.sh" "$ROOT/examples/openshell/showcase/test-contract.sh" "$ROOT/examples/openshell/showcase/README.md" "$STAGE/$NAME/"
cp -r "$ROOT/examples/openshell/showcase/lib" "$STAGE/$NAME/lib"
cp "$ROOT/LICENSE" "$STAGE/$NAME/"
build() { # name package dir
  (cd "$3" && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" -o "$STAGE/$NAME/bin/$1" "$2")
}
build mockprovider ./tests/openshell-live/mockprovider "$ROOT"
build protectedservice ./tests/openshell-live/protectedservice "$ROOT"
build describe ./tests/openshell-live/describe "$ROOT"
build support-agent . "$ROOT/examples/openshell/agent"
# Manifest: every binary the runner may execute, by sha256; talon itself is
# listed by the release's own checksums (the runner verifies the talon it is
# given against the manifest when the operator copies that entry in).
{
  echo '{'
  echo "  \"bundle\": \"$NAME\","
  echo "  \"talon_version\": \"$VERSION\","
  echo "  \"agent_image\": \"$AGENT_IMAGE\","
  echo "  \"openshell_versions\": {\"baseline\": \"v0.1.3\", \"pinned\": [\"v0.1.3\", \"v0.1.4\"]},"
  echo '  "artifacts": {'
  first=1
  for b in mockprovider protectedservice describe support-agent; do
    [[ $first == 1 ]] || echo ','
    first=0
    printf '    "%s": {"path": "bin/%s", "sha256": "%s"}' "$b" "$b" "$(sha256sum "$STAGE/$NAME/bin/$b" | cut -d' ' -f1)"
  done
  echo
  echo '  }'
  echo '}'
} >"$STAGE/$NAME/showcase-manifest.json"
tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
sha256sum "$OUT/$NAME.tar.gz" | sed "s|$OUT/||" >"$OUT/$NAME.tar.gz.sha256"
cp "$STAGE/$NAME/showcase-manifest.json" "$OUT/$NAME.manifest.json"
echo "bundle: $OUT/$NAME.tar.gz ($(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256"))"
