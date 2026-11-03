#!/usr/bin/env bash
# Build the versioned OpenShell showcase bundle (#482, #462/#463/#464, #507):
# the canonical runner, its library and contract test, the helper binaries
# the runner needs (mock provider, protected service, describe probe, the
# sandbox agent for operators who build their own image) and a manifest with
# the sha256 of every binary the runner may execute — talon included — plus
# the pinned agent image reference. The customer path consumes this bundle
# with a published Talon release and never needs a source checkout or a Go
# toolchain; the runner refuses any binary whose digest is not in the
# manifest (TALON_SHOWCASE_RELEASE_MANIFEST), and that includes talon itself.
#
#   scripts/build-showcase-bundle.sh <version> <out-dir> [agent-image-ref] [talon-binary] [talon-archive-name]
#
# talon-binary is the EXACT executable the release ships (extracted from the
# goreleaser archive in the release workflow; `bin/talon` for a local
# bundle). Its `talon version` must report <version>; its sha256 becomes
# `artifacts.talon.sha256`, the digest the runner checks the talon it is
# given against. The manifest never derives this digest from the archive
# checksum (the runner hashes the extracted executable, not the tarball) and
# never from a separately rebuilt binary (it would not match the release).
# With TALON_SHOWCASE_BUNDLE_RELEASE=1 (the release workflow) the binary is
# mandatory: a release manifest without a talon entry makes the documented
# customer path refuse the release's own binary (#507, v1.15.0–v1.15.3).
set -euo pipefail
VERSION="${1:?version (e.g. 1.11.0)}"
OUT="${2:?output directory}"
AGENT_IMAGE="${3:-ghcr.io/dativo-io/talon-openshell-agent:${VERSION}}"
TALON_BIN="${4:-}"
TALON_ARCHIVE="${5:-talon_${VERSION}_linux_amd64.tar.gz}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOOS="${GOOS:-linux}"; GOARCH="${GOARCH:-amd64}"
NAME="talon-openshell-showcase_${VERSION}_${GOOS}_${GOARCH}"
die() { printf 'build-showcase-bundle: %s\n' "$*" >&2; exit 1; }

if [[ -z "$TALON_BIN" && "${TALON_SHOWCASE_BUNDLE_RELEASE:-0}" == 1 ]]; then
  die "release mode requires the released talon binary as the 4th argument: without artifacts.talon the customer path (TALON_SHOWCASE_RELEASE_MANIFEST) refuses the release's own binary (#507)"
fi
TALON_SHA=""
if [[ -n "$TALON_BIN" ]]; then
  [[ -x "$TALON_BIN" ]] || die "talon binary not executable: $TALON_BIN"
  reported="$("$TALON_BIN" version 2>/dev/null | head -n1 || true)"
  [[ "$reported" == "Talon $VERSION" ]] || die "talon binary $TALON_BIN reports '$reported', expected 'Talon $VERSION': the manifest must hash the binary this release ships"
  TALON_SHA="$(sha256sum "$TALON_BIN" | cut -d' ' -f1)"
fi

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
# Manifest: every binary the runner may execute, by sha256. talon is listed
# by the digest of the released executable (path = the release archive it is
# extracted from); the helpers ship in this bundle.
{
  echo '{'
  echo "  \"bundle\": \"$NAME\","
  echo "  \"talon_version\": \"$VERSION\","
  echo "  \"agent_image\": \"$AGENT_IMAGE\","
  echo "  \"openshell_versions\": {\"baseline\": \"v0.1.3\", \"pinned\": [\"v0.1.3\", \"v0.1.4\"]},"
  echo '  "artifacts": {'
  first=1
  if [[ -n "$TALON_SHA" ]]; then
    printf '    "talon": {"path": "%s", "sha256": "%s"}' "$TALON_ARCHIVE" "$TALON_SHA"
    first=0
  fi
  for b in mockprovider protectedservice describe support-agent; do
    [[ $first == 1 ]] || echo ','
    first=0
    printf '    "%s": {"path": "bin/%s", "sha256": "%s"}' "$b" "$b" "$(sha256sum "$STAGE/$NAME/bin/$b" | cut -d' ' -f1)"
  done
  echo
  echo '  }'
  echo '}'
} >"$STAGE/$NAME/showcase-manifest.json"
jq -e . "$STAGE/$NAME/showcase-manifest.json" >/dev/null || die "manifest is not valid JSON"
tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
sha256sum "$OUT/$NAME.tar.gz" | sed "s|$OUT/||" >"$OUT/$NAME.tar.gz.sha256"
cp "$STAGE/$NAME/showcase-manifest.json" "$OUT/$NAME.manifest.json"
echo "bundle: $OUT/$NAME.tar.gz ($(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256"))"
if [[ -n "$TALON_SHA" ]]; then echo "manifest: artifacts.talon.sha256=$TALON_SHA ($TALON_ARCHIVE)"; else echo "manifest: no talon entry (development bundle; the customer path requires a release manifest)"; fi
