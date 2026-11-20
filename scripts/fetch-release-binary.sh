#!/usr/bin/env bash
# Download the linux/amd64 talon executable of a PUBLISHED release into a
# directory, verified against the release's checksums.txt, and check that it
# reports that version. Prints the path of the executable.
#
#   scripts/fetch-release-binary.sh 1.16.1 /tmp/prev    →  /tmp/prev/talon
set -euo pipefail
VERSION="${1:?usage: fetch-release-binary.sh <version> <dir>}"; VERSION="${VERSION#v}"
DIR="${2:?usage: fetch-release-binary.sh <version> <dir>}"
REPO="${GITHUB_REPOSITORY:-dativo-io/talon}"
BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
ARCHIVE="talon_${VERSION}_linux_amd64.tar.gz"
mkdir -p "$DIR"
curl -fsSL --retry 3 -o "$DIR/$ARCHIVE" "$BASE/$ARCHIVE"
curl -fsSL --retry 3 -o "$DIR/checksums.txt" "$BASE/checksums.txt"
(cd "$DIR" && grep -F " $ARCHIVE" checksums.txt | sha256sum -c - >&2 && tar xzf "$ARCHIVE" talon)
got="$("$DIR/talon" version | sed -n 1p)"
[ "$got" = "Talon $VERSION" ] || { echo "fetch-release-binary: expected 'Talon $VERSION', got '$got'" >&2; exit 1; }
echo "$DIR/talon"
