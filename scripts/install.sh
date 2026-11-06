#!/bin/sh
# Dativo Talon installer (#359): installs the PUBLISHED release binary, never
# a source build, and fails closed on anything it cannot verify.
#
#   curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/main/scripts/install.sh | sh
#   curl -fsSL https://install.gettalon.dev | sh
#   TALON_VERSION=v1.15.4 INSTALL_DIR="$HOME/.local/bin" sh install.sh
#
# POSIX sh (dash, busybox, bash): the documented `| sh` must work on Debian
# and Ubuntu, whose /bin/sh is dash.
#
# What it does: resolves the release (TALON_VERSION, default `latest`, which
# never returns a draft or a pre-release), downloads the archive for this
# platform, verifies its sha256 against the release's `checksums.txt` entry or
# the archive's own `.sha256` asset, extracts `talon`, checks that it reports
# exactly `Talon <version>`, prints both digests (the archive's and the
# executable's — the latter is what the OpenShell showcase manifest lists as
# `artifacts.talon.sha256`) and only then moves it into INSTALL_DIR.
#
# What it refuses: an archive without a published digest, a digest mismatch,
# a binary that does not report the requested version, and — unless
# TALON_INSTALL_ALLOW_SOURCE=1 — building from source when no prebuilt archive
# exists for the platform (a source build is not the published artifact and
# cannot be verified against the release). Prebuilt archives: linux/amd64
# (the gated installer path), darwin/arm64 and darwin/amd64 (best effort).
#
# Environment:
#   TALON_VERSION                 vX.Y.Z or `latest` (default)
#   INSTALL_DIR                   default /usr/local/bin (sudo when not writable)
#   TALON_INSTALL_ALLOW_SOURCE    1 permits `go install` when no archive exists
#   TALON_RELEASE_REPO, TALON_INSTALL_API_BASE, TALON_INSTALL_DOWNLOAD_BASE
#                                 overrides used by the repository's offline tests
set -eu

REPO="${TALON_RELEASE_REPO:-dativo-io/talon}"
API_BASE="${TALON_INSTALL_API_BASE:-https://api.github.com}"
DOWNLOAD_BASE="${TALON_INSTALL_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REQUESTED="${TALON_VERSION:-latest}"

die() { echo "Error: $*" >&2; exit 1; }
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die "sha256sum or shasum is required"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) die "Unsupported OS: $OS (prebuilt archives exist for linux/amd64, darwin/arm64 and darwin/amd64)" ;;
esac
echo "Platform: ${OS}/${ARCH}"

# ---------------------------------------------------------------- release metadata
if [ "$REQUESTED" = "latest" ]; then
  RELEASE_URL="${API_BASE}/repos/${REPO}/releases/latest"
else
  case "$REQUESTED" in v*) ;; *) die "TALON_VERSION must be a tag like v1.15.4 (got '$REQUESTED')" ;; esac
  RELEASE_URL="${API_BASE}/repos/${REPO}/releases/tags/${REQUESTED}"
fi
echo "Fetching release metadata (${REQUESTED})..."
# GH_TOKEN / GITHUB_TOKEN, when present, authenticate this metadata read only
# (CI runners share rate-limited IPs); the archive download stays anonymous.
if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
  RELEASE_JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' -H "Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN:-}}" "$RELEASE_URL")" || die "cannot fetch $RELEASE_URL (no such published release, or no network)"
else
  RELEASE_JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' "$RELEASE_URL")" || die "cannot fetch $RELEASE_URL (no such published release, or no network)"
fi
TAG="$(printf '%s' "$RELEASE_JSON" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
[ -n "$TAG" ] || die "release metadata has no tag_name"
if [ "$REQUESTED" != "latest" ] && [ "$TAG" != "$REQUESTED" ]; then die "release metadata is for $TAG, requested $REQUESTED"; fi
case "$(printf '%s' "$RELEASE_JSON" | sed -n 's/.*"draft": *\(true\|false\).*/\1/p' | head -n1)" in
  true) die "$TAG is a draft release; it is not published" ;;
esac
VERSION="${TAG#v}"
echo "Version: ${TAG}"

ASSET_NAME="talon_${VERSION}_${OS}_${ARCH}.tar.gz"
asset_listed() { printf '%s' "$RELEASE_JSON" | grep -q "\"name\": *\"$1\""; }

if ! asset_listed "$ASSET_NAME"; then
  echo "No prebuilt archive ${ASSET_NAME} in ${TAG}."
  if [ "${TALON_INSTALL_ALLOW_SOURCE:-0}" != "1" ]; then
    cat >&2 <<EOT
Error: no published binary for ${OS}/${ARCH}; this installer does not build from source by default
  (a source build is not the released artifact and cannot be verified against the release).
  Options:
    1. Supported path: a linux/amd64 host (release archive verified by checksum).
    2. Build from source knowingly (Go 1.26+ with CGO):
         go install github.com/dativo-io/talon/cmd/talon@${TAG}
       or re-run with TALON_INSTALL_ALLOW_SOURCE=1 to let this script do that.
EOT
    exit 1
  fi
  command -v go >/dev/null 2>&1 || die "TALON_INSTALL_ALLOW_SOURCE=1 but Go is not installed"
  echo "TALON_INSTALL_ALLOW_SOURCE=1: installing from source with go install (${TAG}); this is NOT the published artifact."
  if [ "$OS" = "darwin" ]; then
    env -u CC CC=/usr/bin/clang CGO_ENABLED=1 go install "github.com/dativo-io/talon/cmd/talon@${TAG}" || die "go install failed"
  else
    CGO_ENABLED=1 go install "github.com/dativo-io/talon/cmd/talon@${TAG}" || die "go install failed"
  fi
  GOPATH_BIN="$(go env GOPATH)/bin"
  echo "Installed from source to ${GOPATH_BIN}/talon (ensure ${GOPATH_BIN} is on your PATH)."
  exit 0
fi

# ---------------------------------------------------------------- download and verify
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/talon-install.XXXXXX")"
trap 'rm -rf "${TMP_DIR:?}"' EXIT INT TERM
ARCHIVE="${TMP_DIR}/${ASSET_NAME}"
echo "Downloading ${ASSET_NAME}..."
curl -fsSL --retry 3 --retry-delay 2 -o "$ARCHIVE" "${DOWNLOAD_BASE}/${TAG}/${ASSET_NAME}" || die "download failed: ${DOWNLOAD_BASE}/${TAG}/${ASSET_NAME}"

# The digest comes from the release's checksums.txt (goreleaser; the linux
# archive) or from the archive's own .sha256 asset (the darwin archives).
EXPECTED=""
if curl -fsSL --retry 3 --retry-delay 2 -o "${TMP_DIR}/checksums.txt" "${DOWNLOAD_BASE}/${TAG}/checksums.txt" 2>/dev/null; then
  EXPECTED="$(awk -v n="$ASSET_NAME" '$2 == n {print $1}' "${TMP_DIR}/checksums.txt" | head -n1)"
fi
if [ -z "$EXPECTED" ] && curl -fsSL --retry 3 --retry-delay 2 -o "${TMP_DIR}/${ASSET_NAME}.sha256" "${DOWNLOAD_BASE}/${TAG}/${ASSET_NAME}.sha256" 2>/dev/null; then
  EXPECTED="$(awk '{print $1}' "${TMP_DIR}/${ASSET_NAME}.sha256" | head -n1)"
fi
[ -n "$EXPECTED" ] || die "no published sha256 for ${ASSET_NAME} (neither checksums.txt nor ${ASSET_NAME}.sha256 lists it); refusing to install an unverifiable archive"
case "$EXPECTED" in *[!0-9a-f]*) die "published digest for ${ASSET_NAME} is not a sha256: '$EXPECTED'" ;; esac
[ "${#EXPECTED}" -eq 64 ] || die "published digest for ${ASSET_NAME} is not a sha256: '$EXPECTED'"
ACTUAL="$(sha256_of "$ARCHIVE")"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch for ${ASSET_NAME}" >&2
  echo "  published: $EXPECTED" >&2
  echo "  downloaded: $ACTUAL" >&2
  exit 1
fi
echo "Checksum OK: ${ASSET_NAME} sha256 ${ACTUAL}"

tar -xzf "$ARCHIVE" -C "$TMP_DIR" talon || die "archive does not contain talon at its root"
BINARY="${TMP_DIR}/talon"
[ -f "$BINARY" ] || die "talon not found in archive"
chmod 0755 "$BINARY"
REPORTED="$("$BINARY" version 2>/dev/null | head -n1 || true)"
[ "$REPORTED" = "Talon ${VERSION}" ] || die "extracted binary reports '${REPORTED}', expected 'Talon ${VERSION}'"
BINARY_SHA="$(sha256_of "$BINARY")"
echo "Executable OK: talon reports '${REPORTED}', sha256 ${BINARY_SHA}"

# ---------------------------------------------------------------- install
echo "Installing to ${INSTALL_DIR}..."
if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY" "${INSTALL_DIR}/talon"
elif [ ! -e "$INSTALL_DIR" ] && mkdir -p "$INSTALL_DIR" 2>/dev/null; then
  mv "$BINARY" "${INSTALL_DIR}/talon"
else
  command -v sudo >/dev/null 2>&1 || die "${INSTALL_DIR} is not writable and sudo is unavailable; set INSTALL_DIR to a writable directory"
  echo "Requires sudo for ${INSTALL_DIR}"
  sudo mkdir -p "$INSTALL_DIR"
  sudo mv "$BINARY" "${INSTALL_DIR}/talon"
  sudo chmod 0755 "${INSTALL_DIR}/talon"
fi
[ -x "${INSTALL_DIR}/talon" ] || die "installation failed: ${INSTALL_DIR}/talon is not executable"
echo ""
echo "Talon ${TAG} installed: ${INSTALL_DIR}/talon"
echo "  archive sha256    ${ACTUAL}  (${ASSET_NAME})"
echo "  executable sha256 ${BINARY_SHA}  (the OpenShell showcase manifest's artifacts.talon.sha256)"
"${INSTALL_DIR}/talon" version
case ":${PATH}:" in *":${INSTALL_DIR}:"*) ;; *) echo "Add ${INSTALL_DIR} to your PATH." ;; esac
