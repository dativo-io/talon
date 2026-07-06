#!/usr/bin/env bash
set -euo pipefail

# Dativo Talon installer
# Usage: curl -sSL https://install.gettalon.dev | sh
#
# Prebuilt release assets: linux/amd64 only (see README install matrix).
# Other platforms fall back to "go install" when Go + CGO are available.

REPO="dativo-io/talon"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    linux|darwin) ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *)
        echo "Error: Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Platform: ${OS}/${ARCH}"

# Get latest release metadata
echo "Fetching latest release..."
LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"
RELEASE_JSON=$(curl -sSL "${LATEST_URL}")

if [ -z "$RELEASE_JSON" ] || ! echo "$RELEASE_JSON" | grep -q '"tag_name"'; then
    echo "Error: Failed to fetch latest version. Check network connectivity."
    exit 1
fi

LATEST=$(echo "$RELEASE_JSON" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
echo "Version: ${LATEST}"

VERSION_STR="${LATEST#v}"
if [ "$OS" = "windows" ]; then
    ARCHIVE_EXT="zip"
    ARCHIVE_FILE="talon.zip"
    BINARY_NAME="talon.exe"
else
    ARCHIVE_EXT="tar.gz"
    ARCHIVE_FILE="talon.tar.gz"
    BINARY_NAME="talon"
fi
ASSET_NAME="talon_${VERSION_STR}_${OS}_${ARCH}.${ARCHIVE_EXT}"

asset_available() {
    echo "$RELEASE_JSON" | grep -q "\"name\": *\"${ASSET_NAME}\""
}

install_via_go() {
    if ! command -v go >/dev/null 2>&1; then
        echo "Error: No prebuilt binary for ${OS}/${ARCH} in ${LATEST}, and Go is not installed."
        echo ""
        echo "Options:"
        echo "  1. Install Go 1.22+ with CGO enabled, then:"
        echo "       go install github.com/dativo-io/talon/cmd/talon@${LATEST}"
        echo "     On macOS if linking fails, use:"
        echo "       CC=/usr/bin/clang CGO_ENABLED=1 go install github.com/dativo-io/talon/cmd/talon@${LATEST}"
        echo "  2. Clone the repo and run: make install"
        echo ""
        echo "Prebuilt tarballs are published for linux/amd64 only."
        exit 1
    fi

    echo "No prebuilt binary for ${OS}/${ARCH} in ${LATEST}."
    echo "Installing via go install (${LATEST})..."
    GO_ENV=(env CGO_ENABLED=1)
    if [ "$OS" = "darwin" ]; then
        GO_ENV=(env -u CC CC=/usr/bin/clang CGO_ENABLED=1)
    fi
    if ! "${GO_ENV[@]}" go install "github.com/dativo-io/talon/cmd/talon@${LATEST}"; then
        echo "go install failed. On macOS try: CC=/usr/bin/clang CGO_ENABLED=1 go install github.com/dativo-io/talon/cmd/talon@${LATEST}"
        exit 1
    fi

    GOPATH_BIN=$(go env GOPATH)/bin
    if [ -x "${GOPATH_BIN}/talon" ]; then
        echo ""
        echo "✓ Talon installed to ${GOPATH_BIN}/talon"
        echo "  Ensure ${GOPATH_BIN} is on your PATH."
        "${GOPATH_BIN}/talon" version
    else
        echo "✓ go install completed. Ensure \$(go env GOPATH)/bin is on your PATH."
    fi
    exit 0
}

if ! asset_available; then
    install_via_go
fi

# Download prebuilt asset
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET_NAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

echo "Downloading ${ASSET_NAME}..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

if ! curl -fsSL -o "${TMP_DIR}/${ARCHIVE_FILE}" "${DOWNLOAD_URL}"; then
    echo "Error: Download failed for ${ASSET_NAME}"
    install_via_go
fi
curl -fsSL -o "${TMP_DIR}/checksums.txt" "${CHECKSUM_URL}"

# Verify checksum
echo "Verifying checksum..."
EXPECTED=$(grep "${ASSET_NAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
    echo "Error: ${ASSET_NAME} not found in checksums.txt"
    exit 1
fi
ACTUAL=$( (sha256sum "${TMP_DIR}/${ARCHIVE_FILE}" 2>/dev/null || shasum -a 256 "${TMP_DIR}/${ARCHIVE_FILE}") | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Error: Checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi
echo "Checksum OK"

# Extract (goreleaser archives place the binary at the archive root)
if [ "$OS" = "windows" ]; then
    if ! command -v unzip >/dev/null 2>&1; then
        echo "Error: unzip is required for Windows install."
        exit 1
    fi
    unzip -q -o "${TMP_DIR}/${ARCHIVE_FILE}" -d "${TMP_DIR}"
else
    tar -xzf "${TMP_DIR}/${ARCHIVE_FILE}" -C "${TMP_DIR}"
fi

if [ ! -f "${TMP_DIR}/${BINARY_NAME}" ]; then
    # Some archives nest one directory level
    NESTED=$(find "${TMP_DIR}" -maxdepth 2 -name "${BINARY_NAME}" -type f | head -1)
    if [ -n "$NESTED" ]; then
        BINARY_PATH="$NESTED"
    else
        echo "Error: ${BINARY_NAME} not found in archive"
        exit 1
    fi
else
    BINARY_PATH="${TMP_DIR}/${BINARY_NAME}"
fi

echo "Installing to ${INSTALL_DIR}..."
if [ -w "${INSTALL_DIR}" ]; then
    mv "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Requires sudo for ${INSTALL_DIR}"
    sudo mv "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
fi
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

if [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
    echo ""
    echo "✓ Talon installed successfully!"
    "${INSTALL_DIR}/${BINARY_NAME}" version
else
    echo ""
    echo "✓ Installed at ${INSTALL_DIR}/${BINARY_NAME}. Add ${INSTALL_DIR} to your PATH if needed."
fi
