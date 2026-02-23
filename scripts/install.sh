#!/usr/bin/env bash
set -euo pipefail

# Dativo Talon installer
# Usage: curl -sSL https://get.talon.dativo.io | sh

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

# Get latest release
echo "Fetching latest release..."
LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"
LATEST=$(curl -sSL "${LATEST_URL}" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Error: Failed to fetch latest version. Check network connectivity."
    exit 1
fi

echo "Version: ${LATEST}"

# Windows uses .zip and talon.exe; Linux/macOS use .tar.gz and talon
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

# Download
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET_NAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

echo "Downloading..."
TMP_DIR=$(mktemp -d)
trap "rm -rf ${TMP_DIR}" EXIT

curl -sSL -o "${TMP_DIR}/${ARCHIVE_FILE}" "${DOWNLOAD_URL}"
curl -sSL -o "${TMP_DIR}/checksums.txt" "${CHECKSUM_URL}"

# Verify checksum
echo "Verifying checksum..."
EXPECTED=$(grep "${ASSET_NAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
ACTUAL=$( (sha256sum "${TMP_DIR}/${ARCHIVE_FILE}" 2>/dev/null || shasum -a 256 "${TMP_DIR}/${ARCHIVE_FILE}") | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Error: Checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi
echo "Checksum OK"

# Extract
if [ "$OS" = "windows" ]; then
    if ! command -v unzip >/dev/null 2>&1; then
        echo "Error: unzip is required for Windows install. Install unzip (e.g. from Git for Windows or MSYS2)."
        exit 1
    fi
    unzip -q -o "${TMP_DIR}/${ARCHIVE_FILE}" -d "${TMP_DIR}"
else
    tar -xzf "${TMP_DIR}/${ARCHIVE_FILE}" -C "${TMP_DIR}"
fi

echo "Installing to ${INSTALL_DIR}..."
if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Requires sudo for ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

# Verify
if [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
    echo ""
    echo "✓ Talon installed successfully!"
    "${INSTALL_DIR}/${BINARY_NAME}" version
else
    echo ""
    echo "✓ Installed at ${INSTALL_DIR}/${BINARY_NAME}. Add ${INSTALL_DIR} to your PATH if needed."
fi
