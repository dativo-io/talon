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

# Download
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/talon_${LATEST#v}_${OS}_${ARCH}.tar.gz"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

echo "Downloading..."
TMP_DIR=$(mktemp -d)
trap "rm -rf ${TMP_DIR}" EXIT

curl -sSL -o "${TMP_DIR}/talon.tar.gz" "${DOWNLOAD_URL}"
curl -sSL -o "${TMP_DIR}/checksums.txt" "${CHECKSUM_URL}"

# Verify checksum
echo "Verifying checksum..."
EXPECTED=$(grep "talon_${LATEST#v}_${OS}_${ARCH}.tar.gz" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
ACTUAL=$( (sha256sum "${TMP_DIR}/talon.tar.gz" 2>/dev/null || shasum -a 256 "${TMP_DIR}/talon.tar.gz") | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Error: Checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi
echo "Checksum OK"

# Extract and install
tar -xzf "${TMP_DIR}/talon.tar.gz" -C "${TMP_DIR}"

echo "Installing to ${INSTALL_DIR}..."
if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP_DIR}/talon" "${INSTALL_DIR}/talon"
else
    echo "Requires sudo for ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/talon" "${INSTALL_DIR}/talon"
fi
chmod +x "${INSTALL_DIR}/talon"

# Verify
if command -v talon >/dev/null 2>&1; then
    echo ""
    echo "✓ Talon installed successfully!"
    talon version
else
    echo ""
    echo "✓ Installed. Add ${INSTALL_DIR} to your PATH if needed."
fi
