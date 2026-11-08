#!/usr/bin/env bash
# Install the pinned Open Policy Agent binary with integrity checks.
#
# Why this exists: CI used to fetch `releases/latest/download/...` with a bare
# `curl -L` and `chmod +x` whatever came back. On 2026-11-08 two runs received
# an HTML "504 Gateway Time-out" page and tried to execute it as OPA. This
# script pins the version, validates the HTTP status, bounds retries, verifies
# the SHA-256 against the value recorded here (copied from the release's own
# `opa_linux_amd64_static.sha256` asset, never guessed), checks that the
# binary reports the pinned version, and only then moves it into place
# atomically. A failed download, a checksum mismatch or a wrong version leaves
# no binary behind.
#
# Usage: scripts/install-opa.sh            (installs to $OPA_INSTALL_DIR, default $HOME/.local/bin)
#        OPA_INSTALL_DIR=/usr/local/bin scripts/install-opa.sh
#
# Environment:
#   OPA_INSTALL_DIR     target directory (created if missing; default $HOME/.local/bin)
#   OPA_DOWNLOAD_BASE   base URL of the release assets; the installer's own
#                       tests point it at a local server (default: GitHub releases)
#   OPA_SHA256          expected digest override — ONLY for scripts/test-install-opa.sh
#                       failure injection; CI never sets it (an override is reported)
set -euo pipefail

OPA_VERSION="1.22.2"
# From https://github.com/open-policy-agent/opa/releases/download/v1.22.2/opa_linux_amd64_static.sha256
OPA_SHA256_LINUX_AMD64="24e344d1fc394cd93dc75666f584cfb97c6981f7255af25f8d2979834317317b"
OPA_ASSET="opa_linux_amd64_static"

OPA_DOWNLOAD_BASE="${OPA_DOWNLOAD_BASE:-https://github.com/open-policy-agent/opa/releases/download}"
OPA_INSTALL_DIR="${OPA_INSTALL_DIR:-$HOME/.local/bin}"
expected_sha="${OPA_SHA256:-$OPA_SHA256_LINUX_AMD64}"

log() { printf 'install-opa: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *) die "pinned asset $OPA_ASSET is linux/amd64 only; this host is $(uname -s)/$(uname -m). Install OPA $OPA_VERSION yourself and put it on PATH." ;;
esac
command -v curl >/dev/null || die "curl is required"
command -v sha256sum >/dev/null || die "sha256sum is required"
if [[ -n "${OPA_SHA256:-}" ]]; then
  log "WARNING: OPA_SHA256 override in effect (test mode); the pinned digest is not being enforced"
fi

target="$OPA_INSTALL_DIR/opa"
verify_installed() {
  local file="$1"
  [[ -x "$file" ]] || return 1
  local have
  have="$(sha256sum "$file" | awk '{print $1}')"
  [[ "$have" == "$expected_sha" ]] || return 1
  "$file" version 2>/dev/null | grep -qx "Version: $OPA_VERSION" || return 1
}

if verify_installed "$target"; then
  log "opa $OPA_VERSION already installed at $target (digest verified)"
  exit 0
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/install-opa.XXXXXX")"
trap 'rm -rf "$work"' EXIT
download="$work/$OPA_ASSET"
url="$OPA_DOWNLOAD_BASE/v$OPA_VERSION/$OPA_ASSET"

log "downloading $url"
# --fail: a 4xx/5xx body (like an HTML 504 page) is an error, never saved as
# the binary. Bounded retries with backoff cover transient failures; the
# connect and total timeouts bound a hanging mirror.
if ! curl --fail --silent --show-error --location \
      --retry 4 --retry-delay 3 --retry-all-errors \
      --connect-timeout 20 --max-time 300 \
      --output "$download" "$url"; then
  die "download failed after retries: $url"
fi
[[ -s "$download" ]] || die "download produced an empty file: $url"

have="$(sha256sum "$download" | awk '{print $1}')"
if [[ "$have" != "$expected_sha" ]]; then
  die "checksum mismatch for $OPA_ASSET: expected $expected_sha, got $have — nothing installed"
fi
chmod 0755 "$download"
reported="$("$download" version 2>/dev/null | grep '^Version:' || true)"
if [[ "$reported" != "Version: $OPA_VERSION" ]]; then
  die "downloaded binary reports '${reported:-<nothing>}', expected 'Version: $OPA_VERSION' — nothing installed"
fi

mkdir -p "$OPA_INSTALL_DIR"
staged="$OPA_INSTALL_DIR/.opa.$$.tmp"
cp "$download" "$staged"
chmod 0755 "$staged"
mv -f "$staged" "$target"   # atomic replace on the same filesystem
verify_installed "$target" || die "post-install verification failed for $target"
log "installed opa $OPA_VERSION to $target (sha256 $have)"
