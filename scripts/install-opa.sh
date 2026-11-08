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
#        Supported hosts: Linux x86_64/arm64, macOS x86_64/arm64 (the published assets).
#        OPA_INSTALL_DIR=/usr/local/bin scripts/install-opa.sh
#
# Environment:
#   OPA_INSTALL_DIR     target directory (created if missing; default $HOME/.local/bin)
#   OPA_DOWNLOAD_BASE   base URL of the release assets; the installer's own
#                       tests point it at a local server (default: GitHub releases)
#   OPA_SHA256          expected digest override — ONLY for scripts/test-install-opa.sh
#                       failure injection; CI never sets it (an override is reported)
#   OPA_PLATFORM        uname override ("Linux/x86_64") — tests only
set -euo pipefail

OPA_VERSION="1.22.2"
# Digests copied from the release's own *.sha256 assets at
# https://github.com/open-policy-agent/opa/releases/tag/v1.22.2 (never guessed).
# Bump the version and every digest together.
OPA_SHA256_LINUX_AMD64="24e344d1fc394cd93dc75666f584cfb97c6981f7255af25f8d2979834317317b"  # opa_linux_amd64_static
OPA_SHA256_LINUX_ARM64="8fc1c524f93b4369eb207961aba213d990604205fc49fe3ba923dfc125c8a422"  # opa_linux_arm64_static
OPA_SHA256_DARWIN_AMD64="d0b8203cd6c4540c0e0664fee80b13ca4e89b37f1646d73efd6f6417ff635957" # opa_darwin_amd64 (no static build is published)
OPA_SHA256_DARWIN_ARM64="c7767cb68c21c3ea9866a76a2d6703d132a25ddad3cd1c1213925e2802ed1dce" # opa_darwin_arm64_static

OPA_DOWNLOAD_BASE="${OPA_DOWNLOAD_BASE:-https://github.com/open-policy-agent/opa/releases/download}"
OPA_INSTALL_DIR="${OPA_INSTALL_DIR:-$HOME/.local/bin}"

log() { printf 'install-opa: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# OPA_PLATFORM overrides uname for the installer's own tests only.
platform="${OPA_PLATFORM:-$(uname -s)/$(uname -m)}"
case "$platform" in
  Linux/x86_64)          OPA_ASSET="opa_linux_amd64_static"; pinned_sha="$OPA_SHA256_LINUX_AMD64" ;;
  Linux/aarch64|Linux/arm64) OPA_ASSET="opa_linux_arm64_static"; pinned_sha="$OPA_SHA256_LINUX_ARM64" ;;
  Darwin/x86_64)         OPA_ASSET="opa_darwin_amd64"; pinned_sha="$OPA_SHA256_DARWIN_AMD64" ;;
  Darwin/arm64)          OPA_ASSET="opa_darwin_arm64_static"; pinned_sha="$OPA_SHA256_DARWIN_ARM64" ;;
  *) die "no pinned OPA $OPA_VERSION asset for $platform; supported: Linux/x86_64, Linux/arm64, Darwin/x86_64, Darwin/arm64" ;;
esac
expected_sha="${OPA_SHA256:-$pinned_sha}"
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
if [[ -e "$target" ]]; then
  # Whatever sits at the canonical path is not the pinned, verified binary:
  # move it aside now so a failed download never leaves it where callers
  # would pick it up. The rejected file is kept for inspection.
  rejected="$target.rejected.$$"
  mv -f "$target" "$rejected"
  log "existing $target failed digest/version verification; moved to $rejected and reinstalling"
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
