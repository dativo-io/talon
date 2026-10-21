#!/usr/bin/env bash
# Pinned NVIDIA OpenShell releases and their verified download (#482).
# Sourced by the showcase runner and the live lane. Only versions pinned
# here can run: the release tarballs are cached, re-verified against the
# official checksum manifests on every use, and extracted fresh.
#
#   openshell_release_pins <version>   sets OPENSHELL_CLI_SHA / OPENSHELL_GW_SHA for the host arch
#   openshell_release_fetch <version> <bin-dir> <cache-dir>
#                                       downloads/verifies/extracts openshell + openshell-gateway into <bin-dir>
#
# NVIDIA publishes these binaries under its own release terms; nothing here
# repackages or vendors them — they are fetched from the official release.
# shellcheck disable=SC2034  # consumed by the sourcing scripts
OPENSHELL_SUPPORTED_VERSIONS="v0.1.3 v0.1.4"
# shellcheck disable=SC2034
OPENSHELL_BASELINE_VERSION="v0.1.3"   # validated baseline; v0.1.4 is pinned and exercised as the experimental entry

openshell_release_pins() { # version -> sets OPENSHELL_CLI_SHA OPENSHELL_GW_SHA (host arch) or returns 2
  local version="$1" arch; arch="$(uname -m)"
  case "$version:$arch" in
    v0.1.3:x86_64)  OPENSHELL_CLI_SHA="ed08ea7874c47f22d6e5dcc4b27d9ef1ef5d2060f83035b35ff725d5160830a3"; OPENSHELL_GW_SHA="da8dce943fe01cce90243b2bf2587c71a243e4d641a4b616528829b681ced198" ;;
    v0.1.3:aarch64) OPENSHELL_CLI_SHA="07687dacefc52bc73b01943f5b58f7a5082c1ceaa228461b9a2a78023b8057c0"; OPENSHELL_GW_SHA="801214322227f64f2d3faa6989daaa5e6cd9ef1ab768b5860496deeb1158c27b" ;;
    v0.1.4:x86_64)  OPENSHELL_CLI_SHA="2b65178e62e1ece1d90d482555e9f1f98ff0296e058409b33418104b6333df07"; OPENSHELL_GW_SHA="43f43554bcaabff2a8147444410d1ad0b7f51bdae7589c2d249982bc8b260b91" ;;
    v0.1.4:aarch64) OPENSHELL_CLI_SHA="1cd6e63597e1947c44a753bf5352f949e8d8d02e344af92ab899b7c111112d95"; OPENSHELL_GW_SHA="d0f8a2045e613f612a542abe860e497906169c2483093a9bd52e41737df397f0" ;;
    *) echo "MISSING pin: OpenShell $version on $arch has no pinned checksums (supported: $OPENSHELL_SUPPORTED_VERSIONS on x86_64/aarch64)" >&2; return 2 ;;
  esac
  OPENSHELL_ARCH="$arch"
  OPENSHELL_RELEASE_BASE="https://github.com/NVIDIA/OpenShell/releases/download/${version}"
}

openshell_release_fetch() { # version bin-dir cache-dir
  local version="$1" bin="$2" cache="$3"
  local semver="${version#v}"
  openshell_release_pins "$version" || return $?
  mkdir -p "$bin" "$cache"
  _fetch_one() { # name url sha binary
    local name="$1" url="$2" sha="$3" binary="$4"
    local tgz="$cache/$name.tgz"
    if [[ -f "$tgz" ]] && ! echo "$sha  $tgz" | sha256sum -c - >/dev/null 2>&1; then rm -f "$tgz"; fi
    if [[ ! -f "$tgz" ]]; then
      if ! curl -fsSL --retry 3 -o "$tgz.part" "$url"; then echo "FAIL download $name from $url" >&2; return 1; fi
      mv "$tgz.part" "$tgz"
    fi
    echo "$sha  $tgz" | sha256sum -c - >/dev/null || { rm -f "$tgz"; echo "FAIL checksum mismatch for $name (expected $sha)" >&2; return 1; }
    tar -xzf "$tgz" -C "$bin" "$binary" || { echo "FAIL $name archive did not contain $binary" >&2; return 1; }
    [[ -x "$bin/$binary" ]] || { echo "FAIL $binary is not executable" >&2; return 1; }
  }
  _fetch_one "openshell-cli" "$OPENSHELL_RELEASE_BASE/openshell-${OPENSHELL_ARCH}-unknown-linux-musl.tar.gz" "$OPENSHELL_CLI_SHA" "openshell" || return 1
  _fetch_one "openshell-gateway" "$OPENSHELL_RELEASE_BASE/openshell-gateway-${OPENSHELL_ARCH}-unknown-linux-gnu.tar.gz" "$OPENSHELL_GW_SHA" "openshell-gateway" || return 1
  [[ "$("$bin/openshell" --version)" == *"$semver"* ]] || { echo "FAIL unexpected CLI version: $("$bin/openshell" --version)" >&2; return 1; }
  [[ "$("$bin/openshell-gateway" --version)" == *"$semver"* ]] || { echo "FAIL unexpected gateway version: $("$bin/openshell-gateway" --version)" >&2; return 1; }
}
