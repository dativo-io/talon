#!/usr/bin/env bash
# Which Go toolchain compiled the executables a release distributes.
#
#   scripts/release-toolchain-check.sh --go-mod FILE \
#       [--assets-dir DIR --version X.Y.Z [--work-dir DIR]] [LABEL=EXECUTABLE ...]
#
# The expected toolchain is the `go` directive of FILE (the release's own
# go.mod). Every executable is read with `go version <file>`, which reports
# the compiler recorded in the binary itself: the builder image's tag and the
# GOTOOLCHAIN the build was started with are not evidence. A different
# toolchain, or an executable whose build information cannot be read, fails.
#
# --assets-dir checks the release assets: `talon` from the linux/amd64
# archive and every helper under the showcase bundle's bin/ are required;
# a darwin archive is checked when present (those archives are best effort,
# #359). LABEL=EXECUTABLE adds files extracted elsewhere, for example from
# the released container images.
#
# Needs `go` on PATH (any version that reads build information), tar.
set -euo pipefail

GO_MOD=""; ASSETS_DIR=""; VERSION=""; WORK_DIR=""; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --go-mod) GO_MOD="$2"; shift 2 ;;
    --assets-dir) ASSETS_DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    *=*) EXTRA+=("$1"); shift ;;
    *) echo "release-toolchain-check: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
[ -n "$GO_MOD" ] || { echo "release-toolchain-check: --go-mod FILE is required" >&2; exit 2; }
command -v go >/dev/null || { echo "release-toolchain-check: go is not on PATH" >&2; exit 2; }

want_version="$(sed -n 's/^go \([0-9][0-9.]*\)[[:space:]]*$/\1/p' "$GO_MOD" 2>/dev/null | head -n1)"
if [[ ! "$want_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "FAIL release-toolchain-check: $GO_MOD does not name a full Go version (go MAJOR.MINOR.PATCH)" >&2
  exit 1
fi
WANT="go$want_version"

fails=0; checked=0
check() { # label file
  local label="$1" file="$2" out got
  if [ ! -f "$file" ]; then
    echo "FAIL toolchain $label: no executable at $file"; fails=$((fails + 1)); return
  fi
  # `go version` exits 0 and prints nothing for a file it does not
  # recognize, so the reported version is validated, not the exit status.
  out="$(go version "$file" 2>/dev/null || true)"
  got="${out##* }"
  if [[ ! "$got" =~ ^go[0-9]+\.[0-9]+ ]]; then
    echo "FAIL toolchain $label: build information unreadable (not a Go executable, or stripped of it)"; fails=$((fails + 1)); return
  fi
  if [ "$got" != "$WANT" ]; then
    echo "FAIL toolchain $label: built with $got, go.mod names $WANT"; fails=$((fails + 1)); return
  fi
  echo "PASS toolchain $label: $got"; checked=$((checked + 1))
}

if [ -n "$ASSETS_DIR" ]; then
  [ -n "$VERSION" ] || { echo "release-toolchain-check: --assets-dir needs --version" >&2; exit 2; }
  if [ -z "$WORK_DIR" ]; then WORK_DIR="$(mktemp -d)"; trap 'rm -rf "$WORK_DIR"' EXIT; fi
  mkdir -p "$WORK_DIR"

  for platform in linux_amd64 darwin_arm64 darwin_amd64; do
    archive="$ASSETS_DIR/talon_${VERSION}_${platform}.tar.gz"
    if [ ! -s "$archive" ]; then
      if [ "$platform" = linux_amd64 ]; then
        echo "FAIL toolchain talon ($platform archive): $(basename "$archive") is not among the assets"; fails=$((fails + 1))
      else
        echo "INFO toolchain talon ($platform archive): not among the assets (best effort, #359)"
      fi
      continue
    fi
    mkdir -p "$WORK_DIR/$platform"
    tar -C "$WORK_DIR/$platform" -xzf "$archive" talon 2>/dev/null || true
    check "talon ($platform archive)" "$WORK_DIR/$platform/talon"
  done

  bundle="talon-openshell-showcase_${VERSION}_linux_amd64"
  if [ ! -s "$ASSETS_DIR/$bundle.tar.gz" ]; then
    echo "FAIL toolchain showcase bundle: $bundle.tar.gz is not among the assets"; fails=$((fails + 1))
  else
    mkdir -p "$WORK_DIR/bundle"
    tar -C "$WORK_DIR/bundle" -xzf "$ASSETS_DIR/$bundle.tar.gz" 2>/dev/null || true
    helpers=0
    for f in "$WORK_DIR/bundle/$bundle/bin"/*; do
      [ -f "$f" ] || continue
      check "$(basename "$f") (showcase bundle, linux/amd64)" "$f"; helpers=$((helpers + 1))
    done
    if [ "$helpers" -eq 0 ]; then
      echo "FAIL toolchain showcase bundle: no executables under $bundle/bin"; fails=$((fails + 1))
    fi
  fi
fi

for item in ${EXTRA[@]+"${EXTRA[@]}"}; do
  check "${item%%=*}" "${item#*=}"
done

if [ "$fails" -gt 0 ]; then
  echo "FAIL release-toolchain-check: $fails executable(s) not verified as built with $WANT"
  exit 1
fi
if [ "$checked" -eq 0 ]; then
  echo "FAIL release-toolchain-check: nothing was checked"
  exit 1
fi
echo "PASS release-toolchain-check: $checked executable(s) built with $WANT"
