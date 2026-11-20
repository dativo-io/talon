#!/usr/bin/env bash
# Offline test of scripts/release-toolchain-check.sh: a fake release's assets
# built from a real Go executable. A matching toolchain passes; a go.mod that
# names another version, an executable without Go build information, a
# missing linux archive and an empty bundle all fail. No Docker, no network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/release-toolchain-check.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
V=9.9.9
BUNDLE="talon-openshell-showcase_${V}_linux_amd64"
fail() { echo "FAIL $*" >&2; exit 1; }

# One small CGO-free executable stands in for every artifact: what is under
# test is reading the compiler from a file, per platform.
(cd "$ROOT/examples/openshell/agent" && CGO_ENABLED=0 go build -o "$T/exe" . && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "$T/exe-darwin" .)
built="$(go version "$T/exe" | awk '{print $NF}')"
printf 'module example\n\ngo %s\n' "${built#go}" > "$T/go.mod"
printf 'module example\n\ngo 1.0.1\n' > "$T/other.mod"
printf 'module example\n\ngo 1.26\n' > "$T/short.mod"

assets() { # dir [darwin]
  local d="$1"; mkdir -p "$d/stage/$BUNDLE/bin" "$d/assets"
  cp "$T/exe" "$d/stage/talon"; tar -C "$d/stage" -czf "$d/assets/talon_${V}_linux_amd64.tar.gz" talon
  for b in mockprovider protectedservice describe support-agent; do cp "$T/exe" "$d/stage/$BUNDLE/bin/$b"; done
  tar -C "$d/stage" -czf "$d/assets/$BUNDLE.tar.gz" "$BUNDLE"
  if [ "${2:-}" = darwin ]; then
    cp "$T/exe-darwin" "$d/stage/talon"; tar -C "$d/stage" -czf "$d/assets/talon_${V}_darwin_arm64.tar.gz" talon
  fi
}
run() { bash "$CHECK" "$@" 2>&1; }

assets "$T/good" darwin
out="$(run --go-mod "$T/go.mod" --assets-dir "$T/good/assets" --version "$V" "image talon=$T/exe")" || fail "matching toolchain was refused: $out"
grep -q "^PASS toolchain talon (linux_amd64 archive): $built$" <<<"$out" || fail "linux archive not reported: $out"
grep -q "^PASS toolchain talon (darwin_arm64 archive): $built$" <<<"$out" || fail "darwin archive not reported: $out"
grep -q "^INFO toolchain talon (darwin_amd64 archive): not among the assets" <<<"$out" || fail "absent darwin archive not reported: $out"
grep -q "^PASS toolchain support-agent (showcase bundle, linux/amd64): $built$" <<<"$out" || fail "bundle helper not reported: $out"
grep -q "^PASS toolchain image talon: $built$" <<<"$out" || fail "extra executable not reported: $out"
grep -q "^PASS release-toolchain-check: 7 executable(s) built with $built$" <<<"$out" || fail "verdict: $out"
echo "PASS a release built with the go.mod toolchain is accepted (linux, darwin, bundle, image)"

if out="$(run --go-mod "$T/other.mod" --assets-dir "$T/good/assets" --version "$V")"; then fail "another toolchain was accepted: $out"; fi
grep -q "^FAIL toolchain talon (linux_amd64 archive): built with $built, go.mod names go1.0.1$" <<<"$out" || fail "mismatch message: $out"
echo "PASS an executable built with another toolchain is refused"

if out="$(run --go-mod "$T/short.mod" "x=$T/exe")"; then fail "a go.mod without a patch version was accepted: $out"; fi
echo "PASS a go.mod that does not name a full version is refused"

assets "$T/notgo"
mkdir -p "$T/notgo/stage2/$BUNDLE/bin"; printf '#!/bin/sh\necho hi\n' > "$T/notgo/stage2/$BUNDLE/bin/describe"
tar -C "$T/notgo/stage2" -czf "$T/notgo/assets/$BUNDLE.tar.gz" "$BUNDLE"
if out="$(run --go-mod "$T/go.mod" --assets-dir "$T/notgo/assets" --version "$V")"; then fail "an unreadable executable was accepted: $out"; fi
grep -q "^FAIL toolchain describe (showcase bundle, linux/amd64): build information unreadable" <<<"$out" || fail "unreadable message: $out"
echo "PASS an executable whose build information cannot be read is refused"

assets "$T/nolinux"; rm "$T/nolinux/assets/talon_${V}_linux_amd64.tar.gz"
if out="$(run --go-mod "$T/go.mod" --assets-dir "$T/nolinux/assets" --version "$V")"; then fail "a release without the linux archive was accepted: $out"; fi
echo "PASS a missing linux archive is refused"

assets "$T/empty"; mkdir -p "$T/empty/stage3/$BUNDLE/bin"; tar -C "$T/empty/stage3" -czf "$T/empty/assets/$BUNDLE.tar.gz" "$BUNDLE"
if out="$(run --go-mod "$T/go.mod" --assets-dir "$T/empty/assets" --version "$V")"; then fail "a bundle without executables was accepted: $out"; fi
echo "PASS a bundle without executables is refused"

if out="$(run --go-mod "$T/go.mod" "image agent=$T/absent")"; then fail "a missing extracted executable was accepted: $out"; fi
echo "PASS a missing extracted executable is refused"

echo "ALL PASS release toolchain check"
