#!/usr/bin/env bash
# Which release-acceptance gates apply to a release tag.
#
#   scripts/release-capabilities.sh <tag>      # prints: console=true|false
#                                              #         quickstart=true|false
#                                              #         toolchain=true|false
#
# The Operations Console (talon ui, the talon-ui Compose service and their
# acceptance scripts) ships from v1.17.0, release candidates included. An
# audit of an older release (release.yml and install-smoke.yml with an
# explicit tag) reports the console gates as NOT APPLICABLE instead of
# failing on a feature that release never had. The published-image
# quickstart (scripts/quickstart.sh, #463) ships from the same release.
#
# The rule is the VERSION, not the presence of a script or an asset: on a
# console-enabled release a missing script or artifact is a failed gate,
# never a skipped one. A tag that is not vMAJOR.MINOR.PATCH[-prerelease] is
# an error (exit 2), so an unreadable tag cannot skip anything either.
set -euo pipefail

CONSOLE_SINCE_MAJOR=1
CONSOLE_SINCE_MINOR=17

tag="${1:?usage: release-capabilities.sh <tag>}"
if [[ ! "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release-capabilities: '$tag' is not a release tag (vMAJOR.MINOR.PATCH[-prerelease])" >&2
  exit 2
fi
major=$((10#${BASH_REMATCH[1]})); minor=$((10#${BASH_REMATCH[2]}))

console=false
if [ "$major" -gt "$CONSOLE_SINCE_MAJOR" ] || { [ "$major" -eq "$CONSOLE_SINCE_MAJOR" ] && [ "$minor" -ge "$CONSOLE_SINCE_MINOR" ]; }; then
  console=true
fi
echo "console=$console"
# The no-clone quickstart script is part of a release from the same version.
echo "quickstart=$console"
# Every distributed executable is checked against the toolchain the release's
# go.mod names (scripts/release-toolchain-check.sh) from the same version;
# earlier releases were not built under that rule.
echo "toolchain=$console"
