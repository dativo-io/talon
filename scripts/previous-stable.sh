#!/usr/bin/env bash
# Print the version (without "v") of the stable release that immediately
# precedes a given one — the N-1 release an upgrade gate must start from.
#
#   scripts/previous-stable.sh            # before the next release: the latest published stable release
#   scripts/previous-stable.sh v1.18.0    # the greatest published stable release below v1.18.0
#
# "Stable" is a published GitHub release that is neither a draft nor a
# pre-release. Reads the public API (GH_TOKEN is used when set, to avoid the
# anonymous rate limit). Needs curl and python3.
set -euo pipefail
REPO="${GITHUB_REPOSITORY:-dativo-io/talon}"
BELOW="${1:-}"
auth=()
if [ -n "${GH_TOKEN:-}" ]; then auth=(-H "Authorization: Bearer ${GH_TOKEN}"); fi
curl -fsSL --retry 3 "${auth[@]}" -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/${REPO}/releases?per_page=100" |
  python3 -c '
import json, re, sys
below = sys.argv[1].lstrip("v")
def key(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None
limit = key(re.sub(r"-.*$", "", below)) if below else None
best = None
for r in json.load(sys.stdin):
    if r.get("draft") or r.get("prerelease"):
        continue
    k = key(r["tag_name"].lstrip("v"))
    if k is None or (limit is not None and k >= limit):
        continue
    if best is None or k > best:
        best = k
if best is None:
    sys.exit("previous-stable: no stable release found" + (" below " + below if below else ""))
print(".".join(str(x) for x in best))
' "$BELOW"
