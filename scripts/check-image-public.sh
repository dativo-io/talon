#!/usr/bin/env bash
# Prove that a published image is pullable WITHOUT credentials (#507): the
# documented customer path (`docker pull ghcr.io/dativo-io/talon:<version>`,
# the showcase manifest's agent image pulled by OpenShell) has no GHCR login.
# A GHCR package created by a workflow push is PRIVATE until its visibility is
# changed once in the package settings; a private package fails this check
# exactly the way it fails for a customer, while a `docker login`ed runner
# would have pulled it happily and proven nothing.
#
#   scripts/check-image-public.sh ghcr.io/<owner>/<name>:<tag> [...]
#
# Uses the registry's anonymous token flow (no Docker daemon needed).
set -euo pipefail
[[ $# -ge 1 ]] || { echo "usage: $0 <registry>/<owner>/<name>:<tag> [...]" >&2; exit 2; }
accept='application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
rc=0
for ref in "$@"; do
  registry="${ref%%/*}"; rest="${ref#*/}"; repo="${rest%%:*}"; tag="${rest##*:}"
  [[ "$registry" == *.* && "$repo" == */* && "$tag" != "$rest" ]] || { echo "FAIL $ref: expected <registry>/<owner>/<name>:<tag>" >&2; rc=1; continue; }
  token="$(curl -fsS "https://$registry/token?scope=repository:$repo:pull" 2>/dev/null | jq -r '.token // empty' || true)"
  if [[ -z "$token" ]]; then
    echo "FAIL $ref: $registry issues no anonymous pull token for $repo — the package is private or absent. GHCR: https://github.com/orgs/${repo%%/*}/packages/container/${repo#*/}/settings → Change visibility → Public" >&2
    rc=1; continue
  fi
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" -H "Accept: $accept" "https://$registry/v2/$repo/manifests/$tag")"
  if [[ "$code" != 200 ]]; then
    echo "FAIL $ref: anonymous manifest fetch returned HTTP $code (tag missing, or package private)" >&2
    rc=1; continue
  fi
  echo "PASS $ref: pullable without credentials"
done
exit "$rc"
