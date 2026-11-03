#!/usr/bin/env bash
# Release immutability guard (#507): a tag whose GitHub release is already
# PUBLISHED is never built, uploaded to or edited again by the release
# workflow. Published assets stay what customers downloaded; a defective
# release is corrected by a NEW version, never by replacing files under the
# same tag. While the release is still a DRAFT (unverified, invisible to
# `releases/latest`, the installer and anonymous downloads) re-runs may
# replace its assets freely.
#
#   scripts/release-guard.sh <tag>      exit 0: no release yet, or a draft
#                                       exit 1: the release is published
# Prints the state it found. Needs `gh` authenticated for the repository
# (GH_TOKEN) and GH_REPO or a checkout with the origin remote.
set -euo pipefail
TAG="${1:?tag (e.g. v1.15.4)}"
REPO="${GH_REPO:-${GITHUB_REPOSITORY:-dativo-io/talon}}"
# The tags endpoint does not return drafts, so scan the release list.
state="$(gh api "repos/$REPO/releases?per_page=100" --paginate --jq ".[] | select(.tag_name == \"$TAG\") | .draft" | head -n1)"
case "$state" in
  "")
    echo "release-guard: no release for $TAG yet"
    ;;
  true)
    echo "release-guard: $TAG is a draft (unpublished); assets may be replaced"
    ;;
  false)
    echo "release-guard: $TAG is PUBLISHED — refusing to build, upload or edit its assets; cut a new version instead (#507)" >&2
    exit 1
    ;;
  *)
    echo "release-guard: unexpected state '$state' for $TAG" >&2
    exit 1
    ;;
esac
