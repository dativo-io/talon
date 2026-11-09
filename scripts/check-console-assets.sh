#!/usr/bin/env bash
# Fails when internal/console/web/static (the embedded console build) differs
# from what the frontend source builds to. Run after `npm run build` in
# internal/console/frontend; CI runs the same check.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
git diff --exit-code -- internal/console/web/static
if [ -n "$(git status --porcelain -- internal/console/web/static)" ]; then
  echo "internal/console/web/static is stale: run make console-frontend and commit the result" >&2
  git status --porcelain -- internal/console/web/static >&2
  exit 1
fi
echo "console assets match the source build"
