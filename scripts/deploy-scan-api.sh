#!/bin/sh
# Deploy the scan-api Worker stamped with the commit it is built from, so
# /health reports that commit and scripts/check-live-versions.mjs can tell
# whether main is live.
#
#   sh scripts/deploy-scan-api.sh            # extra args go to `wrangler deploy`
#
# Refuses when the Worker's sources have uncommitted changes: the stamp must
# name exactly the code that runs.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
commit=$(git -C "$root" rev-parse HEAD)

if [ -n "$(git -C "$root" status --porcelain -- workers/scan-api shared)" ]; then
  echo "deploy-scan-api: workers/scan-api or shared/ has uncommitted changes — commit them first so the stamp is true." >&2
  exit 1
fi

cd "$root/workers/scan-api"
exec npx wrangler deploy --var "GIT_COMMIT:$commit" "$@"
