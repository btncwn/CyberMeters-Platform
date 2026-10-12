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

# The version tag and message carry the same commit into Cloudflare's own
# deployment record (`wrangler deployments list`), so a running version can be
# matched to its commit from either side.
short=$(printf '%s' "$commit" | cut -c1-12)
message=$(git -C "$root" log -1 --format=%s | cut -c1-100)

cd "$root/workers/scan-api"
exec npx wrangler deploy --var "GIT_COMMIT:$commit" --tag "$short" --message "$message" "$@"
