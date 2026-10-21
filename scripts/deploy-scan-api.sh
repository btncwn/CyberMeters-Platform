#!/bin/sh
# Deploy the scan-api Worker stamped with the commit it is built from, so
# /health reports that commit and its release stamp (APP_VERSION, computed here
# by scripts/lib/release-stamp.mjs — never committed) and
# scripts/check-live-versions.mjs can tell whether main is live.
#
#   sh scripts/deploy-scan-api.sh            # extra args go to `wrangler deploy`
#
# Refuses when the Worker's sources have uncommitted changes: the stamp must
# name exactly the code that runs. After a real deploy it runs
# scripts/post-deploy-smoke.mjs and exits 1, with the rollback command, if the
# new version is not healthy.
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
stamp=$(node "$root/scripts/lib/release-stamp.mjs" --field app_version)

cd "$root/workers/scan-api"
npx wrangler deploy --var "GIT_COMMIT:$commit" --var "APP_VERSION:$stamp" --tag "$short" --message "$message" "$@"

# A dry run creates no version, so there is nothing live to check.
for arg in "$@"; do
  case "$arg" in --dry-run|--dry-run=*) exit 0 ;; esac
done

# Post-deploy smoke test: is the version we just deployed answering, healthy
# and still auth-gated? On failure it prints the rollback command and exits 1.
cd "$root"
node scripts/post-deploy-smoke.mjs --expect-commit "$commit"
