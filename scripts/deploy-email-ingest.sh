#!/bin/sh
# Deploy the cybermeters-email Worker stamped with the release stamp of the
# commit it is built from (APP_VERSION, computed by scripts/lib/release-stamp.mjs
# — never committed), so /health names the commit and the exact shared-source
# closure that runs. The closure manifest is generated here, just before the
# deploy, into workers/email-ingest/deploy-manifest.json (git-ignored) for the
# release record.
#
#   npm run deploy --prefix workers/email-ingest   # runs this script
#
# Refuses when any closure source has uncommitted changes: the stamp must name
# exactly the code that runs.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
commit=$(git -C "$root" rev-parse HEAD)

if [ -n "$(git -C "$root" status --porcelain -- workers/email-ingest/src workers/email-ingest/wrangler.toml workers/scan-api/src shared)" ]; then
  echo "deploy-email-ingest: the email Worker's sources have uncommitted changes — commit them first so the stamp is true." >&2
  exit 1
fi

short=$(printf '%s' "$commit" | cut -c1-12)
message=$(git -C "$root" log -1 --format=%s | cut -c1-100)
stamp=$(node "$root/scripts/lib/release-stamp.mjs" --field app_version --manifest-out "$root/workers/email-ingest/deploy-manifest.json")
echo "deploy-email-ingest: APP_VERSION $stamp (manifest: workers/email-ingest/deploy-manifest.json)"

cd "$root/workers/email-ingest"
exec ../scan-api/node_modules/.bin/wrangler deploy --config wrangler.toml --var "APP_VERSION:$stamp" --tag "$short" --message "$message" "$@"
