#!/usr/bin/env bash
# Deploy the network probe using its pinned, local Wrangler installation.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
worker_dir="$root/workers/network-probe"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "deploy-network-probe: Docker is not running or is not accessible. Start Docker Desktop and retry." >&2
  exit 1
fi

cd "$worker_dir"
npm ci

log_file=$(mktemp)
trap 'rm -f "$log_file"' EXIT
./node_modules/.bin/wrangler deploy "$@" 2>&1 | tee "$log_file"

for arg in "$@"; do
  if [[ "$arg" == "--dry-run" ]]; then
    echo "deploy-network-probe: dry run complete (no Version ID is created)."
    exit 0
  fi
done

version_id=$(sed -nE 's/.*Current Version ID: *([0-9a-fA-F-]{36}).*/\1/p' "$log_file" | tail -n 1)
if [[ -z "$version_id" ]]; then
  echo "deploy-network-probe: Wrangler did not print a Version ID; check the deployment output." >&2
  exit 1
fi
echo "deploy-network-probe: Version ID: $version_id"
