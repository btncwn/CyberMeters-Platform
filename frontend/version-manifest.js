// Emits /version.json into every production build so anyone can see which
// commit the live site was built from (scripts/check-live-versions.mjs reads it).
// Cloudflare Pages sets CF_PAGES_COMMIT_SHA during its build; CI sets GITHUB_SHA.
// build_id is unique per build and also compiled into the bundle as
// __APP_BUILD_ID__, so an open tab can tell that a newer build has been deployed
// (src/components/NewVersionBanner.jsx). A commit is not enough: rebuilding the
// same commit with a different flag ships a different bundle.
import { execSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'

export function buildVersionManifest(env = process.env, gitHead = () => execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(), buildId = null) {
  let commit = env.CF_PAGES_COMMIT_SHA || env.GITHUB_SHA || null
  if (!commit) { try { commit = gitHead() } catch { commit = null } }
  if (!/^[0-9a-f]{40}$/.test(String(commit || ''))) commit = null
  return {
    service: 'cybermeters-app',
    commit,
    branch: env.CF_PAGES_BRANCH || null,
    built_at: new Date().toISOString(),
    build_id: buildId,
    // Records the Pages build variable for the founder-canary rollback receipt
    // (scripts/rollback-mcp-founder-canary.mjs). It gates no page: the MCP
    // connections page is always available (21 Oct 2026).
    mcp_beta_enabled: env.VITE_MCP_BETA_ENABLED === 'true',
  }
}

export default function versionManifest() {
  let resolvedEnv = process.env
  const buildId = randomUUID()
  return {
    name: 'cybermeters-version-manifest',
    apply: 'build',
    config() {
      return { define: { __APP_BUILD_ID__: JSON.stringify(buildId) } }
    },
    configResolved(config) {
      // Vite can load VITE_* values from .env files without adding them to
      // process.env. Record the value actually compiled into the JS bundle.
      resolvedEnv = { ...process.env, ...config.env }
    },
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'version.json', source: `${JSON.stringify(buildVersionManifest(resolvedEnv, undefined, buildId), null, 2)}\n` })
    },
  }
}
