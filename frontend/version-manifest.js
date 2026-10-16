// Emits /version.json into every production build so anyone can see which
// commit the live site was built from (scripts/check-live-versions.mjs reads it).
// Cloudflare Pages sets CF_PAGES_COMMIT_SHA during its build; CI sets GITHUB_SHA.
import { execSync } from 'node:child_process'

export function buildVersionManifest(env = process.env, gitHead = () => execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()) {
  let commit = env.CF_PAGES_COMMIT_SHA || env.GITHUB_SHA || null
  if (!commit) { try { commit = gitHead() } catch { commit = null } }
  if (!/^[0-9a-f]{40}$/.test(String(commit || ''))) commit = null
  return {
    service: 'cybermeters-app',
    commit,
    branch: env.CF_PAGES_BRANCH || null,
    built_at: new Date().toISOString(),
    // The rollback receipt must identify the flag compiled into this bundle.
    mcp_beta_enabled: env.VITE_MCP_BETA_ENABLED === 'true',
  }
}

export default function versionManifest() {
  let resolvedEnv = process.env
  return {
    name: 'cybermeters-version-manifest',
    apply: 'build',
    configResolved(config) {
      // Vite can load VITE_* values from .env files without adding them to
      // process.env. Record the value actually compiled into the JS bundle.
      resolvedEnv = { ...process.env, ...config.env }
    },
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'version.json', source: `${JSON.stringify(buildVersionManifest(resolvedEnv), null, 2)}\n` })
    },
  }
}
