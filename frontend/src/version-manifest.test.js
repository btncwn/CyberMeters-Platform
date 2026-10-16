import { expect, it } from 'vitest'
import versionManifest from '../version-manifest.js'

it('records the Vite-resolved beta flag compiled into the bundle', () => {
  const plugin = versionManifest()
  plugin.configResolved({ env: { VITE_MCP_BETA_ENABLED: 'true' } })
  let emitted
  plugin.generateBundle.call({ emitFile: (file) => { emitted = file } })
  expect(emitted.fileName).toBe('version.json')
  expect(JSON.parse(emitted.source).mcp_beta_enabled).toBe(true)
})

it('marks an off build as off', () => {
  const plugin = versionManifest()
  plugin.configResolved({ env: { VITE_MCP_BETA_ENABLED: 'false' } })
  let emitted
  plugin.generateBundle.call({ emitFile: (file) => { emitted = file } })
  expect(JSON.parse(emitted.source).mcp_beta_enabled).toBe(false)
})
