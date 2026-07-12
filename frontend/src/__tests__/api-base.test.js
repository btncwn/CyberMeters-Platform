import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Regression guard for the double-/api bug. VITE_API_BASE_URL (BASE) already ends
// in /api, so interpolating BASE and then an "/api/..." path segment resolves to
// /api/api/... → 404. This silently broke the free-scan lead magnet and the GDPR
// data export. Raw fetches must interpolate BASE then the bare path, no leading /api.
describe('no double /api in fetch URLs', () => {
  it('has no ${BASE}/api or ${apiBase}/api pattern anywhere in src', () => {
    const srcRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
    const offenders = []
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name)
        if (entry.isDirectory()) { walk(p); continue }
        if (!/\.(jsx?|tsx?)$/.test(entry.name)) continue
        const src = fs.readFileSync(p, 'utf8')
        if (/\$\{(?:BASE|apiBase)\}\/api\//.test(src)) offenders.push(path.relative(srcRoot, p))
      }
    }
    walk(srcRoot)
    expect(offenders).toEqual([])
  })
})
