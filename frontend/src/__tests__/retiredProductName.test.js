import { describe, it, expect } from 'vitest'
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// Founder order (21 Oct 2026): the product's former check name is retired from
// every customer-visible and public surface: site, app, PDF, emails, alerts,
// MCP text, SEO meta, public docs and code comments. The replacement wording is
// "external security check" (or "security check").
//
// Scans every tracked file in the repository. Only persisted names may remain:
// the D1 table and API field names (snake_case), the checksum-bound snapshot
// key, and the former API path and article address that stay as aliases for
// existing clients and links. Each allowed file has an exact count, so a new
// occurrence anywhere fails. Since 23 Oct 2026 no comment, CI step name or file
// name carries it either, migrations included (091 renamed: the D1 ledger never
// recorded it, migrations being applied with `d1 execute --file`).

const root = resolve(__dirname, '../../..')
const SPACED = /cyber[\s ]+mot\b/gi
const IDENTIFIER = /CyberMot|cyberMot|CYBER_MOT/g
const HYPHEN = /cyber-mot/gi
const SNAKE = /cyber_mot\w*/g
const PERSISTED_SNAKE = new Set(['cyber_mot_domains', 'cyber_mot_domain_states', 'cyber_mot_resolver_version'])

// No file may carry the spaced form (23 Oct 2026: migrations and CI cleaned too).
const SPACED_ALLOWED = {}
// The backend compatibility path and article redirects, kept for old clients/links.
const HYPHEN_ALLOWED = {
  'frontend/public/_redirects': 2,
  'workers/scan-api/src/routes/executive-dashboard.js': 1,
}
// A persisted case-event value ({ source: 'cyber_mot' }) written by this file.
const BARE_SNAKE_ALLOWED = { 'workers/scan-api/src/engines/asm-cases.js': 2 }
const SELF = 'frontend/src/__tests__/retiredProductName.test.js'

const files = execSync('git ls-files -z', { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  .split('\0')
  .filter((f) => f && f !== SELF && !/\.(png|jpe?g|gif|ico|webp|woff2?|ttf|otf|pdf|zip|gz)$/i.test(f))

function text(file) {
  try { return readFileSync(resolve(root, file), 'utf8') } catch { return '' }
}
const count = (s, re) => (s.match(re) || []).length

describe('retired product name', () => {
  const sources = files.map((file) => [file, text(file)])

  it('covers the CI workflow and worker sources as well as frontend files', () => {
    expect(files).toContain('.github/workflows/ci.yml')
    expect(files).toContain('workers/scan-api/src/index.js')
    expect(files).toContain('workers/scan-api/src/routes/executive-dashboard.js')
    expect(files).toContain('workers/scan-api/src/engines/security-check-domains.js')
  })

  it('the spaced name appears nowhere', () => {
    const hits = sources
      .map(([file, s]) => [file, count(s, SPACED)])
      .filter(([file, n]) => n !== (SPACED_ALLOWED[file] || 0))
    expect(hits).toEqual([])
  })

  it('no identifier, component or file name carries it', () => {
    expect(sources
      .filter(([file, s]) => !file.startsWith('database/migrations/') && count(s, IDENTIFIER) > 0)
      .map(([f]) => f)).toEqual([])
    expect(files.filter((f) => /cyber[-_]?mot/i.test(f))).toEqual([])
  })

  it('the hyphenated form is only the kept aliases', () => {
    const hits = sources
      .filter(([file]) => !file.startsWith('database/migrations/'))
      .map(([file, s]) => [file, count(s, HYPHEN)])
      .filter(([file, n]) => n !== (HYPHEN_ALLOWED[file] || 0))
    expect(hits).toEqual([])
  })

  it('snake_case forms are only the persisted names', () => {
    const unknown = []
    for (const [file, s] of sources) {
      if (file.startsWith('database/migrations/')) continue
      const names = s.match(SNAKE) || []
      const bare = names.filter((n) => n === 'cyber_mot').length
      if (bare !== (BARE_SNAKE_ALLOWED[file] || 0)) unknown.push(`${file}: cyber_mot x${bare}`)
      for (const n of names) if (n !== 'cyber_mot' && !PERSISTED_SNAKE.has(n)) unknown.push(`${file}: ${n}`)
    }
    expect(unknown).toEqual([])
  })
})
