/**
 * Product type floor (founder, 15 Oct 2026): no user-facing text inside the
 * authenticated product may be set below 14px. Secondary text, badges and
 * table metadata use the `text-xs` token (14px); body and controls use
 * `text-sm`/`text-base` (16–17px). Arbitrary 10–13px sizes are rejected so
 * the floor cannot erode one class at a time.
 *
 * The public website (landing, public header/footer, free check) sets its own
 * sizes and is outside this rule.
 */
import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'

const SRC = path.resolve(__dirname, '..')
const PUBLIC_SITE = [
  'pages/PublicLandingPage.jsx',
  'pages/FreeScanPage.jsx',
  'components/PublicSiteHeader.jsx',
  'components/PublicSiteFooter.jsx',
]
const SMALL = /text-\[(?:1[0-3]|[0-9])px\]/g

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'landing') continue
      walk(full, out)
    } else if (/\.(jsx|js)$/.test(entry.name) && !entry.name.endsWith('.test.jsx') && !entry.name.endsWith('.test.js')) {
      out.push(full)
    }
  }
  return out
}

describe('product type floor', () => {
  it('sets no product text below 14px', () => {
    const offenders = []
    for (const file of walk(SRC)) {
      const rel = path.relative(SRC, file).split(path.sep).join('/')
      if (PUBLIC_SITE.includes(rel)) continue
      const src = fs.readFileSync(file, 'utf8')
      const hits = src.match(SMALL)
      if (hits) offenders.push(`${rel}: ${hits.join(', ')}`)
    }
    expect(offenders).toEqual([])
  })
})
