import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

// SIRA 4 (founder, 19 Oct 2026): customer-facing copy states only what the
// product does. CyberMeters observes third-party services from the outside; it
// does not rate vendors, score a supply chain, or promise complete protection.
// This scans every customer-facing frontend source file (pages, components,
// guide content) for the retired and overstated phrases.

const src = resolve(__dirname, '..')

const RETIRED = [
  /Vendor Risk Score/i,
  /Supply[ -]Chain Score/i,
  /supply[ -]chain view/i,
  /vendor risk data/i,
  /(multi-customer|third-party|vendor) risk intelligence/i,
  /SC Score/,
  /Continuous Risk Scoring/i,
  /fully protected/i,
  /complete (visibility|protection)/i,
  /(full|total) visibility/i,
  /never surprises you/i,
  /bulletproof|unhackable/i,
]

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : files(path)
    return /\.(jsx?|tsx?)$/.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

describe('no unsupported product claims in customer-facing copy', () => {
  it.each(RETIRED.map((re) => [String(re), re]))('%s appears nowhere', (_, re) => {
    const hits = files(src).filter((file) => re.test(readFileSync(file, 'utf8'))).map((file) => relative(src, file))
    expect(hits).toEqual([])
  })

  it('plan pages name the vendor feature for what it shows', () => {
    for (const file of ['pages/SubscriptionPage.jsx', 'components/PlanUsageCard.jsx']) {
      expect(readFileSync(join(src, file), 'utf8')).toMatch(/vendor_risk:\s*'Third-party services observed on your domains'/)
    }
  })
})
