import { describe, expect, it } from 'vitest'
import { websiteObservations, WEBSITE_FIGURE_KEYS } from '../WebsiteScanOverview'
import { websiteSummaryFigures } from '../../pages/ws/WebsiteSecurityPage'

// S1-SHELL-V2b (Website): HSTS and Content Security Policy read from the headers
// module's own result; the Summary lifts HTTPS, headers, HSTS and CSP into
// "What we observed", each a named anchor; nothing unassessed reads as sent.

const report = (headers) => ({
  scan_quality: { status: 'complete' },
  modules: {
    ssl: { https_available: true, https_probe_executed: true },
    headers: { accessible: true, headers_assessed: true, ...headers },
  },
})

describe('HSTS and CSP tiles', () => {
  it('use the module strength class and its details sentence', () => {
    const tiles = websiteObservations(report({
      present: ['strict-transport-security', 'content-security-policy'], missing: [],
      header_strength: {
        'strict-transport-security': { status: 'weak', details: 'max-age=300 — below recommended minimum of 15,552,000 (180 days)' },
        'content-security-policy': { status: 'valid', details: 'CSP present with no dangerous script-src or default-src token detected' },
      },
    }))
    expect(tiles.find((t) => t.key === 'hsts')).toMatchObject({ value: 'Sent, weak', note: expect.stringContaining('max-age=300') })
    expect(tiles.find((t) => t.key === 'csp')).toMatchObject({ value: 'Sent', note: expect.stringContaining('no dangerous') })
  })
  it('a missing header reads Not sent; unassessed headers read Not confirmed', () => {
    const missing = websiteObservations(report({ present: [], missing: ['strict-transport-security', 'content-security-policy'] }))
    expect(missing.find((t) => t.key === 'hsts').value).toBe('Not sent')
    expect(missing.find((t) => t.key === 'csp').value).toBe('Not sent')
    const unassessed = websiteObservations(report({ headers_assessed: false, present: [], missing: [] }))
    expect(unassessed.find((t) => t.key === 'hsts').value).toBe('Not confirmed')
  })
})

describe('websiteSummaryFigures', () => {
  it('lifts the four headline tiles, each with its sidebar anchor', () => {
    const f = websiteSummaryFigures({ report: report({ present: [], missing: ['strict-transport-security'] }), pending: false })
    expect(f.map((x) => [x.label, x.id])).toEqual([
      ['HTTPS access', 'website-https'], ['Security headers', 'website-security-headers'], ['HSTS', 'website-hsts'], ['Content Security Policy', 'website-csp'],
    ])
    expect(WEBSITE_FIGURE_KEYS).toEqual(['https', 'headers', 'hsts', 'csp'])
  })
  it('says Loading while the scan loads; with no scan the template default stands', () => {
    expect(websiteSummaryFigures({ report: null, pending: true }).every((x) => x.value === 'Loading…')).toBe(true)
    expect(websiteSummaryFigures({ report: null, pending: false })).toBeNull()
  })
})
