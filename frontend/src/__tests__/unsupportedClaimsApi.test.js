import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { buildScorecardSections } from '../../../workers/scan-api/src/engines/scorecard.js'

// SIRA 4 (founder, 19 Oct 2026), API part: report, scorecard, alert and
// guidance wording states only what CyberMeters observes. The per-vendor tier
// is a catalogue label for the kind of service, never a rating of the vendor,
// and no copy promises "full protection".

const engines = resolve(__dirname, '../../../workers/scan-api/src/engines')

const RETIRED = [
  /high-risk vendor/i,
  /medium-risk vendor/i,
  /supply chain exposure/i,
  /Supply chain risk increase/i,
  /Supply Chain Score is incomplete/,
  /Supply Chain dashboard/i,
  /elevated (aggregate|third-party) risk/i,
  /vendor concentration risk/i,
  /High-risk third-party vendor/i,
  /Full DMARC protection/i,
  /for full protection/i,
  /supply-chain signals/i,
  /label:\s*'Third-Party Risk'/,
  /title:\s*'Vendor Risk'/,
]

describe('no unsupported claims in API copy', () => {
  it.each(RETIRED.map((re) => [String(re), re]))('%s appears in no engine', (_, re) => {
    const hits = readdirSync(engines).filter((f) => f.endsWith('.js')).filter((f) => re.test(readFileSync(join(engines, f), 'utf8')))
    expect(hits).toEqual([])
  })

  it('the scorecard lists observed third-party services without rating them', () => {
    const base = {
      cyber_mot_domains: [], admin_surface_evidence_status: null, admin_surfaces: 0,
      brand_risks: { total: 0, active: 0, high: 0, medium: 0, low: 0 },
      certificate_risks: { risk_level: null, signals: 0, days_until_expiry: null, risk_signal_count: 0, risk_signals: [], informational_observation_count: 0, informational_observations: [] },
      third_party_assets: 0, saas_exposures: 0, active_assets: 3, new_assets_30d: 0, asset_events_30d: 0,
      critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0,
    }
    const seen = buildScorecardSections({ ...base, vendors_detected: 4, vendor_risk: { high: 3, medium: 1, low: 0 } })
      .find((s) => s.title === 'Third-party services observed')
    expect(seen).toBeTruthy()
    expect(seen.status).toBe('observed')
    expect(seen.summary).toBe('4 third-party services observed on your domains. This lists what was seen; it does not rate the vendors.')
    expect(seen.summary).not.toMatch(/risk/i)
    const none = buildScorecardSections({ ...base, vendors_detected: 0, vendor_risk: { high: 0, medium: 0, low: 0 } })
      .find((s) => s.title === 'Third-party services observed')
    expect(none.status).toBe('unknown')
    expect(none.summary).toBe('No third-party services were observed in this scan.')
  })
})
