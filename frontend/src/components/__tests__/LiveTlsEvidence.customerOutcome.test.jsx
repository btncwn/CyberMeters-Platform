import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TlsAssessmentEvidence } from '../LiveTlsEvidence'
import { tlsControlOutcome } from '../../../../workers/scan-api/src/engines/tls-quality.js'

// #985 display (Executive 24 Oct 2026): feature controls show the backend's
// customer_outcome.summary — never the engine's Accepted/Rejected ("compression —
// Accepted" read as compression in use). Rows are the real receipt shape, and
// customer_outcome is added by the backend's own projection (tlsControlOutcome),
// exactly as readTlsAssessmentForScan does.
const row = (control, protocol, state, extensions = null, extra = {}) => ({ control, protocol, cipher_id: null, state, reason: null,
  observed_at: '2026-10-24T17:40:12.000Z', evidence: { extensions, ocsp: null, ...extra.evidence }, ...extra.row })
const project = (rows) => rows.map((r) => { const o = tlsControlOutcome(r, rows); return o ? { ...r, customer_outcome: o } : r })
const renderRows = (rows) => render(<TlsAssessmentEvidence assessment={{ source: 'tls_assessment', quality: 'complete', coverage: {},
  endpoints: [{ hostname: 'probe.example.com', address: '203.0.113.10', port: 443, application_protocol: 'https', checks: rows }] }} />)
const headlines = () => [...document.querySelectorAll('summary')].map((s) => s.textContent).filter((t) => / — /.test(t) && !/probe\.example\.com/.test(t))

describe('feature controls read the customer outcome', () => {
  it('the F1 rerun shape: compression, 0-RTT, OCSP, downgrade — the backend summary, no engine state', () => {
    const rows = project([
      row('protocol', 'tls1_3', 'accepted'),
      row('compression', 'tls1_2', 'accepted', { compression: false }),
      row('early_data', 'tls1_3', 'accepted', { early_data_max: 0 }),
      row('ocsp', 'tls1_2', 'accepted', null, { evidence: { ocsp: { state: 'absent' } } }),
      row('fallback_scsv', 'tls1_2', 'rejected', { fallback_scsv: true }, { row: { reason: 'fallback_rejected' } }),
    ])
    renderRows(rows)
    const text = headlines().join('\n')
    expect(text).toContain('TLS compression is not used.')
    expect(text).toContain('0-RTT early data is not advertised.')
    expect(text).toContain('No OCSP response is stapled.')
    expect(text).toContain('Protocol downgrade is blocked (TLS_FALLBACK_SCSV).')
    for (const line of headlines().filter((t) => !/protocol · tls1_3/i.test(t))) expect(line).not.toMatch(/— (Accepted|Rejected)$/)
  })
  it('an outcome the run could not settle shows the backend\'s own words', () => {
    const rows = project([row('compression', 'tls1_2', 'uncertain', null)])
    renderRows(rows)
    expect(headlines().join('\n')).toContain('Not determined in this run.')
  })
  it('an older receipt without customer_outcome reads "Unknown", never the engine state', () => {
    renderRows([row('compression', 'tls1_2', 'accepted', { compression: false }), row('ocsp', 'tls1_2', 'rejected')])
    const lines = headlines()
    expect(lines).toHaveLength(2)
    for (const l of lines) { expect(l).toMatch(/— Unknown$/); expect(l).not.toMatch(/Accepted|Rejected/) }
  })
  it('controls without an outcome (protocol, cipher) are unchanged', () => {
    renderRows(project([row('protocol', 'tls1_2', 'accepted')]))
    expect(headlines().join('\n')).toMatch(/— Accepted$/)
  })
})
