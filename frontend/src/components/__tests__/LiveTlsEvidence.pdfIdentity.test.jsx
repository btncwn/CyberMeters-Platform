import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TlsAssessmentEvidence } from '../LiveTlsEvidence'
import { buildScanReportPdf, pdfEsc } from '../../../../workers/scan-api/src/engines/pdf.js'

// R1 19:55 (#992): the scan page and the PDF print the SAME result string for
// every authorised special check. One receipt (F1 shape) drives both; each PDF
// row must carry exactly the scan page's headline words (the PDF only maps
// typographic punctuation to ASCII, via pdfEsc).
const vuln = (status, profile, n) => ({ status, profile, completed_vectors: n, planned_vectors: n })
const row = (control, state, reason, vulnerability, extra = {}) => ({ control, protocol: 'tls1_2', cipher_id: null, state, reason,
  observed_at: '2026-10-24T17:40:12.000Z', evidence: { vulnerability }, ...extra })
const receipt = { source: 'tls_assessment', quality: 'complete', coverage: {}, endpoints: [
  { hostname: 'probe.example.com', address: '203.0.113.10', port: 443, application_protocol: 'https', checks: [
    row('robot', 'rejected', null, vuln('not_observed', 'robot-finite-v1', 20)),
    row('ccs', 'accepted', null, vuln('confirmed', 'ccs-finished-v1', 5)),
    row('heartbleed', 'unexecutable', 'heartbeat_unavailable', null),
  ] },
  { hostname: 'mail.example.com', address: '203.0.113.11', port: 443, application_protocol: 'https', checks: [
    row('robot', 'unexecutable', 'slice_failed', null, { failure_attempts: 2 }),
    row('ccs', 'uncertain', null, null),
    row('heartbleed', 'rejected', null, null),
  ] },
] }

// Minimal snapshot read the technical PDF renders from.
const snap = { snapshot: { domain: 'example.com', as_of: '2026-10-24T17:40:00.000Z', scan_id: 'scan_x' }, overall: {}, domains: [], observed_findings: [], remediation_actions: [], methodology: {} }
const pdfText = (bytes) => {
  const s = Buffer.from(bytes).toString('latin1')
  return [...s.matchAll(/stream\n([\s\S]*?)\nendstream/g)].map((m) => [...m[1].matchAll(/\(((?:\\.|[^()\\])*)\) Tj/g)].map((x) => x[1]).join(' ')).join(' ').replace(/\s+/g, ' ')
}

describe('one result string, scan page and PDF', () => {
  it('every authorised special check reads the same on both', () => {
    render(<TlsAssessmentEvidence assessment={receipt} />)
    const uiRows = [...document.querySelectorAll('summary')].map((s) => s.textContent)
      .filter((t) => / · tls1_2 — /.test(t)).map((t) => t.split(' · tls1_2 — ')[1])
    expect(uiRows).toHaveLength(6)
    let pdf
    try { pdf = pdfText(buildScanReportPdf({ domain: 'example.com' }, { snapshot: snap, customerSnapshot: snap }, null, null, null, receipt)) }
    catch (e) { throw new Error(`PDF render failed: ${e.message}`) }
    const section = pdf.slice(pdf.lastIndexOf('Authorised active checks'))
    for (const words of uiRows) {
      const printed = pdfEsc(words).replace(/\s+/g, ' ').replace(/\.$/, '')
      expect(section, words).toContain(printed)
    }
    expect(uiRows).toEqual(expect.arrayContaining([
      'Not observed in this test', 'Confirmed by the recorded test',
      'Not applicable — this server did not offer the TLS heartbeat extension that Heartbleed relies on.',
      'Could not complete — this check did not finish on this server after 2 attempts. The other checks were not affected.',
      'Uncertain — the test did not reach a result.', 'Unknown',
    ]))
  })
})
