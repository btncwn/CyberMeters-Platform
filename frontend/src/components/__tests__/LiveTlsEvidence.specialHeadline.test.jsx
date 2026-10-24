import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TlsAssessmentEvidence } from '../LiveTlsEvidence'

// F1 (Executive 24 Oct 2026, live scan_1f24a64a): the headline rows read
// "robot · tls1_2 — Rejected" while the detail said "Not observed in this test
// (20/20 vectors)". For Heartbleed / ROBOT / CCS the headline is the recorded
// vulnerability status — never the engine's Accepted/Rejected. Rows are in the
// F1 receipt shape (network-probe tls-contract: evidence.vulnerability).
const vuln = (status, profile, n) => ({ status, profile, completed_vectors: n, planned_vectors: n })
const row = (control, state, vulnerability, extra = {}) => ({ control, protocol: 'tls1_2', cipher_id: null, state, reason: null,
  observed_at: '2026-10-24T17:40:00Z', evidence: { schema: 'tls-engine-result-v1', vulnerability, negotiated: null, certificates: null, extensions: null }, ...extra })
const render1 = (checks) => render(<TlsAssessmentEvidence assessment={{ source: 'tls_assessment', quality: 'complete', coverage: {},
  endpoints: [{ hostname: 'probe.example.com', address: '203.0.113.10', port: 443, application_protocol: 'https', checks }] }} />)

describe('special-check headlines', () => {
  it('the F1 run: ROBOT and CCS read "Not observed in this test", never "Rejected"', () => {
    render1([row('robot', 'rejected', vuln('not_observed', 'robot-finite-v1', 20)), row('ccs', 'rejected', vuln('not_observed', 'ccs-finished-v1', 5))])
    const summaries = [...document.querySelectorAll('summary')].map((s) => s.textContent).filter((t) => / · tls1_2 — /.test(t))
    expect(summaries).toHaveLength(2)
    for (const s of summaries) {
      expect(s).toMatch(/— Not observed in this test$/)
      expect(s).not.toMatch(/Rejected|Accepted/)
    }
  })
  it('a confirmed result reads "Confirmed by the recorded test"', () => {
    render1([row('heartbleed', 'accepted', vuln('confirmed', 'heartbleed-minimal-v1', 1))])
    expect(document.body.textContent).toMatch(/— Confirmed by the recorded test/)
    expect(document.body.textContent).not.toMatch(/— Accepted/)
  })
  it('no recorded vulnerability status: an engine Accepted/Rejected reads "Unknown"; held reasons keep their words', () => {
    render1([row('robot', 'rejected', null), row('heartbleed', 'unexecutable', null, { reason: 'heartbeat_unavailable' })])
    const text = document.body.textContent
    expect(text).toMatch(/— Unknown/)
    expect(text).toMatch(/Not applicable — this server did not offer the TLS heartbeat extension/)
    expect(text).not.toMatch(/— Rejected/)
  })
  it('ordinary controls are unchanged', () => {
    render1([{ control: 'protocol', protocol: 'tls1_2', state: 'accepted', reason: null, evidence: {} }])
    expect(document.body.textContent).toMatch(/— Accepted/)
  })
  it('the expanded detail reads from the same words', () => {
    render1([row('robot', 'rejected', vuln('not_observed', 'robot-finite-v1', 20))])
    expect(screen.getByText(/Vulnerability test: Not observed in this test/)).toBeInTheDocument()
  })
})
