import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TlsAssessmentEvidence } from '../LiveTlsEvidence'
import refusal from '../../../../scripts/fixtures/tls-refusal-cloudflare-edge-2026-10-18.json'

// Executive 24 Oct 2026: the TLS engine's heartbeat_unavailable (a server that
// offers no heartbeat extension) reads as not applicable, never "Could not execute".
// The row is the real producer output from the captured production receipt.
const producerRow = refusal.checks.find((row) => row.reason === 'heartbeat_unavailable')
const text = 'Not applicable — this server did not offer the TLS heartbeat extension that Heartbleed relies on.'

describe('heartbeat_unavailable', () => {
  it('the captured producer row exists and is a heartbleed check', () => {
    expect(producerRow).toMatchObject({ control: 'heartbleed', state: 'unexecutable', reason: 'heartbeat_unavailable' })
  })
  it('reads as not applicable, never "Could not execute"', () => {
    const { control, protocol, state, reason } = producerRow
    render(<TlsAssessmentEvidence assessment={{
      source: 'tls_assessment', quality: 'complete', phase_state: 'complete',
      coverage: { planned: 1, completed: 0, uncertain: 0, unexecutable: 1, not_authorized: 0, not_applicable: 0 },
      endpoints: [{ hostname: 'example.com', address: '203.0.113.10', port: 443, application_protocol: 'https', checks: [{ control, protocol, state, reason }] }],
    }} />)
    expect(screen.getAllByText(new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).length).toBeGreaterThan(0)
    // The check's own line names the reason (the backend's coverage counter above is separate).
    expect(document.body.textContent).not.toContain('heartbleed · tls1_2 — Could not execute')
  })
})
