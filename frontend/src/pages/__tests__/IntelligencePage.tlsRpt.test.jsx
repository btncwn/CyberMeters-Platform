import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TlsRptStatusPill } from '../IntelligencePage'
import { tlsRptConfiguredStatus } from '../../lib/emailRecordStatus'

// Intelligence page row (email_security_intelligence.tls_rpt): only the TLS-RPT
// pill reads observation_state; an unknown lookup is never "Not configured".
describe('Intelligence page TLS-RPT pill', () => {
  const pill = (row) => {
    const view = render(<TlsRptStatusPill row={row} />)
    const text = view.container.textContent
    view.unmount()
    return text
  }
  it('present, conclusively absent, and not concluded', () => {
    expect(pill({ enabled: true, observation_state: 'present' })).toBe('Configured')
    expect(pill({ enabled: false, observation_state: 'definitive_absent' })).toBe('Not configured')
    expect(pill({ enabled: false, observation_state: 'unavailable' })).toBe('Not available')
    expect(pill({ enabled: false, observation_state: 'not_observed' })).toBe('Not available')
  })
  it('incoherent rows and unknown tokens are not known, never a verdict', () => {
    expect(pill({ enabled: false, observation_state: 'present' })).toBe('Not available')
    expect(pill({ enabled: true, observation_state: 'definitive_absent' })).toBe('Not available')
    expect(pill({ enabled: true, observation_state: 'healthy' })).toBe('Not available')
  })
  it('rows from before observation_state keep the boolean; no row is not available', () => {
    expect(pill({ enabled: true })).toBe('Configured')
    expect(pill({ enabled: false })).toBe('Not configured')
    expect(pill(undefined)).toBe('Not available')
    expect(tlsRptConfiguredStatus({ enabled: false, observation_state: 'unavailable' })).toEqual({ label: 'Not available', kind: 'na' })
  })
})
