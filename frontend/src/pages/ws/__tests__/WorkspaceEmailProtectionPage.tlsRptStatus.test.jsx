import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TlsRptCard } from '../WorkspaceEmailProtectionPage'
import { tlsRptRecordStatus } from '../../../lib/emailRecordStatus'

// TLS-RPT record_found is tri-state (27 Oct 2026): true found, false conclusively
// no valid record, null when the DNS lookup did not conclude. Unknown is never
// "Not found" or "None", and the returned warning is shown as sent.
const found = { record_found: true, observation_state: 'present', coverage_state: 'complete', rua: ['mailto:tls@fixture.example'], warnings: [] }
const absent = { record_found: false, observation_state: 'definitive_absent', coverage_state: 'complete', rua: [], warnings: ['No TXT record found at _smtp._tls.fixture.example.'] }
const unavailable = { record_found: null, observation_state: 'unavailable', coverage_state: 'incomplete', rua: [], warnings: ['TLS-RPT could not be verified during this scan.'] }
const notObserved = { record_found: null, observation_state: 'not_observed', coverage_state: 'not_assessed', rua: [], warnings: [] }
const legacyFound = { record_found: true, rua: ['mailto:tls@fixture.example'], warnings: [] }
const legacyAbsent = { record_found: false, rua: [], warnings: [] }

const card = (detail) => {
  const view = render(<TlsRptCard detail={detail} />)
  const text = view.container.textContent
  view.unmount()
  return text
}

describe('TLS-RPT status word', () => {
  it('found, conclusively absent, and not concluded', () => {
    expect(tlsRptRecordStatus(found)).toEqual({ label: 'Found', kind: 'good' })
    expect(tlsRptRecordStatus(absent)).toEqual({ label: 'Not found', kind: 'na' })
    expect(tlsRptRecordStatus(unavailable)).toEqual({ label: 'Not available', kind: 'na' })
    expect(tlsRptRecordStatus(notObserved)).toEqual({ label: 'Not available', kind: 'na' })
  })
  it('an explicit unavailable state wins over an incoherent false', () => {
    expect(tlsRptRecordStatus({ ...unavailable, record_found: false })).toEqual({ label: 'Not available', kind: 'na' })
  })
  it('no detail and details from before the tri-state keep their reading', () => {
    expect(tlsRptRecordStatus(null)).toEqual({ label: 'Not available', kind: 'na' })
    expect(tlsRptRecordStatus(legacyFound)).toEqual({ label: 'Found', kind: 'good' })
    expect(tlsRptRecordStatus(legacyAbsent)).toEqual({ label: 'Not found', kind: 'na' })
  })
})

describe('TLS-RPT card', () => {
  it('found: Published with its reporting address', () => {
    const text = card(found)
    expect(text).toContain('Found')
    expect(text).toContain('Published')
    expect(text).toContain('mailto:tls@fixture.example')
  })
  it('conclusively absent: Not found / None, with the returned warning', () => {
    const text = card(absent)
    expect(text).toContain('Not found')
    expect(text).toContain('None')
    expect(text).toContain('No TXT record found at _smtp._tls.fixture.example.')
  })
  it('lookup did not conclude: Not available / Not assessed and the warning, never absence', () => {
    render(<TlsRptCard detail={unavailable} />)
    expect(screen.getByText('Not available')).toBeInTheDocument()
    expect(screen.getByText('Not assessed')).toBeInTheDocument()
    expect(screen.getByText('TLS-RPT could not be verified during this scan.')).toBeInTheDocument()
    expect(screen.queryByText('Not found')).toBeNull()
    expect(screen.queryByText('None')).toBeNull()
    expect(screen.queryByText(/Reporting \(rua\)/)).toBeNull()
  })
  it('not observed: Not available / Not assessed, no invented warning', () => {
    const text = card(notObserved)
    expect(text).toContain('Not available')
    expect(text).toContain('Not assessed')
    expect(text).not.toContain('Not found')
    expect(text).not.toMatch(/None|could not be verified/)
  })
  it('details from before the tri-state keep Published / None; no detail keeps its note', () => {
    expect(card(legacyFound)).toContain('Published')
    expect(card(legacyAbsent)).toContain('None')
    expect(card(null)).toContain('TLS-RPT details were not returned for this scan.')
  })
})
