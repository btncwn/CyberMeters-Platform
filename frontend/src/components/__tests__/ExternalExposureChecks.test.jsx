import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import ExternalExposureChecks, { hostCoverageLabel } from '../ExternalExposureChecks'

const exposure = {
  source: 'external_exposure', observed_at: '2026-10-13T09:00:00Z',
  coverage: { completed: 8, pending: 2, blocked: 1, not_applicable: 3, budget_exhausted: 4, uncertain: 1, recorded_total: 15 },
  costs: { requests: 12, redirects: 1, retries: 0, bytes_decoded: 4096, duration_ms: 500 },
  findings: [{ id: 'stable-1', severity: 'high', title: 'Configuration credential exposed', exposure: {
    affected_url: 'https://example.com/.env', observation: 'Credential-shaped configuration was observed.',
    severity_rationale: 'A non-placeholder credential value was present; validity was not tested.',
    indicators: ['configuration_structure', 'credential_shape'], observed_at: '2026-10-13T09:00:00Z',
    recommended_action: 'Restrict the file and replace the credential.', retest_requirement: 'Only an exact successful recheck can confirm absence.',
  } }],
}
const mount = (value) => render(<MemoryRouter><ExternalExposureChecks exposure={value} domain="example.com" scanId="scan-1" /></MemoryRouter>)

describe('Public content evidence', () => {
  it('shows honest missing coverage without a healthy or fixed conclusion', () => {
    mount(null)
    expect(screen.getByText(/These checks were not recorded/)).toBeInTheDocument()
    expect(screen.queryByText(/verified fixed|all clear/i)).toBeNull()
  })
  it('combines completed, blocked and unfinished counts without exposing accounting tiles', () => {
    mount(exposure)
    expect(screen.getByText('8 checks completed · 1 blocked · 6 not completed this scan (of 15 recorded checks)')).toBeInTheDocument()
    for (const label of ['Budget reached', 'Not determined', 'Recorded request cost']) expect(screen.queryByText(label)).toBeNull()
    expect(screen.getByText(/https:\/\/example.com\/\.env/)).toBeInTheDocument()
    expect(screen.getByText(/validity was not tested/)).toBeInTheDocument()
    expect(screen.getByText(/configuration structure/)).toBeInTheDocument()
    expect(screen.getByText(/Restrict the file and replace/)).toBeInTheDocument()
    expect(screen.getByText(/cannot confirm that a previous finding was fixed/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Recheck this website' })).toHaveAttribute('href', '/scans/new?domain=example.com')
  })
  it('renders the observed receipt distribution without dropping unfinished checks', () => {
    mount({ ...exposure, coverage: { completed: 371, blocked: 5, pending: 0, budget_exhausted: 169, uncertain: 8, recorded_total: 384, omitted_checks: 169 } })
    expect(screen.getByText('371 checks completed · 5 blocked · 8 not completed this scan (of 384 recorded checks)')).toBeInTheDocument()
    expect(screen.getByText('169 additional checks were outside this scan’s recorded set.')).toBeInTheDocument()
  })
  it('names the rotating host coverage and keeps unchecked hosts without a current verdict', () => {
    mount({ ...exposure, coverage: { ...exposure.coverage, hosts_checked: 4, hosts_total: 9, pending_assets: 5 },
      host_coverage: [{ hostname: 'api.example.com', checked_this_scan: true, evidence_state: 'checked',
        last_checked_at: '2026-10-18T17:47:20Z' },
      { hostname: 'staging.example.com', checked_this_scan: false, evidence_state: 'awaiting_rotation',
        last_checked_at: null }] })
    expect(screen.getByText(/4 of 9 hosts checked this scan; the rest rotate on the next scans/)).toBeInTheDocument()
    expect(screen.getByText(/Unchecked hosts have no current security verdict/)).toBeInTheDocument()
    expect(screen.getByText(/Host coverage and last checked/)).toBeInTheDocument()
    expect(screen.getByText(/staging.example.com/)).toBeInTheDocument()
  })
  it('never words a non-resolving or failing host as a plain check', () => {
    expect(hostCoverageLabel({ checked_this_scan: true, evidence_state: 'host_does_not_resolve' }))
      .toBe('No DNS address this scan; content not assessed')
    expect(hostCoverageLabel({ checked_this_scan: true, evidence_state: 'target_unavailable' }))
      .toBe('Server unavailable this scan; content not assessed')
    expect(hostCoverageLabel({ checked_this_scan: true, evidence_state: 'checked' })).toBe('Checked this scan')
    expect(hostCoverageLabel({ checked_this_scan: false, evidence_state: 'awaiting_rotation' }))
      .toBe('Awaiting rotation; no current verdict')
  })
  it('renders observation text literally, without creating executable markup', () => {
    const value = structuredClone(exposure)
    value.findings[0].exposure.observation = '<img src=x onerror=alert(1)>'
    const { container } = mount(value)
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })
  it('replaces prior workspace evidence when the selected report changes', () => {
    const { rerender } = mount(exposure)
    rerender(<MemoryRouter><ExternalExposureChecks exposure={{ ...exposure, findings: [] }} domain="other.example" scanId="other-scan" /></MemoryRouter>)
    expect(screen.queryByText('Configuration credential exposed')).toBeNull()
    expect(screen.getByText(/No exposure findings in the recorded checks/)).toBeInTheDocument()
  })
})
