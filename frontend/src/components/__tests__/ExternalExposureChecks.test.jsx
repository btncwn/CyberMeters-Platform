import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import ExternalExposureChecks from '../ExternalExposureChecks'

const exposure = {
  source: 'external_exposure', observed_at: '2026-10-13T09:00:00Z',
  coverage: { completed: 8, pending: 2, blocked: 1, not_applicable: 3, budget_exhausted: 4, uncertain: 1 },
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
  it('shows all coverage states, safe evidence, rationale, remediation and a scoped recheck link', () => {
    mount(exposure)
    for (const label of ['Completed', 'Waiting', 'Blocked', 'Not applicable', 'Budget reached', 'Not determined']) expect(screen.getByText(label)).toBeInTheDocument()
    expect(screen.getByText(/https:\/\/example.com\/\.env/)).toBeInTheDocument()
    expect(screen.getByText(/validity was not tested/)).toBeInTheDocument()
    expect(screen.getByText(/configuration structure/)).toBeInTheDocument()
    expect(screen.getByText(/Restrict the file and replace/)).toBeInTheDocument()
    expect(screen.getByText(/cannot confirm that a previous finding was fixed/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Recheck this website' })).toHaveAttribute('href', '/scans/new?domain=example.com')
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
