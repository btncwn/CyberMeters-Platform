// Attack Surface Findings reflect what the latest scan recorded for the domain:
// registration (RDAP), the critical-name DNS pass, public-content exposure, the
// deep TLS assessment and the check pack's statement on outside vulnerability
// data. Every sentence is the backend's own field; nothing is derived here.
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import AssetsPage from '../AssetsPage'

vi.mock('../../api', () => ({
  api: {
    getManagedCases: vi.fn(),
    getWorkspaceAssetsSummary: vi.fn(),
    getWorkspaceAssets: vi.fn(),
    getWorkspaceAssetsTimeline: vi.fn(),
    getWorkspaceScans: vi.fn(),
    getScanReport: vi.fn(),
  },
}))
vi.mock('../../components/CasesQueue', () => ({ default: () => null }))
vi.mock('../../components/AttackSurfaceAssurance', () => ({ default: () => null }))
vi.mock('../../components/HostnameListPanel', () => ({ default: () => null }))
vi.mock('../../components/NetworkAssetsPanel', () => ({ default: () => null }))

const VULN_STATEMENT = 'Reported software versions are not matched against outside vulnerability databases. A version the server reports is shown as a disclosure, never as a confirmed vulnerability.'
const KEV_STATEMENT = 'Outside lists of exploited vulnerabilities and exploit-likelihood scores are not used, shown or counted in the score.'

const assets = [
  { id: 'a1', hostname: 'vpn.example.com', asset_type: 'subdomain', source: 'dns_bruteforce', last_seen: '2026-10-12T10:00:00Z', lifecycle_state: 'observed', lifecycle_state_label: 'Observed' },
  { id: 'a2', hostname: 'blog.example.com', asset_type: 'subdomain', source: 'dns_bruteforce', last_seen: '2026-10-12T10:00:00Z', lifecycle_state: 'observed', lifecycle_state_label: 'Observed' },
]

function report(over = {}) {
  return {
    scan_id: 'scan_1',
    scan_quality: { status: 'complete' },
    findings: [{ id: 'tls_legacy_protocol', module: 'tls_assessment', severity: 'high', finding_type: 'finding' }],
    check_pack: { version: '2026.10.13.1' },
    modules: {
      whois_intelligence: {
        source: 'rdap', optional: true, domain: 'example.com', registrar: 'Example Registrar Ltd',
        creation_date: '2016-03-01T00:00:00Z', expiration_date: '2026-11-20T00:00:00Z',
        domain_age_days: 3881, days_until_expiry: 35, registration_status: 'client_transfer_prohibited',
        findings: [
          { id: 'whois_expiry_warning', severity: 'medium', title: 'Domain expires within 90 days', description: 'Domain example.com expires in 35 days.', recommendation: 'Schedule domain renewal.' },
          { id: 'whois_registrar_info', severity: 'info', title: 'Registrar information', description: 'Registered through Example Registrar Ltd.' },
        ],
      },
      critical_prefix_discovery: { source: 'critical_prefix_dns', checked: 8, requested: 8, found: 1, items: ['vpn.example.com'] },
      external_exposure: {
        source: 'external_exposure', quality: 'complete', observed_at: '2026-10-12T10:00:00Z',
        coverage: { completed: 4, pending: 0, blocked: 0, not_applicable: 0, budget_exhausted: 0, uncertain: 0, pending_assets: 0 },
        checks: [], findings: [], costs: { requests: 12 },
      },
      tls_assessment: { source: 'tls_assessment', quality: 'partial', observed_at: '2026-10-12T10:00:00Z', coverage: { planned: 4, completed: 3, uncertain: 1 }, endpoints: [{ hostname: 'example.com', address: '192.0.2.1', port: 443, checks: [] }] },
      cve_intelligence: { executed: false, outcome: 'not_in_check_pack', source: 'vulnerability_database_matching', check_pack_version: '2026.10.13.1', customer_message: VULN_STATEMENT, findings: [] },
      known_exploited_vulnerabilities: { executed: false, outcome: 'not_in_check_pack', source: 'exploited_vulnerability_data', check_pack_version: '2026.10.13.1', customer_message: KEV_STATEMENT, findings: [] },
      ...over,
    },
  }
}

async function renderFindings({ scans = [{ id: 'scan_1', domain: 'example.com', status: 'completed', created_at: '2026-10-12T10:00:00Z' }], rep = report() } = {}) {
  api.getWorkspaceAssetsSummary.mockResolvedValue({ total_assets: 2, lifecycle_counts: { observed: 2 } })
  api.getWorkspaceAssets.mockResolvedValue({ assets })
  api.getWorkspaceAssetsTimeline.mockResolvedValue({ timeline: [] })
  api.getManagedCases.mockResolvedValue({ cases: [] })
  api.getWorkspaceScans.mockResolvedValue({ scans })
  api.getScanReport.mockResolvedValue(rep)
  render(<MemoryRouter initialEntries={['/assets?tab=findings']}><AssetsPage /></MemoryRouter>)
  await screen.findByText('vpn.example.com')
}

beforeEach(() => {
  localStorage.setItem('cybermeters_workspace_id', 'ws-1')
  localStorage.setItem('cybermeters_workspace_name', 'Acme')
  vi.clearAllMocks()
})

describe('AssetsPage — latest scan evidence on Findings', () => {
  it('shows the domain registration the registry answered, its findings, and tags the critical name in the table', async () => {
    await renderFindings()
    const reg = await screen.findByLabelText('Domain registration')
    expect(within(reg).getByText('Example Registrar Ltd')).toBeInTheDocument()
    expect(within(reg).getByText('in 35 days')).toBeInTheDocument()
    expect(within(reg).getByText('10 years')).toBeInTheDocument()
    expect(within(reg).getByText('Domain expires within 90 days')).toBeInTheDocument()
    expect(within(reg).getByText('Medium')).toBeInTheDocument()
    // The registrar is a field, so its informational finding is not repeated as a finding.
    expect(within(reg).queryByText('Registrar information')).not.toBeInTheDocument()

    expect(screen.getByTestId('critical-prefix-coverage')).toHaveTextContent('Critical names: 1 found among 8 of 8 checked.')
    expect(within(screen.getByText('vpn.example.com').closest('tr')).getByText('Critical name')).toBeInTheDocument()
    expect(within(screen.getByText('blog.example.com').closest('tr')).queryByText('Critical name')).not.toBeInTheDocument()
  })

  it('summarises public-content exposure and the deep TLS assessment, and repeats the check pack statement on outside vulnerability data', async () => {
    await renderFindings()
    const exposure = await screen.findByLabelText('Public content and management surfaces')
    expect(within(exposure).getByText('Completed').nextSibling).toHaveTextContent('4')
    expect(within(exposure).getByText(/No exposure findings in the recorded checks/)).toBeInTheDocument()

    const tls = screen.getByLabelText('TLS security assessment')
    expect(within(tls).getByText(/Partial — some checks remain unresolved/)).toBeInTheDocument()
    expect(within(tls).getByText('Completed: 3')).toBeInTheDocument()
    expect(within(tls).getByText(/1 endpoint recorded · 1 TLS finding in this scan/)).toBeInTheDocument()
    expect(within(tls).getByRole('link', { name: 'View TLS measurement' })).toHaveAttribute('href', '/scans/scan_1?view=technical')

    const vuln = screen.getByLabelText('Outside vulnerability data')
    expect(within(vuln).getByText(VULN_STATEMENT)).toBeInTheDocument()
    expect(within(vuln).getByText(KEV_STATEMENT)).toBeInTheDocument()
    expect(within(vuln).getByText('Check version 2026.10.13.1')).toBeInTheDocument()
    expect(within(vuln).getByRole('link', { name: 'Open the intelligence page' })).toHaveAttribute('href', '/intelligence')
    expect(screen.queryByText(/KEV match/i)).not.toBeInTheDocument()
  })

  it('says when the registry did not answer, when deep TLS was not recorded, and keeps a stored scan\'s recorded vulnerability data as recorded', async () => {
    await renderFindings({ rep: report({
      whois_intelligence: { source: 'rdap', optional: true, outcome: 'unavailable', unavailable: true, reason: 'lookup_failed', registries_asked: [], findings: [] },
      critical_prefix_discovery: { source: 'critical_prefix_dns', checked: 3, requested: 8, found: 0, items: [], incomplete: true, incomplete_reason: 'subrequest_budget_exhausted', deferred_count: 5 },
      tls_assessment: undefined,
      cve_intelligence: { evidence_publishable: true, critical_count: 1, high_count: 2 },
      known_exploited_vulnerabilities: { evidence_publishable: true, matched: 1, matches: [{ cve_id: 'CVE-2099-0001' }] },
    }) })
    const reg = await screen.findByLabelText('Domain registration')
    expect(within(reg).getByText(/The registry did not answer this scan \(lookup failed\)/)).toBeInTheDocument()
    expect(within(reg).queryByText('Registrar')).not.toBeInTheDocument()
    expect(screen.getByTestId('critical-prefix-coverage')).toHaveTextContent('0 found among 3 of 8 checked; the check did not finish (subrequest budget exhausted)')
    expect(screen.queryByText('Critical name')).not.toBeInTheDocument()
    expect(within(screen.getByLabelText('TLS security assessment')).getByText(/Deep TLS checks were not recorded in this scan/)).toBeInTheDocument()
    const vuln = screen.getByLabelText('Outside vulnerability data')
    expect(within(vuln).getByText(/recorded outside vulnerability data under the checks in force when it ran/)).toBeInTheDocument()
    expect(within(vuln).getByText('1 exploited-vulnerability match · 1 critical and 2 high CVE records')).toBeInTheDocument()
  })

  it('with no scan yet, says so and records nothing', async () => {
    await renderFindings({ scans: [] })
    expect(await screen.findByText(/No scan has run for this workspace yet/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Domain registration')).not.toBeInTheDocument()
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it('a failed scan is not replaced by an older success, and its report is not read', async () => {
    await renderFindings({ scans: [
      { id: 'scan_new', domain: 'example.com', status: 'failed', created_at: '2026-10-13T10:00:00Z' },
      { id: 'scan_old', domain: 'example.com', status: 'completed', created_at: '2026-10-12T10:00:00Z' },
    ] })
    expect(await screen.findByText(/The latest scan has not produced a completed assessment/)).toBeInTheDocument()
    expect(api.getScanReport).not.toHaveBeenCalled()
  })
})
