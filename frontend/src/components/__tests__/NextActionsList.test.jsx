import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import NextActionsList, { buildNextActions } from '../overview/NextActionsList'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: { getShadowItInventory: vi.fn(), getMcpConnections: vi.fn(), getWorkspaces: vi.fn(), getWorkspaceMembers: vi.fn(), getWorkspaceDomains: vi.fn(), createScan: vi.fn(), getScan: vi.fn() },
}))

const row = (domain_key, state = 'assessed_healthy', extra = {}) => ({ domain_key, state, coverage: 'complete', finding_count: 0, finding_details: [], highest_severity: null, ...extra })
const eight = (over = {}) => MODULES.map((m) => over[m.domainKey] || row(m.domainKey))
const mapped = (finding_id, customer_title, recommended_action = 'Do the registered thing.') => ({ finding_id, status: 'resolved', customer_title, recommended_action })

describe('buildNextActions', () => {
  it('orders by severity, then evidence, across areas', () => {
    const rows = buildNextActions({ domains: eight({
      website_security: row('website_security', 'issue_detected', { highest_severity: 'medium', finding_count: 1, finding_details: [mapped('header_weak_hsts', 'Add or strengthen HSTS')] }),
      certificates_trust: row('certificates_trust', 'issue_detected', { highest_severity: 'critical', finding_count: 1, finding_details: [mapped('ssl_expired', 'Renew the certificate')] }),
      attack_surface: row('attack_surface', 'provisional', { highest_severity: 'medium', finding_count: 1, finding_details: [mapped('open_port', 'Close the exposed service')] }),
    }) })
    expect(rows.map((r) => r.title)).toEqual(['Renew the certificate', 'Add or strengthen HSTS', 'Close the exposed service'])
    expect(rows[0].action).toEqual({ label: 'View fix', to: '/ws/certificates?tab=findings' })
  })

  it('MTA-STS and the DMARC policy open exactly where they are done', () => {
    const rows = buildNextActions({ domains: eight({
      email_protection: row('email_protection', 'issue_detected', { highest_severity: 'medium', finding_count: 2, finding_details: [
        mapped('email_intel_mta_sts_missing', 'Publish MTA-STS'), mapped('email_dmarc_policy_none', 'Strengthen DMARC enforcement'),
      ] }),
    }) })
    expect(rows.find((r) => r.key === 'email-mta-sts').action.to).toBe('/ws/email-protection?tab=settings#mta-sts-setup')
    expect(rows.find((r) => r.key === 'email-dmarc-policy').action).toEqual({ label: 'Review DMARC policy steps', to: '/ws/email-protection?tab=settings#dmarc-enforcement' })
  })

  it('Shadow IT classification and DMARC reporting come from their own signals', () => {
    const rows = buildNextActions({ domains: eight(), unclassified: 7, dmarcConnected: false })
    expect(rows.find((r) => r.key === 'shadow-it-classify')).toMatchObject({ title: '7 technologies not yet classified', action: { label: 'Classify', to: '/ws/shadow-it' } })
    expect(rows.find((r) => r.key === 'email-dmarc-reporting').action.to).toBe('/ws/email-protection?tab=settings#dmarc-setup')
    // An unknown DMARC signal or an unread Shadow IT count suggests nothing.
    expect(buildNextActions({ domains: eight(), unclassified: null, dmarcConnected: null })).toEqual([])
  })

  it('an unmapped finding never gets invented advice; an unassessed area asks for a scan, last', () => {
    const rows = buildNextActions({ domains: eight({
      identity_exposure: row('identity_exposure', 'not_yet_assessed'),
      brand_protection: row('brand_protection', 'issue_detected', { highest_severity: 'high', finding_count: 2, finding_details: [{ finding_id: 'x', status: 'unmapped' }] }),
    }) })
    expect(rows[0]).toMatchObject({ title: 'Review the findings in Brand Protection', action: { label: 'Review findings' } })
    expect(rows.at(-1)).toMatchObject({ key: 'scan', action: { scan: true } })
    expect(rows.at(-1).body).toMatch(/Identity Exposure/)
  })

  it('an eligible account with no active MCP connection is offered one; otherwise nothing', () => {
    const row = buildNextActions({ domains: eight(), mcp: { eligible: true, active: 0 } }).find((r) => r.key === 'mcp-connect')
    expect(row).toMatchObject({ title: 'Connect your AI assistant', action: { label: 'Connect', to: '/account/mcp' } })
    expect(buildNextActions({ domains: eight(), mcp: { eligible: true, active: 1 } })).toEqual([])
    expect(buildNextActions({ domains: eight(), mcp: { eligible: false, active: 0 } })).toEqual([])
    expect(buildNextActions({ domains: eight(), mcp: null })).toEqual([])
  })

  it('a failed read suggests nothing', () => {
    expect(buildNextActions({ domains: [], request: 'error', unclassified: 3 })).toEqual([])
  })
})

describe('NextActionsList', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getShadowItInventory.mockResolvedValue({ counts: { unreviewed: 2 } })
    api.getMcpConnections.mockResolvedValue({ eligible: true, connections: [{ id: 'mcpconn_1', status: 'active' }] })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1', role: 'owner' }] })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  })

  it('one labelled action per row, in order, including Shadow IT', async () => {
    render(<MemoryRouter><NextActionsList workspaceId="ws1" request="ok" dmarcConnected domains={eight({
      certificates_trust: row('certificates_trust', 'issue_detected', { highest_severity: 'high', finding_count: 1, finding_details: [mapped('ssl_expiring', 'Renew the certificate')] }),
    })} /></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'Your next actions' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getAllByTestId('next-action-row')).toHaveLength(2))
    const [first, second] = screen.getAllByTestId('next-action-row')
    expect(within(first).getByRole('link', { name: 'View fix: Renew the certificate' })).toHaveAttribute('href', '/ws/certificates?tab=findings')
    expect(within(second).getByRole('link', { name: 'Classify: 2 technologies not yet classified' })).toHaveAttribute('href', '/ws/shadow-it')
    expect(api.getShadowItInventory).toHaveBeenCalledWith('ws1', { limit: 1 })
  })

  it('says plainly when there is nothing to act on', async () => {
    api.getShadowItInventory.mockResolvedValue({ counts: { unreviewed: 0 } })
    render(<MemoryRouter><NextActionsList workspaceId="ws1" request="ok" dmarcConnected domains={eight()} /></MemoryRouter>)
    expect(await screen.findByText(/Nothing to act on from the latest assessment/)).toBeInTheDocument()
  })
})

it('the Overview offers "Connect your AI assistant" by accessible name when eligible and unconnected', async () => {
  api.getShadowItInventory.mockResolvedValue({ counts: { unreviewed: 0 } })
  api.getMcpConnections.mockResolvedValue({ eligible: true, connections: [{ id: 'mcpconn_1', status: 'revoked' }] })
  render(<MemoryRouter><NextActionsList workspaceId="ws1" request="ok" dmarcConnected domains={eight()} /></MemoryRouter>)
  expect(await screen.findByRole('link', { name: 'Connect: Connect your AI assistant' })).toHaveAttribute('href', '/account/mcp')
})
