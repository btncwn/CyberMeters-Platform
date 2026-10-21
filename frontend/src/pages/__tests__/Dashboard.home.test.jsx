import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import Dashboard from '../Dashboard'
import { api } from '../../api'

// The home screen (founder, 16 Oct 2026): the question, the last assessment,
// the scan input that starts the scan flow with the typed domain, and the
// posture card with the backend's words.

vi.mock('../../api', () => ({
  api: {
    getWorkspaces: vi.fn(), getWorkspaceScans: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceScorecard: vi.fn(),
    getSecurityCheckDomains: vi.fn(), getCases: vi.fn(), getScanReport: vi.fn(), getWorkspaceMembers: vi.fn(),
    getWorkspaceSummary: vi.fn(), getDmarcIngestEndpoint: vi.fn(), verifyDmarcDns: vi.fn(),
    createScan: vi.fn(), getScan: vi.fn(),
  },
}))
vi.mock('../../components/OnboardingProgress', () => ({ default: () => null }))
vi.mock('../../components/FirstResultsGuide', () => ({ default: () => null }))
vi.mock('../../components/TeamOnboardingCard', () => ({ default: () => null }))
vi.mock('../../components/RecentChangesCard', () => ({ default: () => null }))

const KEYS = ['email_protection', 'attack_surface', 'website_security', 'identity_exposure', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness']
const eight = (over = {}) => KEYS.map((k) => ({ domain_key: k, display_name: k, description: '', state: 'not_yet_assessed', coverage: null, summary: 'Not yet assessed.', finding_count: 0, recommendation_count: 0, highest_severity: null, limitations: [], last_assessed_at: null, evidence_freshness: 'none', freshness_reason: 'No assessment has been recorded for this domain yet.', ...(over[k] || {}) }))

function renderHome() {
  localStorage.setItem('cybermeters_workspace_id', 'ws_a')
  localStorage.setItem('cybermeters_workspace_name', 'Customer A')
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans/new" element={<div data-testid="new-scan">{window.location.search}</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A' }] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [{ id: 's1', domain: 'example.co.uk', status: 'completed', created_at: new Date(Date.now() - 3 * 86400000).toISOString() }] })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'example.co.uk', domain_id: 'd1', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
  api.createScan.mockResolvedValue({ scan: { id: 'scan_new', status: 'queued' } })
  api.getScan.mockResolvedValue({ scan: { id: 'scan_new', status: 'running' } })
  api.getWorkspaceScorecard.mockResolvedValue(null)
  api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight({ email_protection: { state: 'issue_detected', summary: '2 issues.' }, attack_surface: { state: 'assessed_healthy', last_assessed_at: '2026-10-12T09:00:00Z', evidence_freshness: 'stale' } }) })
  api.getCases.mockResolvedValue({ cases: [] })
  api.getScanReport.mockResolvedValue({ cyber_mot_domains: null })
  api.getWorkspaceSummary.mockResolvedValue({ latest_score: 82 })
  api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: { last_inbound_at: null } })
  api.verifyDmarcDns.mockResolvedValue({ status: 'verified' })
})

describe('Home screen', () => {
  it('uses the setup connection proof before recommending the next email action', async () => {
    api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: { last_inbound_at: '2026-10-18T00:00:00Z' } })
    renderHome()
    const action = within(await screen.findByTestId('next-action'))
    await waitFor(() => expect(action.getByText(/connected DMARC reporting/)).toBeInTheDocument())
    expect(action.queryByText(/Connect Email Protection/)).not.toBeInTheDocument()
  })
  it('asks where the workspace is exposed, names the last assessment, and lists the posture from the backend', async () => {
    renderHome()
    expect(await screen.findByRole('heading', { level: 1, name: 'Where is Customer A exposed today?' })).toHaveClass('cm-hero-title')
    expect(screen.getByText(/Last assessment of example\.co\.uk ·/)).toBeInTheDocument()
    const card = within(await screen.findByTestId('posture-card'))
    expect(card.getByRole('heading', { name: 'Your external posture' })).toBeInTheDocument()
    const rows = card.getAllByRole('listitem')
    expect(rows.map(r => r.getAttribute('data-domain-key'))).toEqual(KEYS)
    await waitFor(() => expect(within(rows[0]).getByText('Action required')).toBeInTheDocument())
    expect(within(rows[1]).getByText('Stale')).toBeInTheDocument()
    expect(within(rows[2]).getByText('Not assessed')).toBeInTheDocument()
    expect(card.queryByText('Established')).not.toBeInTheDocument()
    expect(within(rows[0]).getByRole('link', { name: 'Email Protection' })).toHaveAttribute('href', '/ws/email-protection')
  })

  it('the scan input starts the scan flow with the typed domain; empty input still opens the scan page', async () => {
    renderHome()
    const input = await screen.findByRole('textbox', { name: 'Domain to scan' })
    expect(input).toHaveAttribute('placeholder', 'Enter a domain to scan, e.g. example.co.uk')
    fireEvent.change(input, { target: { value: '  Shop.Example.co.uk ' } })
    fireEvent.submit(screen.getByRole('form', { name: 'Start a scan' }))
    expect(await screen.findByTestId('new-scan')).toBeInTheDocument()
  })

  it('without any scan it says so instead of inventing a last assessment', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [] })
    renderHome()
    expect(await screen.findByText('No assessment has been recorded in this workspace yet.')).toBeInTheDocument()
  })

  it('a failed posture read shows Error on every row', async () => {
    api.getSecurityCheckDomains.mockRejectedValue(new Error('down'))
    renderHome()
    const card = within(await screen.findByTestId('posture-card'))
    await waitFor(() => expect(card.getAllByText('Error')).toHaveLength(8))
  })
})

describe('scan box by workspace role (18 Oct 2026)', () => {
  it.each(['analyst', 'viewer'])('an %s member is not offered the scan box', async (role) => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role }] })
    api.getWorkspaceMembers.mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner' }] })
    renderHome()
    await screen.findByRole('heading', { level: 1, name: 'Where is Customer A exposed today?' })
    await waitFor(() => expect(screen.queryByRole('form', { name: 'Start a scan' })).toBeNull())
    expect(screen.queryByRole('textbox', { name: 'Domain to scan' })).toBeNull()
    expect(screen.queryByTestId('setup-card')).toBeNull()
  })
  it('an analyst gets Scan now for the verified domain; a viewer does not', async () => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role: 'analyst' }] })
    const { unmount } = renderHome()
    const button = await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('example.co.uk', 'ws_a'))
    expect(await screen.findByRole('status')).toHaveTextContent('Scan started — results in about 2–3 minutes.')
    expect(screen.getByRole('link', { name: 'Follow progress' })).toHaveAttribute('href', '/scans/scan_new')
    unmount()
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role: 'viewer' }] })
    api.getWorkspaceMembers.mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner' }] })
    renderHome()
    await screen.findByRole('heading', { level: 1, name: 'Where is Customer A exposed today?' })
    await waitFor(() => expect(api.getWorkspaceMembers).toHaveBeenCalled())
    expect(screen.queryByTestId('dashboard-rescan')).toBeNull()
  })
  it.each(['owner', 'admin'])('an %s keeps the scan box', async (role) => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role }] })
    renderHome()
    await screen.findByRole('heading', { level: 1, name: 'Where is Customer A exposed today?' })
    await waitFor(() => expect(api.getWorkspaces).toHaveBeenCalled())
    expect(screen.getByRole('form', { name: 'Start a scan' })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Domain to scan' })).toBeInTheDocument()
    // The form adds a new domain; Scan now rescans the verified one.
    expect(await screen.findByRole('button', { name: 'Scan now' })).toBeInTheDocument()
  })
})

describe('no score yet (founder, 20 Oct 2026)', () => {
  it('a first scan that did not complete every check gets a calm note, not a blank or a red banner', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [{ id: 's1', domain: 'example.co.uk', status: 'completed', scan_quality: 'partial',
      assessment: { quality: 'partial', provisional: true, authoritative: false, display_score: 71, display_rating: null }, created_at: new Date().toISOString() }] })
    renderHome()
    const note = within(await screen.findByTestId('incomplete-assessment-note'))
    expect(note.getByRole('heading', { name: 'First assessment incomplete' })).toBeInTheDocument()
    expect(note.getByText(/so there is no score yet/)).toBeInTheDocument()
    expect(note.getByRole('link', { name: 'See what was measured' })).toHaveAttribute('href', '/scans/s1')
    expect(screen.queryByText('71')).toBeNull()
  })

  it('a complete, final assessment shows no note', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [{ id: 's2', domain: 'example.co.uk', status: 'completed', scan_quality: 'complete',
      assessment: { quality: 'complete', provisional: false, authoritative: true, comparable: true, display_score: 82, display_rating: 'good' }, created_at: new Date().toISOString() }] })
    renderHome()
    await screen.findByTestId('posture-card')
    expect(screen.queryByTestId('incomplete-assessment-note')).toBeNull()
  })
})
