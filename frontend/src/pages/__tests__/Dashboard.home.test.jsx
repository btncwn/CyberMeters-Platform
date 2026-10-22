import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
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
    createScan: vi.fn(), getScan: vi.fn(), getShadowItInventory: vi.fn(),
  },
}))
vi.mock('../../components/OnboardingProgress', () => ({ default: () => null }))
vi.mock('../../components/FirstResultsGuide', () => ({ default: () => null }))
vi.mock('../../components/TeamOnboardingCard', () => ({ default: () => null }))
vi.mock('../../components/RecentChangesCard', () => ({ default: () => null }))

const KEYS = ['email_protection', 'attack_surface', 'website_security', 'identity_exposure', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness']
const eight = (over = {}) => KEYS.map((k) => ({ domain_key: k, display_name: k, description: '', state: 'not_yet_assessed', coverage: null, summary: 'Not yet assessed.', finding_count: 0, recommendation_count: 0, highest_severity: null, limitations: [], last_assessed_at: null, evidence_freshness: 'none', freshness_reason: 'No assessment has been recorded for this domain yet.', ...(over[k] || {}) }))

function NewScanProbe() {
  const { search } = useLocation()
  return <div data-testid="new-scan-probe">{decodeURIComponent(search)}</div>
}

function renderHome() {
  localStorage.setItem('cybermeters_workspace_id', 'ws_a')
  localStorage.setItem('cybermeters_workspace_name', 'Customer A')
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans/new" element={<NewScanProbe />} />
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
  api.getShadowItInventory.mockResolvedValue({ counts: { unreviewed: 0 } })
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
    const { unmount } = renderHome()
    // No report has arrived yet: the list asks for DMARC reporting, opening exactly where it is set up.
    const list = within(await screen.findByTestId('next-actions'))
    expect(await list.findByRole('link', { name: 'Set up: Connect DMARC reporting' })).toHaveAttribute('href', '/ws/email-protection?tab=settings#dmarc-setup')
    unmount()
    api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: { last_inbound_at: '2026-10-18T00:00:00Z' } })
    renderHome()
    const proven = within(await screen.findByTestId('next-actions'))
    await waitFor(() => expect(api.getDmarcIngestEndpoint).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(proven.queryByText('Connect DMARC reporting')).not.toBeInTheDocument())
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
    // Deterministic (flaked under CI load, Seat 2 on #847): wait for the settled
    // form — the verified domain prefilled — so the domain list has loaded and
    // no later render replaces the field. Typing into a field that is then
    // replaced is lost: the prefill wins and the submit starts a scan instead
    // of opening the new-scan page.
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Domain to scan' })).toHaveValue('example.co.uk'))
    const input = screen.getByRole('textbox', { name: 'Domain to scan' })
    expect(input).toHaveAttribute('placeholder', 'Enter a domain to scan, e.g. example.co.uk')
    fireEvent.change(input, { target: { value: '  Shop.Example.co.uk ' } })
    expect(screen.getByRole('textbox', { name: 'Domain to scan' })).toHaveValue('  Shop.Example.co.uk ')
    fireEvent.submit(screen.getByRole('form', { name: 'Start a scan' }))
    // A domain this workspace has not verified keeps the new-scan path, normalised.
    expect(await screen.findByTestId('new-scan-probe', {}, { timeout: 5000 })).toHaveTextContent('?domain=shop.example.co.uk')
    expect(api.createScan).not.toHaveBeenCalled()
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

describe('scan box by workspace role (18 Oct 2026); one scan control (21 Oct 2026)', () => {
  const scanControls = () => screen.queryAllByRole('button', { name: /^(Scan|Scan now|Run a scan|Run a fresh scan)$/ })

  it('a viewer is not offered the scan box', async () => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role: 'viewer' }] })
    api.getWorkspaceMembers.mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner' }] })
    renderHome()
    await screen.findByRole('heading', { level: 1, name: 'Where is Customer A exposed today?' })
    await waitFor(() => expect(api.getWorkspaceMembers).toHaveBeenCalled())
    expect(screen.queryByRole('form', { name: 'Start a scan' })).toBeNull()
    expect(scanControls()).toHaveLength(0)
    expect(screen.queryByTestId('setup-card')).toBeNull()
  })

  it('an analyst picks a verified domain and scans it in place (no free-text domain)', async () => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role: 'analyst' }] })
    renderHome()
    const picker = await screen.findByRole('combobox', { name: 'Domain to scan' })
    await waitFor(() => expect(picker).toHaveValue('example.co.uk'))
    expect(screen.queryByRole('textbox', { name: 'Domain to scan' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('example.co.uk', 'ws_a'))
    expect(await screen.findByRole('status')).toHaveTextContent('Scan started — results in about 2–3 minutes.')
    expect(screen.getByRole('link', { name: 'Follow progress' })).toHaveAttribute('href', '/scans/scan_new')
  })

  it.each(['owner', 'admin'])('an %s gets ONE scan control: the field prefilled with the verified domain', async (role) => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role }] })
    renderHome()
    const field = await screen.findByRole('textbox', { name: 'Domain to scan' })
    await waitFor(() => expect(field).toHaveValue('example.co.uk'))
    expect(screen.getByRole('form', { name: 'Start a scan' })).toBeInTheDocument()
    expect(scanControls()).toHaveLength(1)
    expect(screen.queryByRole('button', { name: /Reload results/ })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('example.co.uk', 'ws_a'))
  })

  it('a domain not verified yet says so and keeps the new-scan path', async () => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role: 'owner' }] })
    renderHome()
    const field = await screen.findByRole('textbox', { name: 'Domain to scan' })
    await waitFor(() => expect(field).toHaveValue('example.co.uk'))
    fireEvent.change(field, { target: { value: 'new-shop.example' } })
    expect(screen.getByText(/new-shop\.example is not verified in this workspace yet/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    expect(api.createScan).not.toHaveBeenCalled()
    expect(await screen.findByTestId('new-scan-probe')).toHaveTextContent('new-shop.example')
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

describe('after a scan finishes (22 Oct 2026)', () => {
  afterEach(() => vi.useRealTimers())

  it('the page reloads in place: no full-page spinner, and the scan box keeps its "complete" note', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A', role: 'analyst' }] })
    api.getScan.mockResolvedValue({ scan: { id: 'scan_new', status: 'completed' } })
    renderHome()
    const picker = await screen.findByRole('combobox', { name: 'Domain to scan' })
    await waitFor(() => expect(picker).toHaveValue('example.co.uk'))
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    await waitFor(() => expect(api.createScan).toHaveBeenCalled())
    // Hold the reload's scan list open, so the page is observed mid-reload.
    let release
    api.getWorkspaceScans.mockImplementationOnce(() => new Promise((resolve) => { release = () => resolve({ scans: [{ id: 'scan_new', domain: 'example.co.uk', status: 'completed', created_at: new Date().toISOString() }] }) }))
    await vi.advanceTimersByTimeAsync(15000)
    await waitFor(() => expect(release).toBeTypeOf('function'))
    // Mid-reload the page stays mounted: same heading, same scan box, its note intact.
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Where is Customer A exposed today?')
    expect(screen.getByRole('combobox', { name: 'Domain to scan' })).toBe(picker)
    expect(screen.getByRole('status')).toHaveTextContent('The scan of example.co.uk is complete')
    release()
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Domain to scan' })).toBe(picker))
    expect(screen.getByRole('status')).toHaveTextContent('The scan of example.co.uk is complete')
  })
})
