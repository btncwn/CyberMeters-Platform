import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import ModuleContract, { MODULE_TABS, matchesFilter, tabForLocation, useAreaAnchor } from '../module/ModuleContract'
import { api } from '../../api'

// The area page head (founder, 16 Oct 2026): serif title, description, the
// backend word, a filter box, four tabs, and the area's sub-page tiles.

vi.mock('../../api', () => ({ api: { getCyberMotDomains: vi.fn(), getManagedCases: vi.fn() } }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

const KEYS = ['email_protection', 'attack_surface', 'website_security', 'identity_exposure', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness']
const eight = (over = {}) => KEYS.map((k) => ({ domain_key: k, display_name: k, state: 'assessed_healthy', coverage: 'complete', summary: `${k} ok`, finding_count: 0, recommendation_count: 1, highest_severity: null, limitations: [], last_assessed_at: '2026-10-12T09:00:00Z', evidence_freshness: 'current', freshness_reason: 'Last assessed 3 days ago.', ...(over[k] || {}) }))
const CASES = [
  { case_id: 'c1', domain_key: 'email_protection', canonical_phase: 'awaiting_verification', verification_support: 'automated', title: 'DMARC policy is p=none', domain: 'example.co.uk' },
  { case_id: 'c2', domain_key: 'email_protection', canonical_phase: 'action_in_progress', verification_support: 'manual', title: 'DKIM selector rotated', domain: 'mail.example.co.uk' },
]

function renderPage(path = '/ws/email-protection', props = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={(
          <ModuleContract domainKey="email_protection" workspaceId="ws1" workspaceName="Customer A" description="Monitor DMARC alignment." actions={<button type="button">Review DMARC setup</button>} {...props}>
            <p data-testid="body">the page body</p>
          </ModuleContract>
        )} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight({ email_protection: { state: 'issue_detected', highest_severity: 'high', finding_count: 3 } }) })
  api.getManagedCases.mockResolvedValue({ cases: CASES })
})

describe('ModuleContract — head and tabs', () => {
  it('opens on Overview with the serif title, description, backend word, filter box, actions and tiles', async () => {
    renderPage()
    expect(screen.getByRole('heading', { level: 1, name: 'Email Protection' })).toHaveClass('cm-hero-title')
    expect(screen.getByText('Monitor DMARC alignment.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review DMARC setup' })).toBeInTheDocument()
    expect(screen.getByRole('searchbox', { name: 'Filter pages and cases in this area' })).toHaveAttribute('placeholder', 'Filter pages and cases in this area')
    await waitFor(() => expect(within(screen.getByTestId('module-head-status')).getByText('Action required')).toBeInTheDocument())
    expect(within(screen.getByTestId('module-head-status')).getByText(/Last assessed 3 days ago/)).toBeInTheDocument()
    const tabs = screen.getAllByRole('tab')
    expect(tabs.map(t => t.textContent)).toEqual(MODULE_TABS.map(t => t.label))
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    const tiles = within(screen.getByTestId('module-tiles')).getAllByRole('link')
    expect(tiles.map(t => t.getAttribute('href'))).toEqual(['/ws/email-protection#dmarc-setup', '/ws/email-protection#sender-inventory', '/ws/email-protection#auth-detail'])
    // Overview (founder, 16 Oct 2026): the tiles and the summary card only — no
    // numbered strip, no findings, cases, verification or guide sections here.
    expect(screen.queryByTestId('body')).not.toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'On this page' })).not.toBeInTheDocument()
    const headings = screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())
    expect(headings).toEqual(['Scope', 'Evidence state', 'Risk'])
    expect(within(screen.getByTestId('module-summary')).getAllByRole('heading', { level: 2 })).toHaveLength(3)
  })

  it('switches tabs through the URL: Findings shows the body and the action, Cases the cases, Field Guide the guide', async () => {
    renderPage('/ws/email-protection?tab=findings')
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('body')).toBeInTheDocument()
    expect(screen.queryByTestId('module-tiles')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['Findings', 'Recommended action'])

    fireEvent.click(screen.getByRole('tab', { name: 'Cases' }))
    expect(screen.getByRole('tab', { name: 'Cases' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByText('DMARC policy is p=none')).toBeInTheDocument()
    expect(screen.queryByTestId('body')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['Managed case', 'Verification'])

    fireEvent.click(screen.getByRole('tab', { name: 'Field Guide' }))
    expect(screen.getByRole('link', { name: 'Open the Field Guide' })).toHaveAttribute('href', '/guide/email-protection')
    expect(screen.queryByText('DMARC policy is p=none')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['Field Guide'])

    fireEvent.click(screen.getByRole('tab', { name: 'Overview' }))
    expect(screen.getByTestId('module-tiles')).toBeInTheDocument()
  })

  it('an unknown ?tab= is Overview', () => {
    renderPage('/ws/email-protection?tab=nonsense')
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
  })

  it('a deep link into the body — an anchor or another query parameter — opens Findings and scrolls to the anchor', () => {
    const scrolled = []
    Element.prototype.scrollIntoView = function () { scrolled.push(this.id) }
    expect(tabForLocation(new URLSearchParams(''), '')).toBe('overview')
    expect(tabForLocation(new URLSearchParams('tab=cases'), '#x')).toBe('cases')
    expect(tabForLocation(new URLSearchParams('lifecycle=rec_1'), '')).toBe('findings')
    expect(tabForLocation(new URLSearchParams(''), '#dmarc-setup')).toBe('findings')
    let r = renderPage('/ws/email-protection?lifecycle=rec_1')
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    r.unmount()
    r = render(
      <MemoryRouter initialEntries={['/ws/email-protection#body-anchor']}>
        <Routes>
          <Route path="*" element={(
            <ModuleContract domainKey="email_protection" workspaceId="ws1" workspaceName="Customer A">
              <p id="body-anchor">the page body</p>
            </ModuleContract>
          )} />
        </Routes>
      </MemoryRouter>,
    )
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    expect(scrolled).toContain('body-anchor')
    r.unmount()
  })

  it('useAreaAnchor scrolls to an element on the current tab, otherwise opens Findings at that anchor', () => {
    const scrolled = []
    Element.prototype.scrollIntoView = function () { scrolled.push(this.id) }
    function Page() {
      const go = useAreaAnchor()
      return (
        <ModuleContract domainKey="email_protection" workspaceId="ws1" workspaceName="Customer A" actions={<button type="button" onClick={() => go('setup-block')}>Go to setup</button>}>
          <p id="setup-block">setup</p>
        </ModuleContract>
      )
    }
    render(<MemoryRouter initialEntries={['/ws/email-protection']}><Routes><Route path="*" element={<Page />} /></Routes></MemoryRouter>)
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
    fireEvent.click(screen.getByRole('button', { name: 'Go to setup' }))
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('setup')).toBeInTheDocument()
    expect(scrolled).toContain('setup-block')
    scrolled.length = 0
    fireEvent.click(screen.getByRole('button', { name: 'Go to setup' }))
    expect(scrolled).toEqual(['setup-block'])
  })

  it('the filter box narrows the tiles and the case list, and says so when nothing matches', async () => {
    renderPage()
    await waitFor(() => expect(api.getManagedCases).toHaveBeenCalled())
    const box = screen.getByRole('searchbox', { name: 'Filter pages and cases in this area' })
    fireEvent.change(box, { target: { value: 'sender' } })
    expect(within(screen.getByTestId('module-tiles')).getAllByRole('link').map(t => t.textContent)).toEqual(['Sender InventoryEvery source seen sending as your domain'])
    fireEvent.click(screen.getByRole('tab', { name: 'Cases' }))
    expect(screen.getByText('No case in this area matches the filter.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Overview' }))
    fireEvent.change(box, { target: { value: 'dkim' } })
    // The tile whose description names DKIM stays; the others go.
    expect(within(screen.getByTestId('module-tiles')).getAllByRole('link').map(t => t.getAttribute('href'))).toEqual(['/ws/email-protection#auth-detail'])
    fireEvent.click(screen.getByRole('tab', { name: 'Cases' }))
    expect(screen.getByText('DKIM selector rotated')).toBeInTheDocument()
    expect(screen.queryByText('DMARC policy is p=none')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Overview' }))
    fireEvent.change(box, { target: { value: 'zzz-nothing' } })
    expect(screen.queryByTestId('module-tiles')).not.toBeInTheDocument()
    fireEvent.change(box, { target: { value: '' } })
    fireEvent.click(screen.getByRole('tab', { name: 'Cases' }))
    expect(screen.getByText('DMARC policy is p=none')).toBeInTheDocument()
    expect(matchesFilter('Sender Inventory', ' sender ')).toBe(true)
    expect(matchesFilter(null, 'x')).toBe(false)
    expect(matchesFilter('anything', '')).toBe(true)
  })

  it('a failed read shows Error in the head, never a settled word; an area without sub-pages shows no tiles', async () => {
    api.getCyberMotDomains.mockRejectedValue(new Error('down'))
    render(
      <MemoryRouter initialEntries={['/ws/website-security']}>
        <ModuleContract domainKey="website_security" workspaceId="ws1" workspaceName="Customer A"><p>body</p></ModuleContract>
      </MemoryRouter>,
    )
    await waitFor(() => expect(within(screen.getByTestId('module-head-status')).getByText('Error')).toBeInTheDocument())
    expect(within(screen.getByTestId('module-head-status')).getByText('The latest assessment could not be read.')).toBeInTheDocument()
    expect(screen.queryByTestId('module-tiles')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Website Security' })).toBeInTheDocument()
  })
})
