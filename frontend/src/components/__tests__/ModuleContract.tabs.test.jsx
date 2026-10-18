import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import ModuleContract, { MODULE_TABS, matchesFilter, tabForLocation, useAreaAnchor } from '../module/ModuleContract'
import { api } from '../../api'

// The area page head (founder, 16 Oct 2026): serif title, description, the
// backend word, a filter box, four tabs, and the area's sub-page tiles.

vi.mock('../../api', () => ({ api: { getCyberMotDomains: vi.fn(), getCases: vi.fn() } }))
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
  api.getCases.mockResolvedValue({ cases: CASES })
})

describe('ModuleContract — head and tabs', () => {
  it('reaches all five tabs with Tab, arrows, Home and End', async () => {
    const user = userEvent.setup()
    renderPage()
    const overview = screen.getByRole('tab', { name: 'Overview' })
    for (let i = 0; i < 30 && document.activeElement !== overview; i++) await user.tab()
    expect(overview).toHaveFocus()

    for (const name of ['Findings', 'Cases', 'Settings', 'Field Guide', 'Overview']) {
      await user.keyboard('{ArrowRight}')
      const target = screen.getByRole('tab', { name })
      expect(target).toHaveFocus()
      expect(target).toHaveAttribute('aria-selected', 'true')
      expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', target.id)
    }
    await user.keyboard('{End}')
    expect(screen.getByRole('tab', { name: 'Field Guide' })).toHaveFocus()
    await user.keyboard('{Home}')
    expect(overview).toHaveFocus()
    await user.keyboard('{ArrowLeft}')
    expect(screen.getByRole('tab', { name: 'Field Guide' })).toHaveFocus()
  })

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
    expect(tiles.map(t => t.getAttribute('href'))).toEqual(['/ws/email-protection?tab=settings#dmarc-setup', '/ws/email-protection#sender-inventory', '/ws/email-protection#auth-detail', '/ws/email-protection?tab=settings#connect-reporting', '/ws/email-protection#lifecycle-history'])
    // The template (founder, 18 Oct 2026): what we observed, the one next action
    // and the three counts above the tabs; Overview itself carries only the
    // page's own blocks and the tiles; scope & limits at the bottom.
    expect(screen.queryByTestId('body')).not.toBeInTheDocument()
    const headings = screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())
    expect(headings).toEqual(['What we observed', 'Do this next', 'Scope & limits'])
    expect(screen.getByTestId('module-counts')).toBeInTheDocument()
  })

  it('switches tabs through the URL: Findings shows the body and the action, Cases the cases, Field Guide the guide', async () => {
    renderPage('/ws/email-protection?tab=findings')
    expect(screen.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('body')).toBeInTheDocument()
    expect(screen.queryByTestId('module-tiles')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['What we observed', 'Do this next', 'Findings', 'Recommended action', 'Scope & limits'])

    fireEvent.click(screen.getByRole('tab', { name: 'Cases' }))
    expect(screen.getByRole('tab', { name: 'Cases' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByText('DMARC policy is p=none')).toBeInTheDocument()
    expect(screen.queryByTestId('body')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['What we observed', 'Do this next', 'Managed case', 'Verification', 'Scope & limits'])

    fireEvent.click(screen.getByRole('tab', { name: 'Field Guide' }))
    expect(screen.getByRole('link', { name: 'Open the Field Guide' })).toHaveAttribute('href', '/guide/email-protection')
    expect(screen.queryByText('DMARC policy is p=none')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['What we observed', 'Do this next', 'Field Guide', 'Scope & limits'])

    fireEvent.click(screen.getByRole('tab', { name: 'Overview' }))
    expect(screen.getByTestId('module-tiles')).toBeInTheDocument()
  })

  it('shows registry titles and links for latest finding IDs without exposing unknown raw IDs', async () => {
    api.getCyberMotDomains.mockResolvedValueOnce({ cyber_mot_domains: eight({ email_protection: {
      state: 'issue_detected', finding_count: 2, source_scan_id: 'scan_1',
      finding_ids: ['email_missing_spf', 'unmapped_internal_key'],
      finding_details: [{ finding_id: 'email_missing_spf', status: 'resolved', customer_title: 'Publish an SPF record', recommended_action: 'Publish the approved SPF record.', owner_type: 'customer_it', verification_method: 'dns_recheck' }, { finding_id: 'unmapped_internal_key', status: 'unmapped' }],
    } }) })
    renderPage('/ws/email-protection?tab=findings')
    const list = await screen.findByTestId('latest-assessment-findings')
    expect(within(list).getByText('Publish an SPF record')).toBeInTheDocument()
    expect(within(list).getByText('Publish the approved SPF record.')).toBeInTheDocument()
    expect(within(list).getByText('Owner: IT / DNS Administrator')).toBeInTheDocument()
    expect(within(list).getByText('Finding title unavailable')).toBeInTheDocument()
    expect(list).not.toHaveTextContent('unmapped_internal_key')
    expect(within(list).getAllByRole('link', { name: /Open technical scan/ })).toHaveLength(2)
    for (const link of within(list).getAllByRole('link', { name: /Open technical scan/ })) {
      expect(link).toHaveAttribute('href', '/scans/scan_1?view=technical')
    }
  })

  it('renders the page\'s overview blocks on Overview only, before the tiles, after the first-screen blocks', () => {
    renderPage('/ws/email-protection', { overview: <div data-testid="page-overview">the page's own overview</div> })
    const contract = screen.getByTestId('module-contract')
    const order = [...contract.querySelectorAll('[data-testid]')].map((el) => el.dataset.testid)
    expect(order.indexOf('module-observed')).toBeLessThan(order.indexOf('module-next'))
    expect(order.indexOf('module-next')).toBeLessThan(order.indexOf('module-counts'))
    expect(order.indexOf('module-counts')).toBeLessThan(order.indexOf('module-overview'))
    expect(order.indexOf('module-overview')).toBeLessThan(order.indexOf('module-tiles'))
    expect(order.indexOf('module-tiles')).toBeLessThan(order.indexOf('module-scope'))
    expect(within(screen.getByTestId('module-overview')).getByTestId('page-overview')).toBeInTheDocument()
    expect(screen.queryByTestId('body')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent.trim())).toEqual(['What we observed', 'Do this next', 'Scope & limits'])
    fireEvent.click(screen.getByRole('tab', { name: 'Findings' }))
    expect(screen.queryByTestId('page-overview')).not.toBeInTheDocument()
    expect(screen.getByTestId('body')).toBeInTheDocument()
  })

  it('an explicit ?tab=overview with an anchor stays on Overview (a summary block can be a tile target)', () => {
    expect(tabForLocation(new URLSearchParams('tab=overview'), '#brand-summary')).toBe('overview')
    renderPage('/ws/email-protection?tab=overview#x', { overview: <div id="x">anchored summary</div> })
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('anchored summary')).toBeInTheDocument()
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

  it('useAreaAnchor can open an Overview summary block from another tab', () => {
    const scrolled = []
    Element.prototype.scrollIntoView = function () { scrolled.push(this.id) }
    function Page() {
      const go = useAreaAnchor()
      return (
        <ModuleContract domainKey="email_protection" workspaceId="ws1" workspaceName="Customer A"
          actions={<button type="button" onClick={() => go('stats', { tab: 'overview' })}>Go to stats</button>}
          overview={<p id="stats">statistic cards</p>}>
          <p>body</p>
        </ModuleContract>
      )
    }
    render(<MemoryRouter initialEntries={['/ws/email-protection?tab=cases']}><Routes><Route path="*" element={<Page />} /></Routes></MemoryRouter>)
    expect(screen.getByRole('tab', { name: 'Cases' })).toHaveAttribute('aria-selected', 'true')
    fireEvent.click(screen.getByRole('button', { name: 'Go to stats' }))
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('statistic cards')).toBeInTheDocument()
    expect(scrolled).toContain('stats')
  })

  it('the filter box narrows the tiles and the case list, and says so when nothing matches', async () => {
    renderPage()
    await waitFor(() => expect(api.getCases).toHaveBeenCalled())
    const box = screen.getByRole('searchbox', { name: 'Filter pages and cases in this area' })
    fireEvent.change(box, { target: { value: 'sender' } })
    expect(within(screen.getByTestId('module-tiles')).getAllByRole('link').map(t => t.textContent)).toEqual([
      'Sender InventoryEvery source seen sending as your domain',
      'Lifecycle historyChanges to reporting and senders',
    ])
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

  it('a failed read shows Error in the head while Website Security sections remain navigable', async () => {
    api.getCyberMotDomains.mockRejectedValue(new Error('down'))
    render(
      <MemoryRouter initialEntries={['/ws/website-security']}>
        <ModuleContract domainKey="website_security" workspaceId="ws1" workspaceName="Customer A"><p>body</p></ModuleContract>
      </MemoryRouter>,
    )
    await waitFor(() => expect(within(screen.getByTestId('module-head-status')).getByText('Error')).toBeInTheDocument())
    expect(within(screen.getByTestId('module-head-status')).getByText('The latest assessment could not be read.')).toBeInTheDocument()
    expect(within(screen.getByTestId('module-tiles')).getAllByRole('link').map((link) => link.getAttribute('href'))).toEqual([
      '/ws/website-security?tab=overview#website-observations',
      '/ws/website-security?tab=overview#exposure-checks',
      '/ws/website-security#pages-checked',
      '/ws/website-security?tab=settings#sign-in-settings',
    ])
    expect(screen.getByRole('heading', { level: 1, name: 'Website Security' })).toBeInTheDocument()
  })
})
