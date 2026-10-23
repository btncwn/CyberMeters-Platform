import { render, screen, fireEvent, within, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import AreaSidebar, { areaStatusKey } from '../shell/AreaSidebar'
import { SERVICES } from '../WorkspaceNav'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'

// S1-SHELL-V2 (founder-approved 22 Oct 2026): the always-visible sidebar. The
// eight areas in canonical order, each with the SAME status word the area
// header shows (domainStatus → StatusChip) — never derived here; the selected
// area expands into its sub-topics; the logo links to Overview.

vi.mock('../../api', () => ({ api: { getSecurityCheckDomains: vi.fn() } }))

function LocationSpy() { const l = useLocation(); return <div data-testid="location">{`${l.pathname}${l.search}${l.hash}`}</div> }
function renderSidebar({ wsId = 'ws1', path = '/dashboard' } = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={<><AreaSidebar wsId={wsId} /><LocationSpy /></>} />
      </Routes>
    </MemoryRouter>,
  )
}
const domains = (state) => ({
  cyber_mot_domains: MODULES.map((m) => ({ domain_key: m.domainKey, display_name: m.title, state: state(m.domainKey), coverage: 'complete', summary: '' })),
})

beforeEach(() => { vi.clearAllMocks() })

describe('AreaSidebar', () => {
  it('lists the eight areas in canonical order with the backend word on each, exactly as the vocabulary maps it', async () => {
    api.getSecurityCheckDomains.mockResolvedValue(domains((key) => ({
      email_protection: 'provisional', attack_surface: 'evidence_insufficient', website_security: 'issue_detected',
      identity_exposure: 'evidence_insufficient', shadow_it_unmanaged_technology: 'monitoring_only',
      certificates_trust: 'assessed_healthy', brand_protection: 'provisional', cyber_essentials_readiness: 'customer_input_required',
    })[key]))
    renderSidebar()
    const side = screen.getByRole('navigation', { name: 'Security areas' })
    expect(within(side).getAllByRole('button').map((b) => b.dataset.serviceKey)).toEqual(SERVICES.map((s) => s.key))
    expect(screen.getByTestId('area-state-email_protection')).toHaveTextContent('Loading')
    await waitFor(() => expect(screen.getByTestId('area-state-email_protection')).toHaveTextContent('Provisional'))
    expect(screen.getByTestId('area-state-attack_surface')).toHaveTextContent('Evidence insufficient')
    expect(screen.getByTestId('area-state-website_security')).toHaveTextContent('Action required')
    expect(screen.getByTestId('area-state-certificates_trust')).toHaveTextContent('Established')
    expect(screen.getByTestId('area-state-cyber_essentials_readiness')).toHaveTextContent('Customer input required')
    expect(api.getSecurityCheckDomains).toHaveBeenCalledWith('ws1')
    expect(within(side).getByRole('link', { name: 'CyberMeters — Overview' })).toHaveAttribute('href', '/dashboard')
  })

  it('a failed read says Error; no workspace says Not assessed; an unknown or stale state is never healthy', async () => {
    api.getSecurityCheckDomains.mockRejectedValue(new Error('boom'))
    renderSidebar()
    await waitFor(() => expect(screen.getByTestId('area-state-email_protection')).toHaveTextContent('Error'))
    expect(areaStatusKey(null, 'ok', null)).toBe('not_assessed')
    expect(areaStatusKey({ state: 'something_new' }, 'ok', 'ws1')).toBe('evidence_insufficient')
    expect(areaStatusKey({ state: 'assessed_healthy', evidence_freshness: 'stale' }, 'ok', 'ws1')).toBe('stale')
    // A read that succeeded without this area's row is an error, as in the area header.
    expect(areaStatusKey(null, 'ok', 'ws1')).toBe('error')
  })

  it('clicking an area navigates to it and expands only it; its sub-topics link into existing sections', async () => {
    api.getSecurityCheckDomains.mockResolvedValue(domains(() => 'assessed_healthy'))
    renderSidebar()
    const side = screen.getByRole('navigation', { name: 'Security areas' })
    expect(within(side).queryAllByRole('button', { expanded: true })).toHaveLength(0)
    fireEvent.click(within(side).getByRole('button', { name: /Certificates & Trust/ }))
    expect(screen.getByTestId('location')).toHaveTextContent('/ws/certificates')
    expect(within(side).getAllByRole('button', { expanded: true })).toHaveLength(1)
    const topics = within(side).getByRole('list', { name: 'Certificates & Trust topics' })
    // C-38 S28: each sub-topic opens its own named section; aliases were removed.
    expect(within(topics).getAllByRole('link').map((a) => a.textContent)).toEqual(['Expiry', 'Chain & trust', 'Hostname match', 'Issuance policy (CAA)', 'Lifecycle'])
    expect(within(topics).getByRole('link', { name: 'Lifecycle' })).toHaveAttribute('href', '/ws/certificates/lifecycle')
    fireEvent.click(within(side).getByRole('button', { name: /Brand Protection/ }))
    expect(within(side).getAllByRole('button', { expanded: true }).map((b) => b.dataset.serviceKey)).toEqual(['brand'])
  })

  it('from a sub-page, the area row opens the front door and expands it; on the front door it collapses (C-38 S01)', () => {
    api.getSecurityCheckDomains.mockResolvedValue(domains(() => 'assessed_healthy'))
    renderSidebar({ path: '/ws/admin-surfaces' })
    const side = screen.getByRole('navigation', { name: 'Security areas' })
    const row = within(side).getByRole('button', { name: /Attack Surface/ })
    expect(row).toHaveAttribute('aria-expanded', 'true')
    fireEvent.click(row)
    expect(screen.getByTestId('location')).toHaveTextContent('/assets')
    expect(row).toHaveAttribute('aria-expanded', 'true')
    fireEvent.click(row)
    expect(screen.getByTestId('location')).toHaveTextContent('/assets')
    expect(row).toHaveAttribute('aria-expanded', 'false')
  })

  it('no two sub-topics of one area open the same place (no aliases)', () => {
    for (const svc of SERVICES) {
      const targets = svc.subtopics.map((t) => t.to || `${svc.to}${t.hash}`)
      expect(new Set(targets).size, svc.key).toBe(targets.length)
    }
  })

  it('every area has sub-topics, and every sub-topic resolves to an area route or one of its sub-pages', () => {
    for (const svc of SERVICES) {
      expect(svc.subtopics?.length, svc.key).toBeGreaterThan(0)
      for (const t of svc.subtopics) {
        const to = t.to || `${svc.to}${t.hash}`
        expect(to.startsWith('/'), `${svc.key}: ${t.label}`).toBe(true)
        expect(svc.match(to.split(/[?#]/)[0]), `${svc.key}: ${t.label} → ${to}`).toBe(true)
      }
    }
  })
})
