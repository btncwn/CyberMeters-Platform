import { render, screen, fireEvent, within, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import AreaMenu, { areaStateLabel, AREA_SHEET_ID } from '../shell/AreaMenu'
import { SERVICES } from '../WorkspaceNav'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'

// The brand button opens the area sheet: eight areas in founder order with the
// backend's own state word under each name; nothing lists the modules until
// the brand is clicked. Keyboard: Enter/Space open, arrows move, Escape closes.

vi.mock('../../api', () => ({ api: { getCyberMotDomains: vi.fn() } }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

function LocationSpy() { return <div data-testid="pathname">{useLocation().pathname}</div> }

function renderMenu(wsId = 'ws1') {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route path="*" element={<><AreaMenu wsId={wsId} /><LocationSpy /><div data-testid="outside" /></>} />
      </Routes>
    </MemoryRouter>,
  )
}

const domains = (state) => ({
  cyber_mot_domains: MODULES.map((m) => ({ domain_key: m.domainKey, display_name: m.title, state: state(m.domainKey), coverage: 'complete', summary: '' })),
})

beforeEach(() => { vi.clearAllMocks() })

describe('<AreaMenu>', () => {
  it('shows nothing about the areas until the brand is clicked, then lists the eight in founder order with icons', async () => {
    api.getCyberMotDomains.mockResolvedValue(domains(() => 'assessed_healthy'))
    renderMenu()
    const brand = screen.getByRole('button', { name: 'CyberMeters — open areas' })
    expect(brand).toHaveAttribute('aria-haspopup', 'menu')
    expect(brand).toHaveAttribute('aria-expanded', 'false')
    expect(brand).toHaveAttribute('aria-controls', AREA_SHEET_ID)
    expect(brand).toHaveTextContent('CyberMeters')
    expect(screen.queryByRole('menu', { name: 'Areas' })).not.toBeInTheDocument()
    for (const svc of SERVICES) expect(screen.queryByText(svc.title)).not.toBeInTheDocument()

    fireEvent.click(brand)
    expect(brand).toHaveAttribute('aria-expanded', 'true')
    const sheet = screen.getByRole('menu', { name: 'Areas' })
    const items = within(sheet).getAllByRole('menuitem')
    expect(items.map((i) => within(i).getByText(/.+/, { selector: 'b' }).textContent)).toEqual(MODULES.map((m) => m.title))
    expect(items.map((i) => i.dataset.serviceKey)).toEqual(SERVICES.map((s) => s.key))
    expect(items).toHaveLength(8)
    for (const item of items) expect(item.querySelector('svg')).toHaveStyle({ width: '36px', height: '36px' })
    expect(document.activeElement).toBe(items[0])
  })

  it('writes the backend state word under each area, exactly as the vocabulary maps it', async () => {
    api.getCyberMotDomains.mockResolvedValue(domains((key) => ({
      email_protection: 'provisional', attack_surface: 'evidence_insufficient', website_security: 'issue_detected',
      identity_exposure: 'evidence_insufficient', shadow_it_unmanaged_technology: 'monitoring_only',
      certificates_trust: 'assessed_healthy', brand_protection: 'provisional', cyber_essentials_readiness: 'customer_input_required',
    })[key]))
    renderMenu()
    fireEvent.click(screen.getByRole('button', { name: 'CyberMeters — open areas' }))
    expect(screen.getByTestId('area-state-email_protection')).toHaveTextContent('Loading')
    await waitFor(() => expect(screen.getByTestId('area-state-email_protection')).toHaveTextContent('Provisional'))
    expect(screen.getByTestId('area-state-attack_surface')).toHaveTextContent('Evidence insufficient')
    expect(screen.getByTestId('area-state-website_security')).toHaveTextContent('Action required')
    expect(screen.getByTestId('area-state-shadow_it_unmanaged_technology')).toHaveTextContent('Established')
    expect(screen.getByTestId('area-state-certificates_trust')).toHaveTextContent('Established')
    expect(screen.getByTestId('area-state-cyber_essentials_readiness')).toHaveTextContent('Customer input required')
    expect(api.getCyberMotDomains).toHaveBeenCalledWith('ws1')
  })

  it('a failed state read says Error; no workspace says Not assessed; an unknown state is Evidence insufficient', async () => {
    api.getCyberMotDomains.mockRejectedValue(new Error('boom'))
    renderMenu()
    fireEvent.click(screen.getByRole('button', { name: 'CyberMeters — open areas' }))
    await waitFor(() => expect(screen.getByTestId('area-state-email_protection')).toHaveTextContent('Error'))
    expect(areaStateLabel(null, 'ok', null)).toBe('Not assessed')
    expect(areaStateLabel({ state: 'something_new' }, 'ok', 'ws1')).toBe('Evidence insufficient')
    expect(areaStateLabel({ state: 'assessed_healthy', evidence_freshness: 'stale' }, 'ok', 'ws1')).toBe('Stale')
  })

  it('arrows move between items and wrap, Home/End jump, Escape closes and returns focus, an item opens its area', async () => {
    api.getCyberMotDomains.mockResolvedValue(domains(() => 'assessed_healthy'))
    renderMenu()
    const brand = screen.getByRole('button', { name: 'CyberMeters — open areas' })
    fireEvent.click(brand)
    const sheet = screen.getByRole('menu', { name: 'Areas' })
    const items = within(sheet).getAllByRole('menuitem')
    fireEvent.keyDown(sheet, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[1])
    fireEvent.keyDown(sheet, { key: 'ArrowUp' }); fireEvent.keyDown(sheet, { key: 'ArrowUp' })
    expect(document.activeElement).toBe(items[7])     // wraps
    fireEvent.keyDown(sheet, { key: 'Home' })
    expect(document.activeElement).toBe(items[0])
    fireEvent.keyDown(sheet, { key: 'End' })
    expect(document.activeElement).toBe(items[7])
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu', { name: 'Areas' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(brand)
    expect(brand).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(brand)
    fireEvent.click(within(screen.getByRole('menu', { name: 'Areas' })).getAllByRole('menuitem')[2])
    expect(screen.queryByRole('menu', { name: 'Areas' })).not.toBeInTheDocument()
    expect(screen.getByTestId('pathname')).toHaveTextContent(SERVICES[2].to)
  })

  it('closes on an outside click', () => {
    api.getCyberMotDomains.mockResolvedValue(domains(() => 'assessed_healthy'))
    renderMenu()
    fireEvent.click(screen.getByRole('button', { name: 'CyberMeters — open areas' }))
    fireEvent.mouseDown(screen.getByTestId('outside'))
    expect(screen.queryByRole('menu', { name: 'Areas' })).not.toBeInTheDocument()
  })
})
