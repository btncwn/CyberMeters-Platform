import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AREA_ORDER, sortByAreaOrder } from '../../../shared/areas.js'
import { SERVICES } from '../components/WorkspaceNav'
import { MODULES } from '../lib/moduleRegistry'
import { GUIDE_AREAS } from '../data/fieldGuide'
import AreaMenu from '../components/shell/AreaMenu'
import PostureCard from '../components/overview/PostureCard'
import AcademyPage from '../pages/AcademyPage'
import { api } from '../api'

// Area order is ONE constant (shared/areas.js): the area sheet, the Overview
// posture list and the Field Guide all render the eight areas in that order —
// Email, Attack Surface, Website, Identity, Shadow IT, Certificates, Brand,
// Cyber Essentials.

vi.mock('../api', () => ({ api: { getSecurityCheckDomains: vi.fn(), getWorkspaces: vi.fn() } }))
vi.mock('../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../utils/preloadMap', () => ({ routePreloadMap: {} }))

const ORDER = ['email_protection', 'attack_surface', 'website_security', 'identity_exposure', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness']
const positions = (text, labels) => labels.map((l) => { const i = text.indexOf(l); expect(i, l).toBeGreaterThanOrEqual(0); return i })
const ascending = (nums) => nums.every((n, i) => i === 0 || n > nums[i - 1])

describe('shared area order', () => {
  it('is the founder order and sorts records by it', () => {
    expect([...AREA_ORDER]).toEqual(ORDER)
    expect(sortByAreaOrder([{ domainKey: 'brand_protection' }, { domainKey: 'email_protection' }, { domainKey: 'nope' }]).map((x) => x.domainKey)).toEqual(['email_protection', 'brand_protection', 'nope'])
  })
  it('the three data sources carry exactly the eight keys in that order', () => {
    expect(SERVICES.map((s) => s.domainKey)).toEqual(ORDER)
    expect(MODULES.map((m) => m.domainKey)).toEqual(ORDER)
    expect(GUIDE_AREAS.map((a) => a.domainKey)).toEqual(ORDER)
  })
})

describe('the three surfaces render in that order', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: ORDER.map((k) => ({ domain_key: k, display_name: k, state: 'assessed_healthy', coverage: 'complete', summary: '' })) })
  })

  it('area sheet', async () => {
    render(<MemoryRouter><AreaMenu wsId="ws1" /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'CyberMeters — open areas' }))
    const items = within(screen.getByRole('menu', { name: 'Areas' })).getAllByRole('menuitem')
    expect(items.map((i) => i.dataset.serviceKey)).toEqual(SERVICES.map((s) => s.key))
    expect(ascending(positions(items.map((i) => i.textContent).join('|'), MODULES.map((m) => m.title)))).toBe(true)
  })

  it('Overview posture list', () => {
    const { container } = render(<MemoryRouter><PostureCard domains={ORDER.map((k) => ({ domain_key: k, state: 'assessed_healthy', summary: '' }))} domainsRequest="ok" /></MemoryRouter>)
    expect(ascending(positions(container.textContent, MODULES.map((m) => m.title)))).toBe(true)
  })

  it('Field Guide', async () => {
    const { container } = render(<MemoryRouter><AcademyPage /></MemoryRouter>)
    await waitFor(() => expect(container.textContent).toContain(GUIDE_AREAS[0].title))
    expect(ascending(positions(container.textContent, GUIDE_AREAS.map((a) => a.title)))).toBe(true)
  })
})
