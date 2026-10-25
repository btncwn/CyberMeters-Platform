import { act, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ModuleContract from '../module/ModuleContract'
import { api } from '../../api'

// Founder, 25 Oct 2026 (app.cybermeters.com/assets): Summary / Findings / Cases /
// Settings / Field Guide changed the URL and the highlight, but the page showed
// the same top content — the section rendered below the first screen. Picking a
// tab now brings its section into view; a page load does not scroll.
vi.mock('../../api', () => ({
  api: { getSecurityCheckDomains: vi.fn(), getCases: vi.fn(), getWorkspaces: vi.fn(), getWorkspaceMembers: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

let panelTop = 1400
let scrolled = []
let lastOptions = null
let reduceMotion = false
const realRect = Element.prototype.getBoundingClientRect
const realScroll = Element.prototype.scrollIntoView
beforeEach(() => {
  vi.clearAllMocks()
  api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: [] })
  api.getCases.mockResolvedValue({ cases: [] })
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  scrolled = []
  panelTop = 1400
  // The tab panel sits below the first screen (observed / next action / counts above it).
  Element.prototype.getBoundingClientRect = function rect() {
    return this.id === 'module-tabpanel' ? { top: panelTop, bottom: panelTop + 600, left: 0, right: 0, width: 0, height: 600, x: 0, y: panelTop } : realRect.call(this)
  }
  Element.prototype.scrollIntoView = function scroll(options) { scrolled.push(this.id); lastOptions = options }
  reduceMotion = false
  window.matchMedia = (q) => ({ matches: q.includes('prefers-reduced-motion') ? reduceMotion : false, addEventListener() {}, removeEventListener() {} })
  Object.defineProperty(window, 'innerHeight', { configurable: true, value: 900 })
})
afterEach(() => { Element.prototype.getBoundingClientRect = realRect; Element.prototype.scrollIntoView = realScroll })

function Where() {
  const { search } = useLocation()
  const navigate = useNavigate()
  // Stands in for back/forward or a deep link changing ?tab= without a tab pick.
  return <><output data-testid="search">{search}</output><button type="button" onClick={() => navigate('/assets?tab=settings')}>history change</button></>
}
const show = (entry = '/assets') => render(
  <MemoryRouter initialEntries={[entry]}>
    <ModuleContract domainKey="attack_surface" workspaceId="ws1" workspaceName="Example Ltd" overview={<p>overview body</p>} settings={<p>settings body</p>}>
      <p>findings body</p>
    </ModuleContract>
    <Where />
  </MemoryRouter>,
)
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 30)) })

describe('picking an area tab shows its section', () => {
  it.each(['Findings', 'Cases', 'Settings', 'Field Guide'])('%s scrolls the panel into view when it is below the first screen', async (label) => {
    show()
    await flush()
    expect(scrolled).toEqual([]) // a page load never scrolls
    fireEvent.click(screen.getByRole('tab', { name: new RegExp(`^${label}`) }))
    await flush()
    expect(screen.getByTestId('search').textContent).toMatch(/tab=/)
    expect(scrolled).toEqual(['module-tabpanel'])
  })
  it('a panel already in the upper part of the screen is left where it is', async () => {
    panelTop = 200
    show()
    await flush()
    fireEvent.click(screen.getByRole('tab', { name: /^Findings/ }))
    await flush()
    expect(scrolled).toEqual([])
  })
  it('re-picking the current tab leaves nothing armed: a later history change does not scroll (R1 15:30)', async () => {
    show('/assets?tab=findings')
    await flush()
    fireEvent.click(screen.getByRole('tab', { name: /^Findings/ }))
    await flush()
    fireEvent.click(screen.getByRole('button', { name: 'history change' }))
    await flush()
    expect(screen.getByTestId('search').textContent).toBe('?tab=settings')
    expect(scrolled).toEqual([])
  })
  it('smooth by default; instant when the customer prefers reduced motion (R1 15:30)', async () => {
    show()
    await flush()
    fireEvent.click(screen.getByRole('tab', { name: /^Findings/ }))
    await flush()
    expect(lastOptions).toEqual({ block: 'start', behavior: 'smooth' })
    reduceMotion = true
    fireEvent.click(screen.getByRole('tab', { name: /^Cases/ }))
    await flush()
    expect(lastOptions).toEqual({ block: 'start', behavior: 'instant' })
  })
  it('keyboard activation (Arrow keys) shows the section too', async () => {
    show()
    await flush()
    const summary = screen.getByRole('tab', { name: /^Summary|^Overview/ })
    summary.focus()
    fireEvent.keyDown(summary, { key: 'ArrowRight' })
    await flush()
    expect(screen.getByTestId('search').textContent).toMatch(/tab=/)
    expect(scrolled).toEqual(['module-tabpanel'])
  })
  it('a deep link with ?tab= does not add a tab scroll on load', async () => {
    show('/assets?tab=cases')
    await flush()
    expect(scrolled).toEqual([])
  })
})
