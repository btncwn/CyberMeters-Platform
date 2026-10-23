// Founder decision (23 Oct 2026): a context bar on every signed-in page names the
// workspace and the domain the screen is about — stated, never inferred.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import ContextBar, { ScopedDomainProvider, useScopedDomain, useWorkspaceDomains } from '../shell/WorkspaceContext'

vi.mock('../../api', () => ({ api: { getWorkspaceDomains: vi.fn(), getWorkspaces: vi.fn() } }))

const DOMAINS = {
  ws_she: [{ domain: 'sheshire.co.uk' }, { domain: 'blackbullbarbers.co.uk' }],
  ws_one: [{ domain: 'onlyone.example' }],
}
function Harness({ wsId, wsName, scoped = null }) {
  const domainsState = useWorkspaceDomains(wsId)
  function Scoped() { useScopedDomain(scoped); return null }
  return (<><Scoped /><ContextBar wsId={wsId} wsName={wsName} domainsState={domainsState} /></>)
}
const mount = (props, path = '/dashboard') => render(
  <MemoryRouter initialEntries={[path]}>
    <ScopedDomainProvider>
      <Routes><Route path="*" element={<Harness {...props} />} /></Routes>
    </ScopedDomainProvider>
  </MemoryRouter>,
)
const bar = () => screen.getByRole('navigation', { name: 'Workspace context' })

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockImplementation(async (id) => ({ domains: DOMAINS[id] || [] }))
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_she', name: 'She.Shire' }, { id: 'ws_one', name: 'One Ltd' }] })
})

describe('ContextBar', () => {
  it('multi-domain workspace-wide page: "She.Shire › All domains (2) ▾"; the menu lists each domain', async () => {
    mount({ wsId: 'ws_she', wsName: 'She.Shire' })
    const trigger = await within(bar()).findByRole('button', { name: /All domains \(2\)/ })
    expect(bar()).toHaveTextContent('She.Shire›All domains (2)')
    fireEvent.click(trigger)
    const menu = screen.getByRole('menu')
    expect(within(menu).getByRole('menuitem', { name: 'sheshire.co.uk' })).toHaveAttribute('href', '/domain/sheshire.co.uk/history')
    expect(within(menu).getByRole('menuitem', { name: 'blackbullbarbers.co.uk' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).toBeNull()
    expect(trigger).toHaveFocus()
  })
  it('single-domain workspace: the domain, no menu', async () => {
    mount({ wsId: 'ws_one', wsName: 'One Ltd' })
    await waitFor(() => expect(bar()).toHaveTextContent('One Ltd›onlyone.example'))
    expect(within(bar()).queryByRole('button')).toBeNull()
  })
  it('a page about one domain (a case deep link) names that domain, with the others in the menu', async () => {
    mount({ wsId: 'ws_she', wsName: 'She.Shire', scoped: 'sheshire.co.uk' }, '/ws/cases/c1')
    const trigger = await within(bar()).findByRole('button', { name: /sheshire\.co\.uk/ })
    expect(bar()).toHaveTextContent('She.Shire›sheshire.co.uk')
    fireEvent.click(trigger)
    const menu = screen.getByRole('menu')
    expect(within(menu).getByRole('menuitem', { name: 'All domains (2)' })).toHaveAttribute('href', '/dashboard')
    expect(within(menu).getByRole('menuitem', { name: 'blackbullbarbers.co.uk' })).toBeInTheDocument()
    expect(within(menu).queryByRole('menuitem', { name: 'sheshire.co.uk' })).toBeNull()
  })
  it('portfolio pages: "Portfolio › 2 workspaces ▾" listing the workspaces', async () => {
    mount({ wsId: 'ws_she', wsName: 'She.Shire' }, '/portfolio/risk')
    const trigger = await within(bar()).findByRole('button', { name: /2 workspaces/ })
    expect(bar()).toHaveTextContent('Portfolio›2 workspaces')
    fireEvent.click(trigger)
    expect(within(screen.getByRole('menu')).getAllByRole('menuitem').map((m) => m.textContent)).toEqual(['She.Shire', 'One Ltd'])
  })
  it('switch A → B: never the previous workspace\'s domains, loading in between', async () => {
    let releaseOne
    const view = mount({ wsId: 'ws_she', wsName: 'She.Shire' })
    await within(bar()).findByRole('button', { name: /All domains \(2\)/ })
    api.getWorkspaceDomains.mockImplementation((id) => new Promise((r) => { if (id === 'ws_one') releaseOne = () => r({ domains: DOMAINS.ws_one }) }))
    view.rerender(
      <MemoryRouter initialEntries={['/dashboard']}><ScopedDomainProvider><Routes><Route path="*" element={<Harness wsId="ws_one" wsName="One Ltd" />} /></Routes></ScopedDomainProvider></MemoryRouter>,
    )
    expect(bar()).toHaveTextContent('One Ltd›…')
    expect(bar()).not.toHaveTextContent('All domains (2)')
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalledWith('ws_one'))
    releaseOne()
    await waitFor(() => expect(bar()).toHaveTextContent('One Ltd›onlyone.example'))
  })
  it('domains unavailable or none yet say so', async () => {
    api.getWorkspaceDomains.mockRejectedValueOnce(new Error('down'))
    const { unmount } = mount({ wsId: 'ws_she', wsName: 'She.Shire' })
    await waitFor(() => expect(bar()).toHaveTextContent('She.Shire›Domains not available'))
    unmount()
    mount({ wsId: 'ws_none', wsName: 'Empty' })
    await waitFor(() => expect(bar()).toHaveTextContent('Empty›No domains yet'))
  })
})
