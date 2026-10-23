// Codex C-45 reproductions, flipped to the correct behaviour (Executive 21:12):
// they asserted the defects (a late workspace A overwriting B; a card naming a
// domain while its menu named the workspace) and must now pass on the fix.
import React from 'react'
import { render, screen, fireEvent, act, waitFor, cleanup } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useNavigate, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import WorkspaceDetailPage from '../WorkspaceDetailPage'
import WorkspaceMenu from '../../components/shell/WorkspaceMenu'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getWorkspace: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceAssetsSummary: vi.fn(),
  getWorkspaces: vi.fn(), requestWorkspaceDeletion: vi.fn(),
} }))

function deferred() { let resolve; const promise = new Promise(r => { resolve = r }); return { promise, resolve } }
function data(id, name) { return { workspace: { id, name, role: 'member', created_at: '2026-10-01T00:00:00Z' }, stats: { total_domains: 0, total_scans: 0, latest_scan: null } } }
function Navigation() {
  const navigate = useNavigate()
  const location = useLocation()
  return <><button onClick={() => navigate('/workspaces/ws-b')}>Switch to B</button><output data-testid="current-path">{location.pathname}</output></>
}
beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  api.getWorkspaceAssetsSummary.mockResolvedValue({})
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
})
afterEach(cleanup)

it('a late workspace A load never overwrites B after route B has completed (same mounted page)', async () => {
  const a = deferred(), b = deferred()
  api.getWorkspace.mockImplementation(id => id === 'ws-a' ? a.promise : b.promise)
  render(<MemoryRouter initialEntries={['/workspaces/ws-a']}><Navigation/><Routes><Route path="/workspaces/:id" element={<WorkspaceDetailPage/>}/></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspace).toHaveBeenCalledWith('ws-a'))
  fireEvent.click(screen.getByText('Switch to B'))
  await waitFor(() => expect(api.getWorkspace).toHaveBeenCalledWith('ws-b'))
  await act(async () => { b.resolve(data('ws-b', 'Workspace B')) })
  expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws-b')
  await act(async () => { a.resolve(data('ws-a', 'Workspace A')) })
  expect(screen.getByTestId('current-path').textContent).toBe('/workspaces/ws-b')
  expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws-b')
  expect(localStorage.getItem('cybermeters_workspace_name')).toBe('Workspace B')
  expect(screen.getByRole('heading', { name: 'Workspace B', level: 1 })).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Workspace A', level: 1 })).toBeNull()
})

it('the workspace card names the workspace — face, tooltip and menu agree; the domain is only listed', async () => {
  render(<MemoryRouter><WorkspaceMenu wsId="ws-a" wsName="Workspace A" domainsState={{ status: 'ok', domains: ['beta.example.org'] }} size="deck"/></MemoryRouter>)
  expect(screen.getByTestId('workspace-initial').textContent).toBe('W')
  const button = screen.getByRole('button', { name: 'Workspace: Workspace A' })
  expect(button.title).toBe('Workspace · Workspace A · 1 domain')
  fireEvent.click(button)
  expect(screen.getByTestId('active-workspace-name').textContent).toBe('Workspace A')
  expect(screen.getByTestId('active-workspace-domains')).toHaveTextContent('beta.example.org')
  await waitFor(() => expect(api.getWorkspaces).toHaveBeenCalledTimes(1))
})

it('C-47 F03: a late asset summary for A never lands on B', async () => {
  const sumA = deferred()
  api.getWorkspace.mockImplementation(async id => data(id, id === 'ws-a' ? 'Workspace A' : 'Workspace B'))
  api.getWorkspaceAssetsSummary.mockImplementation(id => id === 'ws-a' ? sumA.promise : Promise.resolve({ total_assets: 5, active_assets: 5, inactive_assets: 0, subdomains: 4, exposed_services: 0, cloud_storage_assets: 0, takeover_risks: 0 }))
  render(<MemoryRouter initialEntries={['/workspaces/ws-a']}><Navigation/><Routes><Route path="/workspaces/:id" element={<WorkspaceDetailPage/>}/></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspaceAssetsSummary).toHaveBeenCalledWith('ws-a'))
  fireEvent.click(screen.getByText('Switch to B'))
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Workspace B', level: 1 })).toBeInTheDocument())
  await act(async () => { sumA.resolve({ total_assets: 999, active_assets: 999, inactive_assets: 0, subdomains: 998, exposed_services: 0, cloud_storage_assets: 0, takeover_risks: 0 }) })
  expect(document.body.textContent).not.toContain('999')
})
