import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ScansPage from '../ScansPage'
import { api } from '../../api'

// "New Scan" is offered only to roles that can add domains; an analyst is
// offered Rescan; a viewer neither (18 Oct 2026).

vi.mock('../../api', () => ({ api: { getScans: vi.fn(), getWorkspaces: vi.fn(), getWorkspaceMembers: vi.fn() } }))

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws_bbb')
  api.getScans.mockResolvedValue({ scans: [] })
  api.getWorkspaceMembers.mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner' }] })
})

it('an analyst is offered Rescan, not New Scan', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'analyst' }] })
  render(<MemoryRouter><ScansPage /></MemoryRouter>)
  expect(await screen.findByText('No scans yet')).toBeInTheDocument()
  await waitFor(() => expect(screen.getByTestId('scan-rescan-only')).toHaveTextContent('You can rescan domains this workspace has already verified.'))
  expect(screen.getAllByRole('link', { name: 'Rescan a domain' })).toHaveLength(2)
  expect(screen.queryByRole('link', { name: /New Scan/ })).toBeNull()
  expect(api.getWorkspaceMembers).not.toHaveBeenCalled()
})

it('a viewer sees no scan entry and the plain sentence instead', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'viewer' }] })
  render(<MemoryRouter><ScansPage /></MemoryRouter>)
  expect(await screen.findByText('No scans yet')).toBeInTheDocument()
  await waitFor(() => expect(screen.getByTestId('scan-not-permitted')).toHaveTextContent('Ask Taylor Owner if you need one scanned.'))
  expect(screen.queryByRole('link', { name: /New Scan|Rescan/ })).toBeNull()
})

it('an owner keeps both New Scan entries', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'owner' }] })
  render(<MemoryRouter><ScansPage /></MemoryRouter>)
  expect(await screen.findByText('No scans yet')).toBeInTheDocument()
  await waitFor(() => expect(api.getWorkspaces).toHaveBeenCalled())
  expect(screen.getAllByRole('link', { name: /New Scan/ })).toHaveLength(2)
  expect(screen.queryByTestId('scan-not-permitted')).toBeNull()
})
