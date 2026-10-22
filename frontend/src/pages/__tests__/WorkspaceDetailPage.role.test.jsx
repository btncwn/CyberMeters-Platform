// Workspace domains table by role (18 Oct 2026), from the one role rule: owners
// and admins add, remove and scan any domain; an analyst rescans the domains this
// workspace has already verified; a viewer reads.
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import WorkspaceDetailPage from '../WorkspaceDetailPage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: { getWorkspace: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceAssetsSummary: vi.fn(), createScan: vi.fn() },
}))

const WS_ID = 'ws_bbb'
const VERIFIED = { domain_id: 'd1', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }
const PENDING = { domain_id: 'd2', domain: 'bbb-bookings.co.uk', verification_status: 'pending', verified_at: null }

function mount(role) {
  api.getWorkspace.mockResolvedValue({ workspace: { id: WS_ID, name: 'Black Bull Barbers', created_at: '2026-06-20T00:00:00Z', role }, stats: { total_domains: 2, total_scans: 3 } })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [VERIFIED, PENDING] })
  api.getWorkspaceAssetsSummary.mockResolvedValue({})
  api.createScan.mockResolvedValue({ scan_id: 'scan_9' })
  return render(
    <MemoryRouter initialEntries={[`/workspaces/${WS_ID}`]}>
      <Routes><Route path="/workspaces/:id" element={<WorkspaceDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}
const row = async (domain) => (await screen.findByText(domain)).closest('tr')

beforeEach(() => { vi.clearAllMocks(); try { localStorage.clear() } catch { /* jsdom */ } })

it.each(['owner', 'admin'])('%s: unchanged — Add Domain, Scan Now and remove on every domain', async (role) => {
  mount(role)
  expect(within(await row('bbb-bookings.co.uk')).getByRole('button', { name: 'Scan Now' })).toBeInTheDocument()
  expect(within(await row('blackbullbarbers.co.uk')).getByRole('button', { name: 'Scan Now' })).toBeInTheDocument()
  // One control per job (founder, 22 Oct 2026): Add Domain lives in the header only.
  expect(screen.getAllByRole('button', { name: 'Add Domain' })).toHaveLength(1)
  expect(screen.getAllByRole('button', { name: 'Remove from workspace' })).toHaveLength(2)
})

it('analyst: Rescan on the verified domain only; no Add Domain, no remove', async () => {
  mount('analyst')
  const verified = await row('blackbullbarbers.co.uk')
  const pending = await row('bbb-bookings.co.uk')
  expect(within(pending).queryByRole('button', { name: /Rescan|Scan Now/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Add Domain' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Remove from workspace' })).toBeNull()
  fireEvent.click(within(verified).getByRole('button', { name: 'Rescan' }))
  await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('blackbullbarbers.co.uk', WS_ID))
})

it('viewer: no scan, add or remove actions', async () => {
  mount('viewer')
  await row('blackbullbarbers.co.uk')
  expect(screen.queryByRole('button', { name: /Rescan|Scan Now|Add Domain|Remove from workspace/ })).toBeNull()
})
