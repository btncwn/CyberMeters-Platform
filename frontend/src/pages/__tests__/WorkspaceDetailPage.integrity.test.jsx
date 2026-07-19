// ── Workspace detail — retained-history honesty + owner-only Delete Workspace ──
// Context: the "Deneme" workspace showed 0 monitored domains yet 12 scans / 238 assets /
// a Latest Scan — all correctly tenant-scoped retained history. The bug was never a leak;
// it was PRESENTATION: retained history read as current monitoring, and the scan total
// under-counted. These tests render the page and assert:
//   • zero currently-monitored domains → an explicit retained-history notice;
//   • retained cards are labelled historical, and Cyber Score does not read as current;
//   • the Delete Workspace Danger Zone is owner-only;
//   • deletion requires the exact workspace name typed, and is submit-guarded.
import React from 'react'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceDetailPage from '../WorkspaceDetailPage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getWorkspace: vi.fn(),
    getWorkspaceDomains: vi.fn(),
    getWorkspaceAssetsSummary: vi.fn(),
    requestWorkspaceDeletion: vi.fn(),
  },
}))

const WS_ID = 'workspace_test_1'

function mountPage() {
  return render(
    <MemoryRouter initialEntries={[`/workspaces/${WS_ID}`]}>
      <Routes>
        <Route path="/workspaces/:id" element={<WorkspaceDetailPage />} />
        <Route path="/workspaces" element={<div>WORKSPACE LIST</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

function setup({ role = 'owner', total_domains = 0, total_scans = 22 } = {}) {
  api.getWorkspace.mockResolvedValue({
    workspace: { id: WS_ID, name: 'Deneme', created_at: '2026-06-20T00:00:00Z', role },
    stats: {
      total_domains, total_scans,
      cyber_score_average: null,
      latest_scan: { id: 's1', domain: 'blackbullbarbers.co.uk', status: 'completed', score: null, rating: null, created_at: '2026-07-05T23:18:39Z' },
      posture_established: false, posture_score: null, posture_rating: null,
      posture_message: 'Current posture not yet established',
    },
  })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  api.getWorkspaceAssetsSummary.mockResolvedValue({
    total_assets: 238, active_assets: 0, inactive_assets: 238, subdomains: 230,
    exposed_services: 0, cloud_storage_assets: 0, takeover_risks: 0,
  })
  api.requestWorkspaceDeletion.mockResolvedValue({ deleted: true, workspace_id: WS_ID, restorable_until: '2026-08-01T00:00:00Z' })
}

beforeEach(() => {
  vi.clearAllMocks()
  try { localStorage.clear() } catch { /* jsdom */ }
})

describe('WorkspaceDetailPage — retained-history honesty (0 domains)', () => {
  it('shows an explicit no-current-monitoring notice with retained history', async () => {
    setup({ total_domains: 0, total_scans: 22 })
    mountPage()
    expect(await screen.findByText(/No domains are currently monitored in this workspace/i)).toBeInTheDocument()
    expect(screen.getByText(/reflects past activity, not current monitoring/i)).toBeInTheDocument()
  })

  it('labels retained scans as historical and does not present a current Cyber Score', async () => {
    setup({ total_domains: 0, total_scans: 22 })
    mountPage()
    expect(await screen.findByText('Total Scans (historical)')).toBeInTheDocument()
    expect(screen.getByText('22')).toBeInTheDocument()               // own retained total, not the under-counted 12
    expect(screen.getByText('No current monitoring')).toBeInTheDocument()
    expect(screen.getByText(/Asset Inventory \(historical — retained\)/i)).toBeInTheDocument()
  })

  it('does NOT show the retained-history notice when domains are actively monitored', async () => {
    setup({ total_domains: 3, total_scans: 22 })
    mountPage()
    expect(await screen.findByText('Total Scans')).toBeInTheDocument()
    expect(screen.queryByText(/No domains are currently monitored/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Total Scans (historical)')).not.toBeInTheDocument()
  })
})

describe('WorkspaceDetailPage — owner-only Delete Workspace', () => {
  it('shows the Danger Zone to an owner', async () => {
    setup({ role: 'owner' })
    mountPage()
    expect(await screen.findByRole('button', { name: /Delete Workspace/i })).toBeInTheDocument()
  })

  it('hides the Danger Zone from a non-owner', async () => {
    setup({ role: 'member' })
    mountPage()
    await screen.findByText(/No domains are currently monitored/i)
    expect(screen.queryByRole('button', { name: /Delete Workspace/i })).not.toBeInTheDocument()
  })

  it('requires the exact workspace name before enabling delete, then submits + leaves', async () => {
    setup({ role: 'owner' })
    localStorage.setItem('cybermeters_workspace_id', WS_ID)
    mountPage()
    fireEvent.click(await screen.findByRole('button', { name: /Delete Workspace/i }))

    // Modal open; submit button (scoped to the dialog) disabled until exact name typed.
    const dialog = await screen.findByRole('dialog', { name: /Delete workspace/i })
    const submit = within(dialog).getByRole('button', { name: /^Delete workspace$/i })
    expect(submit).toBeDisabled()

    const input = within(dialog).getByPlaceholderText('Deneme')
    fireEvent.change(input, { target: { value: 'Denem' } })   // wrong
    expect(submit).toBeDisabled()
    expect(api.requestWorkspaceDeletion).not.toHaveBeenCalled()

    fireEvent.change(input, { target: { value: 'Deneme' } })  // exact
    expect(submit).toBeEnabled()

    fireEvent.click(submit)
    await waitFor(() => expect(api.requestWorkspaceDeletion).toHaveBeenCalledWith(WS_ID))
    // Redirects to the workspace list and clears the cached workspace id.
    expect(await screen.findByText('WORKSPACE LIST')).toBeInTheDocument()
    expect(localStorage.getItem('cybermeters_workspace_id')).toBeNull()
  })
})
