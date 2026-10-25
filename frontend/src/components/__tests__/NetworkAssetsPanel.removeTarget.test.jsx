import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import NetworkAssetsPanel from '../NetworkAssetsPanel'
import { api } from '../../api'

// Founder-approved (25 Oct 2026): each Network assets target row gets a secondary
// "Remove" beside "Run scan"; the real confirmation (no dialog mock) says exactly
// what happens; Remove withdraws, Cancel does nothing.
vi.mock('../../api', () => ({ api: {
  getNetworkTargets: vi.fn(), getNetworkAssets: vi.fn(), getNetworkScans: vi.fn(),
  addNetworkTarget: vi.fn(), revokeNetworkRangeConsent: vi.fn(), startNetworkScan: vi.fn(), getNetworkScan: vi.fn(), retestNetworkScan: vi.fn(),
  getNetworkSuggestions: vi.fn(), removeNetworkTarget: vi.fn(),
} }))

const capabilities = { can_manage: true, can_scan: true, collector_available: true, allowed_ports: [22, 80, 443], limits: { max_addresses: 32, max_ports: 16, max_pairs: 256, max_targets: 32 } }
const target = { id: 'target-1', target: '93.184.216.34', target_type: 'ip', address_count: 1, authorization_status: 'attested', authorized_at: '2026-10-09T00:00:00Z' }
const CONFIRM = 'Remove 93.184.216.34 and withdraw your authorisation? Future scans will not check it. Past scan results stay in your history.'

beforeEach(() => {
  vi.resetAllMocks()
  api.getNetworkTargets.mockResolvedValue({ targets: [target], capabilities })
  api.getNetworkAssets.mockResolvedValue({ assets: [], changes: [] })
  api.getNetworkScans.mockResolvedValue({ scans: [] })
  api.removeNetworkTarget.mockResolvedValue({ withdrawn: true, target_id: 'target-1' })
})
const ready = async () => { render(<NetworkAssetsPanel workspaceId="workspace-a" />); await screen.findByRole('tab', { name: 'Targets' }); return screen.findByRole('button', { name: 'Remove' }) }

describe('Remove a network target', () => {
  it('a secondary Remove sits beside Run scan', async () => {
    const remove = await ready()
    expect(remove).toHaveClass('btn-secondary')
    expect(remove.closest('td')).toContainElement(screen.getByRole('button', { name: 'Run scan' }))
  })
  it('Remove → the exact confirmation → Remove withdraws it and the list refreshes', async () => {
    fireEvent.click(await ready())
    const dialog = await screen.findByTestId('app-dialog')
    expect(within(dialog).getByRole('heading')).toHaveTextContent(CONFIRM)
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    api.getNetworkTargets.mockResolvedValue({ targets: [], capabilities })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.removeNetworkTarget).toHaveBeenCalledWith('workspace-a', 'target-1'))
    await waitFor(() => expect(screen.queryByText('93.184.216.34')).toBeNull())
  })
  it('Cancel withdraws nothing', async () => {
    fireEvent.click(await ready())
    fireEvent.click(within(await screen.findByTestId('app-dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByTestId('app-dialog')).toBeNull())
    expect(api.removeNetworkTarget).not.toHaveBeenCalled()
  })
  it('a member who cannot manage targets sees no Remove', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets: [target], capabilities: { ...capabilities, can_manage: false } })
    render(<NetworkAssetsPanel workspaceId="workspace-a" />)
    await screen.findByRole('tab', { name: 'Targets' })
    await screen.findByText('93.184.216.34')
    expect(screen.queryByRole('button', { name: 'Remove' })).toBeNull()
  })
})
