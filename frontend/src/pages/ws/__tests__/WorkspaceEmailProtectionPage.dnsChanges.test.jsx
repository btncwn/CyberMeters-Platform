import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceEmailProtectionPage from '../WorkspaceEmailProtectionPage'
import { useWorkspace } from '../../../hooks/useWorkspace'
import { api } from '../../../api'
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))
vi.mock('../../../api', () => ({ BASE: 'https://api.example.test/api', api: {
  getWorkspaceScans: vi.fn(), getEmailProtectionLifecycle: vi.fn(), getDmarcSummary: vi.fn(), getEmailSenders: vi.fn(),
  getDnsConnections: vi.fn(), getDnsConnection: vi.fn(), connectDns: vi.fn(),
} }))
const connection = { can_manage: true, can_apply: true, reporting_ready: false, connection: null, changes: [] }
beforeEach(() => {
  vi.resetAllMocks()
  useWorkspace.mockReturnValue({ wsId: 'workspace-a', wsName: 'Workspace A' })
  api.getWorkspaceScans.mockResolvedValue({ scans: [] }); api.getEmailProtectionLifecycle.mockResolvedValue({})
  api.getDmarcSummary.mockResolvedValue({}); api.getEmailSenders.mockResolvedValue({})
  api.getDnsConnections.mockResolvedValue({ can_manage: true, can_apply: true, domains: [{ id: 'domain-a', domain: 'example.com' }], supported_actions: [{ id: 'spf_publish' }] })
  api.getDnsConnection.mockResolvedValue(connection)
  api.connectDns.mockResolvedValue({ ...connection, connection: { id: 'connection-a', zone_name: 'example.com' } })
})
describe('Email Protection DNS connection integration', () => {
  it('connects a verified domain inside the actual page with no completed scan and keeps existing scan guidance', async () => {
    render(<MemoryRouter><WorkspaceEmailProtectionPage /></MemoryRouter>)
    expect(await screen.findByText('No email authentication guidance yet')).toBeInTheDocument()
    fireEvent.change(await screen.findByLabelText('Domain for this DNS change'), { target: { value: 'example.com' } })
    fireEvent.change(await screen.findByLabelText('Cloudflare zone ID'), { target: { value: 'a'.repeat(32) } })
    fireEvent.change(screen.getByLabelText('Restricted Cloudflare API token'), { target: { value: 'synthetic-token' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /I control this zone/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Connect Cloudflare' }))
    expect(await screen.findByText(/Connected zone:/)).toHaveTextContent('example.com')
    expect(api.connectDns).toHaveBeenCalledWith('workspace-a', 'example.com', expect.objectContaining({ token: 'synthetic-token' }), expect.any(Object))
    expect(screen.getByRole('link', { name: 'Run a scan' })).toBeInTheDocument()
    // Selection also scopes the existing guided page's read paths to this domain.
    expect(api.getDmarcSummary).toHaveBeenLastCalledWith('workspace-a', 'example.com')
    expect(api.getEmailSenders).toHaveBeenLastCalledWith('workspace-a', 'example.com')
  })
  it('mounts a fresh empty DNS selection after a workspace switch', async () => {
    const view = render(<MemoryRouter><WorkspaceEmailProtectionPage /></MemoryRouter>)
    fireEvent.change(await screen.findByLabelText('Domain for this DNS change'), { target: { value: 'example.com' } })
    fireEvent.change(await screen.findByLabelText('Restricted Cloudflare API token'), { target: { value: 'synthetic-token' } })
    useWorkspace.mockReturnValue({ wsId: 'workspace-b', wsName: 'Workspace B' })
    view.rerender(<MemoryRouter><WorkspaceEmailProtectionPage /></MemoryRouter>)
    await waitFor(() => expect(api.getDnsConnections).toHaveBeenLastCalledWith('workspace-b', expect.any(Object)))
    expect(await screen.findByLabelText('Domain for this DNS change')).toHaveValue('')
    expect(screen.queryByLabelText('Restricted Cloudflare API token')).not.toBeInTheDocument()
    expect(api.connectDns).not.toHaveBeenCalled()
  })
})
