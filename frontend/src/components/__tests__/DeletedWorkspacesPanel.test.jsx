import React from 'react'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import DeletedWorkspacesPanel from '../DeletedWorkspacesPanel'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getDeletedWorkspaces: vi.fn(), restoreWorkspace: vi.fn() } }))

const WS = (id, name) => ({ id, name, deleted_at: '2026-10-09T10:00:00.000Z', restorable_until: '2026-11-08T10:00:00.000Z' })
const httpError = (status, message) => Object.assign(new Error(message), { status })

beforeEach(() => { vi.resetAllMocks() })

describe('DeletedWorkspacesPanel', () => {
  it('renders nothing when there is nothing to restore', async () => {
    api.getDeletedWorkspaces.mockResolvedValue({ workspaces: [] })
    const { container } = render(<DeletedWorkspacesPanel />)
    await waitFor(() => expect(api.getDeletedWorkspaces).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it('offers an immediate Undo for the workspace just deleted and restores it', async () => {
    api.getDeletedWorkspaces.mockResolvedValue({ workspaces: [WS('ws_1', 'Acme')] })
    api.restoreWorkspace.mockResolvedValue({ restored: true, workspace_id: 'ws_1', note: 'Scheduled scans remain paused' })
    const onRestored = vi.fn()
    render(<DeletedWorkspacesPanel justDeleted={{ id: 'ws_1', name: 'Acme' }} onRestored={onRestored} />)
    expect(await screen.findByText(/“Acme” was deleted\./)).toBeInTheDocument()
    expect(screen.getByText(/You can undo this until/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /undo delete/i }))
    await waitFor(() => expect(api.restoreWorkspace).toHaveBeenCalledWith('ws_1'))
    expect(await screen.findByText(/“Acme” was restored\./)).toBeInTheDocument()
    expect(screen.getByText(/Scheduled scans stay paused/)).toBeInTheDocument()
    expect(onRestored).toHaveBeenCalledWith('ws_1')
    expect(screen.queryByRole('button', { name: /undo delete/i })).not.toBeInTheDocument()
  })

  it('lists other restorable workspaces with their deadline and restores one', async () => {
    api.getDeletedWorkspaces.mockResolvedValue({ workspaces: [WS('ws_a', 'Alpha'), WS('ws_b', 'Beta')] })
    api.restoreWorkspace.mockResolvedValue({ restored: true })
    render(<DeletedWorkspacesPanel />)
    expect(await screen.findByText('Recently deleted')).toBeInTheDocument()
    expect(screen.getAllByText(/Can be restored until/)).toHaveLength(2)
    expect(screen.getByText(/Restoring does not restart scheduled scans/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Restore Beta' }))
    await waitFor(() => expect(api.restoreWorkspace).toHaveBeenCalledWith('ws_b'))
    await waitFor(() => expect(screen.queryByText('Beta')).not.toBeInTheDocument())
    expect(screen.getByText('Alpha')).toBeInTheDocument()
  })

  it('shows the server reason when restore is refused and re-reads the list', async () => {
    api.getDeletedWorkspaces.mockResolvedValue({ workspaces: [WS('ws_a', 'Alpha')] })
    api.restoreWorkspace.mockRejectedValue(httpError(409, 'This workspace can no longer be restored — permanent deletion has already started.'))
    render(<DeletedWorkspacesPanel />)
    fireEvent.click(await screen.findByRole('button', { name: 'Restore Alpha' }))
    expect(await screen.findByText(/permanent deletion has already started/)).toBeInTheDocument()
    await waitFor(() => expect(api.getDeletedWorkspaces).toHaveBeenCalledTimes(2))
    expect(screen.queryByText(/was restored/)).not.toBeInTheDocument()
  })

  it('a load failure is visible with a retry, never silently empty', async () => {
    api.getDeletedWorkspaces.mockRejectedValueOnce(httpError(503, 'unavailable'))
      .mockResolvedValueOnce({ workspaces: [WS('ws_a', 'Alpha')] })
    render(<DeletedWorkspacesPanel />)
    expect(await screen.findByText('Deleted workspaces could not be loaded.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Alpha')).toBeInTheDocument()
  })
})
