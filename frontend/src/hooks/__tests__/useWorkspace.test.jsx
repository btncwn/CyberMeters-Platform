import { act, renderHook, waitFor } from '@testing-library/react'
import { api } from '../../api'
import { useWorkspace } from '../useWorkspace'

vi.mock('../../api', () => ({
  api: {
    getWorkspaces: vi.fn(),
    bootstrapWorkspace: vi.fn(),
  },
}))

const workspaceA = { id: 'ws_a', name: 'Alpha Ltd', role: 'owner' }
const workspaceB = { id: 'ws_b', name: 'Beta Ltd', role: 'admin' }

describe('useWorkspace', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('does not call the API when there is no auth token', async () => {
    const { result } = renderHook(() => useWorkspace())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(api.getWorkspaces).not.toHaveBeenCalled()
    expect(result.current.wsId).toBeNull()
  })

  it('bootstraps a workspace for authenticated users with no workspaces', async () => {
    localStorage.setItem('cybermeters_auth_token', 'token')
    api.getWorkspaces.mockResolvedValue({ workspaces: [], default_workspace_id: null })
    api.bootstrapWorkspace.mockResolvedValue({ workspace: workspaceA, created: true })

    const { result } = renderHook(() => useWorkspace())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(api.bootstrapWorkspace).toHaveBeenCalledTimes(1)
    expect(result.current.wsId).toBe(workspaceA.id)
    expect(result.current.wsName).toBe(workspaceA.name)
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe(workspaceA.id)
  })

  it('keeps a valid cached workspace and refreshes its name', async () => {
    localStorage.setItem('cybermeters_auth_token', 'token')
    localStorage.setItem('cybermeters_workspace_id', workspaceB.id)
    localStorage.setItem('cybermeters_workspace_name', 'Old name')
    api.getWorkspaces.mockResolvedValue({ workspaces: [workspaceA, workspaceB], default_workspace_id: workspaceA.id })

    const { result } = renderHook(() => useWorkspace())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.wsId).toBe(workspaceB.id)
    expect(result.current.wsName).toBe(workspaceB.name)
    expect(localStorage.getItem('cybermeters_workspace_name')).toBe(workspaceB.name)
  })

  it('falls back to the server default when the cached workspace is stale', async () => {
    localStorage.setItem('cybermeters_auth_token', 'token')
    localStorage.setItem('cybermeters_workspace_id', 'deleted_ws')
    api.getWorkspaces.mockResolvedValue({ workspaces: [workspaceA, workspaceB], default_workspace_id: workspaceB.id })

    const { result } = renderHook(() => useWorkspace())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.wsId).toBe(workspaceB.id)
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe(workspaceB.id)
  })

  it('updates localStorage when setWorkspace is called', async () => {
    localStorage.setItem('cybermeters_auth_token', 'token')
    api.getWorkspaces.mockResolvedValue({ workspaces: [workspaceA], default_workspace_id: workspaceA.id })

    const { result } = renderHook(() => useWorkspace())
    await waitFor(() => expect(result.current.loading).toBe(false))

    act(() => {
      result.current.setWorkspace(workspaceB.id, workspaceB.name)
    })

    expect(localStorage.getItem('cybermeters_workspace_id')).toBe(workspaceB.id)
    expect(localStorage.getItem('cybermeters_workspace_name')).toBe(workspaceB.name)
  })

  it('clears local workspace state when setWorkspace receives no id', async () => {
    localStorage.setItem('cybermeters_auth_token', 'token')
    api.getWorkspaces.mockResolvedValue({ workspaces: [workspaceA], default_workspace_id: workspaceA.id })

    const { result } = renderHook(() => useWorkspace())
    await waitFor(() => expect(result.current.loading).toBe(false))

    act(() => {
      result.current.setWorkspace(null, null)
    })

    expect(localStorage.getItem('cybermeters_workspace_id')).toBeNull()
    expect(localStorage.getItem('cybermeters_workspace_name')).toBeNull()
    expect(result.current.wsId).toBeNull()
  })

  it('leaves cached workspace hints intact if server validation fails', async () => {
    localStorage.setItem('cybermeters_auth_token', 'token')
    localStorage.setItem('cybermeters_workspace_id', workspaceA.id)
    localStorage.setItem('cybermeters_workspace_name', workspaceA.name)
    api.getWorkspaces.mockRejectedValue(new Error('network down'))

    const { result } = renderHook(() => useWorkspace())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.wsId).toBe(workspaceA.id)
    expect(result.current.wsName).toBe(workspaceA.name)
  })
})
