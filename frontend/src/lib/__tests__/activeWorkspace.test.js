import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ACTIVE_WORKSPACE_EVENT, clearAccountWorkspaceState, pickActiveWorkspace, readActiveWorkspace,
  setActiveWorkspace, validateActiveWorkspace,
} from '../activeWorkspace'

const A = { id: 'ws_sheshire', name: 'SheShire', role: 'owner' }
const B1 = { id: 'ws_b1', name: 'Bravo Bakery', role: 'owner' }
const B2 = { id: 'ws_b2', name: 'Bravo Client', role: 'analyst' }

beforeEach(() => { localStorage.clear() })

describe('active workspace', () => {
  it('picks the stored workspace only when the account has it, else the default, an owned one, the first', () => {
    expect(pickActiveWorkspace([B1, B2], 'ws_b2', 'ws_b1')).toBe(B2)
    expect(pickActiveWorkspace([B1, B2], A.id, 'ws_b2')).toBe(B2)
    expect(pickActiveWorkspace([B2, B1], A.id, null)).toBe(B1)
    expect(pickActiveWorkspace([B2], A.id, null)).toBe(B2)
    expect(pickActiveWorkspace([], A.id, null)).toBeNull()
  })

  it('sign-out clears the account workspace state and keeps what belongs to the browser', () => {
    setActiveWorkspace(A.id, A.name)
    localStorage.setItem('cybermeters_joined_via_invite', 'true')
    localStorage.setItem('cybermeters_pending_invite', `cmi_${'a'.repeat(64)}`)
    localStorage.setItem('cybermeters_results_guide_dismissed', '1')
    clearAccountWorkspaceState()
    expect(readActiveWorkspace()).toEqual({ id: null, name: '' })
    expect(localStorage.getItem('cybermeters_joined_via_invite')).toBeNull()
    expect(localStorage.getItem('cybermeters_pending_invite')).not.toBeNull()
    expect(localStorage.getItem('cybermeters_results_guide_dismissed')).toBe('1')
  })

  it('announces every change in the same tab', () => {
    const seen = vi.fn()
    window.addEventListener(ACTIVE_WORKSPACE_EVENT, seen)
    setActiveWorkspace(B1.id, B1.name)
    clearAccountWorkspaceState()
    window.removeEventListener(ACTIVE_WORKSPACE_EVENT, seen)
    expect(seen).toHaveBeenCalledTimes(2)
  })

  it("replaces another account's stored workspace with one this account has", async () => {
    setActiveWorkspace(A.id, A.name)
    const api = { getWorkspaces: vi.fn(async () => ({ workspaces: [B1, B2], default_workspace_id: 'ws_b1' })) }
    expect(await validateActiveWorkspace(api)).toBe(B1)
    expect(readActiveWorkspace()).toEqual({ id: 'ws_b1', name: 'Bravo Bakery' })
  })

  it('keeps a valid stored workspace and refreshes a renamed one', async () => {
    setActiveWorkspace('ws_b2', 'Old name')
    const api = { getWorkspaces: async () => ({ workspaces: [B1, B2], default_workspace_id: 'ws_b1' }) }
    await validateActiveWorkspace(api)
    expect(readActiveWorkspace()).toEqual({ id: 'ws_b2', name: 'Bravo Client' })
  })

  it('clears the stored workspace when the account has none', async () => {
    setActiveWorkspace(A.id, A.name)
    await validateActiveWorkspace({ getWorkspaces: async () => ({ workspaces: [] }) })
    expect(readActiveWorkspace()).toEqual({ id: null, name: '' })
  })

  it('leaves things alone when the list cannot be read (the API still refuses foreign data)', async () => {
    setActiveWorkspace('ws_b1', 'Bravo Bakery')
    expect(await validateActiveWorkspace({ getWorkspaces: async () => { throw new Error('offline') } })).toBeNull()
    expect(readActiveWorkspace()).toEqual({ id: 'ws_b1', name: 'Bravo Bakery' })
  })
})
