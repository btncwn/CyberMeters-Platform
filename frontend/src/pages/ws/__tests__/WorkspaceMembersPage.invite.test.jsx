// ── Workspace invitations — success is coupled to a real backend dispatch ─────
// Production defect (2026-07-19): the invitation POST created a row and returned
// 201 but NEVER sent an email, so the UI showed "Invitation sent" for an
// invitation that was never delivered. The backend now fails CLOSED on a send
// failure (compensating-delete + non-2xx), which makes api.createWorkspaceInvitation
// throw. These tests pin the frontend contract:
//   • "Invitation sent" appears ONLY when the backend resolves successfully;
//   • a backend failure surfaces a generic error and NEVER the success message.
import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceMembersPage from '../WorkspaceMembersPage'
import { api } from '../../../api'
import { useAuth } from '../../../context/AuthContext'

vi.mock('../../../api', () => ({
  api: {
    getWorkspaceMembers: vi.fn(),
    getWorkspaceInvitations: vi.fn(),
    createWorkspaceInvitation: vi.fn(),
    updateMemberRole: vi.fn(),
    removeWorkspaceMember: vi.fn(),
    cancelWorkspaceInvitation: vi.fn(),
  },
}))
vi.mock('../../../context/AuthContext', () => ({ useAuth: vi.fn() }))

const WS_ID = 'ws_test_1'

function mountPage() {
  return render(<MemoryRouter><WorkspaceMembersPage /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  try { localStorage.clear() } catch { /* jsdom */ }
  localStorage.setItem('cybermeters_workspace_id', WS_ID)
  useAuth.mockReturnValue({ user: { id: 'u1', email: 'owner@acme.com' } })
  api.getWorkspaceMembers.mockResolvedValue({
    caller_role: 'owner',
    members: [{ id: 'm1', user_id: 'u1', email: 'owner@acme.com', name: 'Owner', role: 'owner', created_at: '2026-07-01T00:00:00Z' }],
  })
  api.getWorkspaceInvitations.mockResolvedValue({ invitations: [] })
})

async function fillAndSubmitInvite(email = 'colleague@acme.com') {
  // Wait for the invite form (admin+ only) to render after the initial load.
  const input = await screen.findByPlaceholderText('colleague@company.com')
  fireEvent.change(input, { target: { value: email } })
  fireEvent.click(screen.getByRole('button', { name: /Send Invite/i }))
}

describe('WorkspaceMembersPage — invite success is coupled to backend dispatch', () => {
  it('shows "Invitation sent" only after the backend resolves successfully', async () => {
    api.createWorkspaceInvitation.mockResolvedValue({
      invitation: { id: 'wsi1', workspace_id: WS_ID, email: 'colleague@acme.com', role: 'viewer', status: 'pending' },
      token: 'tok_raw',
    })
    mountPage()
    await fillAndSubmitInvite('colleague@acme.com')

    expect(await screen.findByText(/Invitation sent to colleague@acme\.com/i)).toBeInTheDocument()
    expect(api.createWorkspaceInvitation).toHaveBeenCalledWith(WS_ID, 'colleague@acme.com', 'viewer')
  })

  it('does NOT show "Invitation sent" when the backend send fails (fail-closed 502)', async () => {
    // The fail-closed backend returns a generic non-2xx; the api layer throws.
    api.createWorkspaceInvitation.mockRejectedValue(new Error("We couldn't send the invitation email. Please try again."))
    mountPage()
    await fillAndSubmitInvite('colleague@acme.com')

    // A generic failure message is shown…
    expect(await screen.findByText(/We couldn't send the invitation email/i)).toBeInTheDocument()
    // …and the misleading success message never appears.
    await waitFor(() => {
      expect(screen.queryByText(/Invitation sent/i)).not.toBeInTheDocument()
    })
  })
})
