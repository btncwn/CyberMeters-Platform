import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../api'
import OwnerPicker from '../OwnerPicker'

vi.mock('../../api', () => ({ api: { getWorkspaceMembers: vi.fn(), assignCase: vi.fn() } }))

const MEMBERS = [
  { user_id: 'u1', name: 'Ada Lovelace', email: 'ada@example.com', role: 'admin' },
  { user_id: 'u2', name: '', email: 'grace@example.com', role: 'analyst' },
]

beforeEach(() => {
  api.getWorkspaceMembers.mockReset()
  api.assignCase.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: MEMBERS })
})

describe('OwnerPicker', () => {
  it('shows explicit Unassigned when there is no owner', async () => {
    render(<OwnerPicker wsId="ws1" caseId="c1" caseRow={{}} canManage />)
    expect(await screen.findByText('Unassigned')).toBeInTheDocument()
  })

  it('resolves assigned_user_id to a current member identity', async () => {
    render(<OwnerPicker wsId="ws1" caseId="c1" caseRow={{ owner_ref: 'Ada Lovelace', assigned_user_id: 'u1' }} canManage />)
    expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument()
    expect(screen.getByText('· ada@example.com')).toBeInTheDocument()
  })

  it('offers a MEMBER picker and no free-text platform-user input', async () => {
    render(<OwnerPicker wsId="ws1" caseId="c1" caseRow={{}} canManage />)
    // The one control is a <select> of real members — never a free-text input.
    const select = await screen.findByLabelText('Assign owner')
    expect(select.tagName).toBe('SELECT')
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.getByRole('option', { name: /Ada Lovelace \(ada@example.com\)/ })).toBeInTheDocument()
    // A member with no name falls back to email, never a fabricated label.
    expect(screen.getByRole('option', { name: /grace@example.com \(grace@example.com\)/ })).toBeInTheDocument()
  })

  it('assigns by sending assigned_user_id (person owner), not free text', async () => {
    api.assignCase.mockResolvedValue({ case: { case_id: 'c1', owner_ref: 'Ada Lovelace', assigned_user_id: 'u1' } })
    const onAssigned = vi.fn()
    render(<OwnerPicker wsId="ws1" caseId="c1" caseRow={{}} canManage onAssigned={onAssigned} />)
    fireEvent.change(await screen.findByLabelText('Assign owner'), { target: { value: 'u1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
    await waitFor(() => expect(api.assignCase).toHaveBeenCalledWith('ws1', 'c1', {
      owner_type: 'person',
      owner_ref: 'Ada Lovelace',
      assigned_user_id: 'u1',
    }))
    await waitFor(() => expect(onAssigned).toHaveBeenCalled())
  })

  it('surfaces the server assignee_not_member refusal honestly', async () => {
    const err = new Error('nope'); err.code = 'assignee_not_member'
    api.assignCase.mockRejectedValue(err)
    render(<OwnerPicker wsId="ws1" caseId="c1" caseRow={{}} canManage />)
    fireEvent.change(await screen.findByLabelText('Assign owner'), { target: { value: 'u1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
    expect(await screen.findByText(/no longer an active member/i)).toBeInTheDocument()
  })

  it('hides the picker and shows an admin-only note without manage rights', async () => {
    render(<OwnerPicker wsId="ws1" caseId="c1" caseRow={{}} canManage={false} />)
    await waitFor(() => expect(api.getWorkspaceMembers).toHaveBeenCalled())
    expect(screen.queryByLabelText('Assign owner')).toBeNull()
    expect(screen.getByText(/Only workspace admins and owners/i)).toBeInTheDocument()
  })
})
