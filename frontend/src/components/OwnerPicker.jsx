// OwnerPicker — canonical case-owner assignment backed by REAL workspace members.
//
// There is deliberately no free-text platform-user input: a person owner is
// chosen from the workspace's active members, and the server (assignCaseOwner)
// re-validates that assigned_user_id is an active member of THIS workspace and
// fails closed. Membership is server-authoritative; this control only offers the
// choices and shows the result honestly. Assignment does not imply remediation
// or verification — it only records who is accountable.
import { useEffect, useState } from 'react'
import { UserCircle2, Loader2 } from 'lucide-react'
import { api } from '../api'

function memberLabel(m) {
  return m?.name?.trim() || m?.email || m?.user_id || 'Unknown member'
}

export default function OwnerPicker({ wsId, caseId, caseRow, canManage = false, onAssigned }) {
  const [members, setMembers] = useState([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.getWorkspaceMembers(wsId)
      .then((data) => { if (!cancelled) setMembers(data.members || []) })
      .catch(() => { if (!cancelled) setError('Could not load workspace members.') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [wsId])

  const ownerRef = caseRow?.owner_ref || null
  const assignedUserId = caseRow?.assigned_user_id || null
  // Prefer resolving the platform-user link to a current member identity; fall
  // back to the stored owner_ref label. Explicit "Unassigned" when neither.
  const assignedMember = assignedUserId ? members.find((m) => m.user_id === assignedUserId) : null

  async function handleAssign() {
    const member = members.find((m) => m.user_id === selected)
    if (!member) return
    setSaving(true)
    setError(null)
    try {
      const res = await api.assignCase(wsId, caseId, {
        owner_type: 'person',
        owner_ref: memberLabel(member),
        assigned_user_id: member.user_id,
      })
      setSelected('')
      if (onAssigned) onAssigned(res.case)
    } catch (e) {
      // The server is authoritative: a non-member (e.g. just-removed) is refused
      // with assignee_not_member. Surface it honestly rather than pretending it worked.
      setError(e?.code === 'assignee_not_member'
        ? 'That person is no longer an active member of this workspace.'
        : 'Could not assign the owner. Please try again.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <UserCircle2 className="w-4 h-4 text-slate-400" />
        <span className="text-sm font-medium text-slate-800">Accountable owner</span>
      </div>

      <div className="text-sm text-slate-700 mb-1">
        {assignedMember ? (
          <span>{memberLabel(assignedMember)} <span className="text-slate-400 text-xs">· {assignedMember.email}</span></span>
        ) : ownerRef ? (
          <span>{ownerRef}{assignedUserId ? <span className="text-slate-400 text-xs"> · former member</span> : null}</span>
        ) : (
          <span className="text-slate-400">Unassigned</span>
        )}
      </div>

      {canManage && (
        <div className="mt-3 flex items-center gap-2">
          <select
            aria-label="Assign owner"
            className="text-sm border border-slate-200 rounded-md px-2 py-1.5 text-slate-700 min-w-[12rem]"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            disabled={loading || saving || members.length === 0}
          >
            <option value="">{loading ? 'Loading members…' : members.length === 0 ? 'No members' : 'Select a member…'}</option>
            {members.map((m) => (
              <option key={m.user_id} value={m.user_id}>{memberLabel(m)} ({m.email})</option>
            ))}
          </select>
          <button
            type="button"
            className="btn-secondary text-sm px-3 py-1.5 disabled:opacity-50 inline-flex items-center gap-1.5"
            onClick={handleAssign}
            disabled={!selected || saving}
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Assign
          </button>
        </div>
      )}
      {!canManage && (
        <p className="text-xs text-slate-400 mt-1">Only workspace admins and owners can change the accountable owner.</p>
      )}
      {error && <p className="text-xs text-red-600 mt-2">{error}</p>}
    </div>
  )
}
