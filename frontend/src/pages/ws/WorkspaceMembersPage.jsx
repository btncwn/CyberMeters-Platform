/**
 * WorkspaceMembersPage — Workspace Invitations & Team Collaboration v1
 *
 * Route: /ws/members
 * Sections:
 *   1. Members list — name, email, role badge, change role (owner), remove (owner)
 *   2. Pending Invitations — email, role, date, cancel (admin+)
 *   3. Invite form — email + role + button (admin+)
 *
 * Role model (maps to existing RBAC):
 *   owner   → full control, change roles, remove members
 *   admin   → invite, cancel invitations, remove non-owner members
 *   analyst → read-only view
 *   viewer  → read-only view
 */

import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import {
  Users, UserPlus, Mail, Shield, Trash2, RefreshCw,
  ChevronDown, CheckCircle, Clock, AlertTriangle, X,
} from 'lucide-react'
import { api } from '../../api'
import Spinner from '../../components/Spinner'
import ErrorAlert from '../../components/ErrorAlert'

// ── Helpers ────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  return new Date(str.includes('T') ? str : str.replace(' ', 'T') + 'Z')
    .toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

const ROLE_COLORS = {
  owner:   'bg-brand-100 text-brand-800',
  admin:   'bg-purple-100 text-purple-700',
  analyst: 'bg-amber-100 text-amber-700',
  viewer:  'bg-gray-100 text-gray-600',
}

const ROLE_LABEL = {
  owner:   'Owner',
  admin:   'Admin',
  analyst: 'Analyst',
  viewer:  'Viewer',
}

function RoleBadge({ role }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold ${ROLE_COLORS[role] || 'bg-gray-100 text-gray-600'}`}>
      {ROLE_LABEL[role] || role}
    </span>
  )
}

function isAdminPlus(role) { return role === 'owner' || role === 'admin' }
function isOwner(role)     { return role === 'owner' }

// ── Invite Form ─────────────────────────────────────────────────────────────

function InviteForm({ workspaceId, callerRole, onSuccess }) {
  const [email,   setEmail]   = useState('')
  const [role,    setRole]    = useState('viewer')
  const [saving,  setSaving]  = useState(false)
  const [error,   setError]   = useState(null)
  const [success, setSuccess] = useState(null)
  const canInviteAdmin = callerRole === 'owner'

  async function submit(e) {
    e.preventDefault()
    setError(null)
    setSuccess(null)
    const trimmed = email.trim().toLowerCase()
    if (!trimmed) { setError('Email is required.'); return }
    setSaving(true)
    try {
      await api.createWorkspaceInvitation(workspaceId, trimmed, role)
      setEmail('')
      setRole('viewer')
      setSuccess(`Invitation sent to ${trimmed}.`)
      onSuccess?.()
    } catch (err) {
      setError(err.message || 'Failed to send invitation.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="card p-6">
      <div className="flex items-center gap-2.5 mb-5">
        <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center">
          <UserPlus className="w-4 h-4 text-brand-600" />
        </div>
        <div>
          <p className="text-sm font-bold text-gray-900">Invite a team member</p>
          <p className="text-xs text-gray-400">They'll receive a link to accept via email.</p>
        </div>
      </div>

      {error   && <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-100 text-sm text-red-700">{error}</div>}
      {success && <div className="mb-4 p-3 rounded-lg bg-brand-50 border border-brand-100 text-sm text-brand-700 flex items-center gap-2"><CheckCircle className="w-4 h-4 flex-shrink-0" />{success}</div>}

      <form onSubmit={submit} className="flex flex-col sm:flex-row gap-3">
        <input
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          placeholder="colleague@company.com"
          required
          className="input flex-1"
          disabled={saving}
        />
        <div className="relative flex-shrink-0">
          <select
            value={role}
            onChange={e => setRole(e.target.value)}
            className="input pr-8 appearance-none min-w-[130px]"
            disabled={saving}
          >
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            {canInviteAdmin && <option value="admin">Admin</option>}
          </select>
          <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
        </div>
        <button type="submit" className="btn-primary flex-shrink-0" disabled={saving}>
          {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />}
          {saving ? 'Sending…' : 'Send Invite'}
        </button>
      </form>

      {/* Role descriptions */}
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-2 pt-4 border-t border-gray-100">
        {[
          { role: 'viewer',  desc: 'View workspace, reports, and scans.'                    },
          { role: 'analyst', desc: 'Everything Viewer does, plus run scans.'                },
          { role: 'admin',   desc: 'Everything Analyst does, plus manage domains, reports, and invite viewers/analysts. Owners can assign this role.' },
        ].filter(({ role: r }) => r !== 'admin' || canInviteAdmin)
        .map(({ role: r, desc }) => (
          <div key={r} className="flex items-start gap-2">
            <RoleBadge role={r} />
            <p className="text-[11px] text-gray-400 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Role Change Dropdown ─────────────────────────────────────────────────────

function RoleSelector({ currentRole, memberId, workspaceId, callerRole, onChanged }) {
  const [changing, setChanging] = useState(false)
  const [err,      setErr]      = useState(null)

  async function change(e) {
    const newRole = e.target.value
    if (newRole === currentRole) return
    setErr(null)
    setChanging(true)
    try {
      await api.updateMemberRole(workspaceId, memberId, newRole)
      onChanged?.()
    } catch (error) {
      setErr(error.message)
    } finally {
      setChanging(false)
    }
  }

  return (
    <div>
      <div className="relative inline-block">
        <select
          value={currentRole}
          onChange={change}
          disabled={changing}
          className="text-[11px] font-semibold border border-gray-200 rounded-lg px-2.5 py-1.5 pr-6 bg-white appearance-none cursor-pointer hover:border-brand-300 transition-colors focus:outline-none focus:ring-2 focus:ring-brand-200"
        >
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          {callerRole === 'owner' && <option value="admin">Admin</option>}
        </select>
        {changing
          ? <RefreshCw className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 animate-spin pointer-events-none" />
          : <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />}
      </div>
      {err && <p className="text-[11px] text-red-600 mt-1">{err}</p>}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function WorkspaceMembersPage() {
  const [members,      setMembers]      = useState([])
  const [invitations,  setInvitations]  = useState([])
  const [callerRole,   setCallerRole]   = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [refreshing,   setRefreshing]   = useState(false)
  const [removingId,   setRemovingId]   = useState(null)
  const [cancellingId, setCancellingId] = useState(null)
  const navigate = useNavigate()
  const { user: currentUser } = useAuth()

  const workspaceId = localStorage.getItem('cybermeters_workspace_id')

  const load = useCallback(async (silent = false) => {
    if (!workspaceId) { setLoading(false); return }
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const [membersData, invitesData] = await Promise.all([
        api.getWorkspaceMembers(workspaceId),
        api.getWorkspaceInvitations(workspaceId).catch(() => ({ invitations: [] })),
      ])
      setMembers(membersData.members || [])
      setCallerRole(membersData.caller_role || null)
      // Only show pending invitations
      setInvitations((invitesData.invitations || []).filter(i => i.status === 'pending'))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [workspaceId])

  useEffect(() => { load() }, [load])

  async function removeMember(memberId) {
    if (!window.confirm('Remove this member from the workspace?')) return
    setRemovingId(memberId)
    try {
      await api.removeWorkspaceMember(workspaceId, memberId)
      setMembers(prev => prev.filter(m => m.id !== memberId))
    } catch (e) {
      alert(e.message || 'Failed to remove member.')
    } finally {
      setRemovingId(null)
    }
  }

  async function cancelInvitation(invId) {
    if (!window.confirm('Cancel this invitation?')) return
    setCancellingId(invId)
    try {
      await api.cancelWorkspaceInvitation(workspaceId, invId)
      setInvitations(prev => prev.filter(i => i.id !== invId))
    } catch (e) {
      alert(e.message || 'Failed to cancel invitation.')
    } finally {
      setCancellingId(null)
    }
  }

  if (!workspaceId) {
    return (
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <div className="card p-12 text-center">
          <Users className="w-10 h-10 text-gray-200 mx-auto mb-3" />
          <p className="text-sm font-semibold text-gray-900 mb-1">No workspace selected</p>
          <p className="text-xs text-gray-400 mb-4">Select a workspace to manage team members.</p>
          <button onClick={() => navigate('/workspaces')} className="btn-primary mx-auto">Go to Workspaces</button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Team Members</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {members.length} member{members.length !== 1 ? 's' : ''}
            {invitations.length > 0 && ` · ${invitations.length} pending invitation${invitations.length !== 1 ? 's' : ''}`}
          </p>
        </div>
        <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && <ErrorAlert message={error} onRetry={() => load()} />}

      {loading ? (
        <div className="flex items-center justify-center py-24"><Spinner size="lg" /></div>
      ) : (
        <>
          {/* ── 1. Invite Form (admin+) ── */}
          {isAdminPlus(callerRole) && (
            <InviteForm workspaceId={workspaceId} callerRole={callerRole} onSuccess={() => load(true)} />
          )}

          {/* ── 2. Members list ── */}
          <div className="card overflow-hidden">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-100">
              <div className="w-7 h-7 rounded-lg bg-gray-100 flex items-center justify-center">
                <Users className="w-3.5 h-3.5 text-gray-500" />
              </div>
              <p className="text-sm font-bold text-gray-900">Members</p>
              <span className="text-xs text-gray-400 ml-auto">{members.length} total</span>
            </div>

            {members.length === 0 ? (
              <div className="py-16 text-center">
                <Users className="w-8 h-8 text-gray-200 mx-auto mb-3" />
                <p className="text-sm text-gray-400">No members found.</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="text-left border-b border-gray-100">
                    <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Member</th>
                    <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Role</th>
                    <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide hidden sm:table-cell">Joined</th>
                    {isAdminPlus(callerRole) && (
                      <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide text-right">Actions</th>
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {members.map(member => {
                    const isCurrentUser = member.email === currentUser?.email
                    // Owner can manage any non-owner member.
                    // Admin can manage analyst/viewer only (not other admins, not owners).
                    const canManage = isAdminPlus(callerRole)
                      && member.role !== 'owner'
                      && !(callerRole === 'admin' && member.role === 'admin')
                    return (
                      <tr key={member.id} className="hover:bg-gray-50/40 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-brand-100 flex items-center justify-center flex-shrink-0">
                              <span className="text-xs font-bold text-brand-700">
                                {(member.name || member.email || '?')[0].toUpperCase()}
                              </span>
                            </div>
                            <div className="min-w-0">
                              <p className="text-sm font-semibold text-gray-900 truncate">
                                {member.name || '—'}
                                {isCurrentUser && (
                                  <span className="ml-2 text-[10px] font-medium text-gray-400">(you)</span>
                                )}
                              </p>
                              <p className="text-xs text-gray-400 truncate">{member.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          {canManage ? (
                            <RoleSelector
                              currentRole={member.role}
                              memberId={member.id}
                              workspaceId={workspaceId}
                              callerRole={callerRole}
                              onChanged={() => load(true)}
                            />
                          ) : (
                            <RoleBadge role={member.role} />
                          )}
                        </td>
                        <td className="px-6 py-4 text-xs text-gray-400 hidden sm:table-cell">
                          {formatDate(member.created_at)}
                        </td>
                        {isAdminPlus(callerRole) && (
                          <td className="px-6 py-4 text-right">
                            {canManage && (
                              <button
                                onClick={() => removeMember(member.id)}
                                disabled={removingId === member.id}
                                className="inline-flex items-center gap-1.5 text-xs font-medium text-red-500 hover:text-red-700 hover:bg-red-50 px-2.5 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                                title="Remove member"
                              >
                                {removingId === member.id
                                  ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                  : <Trash2 className="w-3.5 h-3.5" />}
                                Remove
                              </button>
                            )}
                          </td>
                        )}
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* ── 3. Pending Invitations (admin+) ── */}
          {isAdminPlus(callerRole) && (
            <div className="card overflow-hidden">
              <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-100">
                <div className="w-7 h-7 rounded-lg bg-amber-50 flex items-center justify-center">
                  <Mail className="w-3.5 h-3.5 text-amber-600" />
                </div>
                <p className="text-sm font-bold text-gray-900">Pending Invitations</p>
                <span className="text-xs text-gray-400 ml-auto">{invitations.length} pending</span>
              </div>

              {invitations.length === 0 ? (
                <div className="py-12 text-center">
                  <CheckCircle className="w-8 h-8 text-gray-200 mx-auto mb-3" />
                  <p className="text-sm text-gray-400">No pending invitations.</p>
                </div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="text-left border-b border-gray-100">
                      <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Email</th>
                      <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Role</th>
                      <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide hidden sm:table-cell">Invited</th>
                      <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide hidden sm:table-cell">Expires</th>
                      <th className="px-6 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-50">
                    {invitations.map(inv => (
                      <tr key={inv.id} className="hover:bg-gray-50/40 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-2.5">
                            <div className="w-7 h-7 rounded-full bg-amber-50 flex items-center justify-center flex-shrink-0">
                              <Mail className="w-3.5 h-3.5 text-amber-500" />
                            </div>
                            <span className="text-sm text-gray-700">{inv.email}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4"><RoleBadge role={inv.role} /></td>
                        <td className="px-6 py-4 text-xs text-gray-400 hidden sm:table-cell">
                          {formatDate(inv.created_at)}
                        </td>
                        <td className="px-6 py-4 text-xs hidden sm:table-cell">
                          <span className={`flex items-center gap-1 ${
                            new Date(inv.expires_at) < new Date(Date.now() + 24 * 3600000)
                              ? 'text-amber-600' : 'text-gray-400'
                          }`}>
                            <Clock className="w-3 h-3" />
                            {formatDate(inv.expires_at)}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={() => cancelInvitation(inv.id)}
                            disabled={cancellingId === inv.id}
                            className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-red-600 hover:bg-red-50 px-2.5 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                            title="Cancel invitation"
                          >
                            {cancellingId === inv.id
                              ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                              : <X className="w-3.5 h-3.5" />}
                            Cancel
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* Read-only notice for non-admins */}
          {callerRole && !isAdminPlus(callerRole) && (
            <div className="card p-4 flex items-start gap-3 border-amber-100 bg-amber-50/40">
              <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-gray-900">Read-only view</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  Your role ({ROLE_LABEL[callerRole]}) can view team members but cannot invite or remove them.
                  Contact a workspace Admin or Owner to make changes.
                </p>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
