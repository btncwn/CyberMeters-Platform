import { parseServerDate } from '../utils/dates'
/**
 * WorkspaceMembersPanel
 *
 * Displays the member list for the active workspace, with role badges.
 * Owners can add new members (by email + role) and remove existing ones.
 * Non-owners see the list read-only.
 *
 * Props:
 *   workspaceId  (string)  — active workspace id
 *   currentUser  (object)  — { id, email, name } from useAuth()
 *
 * The panel fetches its own data so it can be dropped into any page.
 */

import { useState, useEffect, useCallback } from 'react'
import {
  Users, UserPlus, Trash2, Crown, Shield,
  Eye, ScanLine, AlertTriangle, RefreshCw,
} from 'lucide-react'
import { api } from '../api'

// ── Role display helpers ─────────────────────────────────────────────────────

const ROLE_CFG = {
  owner:   { label: 'Owner',   icon: Crown,    bg: 'bg-amber-50',  text: 'text-amber-700',  border: 'border-amber-200' },
  admin:   { label: 'Admin',   icon: Shield,   bg: 'bg-brand-50',  text: 'text-brand-700',  border: 'border-brand-200' },
  analyst: { label: 'Analyst', icon: ScanLine, bg: 'bg-blue-50',   text: 'text-blue-700',   border: 'border-blue-200'  },
  viewer:  { label: 'Viewer',  icon: Eye,      bg: 'bg-gray-50',   text: 'text-gray-600',   border: 'border-gray-200'  },
}

function RoleBadge({ role }) {
  const cfg = ROLE_CFG[role] ?? ROLE_CFG.viewer
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-semibold ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  )
}

// ── Role rank (mirrors backend) ───────────────────────────────────────────────

const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2, owner: 3 }
function myRoleRank(members, currentUserId) {
  const me = members.find(m => m.user_id === currentUserId)
  return me ? (ROLE_RANK[me.role] ?? -1) : -1
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function WorkspaceMembersPanel({ workspaceId, currentUser }) {
  const [members,     setMembers]     = useState([])
  const [invitations, setInvitations] = useState([])
  const [callerRole,  setCallerRole]  = useState(null)
  const [loading,     setLoading]     = useState(false)
  const [error,       setError]       = useState(null)

  // Invite form state
  const [addEmail, setAddEmail] = useState('')
  const [addRole,  setAddRole]  = useState('analyst')
  const [adding,   setAdding]   = useState(false)
  const [addError, setAddError] = useState(null)
  const [inviteLink, setInviteLink] = useState(null)

  const [removingId, setRemovingId] = useState(null)

  const load = useCallback(async (silent = false) => {
    if (!workspaceId) return
    if (!silent) setLoading(true)
    setError(null)
    try {
      const data = await api.getWorkspaceMembers(workspaceId)
      const nextMembers = data.members || []
      const nextRole = data.caller_role || null
      setMembers(nextMembers)
      setCallerRole(nextRole)
      if ((ROLE_RANK[nextRole] ?? myRoleRank(nextMembers, currentUser?.id)) >= ROLE_RANK.admin) {
        const inviteData = await api.getWorkspaceInvitations(workspaceId)
        setInvitations(inviteData.invitations || [])
      } else {
        setInvitations([])
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [workspaceId, currentUser?.id])

  useEffect(() => { load() }, [load])

  const effectiveRank = ROLE_RANK[callerRole] ?? myRoleRank(members, currentUser?.id)
  const isOwner = effectiveRank >= ROLE_RANK.owner
  const canInvite = effectiveRank >= ROLE_RANK.admin

  async function handleInvite(e) {
    e.preventDefault()
    if (!addEmail.trim() || !workspaceId) return
    setAdding(true)
    setAddError(null)
    setInviteLink(null)
    try {
      const res = await api.createWorkspaceInvitation(workspaceId, addEmail.trim(), addRole)
      const link = `${window.location.origin}/invitations/${res.token}`
      setInviteLink(link)
      setAddEmail('')
      setAddRole('analyst')
      await load(true)
    } catch (e) {
      setAddError(e.message)
    } finally {
      setAdding(false)
    }
  }

  async function handleRemove(memberId) {
    if (!workspaceId || removingId) return
    setRemovingId(memberId)
    try {
      await api.removeWorkspaceMember(workspaceId, memberId)
      setMembers(prev => prev.filter(m => m.id !== memberId))
    } catch (e) {
      setError(e.message)
    } finally {
      setRemovingId(null)
    }
  }

  if (!workspaceId) return null

  return (
    <div className="card">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-brand-600" />
          <h3 className="font-semibold text-gray-900 text-sm">Team Members</h3>
          {members.length > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-gray-100 text-gray-500">
              {members.length}
            </span>
          )}
        </div>
        <button
          onClick={() => load(true)}
          disabled={loading}
          className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
          title="Refresh"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 border border-red-100 mb-4">
          <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
          <p className="text-xs text-red-600">{error}</p>
        </div>
      )}

      {/* Member list */}
      {loading && members.length === 0 ? (
        <div className="text-sm text-gray-400 text-center py-6">Loading…</div>
      ) : members.length === 0 ? (
        <div className="text-sm text-gray-400 text-center py-6">No members yet.</div>
      ) : (
        <ul className="divide-y divide-gray-50 mb-4">
          {members.map(m => {
            const isSelf     = m.user_id === currentUser?.id
            const canRemove  = isOwner && !isSelf && m.role !== 'owner'
            return (
              <li key={m.id} className="flex items-center justify-between py-2.5 gap-3">
                {/* Avatar + info */}
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-7 h-7 rounded-full bg-brand-100 flex items-center justify-center text-xs font-bold text-brand-700 flex-shrink-0">
                    {(m.name || m.email || '?')[0].toUpperCase()}
                  </div>
                  <div className="min-w-0">
                    {m.name && (
                      <p className="text-xs font-semibold text-gray-900 truncate">
                        {m.name}{isSelf ? ' (you)' : ''}
                      </p>
                    )}
                    <p className={`text-xs truncate ${m.name ? 'text-gray-400' : 'text-gray-700'}`}>
                      {m.email}{!m.name && isSelf ? ' (you)' : ''}
                    </p>
                  </div>
                </div>

                {/* Role + actions */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <RoleBadge role={m.role} />
                  {canRemove && (
                    <button
                      onClick={() => handleRemove(m.id)}
                      disabled={removingId === m.id}
                      title="Remove member"
                      className="w-6 h-6 flex items-center justify-center rounded text-gray-300 hover:text-red-500 hover:bg-red-50 transition-colors disabled:opacity-50"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      )}

      {/* Pending invitations */}
      {canInvite && invitations.length > 0 && (
        <div className="border-t border-gray-100 pt-4 mb-4">
          <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Pending invitations</p>
          <ul className="space-y-2">
            {invitations.filter(i => i.status === 'pending').map(inv => (
              <li key={inv.id} className="flex items-center justify-between gap-2 p-2 rounded-lg bg-gray-50">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-gray-700 truncate">{inv.email}</p>
                  <p className="text-[10px] text-gray-400">Expires {inv.expires_at ? parseServerDate(inv.expires_at).toLocaleDateString() : '—'}</p>
                </div>
                <RoleBadge role={inv.role} />
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Add member form — only visible to owners */}
      {canInvite && (
        <div className="border-t border-gray-100 pt-4">
          <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">Invite member</p>
          <form onSubmit={handleInvite} className="flex flex-col gap-2">
            <input
              type="email"
              value={addEmail}
              onChange={e => {
                setAddEmail(e.target.value)
                setInviteLink(null)
              }}
              placeholder="colleague@company.com"
              required
              className="input text-sm"
            />
            <div className="flex gap-2">
              <select
                value={addRole}
                onChange={e => setAddRole(e.target.value)}
                className="input text-sm flex-1"
              >
                <option value="viewer">Viewer — read-only</option>
                <option value="analyst">Analyst — trigger scans</option>
                <option value="admin">Admin — manage domains &amp; reports</option>
              </select>
              <button
                type="submit"
                disabled={adding || !addEmail.trim()}
                className="btn-primary flex items-center gap-1.5 flex-shrink-0 disabled:opacity-50"
              >
                <UserPlus className="w-4 h-4" />
                {adding ? 'Inviting…' : 'Invite'}
              </button>
            </div>
            {addError && (
              <p className="text-xs text-red-500 mt-1">{addError}</p>
            )}
            {inviteLink && (
              <div className="p-3 rounded-xl bg-amber-50 border border-amber-100">
                <p className="text-xs font-semibold text-amber-800 mb-1">Copy this invite link now. It will not be shown again.</p>
                <code className="block text-xs text-amber-900 break-all bg-white/60 rounded-lg p-2">{inviteLink}</code>
              </div>
            )}
          </form>
          <p className="text-[10px] text-gray-400 mt-2">
            No email will be sent. Share the generated invite link manually.
          </p>
        </div>
      )}
    </div>
  )
}
