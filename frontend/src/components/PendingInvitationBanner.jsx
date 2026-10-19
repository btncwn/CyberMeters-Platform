// PendingInvitationBanner — the safety net for invited people (P1, 18 Oct 2026).
//
// After any sign-in, if this browser holds a live invitation for the signed-in
// account, show "You've been invited to <workspace>" with Join / Not now BEFORE
// onboarding. Nothing is accepted automatically: Join calls the same accept
// endpoint as the invitation page. "Not now" hides it for this session. The
// invitation is offered only while the backend says it is pending, unexpired
// and (when it can tell) addressed to the signed-in account; every failure
// reads in plain English. `onState` tells the host page whether an invitation
// is being offered, so onboarding can hold back "Get Started" meanwhile.
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { setActiveWorkspace } from '../lib/activeWorkspace'
import {
  INVITATION_ERRORS, invitationErrorKind, pendingInviteToken, clearPendingInvite,
  dismissPendingInvite, isPendingInviteDismissed,
} from '../lib/invitationFlow'

const ROLE_LABELS = { owner: 'an owner', admin: 'an admin', analyst: 'an analyst', viewer: 'a viewer' }

function expired(at) {
  if (!at) return false
  const t = new Date(String(at).includes('T') ? at : String(at).replace(' ', 'T') + 'Z').getTime()
  return Number.isFinite(t) && t <= Date.now()
}

export default function PendingInvitationBanner({ onState = () => {} }) {
  const navigate = useNavigate()
  const [token] = useState(() => pendingInviteToken())
  const [state, setState] = useState(() => (token && !isPendingInviteDismissed(token) ? { status: 'checking' } : { status: 'none' }))
  const [joining, setJoining] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (state.status !== 'checking') return undefined
    let alive = true
    Promise.resolve().then(() => api.getInvitationPreview(token))
      .then((preview) => {
        if (!alive) return
        const live = preview?.status === 'pending' && !expired(preview.expires_at) && preview.signed_in_matches !== false
        if (!live) { clearPendingInvite(); setState({ status: 'none' }); return }
        setState({ status: 'offer', preview })
      })
      .catch(() => { if (alive) setState({ status: 'none' }) })
    return () => { alive = false }
  }, [state.status, token])

  useEffect(() => { onState(state.status) }, [state.status]) // eslint-disable-line react-hooks/exhaustive-deps

  if (state.status !== 'offer') return null
  const { preview } = state

  async function join() {
    setJoining(true); setError(null)
    try {
      const result = await api.acceptWorkspaceInvitation(token)
      clearPendingInvite()
      if (result?.workspace_id) {
        setActiveWorkspace(result.workspace_id, preview.workspace_name || '')
      }
      localStorage.setItem('cybermeters_joined_via_invite', 'true')
      setState({ status: 'joined' })
      navigate('/dashboard', { replace: true })
    } catch (e) {
      setError(INVITATION_ERRORS[invitationErrorKind(e)])
    } finally {
      setJoining(false)
    }
  }

  function notNow() {
    dismissPendingInvite(token)
    setState({ status: 'dismissed' })
  }

  return (
    <section className="card p-6 border-l-4 border-l-brand-700" aria-labelledby="pending-invite-title" data-testid="pending-invitation">
      <h2 id="pending-invite-title" className="text-lg font-semibold text-gray-900">You&apos;ve been invited to {preview.workspace_name}</h2>
      <p className="text-sm text-gray-700 mt-1">
        {preview.invited_by_name} invited you to join as {ROLE_LABELS[preview.role] || 'a member'}. Join to see the workspace’s monitoring, reports and cases.
      </p>
      {error && <p role="alert" className="text-sm text-red-700 mt-3">{error}</p>}
      <div className="mt-4 flex flex-wrap gap-3">
        <button type="button" onClick={join} disabled={joining} className="btn-primary">{joining ? 'Joining…' : `Join ${preview.workspace_name}`}</button>
        <button type="button" onClick={notNow} className="btn-secondary">Not now</button>
      </div>
    </section>
  )
}
