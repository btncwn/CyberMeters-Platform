import { parseServerDate, formatDay } from '../utils/dates'
/**
 * InvitationLandingPage — public, no auth required.
 *
 * Route: /invitations — the token arrives in the fragment (#t=…) or, for links
 * sent before 19 Oct 2026, in the path; either way it is cleared from the address
 * bar on load and read from router state (lib/urlSecrets.js).
 *
 * Flow:
 *  1. Load invitation preview (workspace name, role, invited-by, expiry) via
 *     POST /api/invitations/preview with { token } — public, no bearer token needed;
 *     the token goes in the body, never in the request path.
 *  2. Logged-out user: show Sign Up / Sign In CTAs that preserve the invite
 *     token through the auth flow.
 *  3. Logged-in user with matching email: show Join Workspace CTA.
 *  4. Logged-in user with wrong email: show clear explanation.
 *  5. Handle all error states: expired, already used, invalid token.
 *  6. On success: set active workspace + redirect to workspace dashboard.
 *
 * Token preservation (P1, 18 Oct 2026):
 *  - Sign In  → /login with state.from pointing back here; login returns here
 *               even when the account has no workspace yet.
 *  - Sign Up  → the token rides to /signup, then inside the verification link
 *               (allow-listed /invitations/cmi_<hex> only), so verifying on any
 *               device lands back on this page. It is also remembered locally as
 *               a safety net for the pending-invitation banner.
 *
 * Email mismatch: "Join Workspace" is hidden, the invited address is shown
 * masked (the server masks it), and the one action is "Sign out and continue
 * as the invited address". No raw API error string ever reaches the screen.
 */
import { useEffect, useState } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { urlSecret } from '../lib/urlSecrets'
import { RefreshCw } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { api, logoutWithToken } from '../api'
import { TOKEN_KEY } from '../context/authKeys'
import {
  INVITATION_ERRORS, invitationErrorKind, rememberPendingInvite, clearPendingInvite,
} from '../lib/invitationFlow'
import CyberMetersLogoMark from '../components/CyberMetersLogo'
import { setActiveWorkspace } from '../lib/activeWorkspace'

// ── Constants ─────────────────────────────────────────────────────────────────

const JOINED_VIA_INVITE_KEY = 'cybermeters_joined_via_invite'

const ROLE_LABELS = {
  owner:   'Owner',
  admin:   'Admin',
  analyst: 'Analyst',
  viewer:  'Viewer',
}

const ROLE_DESCRIPTIONS = {
  owner:   'Full control over the workspace, including billing and member management.',
  admin:   'Can manage members and invitations, run scans, and view all reports.',
  analyst: 'Can run scans, view findings, and generate reports.',
  viewer:  'Read-only access to dashboards, findings, and reports.',
}

const BENEFITS = [
  {
    title: 'Shared Security Monitoring',
    desc: 'Scheduled scans of the domains in your workspace, shared with the whole team.',
  },
  {
    title: 'Executive Reporting',
    desc: 'Generate PDF risk reports for clients and stakeholders in one click.',
  },
  {
    title: 'Asset Inventory',
    desc: 'Track the subdomains, certificates, cloud services and admin pages CyberMeters finds.',
  },
  {
    title: 'Historical Tracking',
    desc: 'Score trends over time so you can demonstrate improvement to stakeholders.',
  },
  {
    title: 'Shadow IT Visibility',
    desc: 'See the SaaS portals, third-party scripts and providers observed on your domains, and keep an approved inventory.',
  },
  {
    title: 'Team Collaboration',
    desc: 'Work alongside colleagues with role-based access so everyone sees what they need.',
  },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return formatDay(s)
}

function isExpired(expiresAt) {
  if (!expiresAt) return false
  const d = new Date(expiresAt.includes('T') ? expiresAt : expiresAt.replace(' ', 'T') + 'Z')
  return d.getTime() <= Date.now()
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBanner({ type, children }) {
  const styles = {
    error:   'bg-red-50 border-red-200 text-red-700',
    warning: 'bg-transparent border-[1.5px] border-brand-700 text-brand-700',
    success: 'bg-brand-200 border-brand-200 text-brand-900',
    info:    'bg-blue-50 border-blue-200 text-blue-700',
  }
  return (
    <div className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm font-medium ${styles[type]}`}>
      <span>{children}</span>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function InvitationLandingPage() {
  const params     = useParams()
  const location   = useLocation()
  const navigate   = useNavigate()
  // Router state holds the token (never the URL). A path-form address reached
  // from inside the app is cleaned to /invitations straight away.
  const token      = urlSecret(location, 'invitationToken') || params.token || ''
  useEffect(() => {
    if (params.token) navigate('/invitations', { replace: true, state: { urlSecrets: { invitationToken: params.token } } })
  }, [params.token, navigate])
  const { isAuthenticated, isLoading: authLoading, user, logout } = useAuth()

  const [preview,   setPreview]   = useState(null)   // { workspace_name, invited_by_name, role, expires_at, status }
  const [loading,   setLoading]   = useState(true)
  const [loadError, setLoadError] = useState(null)   // string | null — error from preview fetch
  const [joining,   setJoining]   = useState(false)
  const [joinError, setJoinError] = useState(null)
  const [joined,    setJoined]    = useState(false)
  const [joinedWsId, setJoinedWsId] = useState(null)

  // Load the public preview on mount
  useEffect(() => {
    async function loadPreview() {
      setLoading(true)
      setLoadError(null)
      try {
        const data = await api.getInvitationPreview(token)
        setPreview(data)
        // Safety net: remember a live invitation so login and onboarding can offer it.
        if (data?.status === 'pending') rememberPendingInvite(token)
      } catch (e) {
        // Never the server's raw string — the mapped, customer wording only.
        setLoadError(INVITATION_ERRORS[invitationErrorKind(e)] || INVITATION_ERRORS.not_found)
      } finally {
        setLoading(false)
      }
    }
    loadPreview()
  }, [token])

  // ── Derived state ──────────────────────────────────────────────────────────

  const expired        = preview && (preview.status === 'expired' || isExpired(preview.expires_at))
  const alreadyUsed    = preview && preview.status === 'accepted'
  const cancelled      = preview && preview.status === 'cancelled'
  const [wrongEmailMsg, setWrongEmailMsg] = useState(null)
  // Mismatch: the server says the signed-in account is not the invited one, or a
  // Join attempt came back as an email mismatch (older API without the flag).
  const emailMismatch = isAuthenticated && (preview?.signed_in_matches === false || Boolean(wrongEmailMsg))

  // ── Handlers ──────────────────────────────────────────────────────────────

  function handleSignIn() {
    navigate('/login', { state: { from: { pathname: `/invitations/${token}` } } })
  }

  function handleSignUp() {
    // The token rides to signup (and from there inside the verification link).
    rememberPendingInvite(token)
    navigate('/signup', { state: { invitationToken: token } })
  }

  function handleSignOutAndContinue() {
    // Sign out, then come back to this same invitation so sign-in / sign-up opens
    // for the invited address.
    const currentToken = localStorage.getItem(TOKEN_KEY)
    logout()
    if (currentToken) logoutWithToken(currentToken)
    setWrongEmailMsg(null)
    navigate('/invitations', { replace: true, state: { urlSecrets: { invitationToken: token } } })
  }

  async function handleJoin() {
    setJoining(true)
    setJoinError(null)
    setWrongEmailMsg(null)
    try {
      const result = await api.acceptWorkspaceInvitation(token)
      // Store workspace context
      if (result.workspace_id) {
        // Id and name together, through the one notifying writer (C-45 W02): a
        // missing preview name is left empty for useWorkspace to fill, never the
        // previous workspace's name.
        setActiveWorkspace(result.workspace_id, preview?.workspace_name || '')
        setJoinedWsId(result.workspace_id)
      }
      // Signal to Dashboard that this is a team-joined session → show onboarding card
      localStorage.setItem(JOINED_VIA_INVITE_KEY, 'true')
      clearPendingInvite()
      setJoined(true)
    } catch (e) {
      // Plain English only — "Unauthorized", status codes and server strings never render.
      const kind = invitationErrorKind(e)
      if (kind === 'email_mismatch') setWrongEmailMsg(INVITATION_ERRORS.email_mismatch)
      else setJoinError(INVITATION_ERRORS[kind])
    } finally {
      setJoining(false)
    }
  }

  function handleGoToWorkspace() {
    if (joinedWsId) {
      navigate(`/workspaces/${joinedWsId}`)
    } else {
      navigate('/workspaces')
    }
  }

  // ── Render states ──────────────────────────────────────────────────────────

  // Loading preview
  if (loading || authLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center gap-4">
        <CyberMetersLogoMark size={36} showWordmark animated />
        <RefreshCw className="w-6 h-6 text-brand-700 animate-spin mt-4" />
        <p className="text-sm text-gray-400">Loading invitation…</p>
      </div>
    )
  }

  // Preview load error (invalid token / network)
  if (loadError) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="w-full flex flex-col items-center gap-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="card auth-card text-center">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Invitation not available</h1>
            <p className="text-sm text-gray-600 mb-6" data-testid="invitation-load-error">{loadError}</p>
            <button onClick={() => navigate('/login')} className="btn-primary w-full justify-center">
              Go to Sign In
            </button>
          </div>
        </div>
      </div>
    )
  }

  // Expired invitation
  if (expired) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="w-full flex flex-col items-center gap-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="card auth-card text-center">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Invitation expired</h1>
            <p className="text-sm text-gray-400 mb-6">
              This invitation to <strong className="text-gray-700">{preview.workspace_name}</strong> expired
              on {formatDate(preview.expires_at)}. Ask a workspace admin or owner to send a fresh invitation.
            </p>
            <button onClick={() => navigate(isAuthenticated ? '/workspaces' : '/login')} className="btn-primary w-full justify-center">
              {isAuthenticated ? 'Go to Workspaces' : 'Go to Sign In'}
            </button>
          </div>
        </div>
      </div>
    )
  }

  // Already accepted
  if (alreadyUsed) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="w-full flex flex-col items-center gap-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="card auth-card text-center">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Invitation already used</h1>
            <p className="text-sm text-gray-400 mb-6">
              This invitation has already been accepted. If you're trying to access{' '}
              <strong className="text-gray-700">{preview.workspace_name}</strong>, sign in to your account.
            </p>
            <button onClick={() => navigate(isAuthenticated ? '/workspaces' : '/login')} className="btn-primary w-full justify-center">
              {isAuthenticated ? 'Go to Workspaces' : 'Go to Sign In'}
            </button>
          </div>
        </div>
      </div>
    )
  }

  // Cancelled invitation
  if (cancelled) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="w-full flex flex-col items-center gap-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="card auth-card text-center">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Invitation cancelled</h1>
            <p className="text-sm text-gray-400 mb-6">
              This invitation to <strong className="text-gray-700">{preview.workspace_name}</strong> was cancelled
              by the workspace admin. Ask them to send a new invitation.
            </p>
            <button onClick={() => navigate(isAuthenticated ? '/workspaces' : '/login')} className="btn-primary w-full justify-center">
              {isAuthenticated ? 'Go to Workspaces' : 'Go to Sign In'}
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ── Success state (after joining) ──────────────────────────────────────────
  if (joined) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="w-full flex flex-col items-center gap-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="card auth-card text-center">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Successfully joined workspace</h1>
            <p className="text-sm text-gray-400 mb-6">
              You're now a <strong className="text-gray-700">{ROLE_LABELS[preview?.role] || preview?.role}</strong> in{' '}
              <strong className="text-gray-700">{preview?.workspace_name}</strong>.
            </p>
            <button onClick={handleGoToWorkspace} className="btn-primary w-full justify-center">
              Go to Workspace
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ── Main landing page ──────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top bar */}
      <header className="bg-white border-b border-gray-100 px-6 py-4">
        <div className="max-w-(--breakpoint-md) mx-auto">
          <CyberMetersLogoMark size={36} showWordmark animated />
        </div>
      </header>

      <main className="max-w-(--breakpoint-md) mx-auto px-4 py-10 space-y-8">

        {/* ── Invitation card ──────────────────────────────────────────────── */}
        <div className="bg-white rounded-2xl shadow-xs border border-gray-100 overflow-hidden">
          {/* Header band */}
          <div className="bg-brand-200 px-8 py-6">
            <h1 className="text-2xl font-bold text-brand-900 mb-1">
              You've been invited to join a workspace
            </h1>
            <p className="text-brand-900/80 text-sm">
              {preview.invited_by_name} has invited you to collaborate on CyberMeters.
            </p>
          </div>

          {/* Details */}
          <div className="px-8 py-6 space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-gray-50 rounded-xl p-4">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">Workspace</p>
                <p className="text-sm font-bold text-gray-900">{preview.workspace_name}</p>
              </div>
              <div className="bg-gray-50 rounded-xl p-4">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">Invited by</p>
                <p className="text-sm font-bold text-gray-900">{preview.invited_by_name}</p>
              </div>
              <div className="bg-gray-50 rounded-xl p-4">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">Your role</p>
                <p className="text-sm font-bold text-gray-900">{ROLE_LABELS[preview.role] || preview.role}</p>
              </div>
            </div>

            {/* Role description */}
            <div className="flex items-start gap-2.5 bg-brand-50 rounded-xl px-4 py-3">
              <p className="text-sm text-brand-700">
                <strong>{ROLE_LABELS[preview.role] || preview.role}:</strong>{' '}
                {ROLE_DESCRIPTIONS[preview.role] || 'Access to workspace data and reports.'}
              </p>
            </div>

            {/* Which address the invitation was sent to — masked by the server. */}
            {preview.invited_email_masked && (
              <p className="text-sm text-gray-700" data-testid="invited-address">
                Sent to <strong className="font-semibold">{preview.invited_email_masked}</strong>
              </p>
            )}

            {/* Expiry */}
            {preview.expires_at && (
              <p className="text-xs text-gray-400 flex items-center gap-1.5">
                Invitation expires {formatDate(preview.expires_at)}
              </p>
            )}

            {/* Error banner — mapped wording only */}
            {joinError && <StatusBanner type="error">{joinError}</StatusBanner>}

            {/* ── CTAs ───────────────────────────────────────────────────── */}
            {emailMismatch ? (
              /* Signed in as someone else: no Join at all, one way forward. */
              <div className="pt-2 space-y-3" data-testid="invitation-mismatch">
                <StatusBanner type="warning">
                  This invitation was sent to {preview.invited_email_masked ? <strong>{preview.invited_email_masked}</strong> : 'a different email address'}.
                  {' '}You are signed in as <strong>{user?.email}</strong>.
                </StatusBanner>
                <button onClick={handleSignOutAndContinue} className="btn-primary w-full justify-center">
                  Sign out and continue as the invited address
                </button>
              </div>
            ) : isAuthenticated ? (
              /* Logged-in user */
              <div className="pt-2">
                <p className="text-xs text-gray-400 mb-4">
                  Signed in as <strong className="text-gray-600">{user?.email}</strong>.
                  {' '}Make sure this matches the email the invitation was sent to.
                </p>
                <button
                  onClick={handleJoin}
                  disabled={joining}
                  className="btn-primary w-full justify-center disabled:opacity-50"
                >
                  {joining ? (
                    <><RefreshCw className="w-4 h-4 animate-spin" /> Joining…</>
                  ) : (
                    'Join Workspace'
                  )}
                </button>
              </div>
            ) : (
              /* Logged-out user */
              <div className="pt-2 space-y-3">
                <p className="text-xs text-gray-400">
                  Create an account or sign in to accept this invitation.
                </p>
                <button onClick={handleSignUp} className="btn-primary w-full justify-center">
                  Sign Up &amp; Join Workspace
                </button>
                <button onClick={handleSignIn} className="btn-secondary w-full justify-center">
                  Sign In &amp; Join Workspace
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ── Workspace benefits ───────────────────────────────────────────── */}
        <div>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-widest mb-4 px-1">
            What you'll get access to
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {BENEFITS.map(({ title, desc }) => (
              <div key={title} className="bg-white rounded-xl border border-gray-100 p-5 shadow-xs">
                <p className="text-sm font-semibold text-gray-900 mb-1">{title}</p>
                <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-600 pb-4">
          CyberMeters — Attack Surface Management &amp; Security Posture Platform
        </p>
      </main>
    </div>
  )
}
