/**
 * InvitationLandingPage — public, no auth required.
 *
 * Route: /invitations/:token
 *
 * Flow:
 *  1. Load invitation preview (workspace name, role, invited-by, expiry) via
 *     GET /api/invitations/:token — public endpoint, no bearer token needed.
 *  2. Logged-out user: show Sign Up / Sign In CTAs that preserve the invite
 *     token through the auth flow.
 *  3. Logged-in user with matching email: show Join Workspace CTA.
 *  4. Logged-in user with wrong email: show clear explanation.
 *  5. Handle all error states: expired, already used, invalid token.
 *  6. On success: set active workspace + redirect to workspace dashboard.
 *
 * Token preservation:
 *  - Sign In  → navigate to /login with state.from pointing back here
 *               (LoginPage already reads state.from.pathname).
 *  - Sign Up  → save token to localStorage (cybermeters_pending_invite),
 *               navigate to /signup; Dashboard picks it up after first load.
 */
import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Shield, Users, BarChart2, Server, TrendingUp, Package2,
  CheckCircle, AlertTriangle, Clock, LogIn, UserPlus, RefreshCw,
  Briefcase, ArrowRight, X,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { api } from '../api'
import CyberMetersLogoMark from '../components/CyberMetersLogo'

// ── Constants ─────────────────────────────────────────────────────────────────

const PENDING_INVITE_KEY    = 'cybermeters_pending_invite'
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
    icon: BarChart2,
    color: 'bg-brand-50 text-brand-600',
    title: 'Shared Security Monitoring',
    desc: 'Real-time visibility across all domains in your workspace — shared with the whole team.',
  },
  {
    icon: Shield,
    color: 'bg-red-50 text-red-500',
    title: 'Executive Reporting',
    desc: 'Generate PDF risk reports for clients and stakeholders in one click.',
  },
  {
    icon: Server,
    color: 'bg-amber-50 text-amber-600',
    title: 'Asset Inventory',
    desc: 'Track every subdomain, certificate, cloud service, and exposed admin surface.',
  },
  {
    icon: TrendingUp,
    color: 'bg-green-50 text-green-600',
    title: 'Historical Tracking',
    desc: 'Score trends over time so you can demonstrate improvement to stakeholders.',
  },
  {
    icon: Package2,
    color: 'bg-purple-50 text-purple-600',
    title: 'Vendor Risk Visibility',
    desc: "Understand your organisation's third-party exposure and supply chain risk.",
  },
  {
    icon: Users,
    color: 'bg-sky-50 text-sky-600',
    title: 'Team Collaboration',
    desc: 'Work alongside colleagues with role-based access so everyone sees what they need.',
  },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleDateString(undefined, {
    day: 'numeric', month: 'long', year: 'numeric',
  })
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
    warning: 'bg-amber-50 border-amber-200 text-amber-700',
    success: 'bg-green-50 border-green-200 text-green-700',
    info:    'bg-blue-50 border-blue-200 text-blue-700',
  }
  const icons = {
    error:   <AlertTriangle className="w-4 h-4 flex-shrink-0" />,
    warning: <AlertTriangle className="w-4 h-4 flex-shrink-0" />,
    success: <CheckCircle   className="w-4 h-4 flex-shrink-0" />,
    info:    <Shield        className="w-4 h-4 flex-shrink-0" />,
  }
  return (
    <div className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm font-medium ${styles[type]}`}>
      {icons[type]}
      <span>{children}</span>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function InvitationLandingPage() {
  const { token }  = useParams()
  const navigate   = useNavigate()
  const { isAuthenticated, isLoading: authLoading, user } = useAuth()

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
      } catch (e) {
        setLoadError(e.message || 'Invitation not found.')
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

  // ── Handlers ──────────────────────────────────────────────────────────────

  function handleSignIn() {
    navigate('/login', { state: { from: { pathname: `/invitations/${token}` } } })
  }

  function handleSignUp() {
    // Save pending invite so Dashboard can redirect after signup
    localStorage.setItem(PENDING_INVITE_KEY, token)
    navigate('/signup')
  }

  async function handleJoin() {
    setJoining(true)
    setJoinError(null)
    setWrongEmailMsg(null)
    try {
      const result = await api.acceptWorkspaceInvitation(token)
      // Store workspace context
      if (result.workspace_id) {
        localStorage.setItem('cybermeters_workspace_id', result.workspace_id)
        if (preview?.workspace_name) {
          localStorage.setItem('cybermeters_workspace_name', preview.workspace_name)
        }
        setJoinedWsId(result.workspace_id)
      }
      // Signal to Dashboard that this is a team-joined session → show onboarding card
      localStorage.setItem(JOINED_VIA_INVITE_KEY, 'true')
      setJoined(true)
    } catch (e) {
      const msg = e.message || 'Failed to join workspace.'
      if (msg.toLowerCase().includes('email')) {
        setWrongEmailMsg(msg)
      } else {
        setJoinError(msg)
      }
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
        <RefreshCw className="w-6 h-6 text-brand-500 animate-spin mt-4" />
        <p className="text-sm text-gray-400">Loading invitation…</p>
      </div>
    )
  }

  // Preview load error (invalid token / network)
  if (loadError) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="w-full max-w-md space-y-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-red-50 flex items-center justify-center mx-auto mb-4">
              <X className="w-7 h-7 text-red-500" />
            </div>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Invitation not found</h1>
            <p className="text-sm text-gray-400 mb-6">
              This invitation link is invalid or has already been removed. Ask the workspace owner to send a new invitation.
            </p>
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
        <div className="w-full max-w-md space-y-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-amber-50 flex items-center justify-center mx-auto mb-4">
              <Clock className="w-7 h-7 text-amber-500" />
            </div>
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
        <div className="w-full max-w-md space-y-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-green-50 flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="w-7 h-7 text-green-500" />
            </div>
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
        <div className="w-full max-w-md space-y-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-gray-50 flex items-center justify-center mx-auto mb-4">
              <X className="w-7 h-7 text-gray-400" />
            </div>
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
        <div className="w-full max-w-md space-y-6">
          <div className="flex justify-center"><CyberMetersLogoMark size={36} showWordmark animated /></div>
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-green-50 flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="w-7 h-7 text-green-500" />
            </div>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Successfully joined workspace</h1>
            <p className="text-sm text-gray-400 mb-6">
              You're now a <strong className="text-gray-700">{ROLE_LABELS[preview?.role] || preview?.role}</strong> in{' '}
              <strong className="text-gray-700">{preview?.workspace_name}</strong>.
            </p>
            <button onClick={handleGoToWorkspace} className="btn-primary w-full justify-center">
              <ArrowRight className="w-4 h-4" />
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
        <div className="max-w-screen-md mx-auto">
          <CyberMetersLogoMark size={36} showWordmark animated />
        </div>
      </header>

      <main className="max-w-screen-md mx-auto px-4 py-10 space-y-8">

        {/* ── Invitation card ──────────────────────────────────────────────── */}
        <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
          {/* Header band */}
          <div className="bg-brand-600 px-8 py-6">
            <div className="w-12 h-12 rounded-xl bg-white/20 flex items-center justify-center mb-3">
              <Briefcase className="w-6 h-6 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-1">
              You've been invited to join a workspace
            </h1>
            <p className="text-brand-100 text-sm">
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
              <Shield className="w-4 h-4 text-brand-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-brand-700">
                <strong>{ROLE_LABELS[preview.role] || preview.role}:</strong>{' '}
                {ROLE_DESCRIPTIONS[preview.role] || 'Access to workspace data and reports.'}
              </p>
            </div>

            {/* Expiry */}
            {preview.expires_at && (
              <p className="text-xs text-gray-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                Invitation expires {formatDate(preview.expires_at)}
              </p>
            )}

            {/* Error banners */}
            {joinError && <StatusBanner type="error">{joinError}</StatusBanner>}
            {wrongEmailMsg && (
              <StatusBanner type="warning">
                This invitation was sent to a different email address. Sign in with the correct account or ask for a new invitation.
              </StatusBanner>
            )}

            {/* ── CTAs ───────────────────────────────────────────────────── */}
            {isAuthenticated ? (
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
                    <><CheckCircle className="w-4 h-4" /> Join Workspace</>
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
                  <UserPlus className="w-4 h-4" />
                  Sign Up &amp; Join Workspace
                </button>
                <button onClick={handleSignIn} className="btn-secondary w-full justify-center">
                  <LogIn className="w-4 h-4" />
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
            {BENEFITS.map(({ icon: Icon, color, title, desc }) => (
              <div key={title} className="bg-white rounded-xl border border-gray-100 p-5 shadow-sm">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center mb-3 ${color}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <p className="text-sm font-semibold text-gray-900 mb-1">{title}</p>
                <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-300 pb-4">
          CyberMeters — Attack Surface Management &amp; Security Posture Platform
        </p>
      </main>
    </div>
  )
}
