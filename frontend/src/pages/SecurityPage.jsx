import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Monitor, Clock, MapPin, Trash2,
  AlertTriangle, RefreshCw, CheckCircle, XCircle,
} from 'lucide-react'
import { api } from '../api'

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function shortUA(ua) {
  if (!ua) return 'Unknown browser'
  // Best-effort extraction of browser + OS from UA string
  let browser = 'Unknown'
  let os = ''
  if (/Edg\//.test(ua))        browser = 'Edge'
  else if (/Chrome\//.test(ua)) browser = 'Chrome'
  else if (/Safari\//.test(ua)) browser = 'Safari'
  else if (/Firefox\//.test(ua)) browser = 'Firefox'
  if (/Windows/.test(ua))      os = 'Windows'
  else if (/Mac OS/.test(ua))  os = 'macOS'
  else if (/iPhone|iPad/.test(ua)) os = 'iOS'
  else if (/Android/.test(ua)) os = 'Android'
  else if (/Linux/.test(ua))   os = 'Linux'
  return [browser, os].filter(Boolean).join(' · ')
}

function EventIcon({ result }) {
  if (result === 'success') return <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
  return <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
}

// ── Login History Section ────────────────────────────────────────────────────

function LoginHistory() {
  const [events, setEvents]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.getLoginHistory()
      setEvents(data.events || [])
    } catch (e) {
      setError(e.message || 'Failed to load login history')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const EVENT_LABELS = {
    login:                 'Signed in',
    login_failed:          'Failed sign-in attempt',
    mfa_challenge_success: 'MFA verified',
    mfa_challenge_failed:  'MFA failed',
    recovery_code_used:    'Recovery code used',
    password_reset_completed: 'Password reset',
    password_reset_failed:    'Password reset failed',
  }

  return (
    <section className="card p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-gray-400" />
          <h2 className="text-sm font-semibold text-gray-900">Login History</h2>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-600 disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600 mb-4">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {loading && !events.length ? (
        <div className="py-8 text-center text-sm text-gray-400">Loading…</div>
      ) : events.length === 0 ? (
        <div className="py-8 text-center text-sm text-gray-400">No login events recorded yet.</div>
      ) : (
        <div className="space-y-0.5">
          {events.map(ev => (
            <div
              key={ev.id}
              className="flex items-start gap-3 px-3 py-2.5 rounded-xl hover:bg-gray-50 transition-colors"
            >
              <EventIcon result={ev.result} />
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                  <span className="text-sm font-medium text-gray-900">
                    {EVENT_LABELS[ev.event_type] || ev.event_type}
                  </span>
                  <span className="text-xs text-gray-400">{formatDate(ev.timestamp)}</span>
                </div>
                <div className="flex flex-wrap gap-x-3 mt-0.5">
                  {ev.ip_address && (
                    <span className="flex items-center gap-1 text-xs text-gray-400">
                      <MapPin className="w-3 h-3" />
                      {ev.ip_address}
                    </span>
                  )}
                  {ev.user_agent && (
                    <span className="flex items-center gap-1 text-xs text-gray-400">
                      <Monitor className="w-3 h-3" />
                      {shortUA(ev.user_agent)}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <p className="mt-4 text-xs text-gray-400">
        Showing the last {events.length} auth event{events.length !== 1 ? 's' : ''}.
        IP addresses are captured at sign-in time and are not retained indefinitely.
      </p>
    </section>
  )
}

// ── Active Sessions Section ──────────────────────────────────────────────────

function ActiveSessions() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [revoking, setRevoking] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.getActiveSessions()
      setSessions(data.sessions || [])
    } catch (e) {
      setError(e.message || 'Failed to load sessions')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleRevoke(sessionId) {
    if (revoking) return
    setRevoking(sessionId)
    try {
      await api.revokeSession(sessionId)
      setSessions(prev => prev.filter(s => s.session_id !== sessionId))
    } catch (e) {
      setError(e.message || 'Failed to revoke session')
    } finally {
      setRevoking(null)
    }
  }

  return (
    <section className="card p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Monitor className="w-4 h-4 text-gray-400" />
          <h2 className="text-sm font-semibold text-gray-900">Active Sessions</h2>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-600 disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600 mb-4">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {loading && !sessions.length ? (
        <div className="py-8 text-center text-sm text-gray-400">Loading…</div>
      ) : sessions.length === 0 ? (
        <div className="py-8 text-center text-sm text-gray-400">No active sessions.</div>
      ) : (
        <div className="space-y-2">
          {sessions.map(s => (
            <div
              key={s.session_id}
              className={`flex items-start gap-3 px-4 py-3 rounded-xl border transition-colors ${
                s.current
                  ? 'border-brand-200 bg-brand-50'
                  : 'border-gray-100 bg-white hover:bg-gray-50'
              }`}
            >
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                s.current ? 'bg-brand-100' : 'bg-gray-100'
              }`}>
                <Monitor className={`w-4 h-4 ${s.current ? 'text-brand-600' : 'text-gray-400'}`} />
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-gray-900">
                    {shortUA(s.user_agent)}
                  </span>
                  {s.current && (
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-brand-100 text-brand-700 uppercase tracking-wide">
                      This session
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-x-3 mt-0.5">
                  {s.ip_address && (
                    <span className="flex items-center gap-1 text-xs text-gray-400">
                      <MapPin className="w-3 h-3" />
                      {s.ip_address}
                    </span>
                  )}
                  <span className="flex items-center gap-1 text-xs text-gray-400">
                    <Clock className="w-3 h-3" />
                    Started {formatDate(s.created_at)}
                  </span>
                  {s.last_seen_at && (
                    <span className="text-xs text-gray-400">
                      Last seen {formatDate(s.last_seen_at)}
                    </span>
                  )}
                </div>
              </div>

              {!s.current && (
                <button
                  onClick={() => handleRevoke(s.session_id)}
                  disabled={revoking === s.session_id}
                  title="Revoke session"
                  className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-red-500 hover:text-red-700 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50 flex-shrink-0"
                >
                  {revoking === s.session_id
                    ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    : <Trash2 className="w-3.5 h-3.5" />
                  }
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      <p className="mt-4 text-xs text-gray-400">
        To end the current session, use Sign Out. Revoking another session
        will immediately invalidate that login.
      </p>
    </section>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SecurityPage() {
  return (
    <div className="max-w-2xl mx-auto px-6 py-10">

      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-xl bg-brand-50 flex items-center justify-center">
          <Shield className="w-5 h-5 text-brand-600" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-gray-900">Security</h1>
          <p className="text-sm text-gray-400">Monitor your account activity and active sessions.</p>
        </div>
      </div>

      <div className="space-y-6">
        <ActiveSessions />
        <LoginHistory />
      </div>
    </div>
  )
}
