import { useState } from 'react'
import { Link, useLocation, useSearchParams, useNavigate } from 'react-router-dom'
import { urlSecret } from '../lib/urlSecrets'
import AuthShell from '../components/AuthShell'
import { api } from '../api'

export default function ResetPasswordPage() {
  const [searchParams]               = useSearchParams()
  const navigate                     = useNavigate()
  const location                     = useLocation()
  // The token arrives in the fragment (older links: ?token=), is cleared from the
  // address bar on load and is read from router state (lib/urlSecrets.js).
  const token                        = urlSecret(location, 'resetToken') || searchParams.get('token') || ''

  const [password,  setPassword]  = useState('')
  const [confirm,   setConfirm]   = useState('')
  const [done,      setDone]      = useState(false)
  const [error,     setError]     = useState(null)
  const [loading,   setLoading]   = useState(false)

  // If no token in URL, show an error immediately — with the same canonical
  // brand header and footer as every other auth state, so an invalid link never
  // lands on an unbranded page.
  if (!token) {
    return (
      <AuthShell>
        <div className="card auth-card text-center">
          <h1 className="text-lg font-bold text-gray-900 mb-2">This reset link is invalid or has expired</h1>
          <p className="text-sm text-gray-400 mb-6">
            The link is missing its reset token, or it may already have been used or expired.
            Password reset links only work once. Please request a new one.
          </p>
          <Link to="/forgot-password" className="btn-primary w-full justify-center">
            Request new link
          </Link>
        </div>
        <p className="mt-5 text-sm text-gray-500">
          Remember your password?{' '}
          <Link to="/login" className="text-brand-700 font-semibold hover:underline">
            Sign in
          </Link>
        </p>
        <p className="mt-8 text-xs text-gray-500">
          © {new Date().getFullYear()} CyberMeters — External Security Monitoring
        </p>
      </AuthShell>
    )
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)

    if (password !== confirm) {
      setError("Passwords don't match")
      return
    }
    if (password.length < 12) {
      setError('Password must be at least 12 characters')
      return
    }

    setLoading(true)
    try {
      await api.resetPassword(token, password)
      setDone(true)
      // Redirect to login after 3 seconds
      setTimeout(() => navigate('/login', { replace: true }), 3000)
    } catch (err) {
      setError(err.message || 'Reset failed. The link may have expired.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell>

      <div className="card auth-card">
        {done ? (
          /* ── Success state ── */
          <div className="text-center">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Password updated</h1>
            <p className="text-sm text-gray-500 mb-6">
              Your password has been changed. All existing sessions have been signed out.
              Redirecting you to sign in…
            </p>
            <Link to="/login" className="btn-primary w-full justify-center">
              Sign in now
            </Link>
          </div>
        ) : (
          /* ── Form state ── */
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-1">Set a new password</h1>
            <p className="text-sm text-gray-400 mb-6">
              Choose a strong password for your account.
            </p>

            {error && (
              <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">New password</label>
                <div className="relative">
                  <input
                    type="password"
                    className="input"
                    placeholder="At least 12 characters"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                    minLength={12}
                    autoComplete="new-password"
                    autoFocus
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">Confirm password</label>
                <div className="relative">
                  <input
                    type="password"
                    className="input"
                    placeholder="Re-enter your password"
                    value={confirm}
                    onChange={e => setConfirm(e.target.value)}
                    required
                    autoComplete="new-password"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full justify-center mt-2"
              >
                {loading
                  ? <span className="opacity-70">Updating…</span>
                  : 'Update password'
                }
              </button>
            </form>
          </>
        )}
      </div>

      <p className="mt-5 text-sm text-gray-500">
        Remember your password?{' '}
        <Link to="/login" className="text-brand-700 font-semibold hover:underline">
          Sign in
        </Link>
      </p>

      <p className="mt-8 text-xs text-gray-500">
        © {new Date().getFullYear()} CyberMeters — External Security Monitoring
      </p>
    </AuthShell>
  )
}
