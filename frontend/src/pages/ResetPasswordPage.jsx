import { useState } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { Lock, AlertTriangle, CheckCircle2 } from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { api } from '../api'

export default function ResetPasswordPage() {
  const [searchParams]               = useSearchParams()
  const navigate                     = useNavigate()
  const token                        = searchParams.get('token') || ''

  const [password,  setPassword]  = useState('')
  const [confirm,   setConfirm]   = useState('')
  const [done,      setDone]      = useState(false)
  const [error,     setError]     = useState(null)
  const [loading,   setLoading]   = useState(false)

  // If no token in URL, show an error immediately
  if (!token) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
        <div className="card w-full max-w-sm p-8 text-center">
          <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto mb-3" />
          <h1 className="text-lg font-bold text-gray-900 mb-2">Invalid reset link</h1>
          <p className="text-sm text-gray-400 mb-6">
            This link is missing a reset token. Please request a new one.
          </p>
          <Link to="/forgot-password" className="btn-primary w-full justify-center">
            Request new link
          </Link>
        </div>
      </div>
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
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">

      {/* Brand */}
      <CyberMetersLogo size={48} showWordmark animated className="mb-8" />

      <div className="card w-full max-w-sm p-8">
        {done ? (
          /* ── Success state ── */
          <div className="text-center">
            <div className="w-12 h-12 rounded-full bg-brand-50 flex items-center justify-center mx-auto mb-4">
              <CheckCircle2 className="w-6 h-6 text-brand-600" />
            </div>
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
              <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">New password</label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                  <input
                    type="password"
                    className="input pl-10"
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
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                  <input
                    type="password"
                    className="input pl-10"
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

      <p className="mt-5 text-sm text-gray-400">
        Remember your password?{' '}
        <Link to="/login" className="text-brand-600 font-semibold hover:underline">
          Sign in
        </Link>
      </p>

      <p className="mt-8 text-xs text-gray-300">
        © {new Date().getFullYear()} CyberMeters — Attack Surface Management
      </p>
    </div>
  )
}
