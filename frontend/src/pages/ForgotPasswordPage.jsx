import { useState } from 'react'
import { Link } from 'react-router-dom'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { api } from '../api'

export default function ForgotPasswordPage() {
  const [email,     setEmail]     = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [error,     setError]     = useState(null)
  const [loading,   setLoading]   = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)
    setLoading(true)
    try {
      await api.forgotPassword(email.trim().toLowerCase())
      setSubmitted(true)
    } catch (err) {
      setError(err.message || 'Something went wrong. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">

      {/* Brand */}
      <CyberMetersLogo size={48} showWordmark animated className="mb-8" />

      {/*
        Both the form and the "Check your email" success state share the ONE
        canonical `.auth-card` size (see index.css) — same width, same padding —
        so the confirmation is never a different size family from the form.
      */}
      <div className="card auth-card">
        {submitted ? (
          /* ── Success state ── */
          <div className="text-center">
            <h1 className="text-2xl font-bold text-gray-900 mb-3">Check your email</h1>
            <p className="text-base text-gray-500 leading-relaxed mb-6">
              If <span className="font-medium text-gray-700">{email}</span> is registered,
              you'll receive a reset link within a few minutes. The link expires in 1 hour.
            </p>
            <p className="text-sm text-gray-400 mb-7">
              Didn't receive anything? Check your spam folder, or{' '}
              <button
                className="text-brand-600 font-semibold hover:underline"
                onClick={() => { setSubmitted(false); setError(null) }}
              >
                try again
              </button>.
            </p>
            <Link to="/login" className="btn-primary w-full justify-center py-3.5 text-base">
              Back to sign in
            </Link>
          </div>
        ) : (
          /* ── Form state ── */
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-1">Forgot your password?</h1>
            <p className="text-sm text-gray-400 mb-6">
              Enter your email and we'll send you a reset link.
            </p>

            {error && (
              <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">Email</label>
                <div className="relative">
                  <input
                    type="email"
                    className="input"
                    placeholder="you@example.com"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                    autoFocus
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full justify-center mt-2"
              >
                {loading
                  ? <span className="opacity-70">Sending…</span>
                  : 'Send reset link'
                }
              </button>
            </form>
          </>
        )}
      </div>

      <p className="mt-5 text-sm text-gray-400 flex items-center gap-1.5">
        <Link to="/login" className="text-brand-600 font-semibold hover:underline">
          Back to sign in
        </Link>
      </p>

      <p className="mt-8 text-xs text-gray-300">
        © {new Date().getFullYear()} CyberMeters — External Security Monitoring
      </p>
    </div>
  )
}
