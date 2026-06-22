/**
 * EmailVerificationPage
 *
 * Landing page for the GET /api/auth/verify-email redirect.
 * The Worker redirects here after validating (or rejecting) a verification token:
 *
 *   /verify-email?success=1          — token was valid; account is now active
 *   /verify-email?error=<reason>     — token was invalid or expired
 */
import { useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { Shield, CheckCircle, AlertTriangle, Mail } from 'lucide-react'
import { api } from '../api'

export default function EmailVerificationPage() {
  const [searchParams] = useSearchParams()
  const success = searchParams.get('success') === '1'
  const error   = searchParams.get('error')

  // For the "resend" flow shown on the error state
  const [resendEmail,   setResendEmail]   = useState('')
  const [resendLoading, setResendLoading] = useState(false)
  const [resendDone,    setResendDone]    = useState(false)

  async function handleResend(e) {
    e.preventDefault()
    if (resendLoading || resendDone || !resendEmail.trim()) return
    setResendLoading(true)
    try {
      await api.resendVerification(resendEmail.trim().toLowerCase())
      setResendDone(true)
    } catch {
      setResendDone(true) // always show success — server is silent on unknown emails
    } finally {
      setResendLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">

      {/* Brand */}
      <div className="flex items-center gap-2.5 mb-8">
        <div className="w-10 h-10 rounded-xl bg-brand-600 flex items-center justify-center shadow-sm">
          <Shield className="w-5 h-5 text-white" strokeWidth={2.5} />
        </div>
        <div className="leading-none">
          <div className="font-bold text-gray-900 text-lg tracking-tight">CyberMeters</div>
          <div className="text-[10px] font-semibold text-brand-600 tracking-widest uppercase mt-0.5">Platform</div>
        </div>
      </div>

      <div className="card w-full max-w-sm p-8 text-center">

        {/* ── Success ── */}
        {success && (
          <>
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 rounded-full bg-green-50 flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-green-500" />
              </div>
            </div>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Email verified</h1>
            <p className="text-sm text-gray-500 mb-6">
              Your email address has been verified. You can now sign in to CyberMeters.
            </p>
            <Link to="/login" className="btn-primary w-full justify-center">
              Sign in
            </Link>
          </>
        )}

        {/* ── Error / expired token ── */}
        {!success && (
          <>
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 rounded-full bg-red-50 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-red-400" />
              </div>
            </div>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Verification failed</h1>
            <p className="text-sm text-gray-500 mb-6">
              {error || 'This verification link is invalid or has expired.'}
            </p>

            {resendDone ? (
              <div className="flex items-center gap-2 px-4 py-3 bg-green-50 border border-green-100 rounded-xl text-sm text-green-700 text-left mb-4">
                <CheckCircle className="w-4 h-4 flex-shrink-0" />
                If that address has an unverified account, a new link is on its way.
              </div>
            ) : (
              <form onSubmit={handleResend} className="text-left space-y-3 mb-4">
                <p className="text-xs text-gray-400 text-center mb-2">Get a new verification link</p>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                  <input
                    type="email"
                    className="input pl-10"
                    placeholder="you@example.com"
                    value={resendEmail}
                    onChange={e => setResendEmail(e.target.value)}
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={resendLoading || !resendEmail.trim()}
                  className="btn-primary w-full justify-center disabled:opacity-50"
                >
                  {resendLoading ? 'Sending…' : 'Resend verification email'}
                </button>
              </form>
            )}

            <Link to="/login" className="text-sm text-brand-600 font-semibold hover:underline">
              Back to sign in
            </Link>
          </>
        )}
      </div>

      <div className="mt-8 text-center">
        <p className="text-xs text-gray-300">
          © {new Date().getFullYear()} CyberMeters — Attack Surface Management
        </p>
      </div>
    </div>
  )
}
