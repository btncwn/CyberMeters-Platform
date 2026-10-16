/**
 * EmailVerificationPage
 *
 * Landing page for the GET /api/auth/verify-email redirect.
 * The Worker redirects here after validating (or rejecting) a verification token:
 *
 *   /verify-email?success=1          — token was valid; account is now active
 *   /verify-email?error=<reason>     — token was invalid or expired
 */
import { useState, useEffect } from 'react'
import { useSearchParams, Link, useNavigate } from 'react-router-dom'
import AuthShell from '../components/AuthShell'
import { api } from '../api'

export default function EmailVerificationPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const success = searchParams.get('success') === '1'
  const errorCode = searchParams.get('error')

  // Map server-provided reason codes to calm, customer-friendly copy. A raw code
  // (e.g. "token_expired") should never reach the screen; unknown codes fall back
  // to a generic message and the resend flow below.
  const ERROR_MESSAGES = {
    expired:       'This verification link has expired. Request a new one below.',
    token_expired: 'This verification link has expired. Request a new one below.',
    invalid:       'This verification link is invalid. Request a new one below.',
    invalid_token: 'This verification link is invalid. Request a new one below.',
    used:          'This verification link has already been used. Try signing in, or request a new link below.',
    not_found:     'We couldn’t find this verification link. Request a new one below.',
  }
  const looksFriendly = errorCode && errorCode.includes(' ')
  const error = errorCode
    ? (ERROR_MESSAGES[errorCode] || (looksFriendly ? errorCode : 'This verification link is invalid or has expired.'))
    : null

  // For the "resend" flow shown on the error state
  const [resendEmail,   setResendEmail]   = useState('')
  const [resendLoading, setResendLoading] = useState(false)
  const [resendDone,    setResendDone]    = useState(false)
  const [resendError,   setResendError]   = useState(false)
  const [countdown,     setCountdown]     = useState(3)

  // Auto-redirect to /login 3 seconds after successful verification.
  useEffect(() => {
    if (!success) return
    const interval = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          clearInterval(interval)
          navigate('/login', { replace: true })
          return 0
        }
        return prev - 1
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [success, navigate])

  async function handleResend(e) {
    e.preventDefault()
    if (resendLoading || resendDone || !resendEmail.trim()) return
    setResendLoading(true)
    setResendError(false)
    try {
      await api.resendVerification(resendEmail.trim().toLowerCase())
      setResendDone(true)
    } catch {
      setResendError(true)
    } finally {
      setResendLoading(false)
    }
  }

  return (
    <AuthShell>

      <div className="card auth-card text-center">

        {/* ── Success ── */}
        {success && (
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Email verified</h1>
            <p className="text-sm text-gray-500 mb-6">
              Your email address has been verified. You can now sign in to CyberMeters.
            </p>
            <Link to="/login" className="btn-primary w-full justify-center">
              Sign in
            </Link>
            <p className="text-xs text-gray-400 mt-3">
              Redirecting in {countdown}…
            </p>
          </>
        )}

        {/* ── Error / expired token ── */}
        {!success && (
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Verification failed</h1>
            <p className="text-sm text-gray-500 mb-6">
              {error || 'This verification link is invalid or has expired.'}
            </p>

            {resendDone ? (
              <div className="flex items-center gap-2 px-4 py-3 bg-green-50 border border-green-100 rounded-xl text-sm text-green-700 text-left mb-4">
                If that address has an unverified account, a new link is on its way.
              </div>
            ) : (
              <form onSubmit={handleResend} className="text-left space-y-3 mb-4">
                <p className="text-xs text-gray-400 text-center mb-2">Get a new verification link</p>
                <div className="relative">
                  <input
                    type="email"
                    className="input"
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
                {resendError && <p role="alert" className="text-xs text-red-700">Could not send the link right now. Please try again.</p>}
              </form>
            )}

            <Link to="/login" className="text-sm text-brand-600 font-semibold hover:underline">
              Back to sign in
            </Link>
          </>
        )}
      </div>

      <div className="mt-8 text-center">
        <p className="text-xs text-gray-500">
          © {new Date().getFullYear()} CyberMeters — External Security Monitoring
        </p>
      </div>
    </AuthShell>
  )
}
