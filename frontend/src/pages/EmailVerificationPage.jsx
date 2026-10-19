/**
 * EmailVerificationPage
 *
 * Landing page of the emailed verification link (19 Oct 2026):
 *
 *   /verify-email#t=<token>[&next=…] — the token stays in the fragment; it is
 *                                      cleared from the address bar on load and
 *                                      POSTed to /api/auth/verify-email.
 *
 * Links sent earlier go to GET /api/auth/verify-email, which redirects here:
 *
 *   /verify-email?success=1          — token was valid; account is now active
 *   /verify-email?error=<reason>     — token was invalid or expired
 *   …#next=/invitations/cmi_<hex>    — an invited signup: after verifying, sign-in
 *                                      returns to the invitation (P1, 18 Oct 2026).
 *                                      Only that exact allow-listed shape is used.
 *                                      (Older redirects carried it as ?next=.)
 */
import { useState, useEffect } from 'react'
import { useSearchParams, Link, useLocation, useNavigate } from 'react-router-dom'
import AuthShell from '../components/AuthShell'
import { api } from '../api'
import { safeInvitationPath, tokenFromInvitationPath, rememberPendingInvite } from '../lib/invitationFlow'
import { urlSecret } from '../lib/urlSecrets'

// One request per token, even when React runs the effect twice: a second POST
// of a token that was just used would read as "already used".
const verificationRequests = new Map()
function verifyOnce(token) {
  if (!verificationRequests.has(token)) verificationRequests.set(token, api.verifyEmail(token))
  return verificationRequests.get(token)
}

export default function EmailVerificationPage() {
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const navigate = useNavigate()
  const verificationToken = urlSecret(location, 'verificationToken')
  // New links: the page verifies the token itself. Older links: the Worker did,
  // and the outcome is in the query.
  const [checked, setChecked] = useState(() => (verificationToken ? null : {
    success: searchParams.get('success') === '1',
    errorCode: searchParams.get('error'),
  }))
  useEffect(() => {
    if (!verificationToken) return undefined
    let live = true
    verifyOnce(verificationToken)
      .then(() => { if (live) setChecked({ success: true, errorCode: null }) })
      .catch(err => { if (live) setChecked({ success: false, errorCode: err?.code || 'failed' }) })
    return () => { live = false }
  }, [verificationToken])
  const success = Boolean(checked?.success)
  const errorCode = checked?.errorCode || null
  // The invitation this signup came from, if any — allow-listed, never free-form.
  const invitationReturn = safeInvitationPath(urlSecret(location, 'invitationReturn') || searchParams.get('next'))
  useEffect(() => {
    const token = tokenFromInvitationPath(invitationReturn)
    if (token) rememberPendingInvite(token)
  }, [invitationReturn])
  const loginState = invitationReturn ? { from: { pathname: invitationReturn } } : undefined

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
    missing:       'This verification link is incomplete. Request a new one below.',
    failed:        'Verification failed. Please try again, or request a new link below.',
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
    if (!success) return undefined
    const interval = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          clearInterval(interval)
          navigate('/login', { replace: true, state: loginState })
          return 0
        }
        return prev - 1
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [success, navigate, loginState?.from?.pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleResend(e) {
    e.preventDefault()
    if (resendLoading || resendDone || !resendEmail.trim()) return
    setResendLoading(true)
    setResendError(false)
    try {
      await api.resendVerification(resendEmail.trim().toLowerCase(), invitationReturn)
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

        {/* ── Checking a link that carried its token ── */}
        {!checked && (
          <div role="status" className="py-6">
            <h1 className="text-xl font-bold text-gray-900 mb-2">Verifying your email…</h1>
            <p className="text-sm text-gray-500">This takes a moment.</p>
          </div>
        )}

        {/* ── Success ── */}
        {success && (
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Email verified</h1>
            <p className="text-sm text-gray-500 mb-6">
              Your email address has been verified. You can now sign in to CyberMeters.
            </p>
            <Link to="/login" state={loginState} className="btn-primary w-full justify-center">
              Sign in
            </Link>
            <p className="text-xs text-gray-400 mt-3">
              Redirecting in {countdown}…
            </p>
          </>
        )}

        {/* ── Error / expired token ── */}
        {checked && !success && (
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-2">Verification failed</h1>
            <p className="text-sm text-gray-500 mb-6">
              {error || 'This verification link is invalid or has expired.'}
            </p>

            {resendDone ? (
              <div className="flex items-center gap-2 px-4 py-3 bg-brand-200 border border-brand-200 rounded-xl text-sm text-brand-900 text-left mb-4">
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

            <Link to="/login" state={loginState} className="text-sm text-brand-700 font-semibold hover:underline">
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
