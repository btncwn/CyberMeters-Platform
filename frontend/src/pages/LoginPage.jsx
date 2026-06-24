import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { Mail, Lock, AlertTriangle, LogIn, KeyRound, Smartphone, LifeBuoy, MailCheck } from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { useAuth } from '../context/AuthContext'
import { api, BASE } from '../api'

export default function LoginPage() {
  const navigate  = useNavigate()
  const location  = useLocation()
  const { login } = useAuth()

  // If ProtectedRoute redirected here with a destination, go back there after login.
  const from = location.state?.from?.pathname || '/dashboard'

  // ── Step 1: password ──
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState(null)
  const [loading,  setLoading]  = useState(false)

  // ── Email verification flow ──
  const [verificationRequired, setVerificationRequired] = useState(false)
  const [resendLoading,        setResendLoading]        = useState(false)
  const [resendDone,           setResendDone]           = useState(false)

  // ── Step 2: MFA challenge ──
  const [mfaRequired,     setMfaRequired]     = useState(false)
  const [challengeToken,  setChallengeToken]  = useState(null)
  const [mfaCode,         setMfaCode]         = useState('')
  const [showRecovery,    setShowRecovery]    = useState(false)
  const [recoveryCode,    setRecoveryCode]    = useState('')

  async function handleResendVerification() {
    if (resendLoading || resendDone) return
    setResendLoading(true)
    try {
      await api.resendVerification(email.trim().toLowerCase())
      setResendDone(true)
    } catch {
      setResendDone(true) // always show success — server is silent
    } finally {
      setResendLoading(false)
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)
    setVerificationRequired(false)
    setResendDone(false)
    setLoading(true)
    try {
      const data = await api.authLogin(email.trim().toLowerCase(), password)

      if (data.mfa_required) {
        // Password OK but MFA required — move to second step
        setChallengeToken(data.challenge_token)
        setMfaRequired(true)
        return
      }

      await navigateAfterLogin(data.token, data.user)
    } catch (err) {
      if (err.message === 'email_verification_required') {
        setVerificationRequired(true)
      } else {
        setError(err.message || 'Login failed')
      }
    } finally {
      setLoading(false)
    }
  }

  async function handleMfaSubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)
    setLoading(true)
    try {
      const data = await api.mfaChallenge(challengeToken, mfaCode.replace(/\s/g, ''))
      await navigateAfterLogin(data.token, data.user)
    } catch (err) {
      setError(err.message || 'Verification failed')
      setMfaCode('')
    } finally {
      setLoading(false)
    }
  }

  async function handleRecoverySubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)
    setLoading(true)
    try {
      const data = await api.mfaRecoveryCode(challengeToken, recoveryCode.trim())
      await navigateAfterLogin(data.token, data.user)
    } catch (err) {
      setError(err.message || 'Recovery code invalid')
      setRecoveryCode('')
    } finally {
      setLoading(false)
    }
  }

  // After a successful login, redirect new users (no workspaces) to onboarding.
  async function navigateAfterLogin(token, user) {
    login(token, user)
    try {
      const wsData = await api.getWorkspaces()
      if ((wsData?.workspaces?.length ?? 0) === 0) {
        navigate('/onboarding', { replace: true })
        return
      }
    } catch {
      // If workspace check fails, fall through to the normal destination.
    }
    navigate(from, { replace: true })
  }

  function resetToPassword() {
    setMfaRequired(false)
    setChallengeToken(null)
    setMfaCode('')
    setRecoveryCode('')
    setShowRecovery(false)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">

      {/* Brand */}
      <CyberMetersLogo size={40} showWordmark className="mb-8" />

      <div className="card w-full max-w-sm p-8">

        {/* ── Step 1: Email + Password ── */}
        {!mfaRequired && (
          <>
            <h1 className="text-xl font-bold text-gray-900 mb-1">Sign in</h1>
            <p className="text-sm text-gray-400 mb-6">Enter your credentials to continue.</p>

            {error && (
              <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            {verificationRequired && (
              <div className="px-4 py-3 mb-5 bg-amber-50 border border-amber-100 rounded-xl text-sm">
                <div className="flex items-center gap-2.5 text-amber-700 mb-2">
                  <MailCheck className="w-4 h-4 flex-shrink-0" />
                  <span className="font-semibold">Email not verified</span>
                </div>
                <p className="text-amber-600 text-xs mb-3">
                  Please check your inbox and click the verification link before signing in.
                </p>
                {resendDone ? (
                  <span className="text-xs text-green-600 font-medium">Verification email resent!</span>
                ) : (
                  <button
                    type="button"
                    onClick={handleResendVerification}
                    disabled={resendLoading}
                    className="text-xs text-brand-600 font-semibold hover:underline disabled:opacity-50"
                  >
                    {resendLoading ? 'Sending…' : 'Resend verification email'}
                  </button>
                )}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                  <input
                    type="email"
                    className="input pl-10"
                    placeholder="you@example.com"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                    autoFocus
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                  <input
                    type="password"
                    className="input pl-10"
                    placeholder="••••••••"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                  />
                </div>
              </div>

              <div className="flex justify-end -mt-1 mb-1">
                <Link
                  to="/forgot-password"
                  className="text-xs text-brand-600 font-medium hover:underline flex items-center gap-1"
                >
                  <KeyRound className="w-3 h-3" />
                  Forgot password?
                </Link>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full justify-center mt-2"
              >
                {loading
                  ? <span className="opacity-70">Signing in…</span>
                  : <><LogIn className="w-4 h-4" /> Sign in</>
                }
              </button>
            </form>

            {/* ── SSO divider ── */}
            <div className="flex items-center gap-3 my-5">
              <div className="flex-1 h-px bg-gray-100" />
              <span className="text-xs text-gray-300 font-medium">or</span>
              <div className="flex-1 h-px bg-gray-100" />
            </div>

            {/* ── Continue with Microsoft ── */}
            <a
              href={`${BASE}/auth/microsoft/login`}
              className="flex items-center justify-center gap-2.5 w-full px-4 py-2.5 rounded-xl border border-gray-200 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 hover:border-gray-300 transition-colors"
            >
              {/* Microsoft logo mark */}
              <svg width="18" height="18" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <rect x="1"  y="1"  width="9" height="9" fill="#f25022" />
                <rect x="11" y="1"  width="9" height="9" fill="#7fba00" />
                <rect x="1"  y="11" width="9" height="9" fill="#00a4ef" />
                <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
              </svg>
              Continue with Microsoft
            </a>
          </>
        )}

        {/* ── Step 2: MFA Challenge ── */}
        {mfaRequired && !showRecovery && (
          <>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0">
                <Smartphone className="w-4 h-4 text-brand-600" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900 leading-tight">Two-factor authentication</h1>
                <p className="text-xs text-gray-400">Enter the 6-digit code from your authenticator app.</p>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2.5 px-4 py-3 mb-4 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">Verification code</label>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="\d{6}"
                  maxLength={6}
                  className="input text-center text-xl font-mono tracking-[0.4em] py-3"
                  placeholder="000000"
                  value={mfaCode}
                  onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  required
                  autoFocus
                  autoComplete="one-time-code"
                />
              </div>

              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="btn-primary w-full justify-center disabled:opacity-50"
              >
                {loading ? <span className="opacity-70">Verifying…</span> : 'Verify'}
              </button>
            </form>

            <div className="mt-4 pt-4 border-t border-gray-100 flex items-center justify-between">
              <button
                type="button"
                onClick={resetToPassword}
                className="text-xs text-gray-400 hover:text-gray-600"
              >
                ← Back to sign in
              </button>
              <button
                type="button"
                onClick={() => { setShowRecovery(true); setError(null) }}
                className="text-xs text-brand-600 font-medium hover:underline flex items-center gap-1"
              >
                <LifeBuoy className="w-3 h-3" />
                Use recovery code
              </button>
            </div>
          </>
        )}

        {/* ── Step 2b: Recovery Code ── */}
        {mfaRequired && showRecovery && (
          <>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-amber-50 flex items-center justify-center flex-shrink-0">
                <LifeBuoy className="w-4 h-4 text-amber-600" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900 leading-tight">Recovery code</h1>
                <p className="text-xs text-gray-400">Enter one of your saved backup codes.</p>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2.5 px-4 py-3 mb-4 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleRecoverySubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-500 mb-1.5">Recovery code</label>
                <input
                  type="text"
                  className="input font-mono text-center tracking-widest"
                  placeholder="XXXX-XXXX-XXXX"
                  value={recoveryCode}
                  onChange={e => setRecoveryCode(e.target.value.toUpperCase())}
                  required
                  autoFocus
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <button
                type="submit"
                disabled={loading || !recoveryCode.trim()}
                className="btn-primary w-full justify-center disabled:opacity-50"
              >
                {loading ? <span className="opacity-70">Verifying…</span> : 'Verify recovery code'}
              </button>
            </form>

            <div className="mt-4 pt-4 border-t border-gray-100">
              <button
                type="button"
                onClick={() => { setShowRecovery(false); setError(null) }}
                className="text-xs text-gray-400 hover:text-gray-600"
              >
                ← Back to authenticator code
              </button>
            </div>
          </>
        )}
      </div>

      {!mfaRequired && (
        <p className="mt-5 text-sm text-gray-400">
          Don't have an account?{' '}
          <Link to="/signup" className="text-brand-600 font-semibold hover:underline">
            Create one
          </Link>
        </p>
      )}

      <div className="mt-8 text-center">
        <div className="flex flex-wrap justify-center gap-3 text-xs text-gray-300 mb-2">
          <Link to="/terms"   className="hover:text-gray-500">Terms</Link>
          <Link to="/privacy" className="hover:text-gray-500">Privacy</Link>
          <Link to="/dpa"     className="hover:text-gray-500">DPA</Link>
          <Link to="/cookies" className="hover:text-gray-500">Cookies</Link>
        </div>
        <p className="text-xs text-gray-300">
          © {new Date().getFullYear()} CyberMeters — Attack Surface Management
        </p>
      </div>
    </div>
  )
}
