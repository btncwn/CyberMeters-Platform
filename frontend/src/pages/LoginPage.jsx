import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import AuthShell, { AuthAlert, AuthHeading, Field, SignInAside } from '../components/AuthShell'
import { useAuth } from '../context/AuthContext'
import { api, BASE } from '../api'

export default function LoginPage() {
  const navigate  = useNavigate()
  const location  = useLocation()
  const { login } = useAuth()

  // If ProtectedRoute redirected here with a real destination, return there after
  // login; otherwise land on the Services launcher. /login is never a useful
  // destination, so it falls through to /services (prevents redirect loops).
  const rawFrom = location.state?.from?.pathname
  const from = (rawFrom && rawFrom !== '/login') ? rawFrom : '/services'

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
  // A Microsoft SSO sign-in for an MFA-enabled account redirects here with the
  // challenge token in navigation state; initialise the MFA step directly from it
  // so the same second-factor UI serves both password and SSO logins.
  const ssoMfaChallenge = location.state?.mfaChallengeToken || null
  const [mfaRequired,     setMfaRequired]     = useState(!!ssoMfaChallenge)
  const [challengeToken,  setChallengeToken]  = useState(ssoMfaChallenge)
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

  const microsoftButton = (
    <a
      href={`${BASE}/auth/microsoft/login`}
      className="flex items-center justify-center gap-3 w-full h-12 rounded-[10px] border border-rule bg-white text-[15px] font-semibold text-ink hover:bg-bay transition-colors"
    >
      <svg width="18" height="18" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <rect x="1"  y="1"  width="9" height="9" fill="#f25022" />
        <rect x="11" y="1"  width="9" height="9" fill="#7fba00" />
        <rect x="1"  y="11" width="9" height="9" fill="#00a4ef" />
        <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
      </svg>
      Continue with Microsoft
    </a>
  )

  return (
    <AuthShell aside={<SignInAside />}>
      {/* ── Step 1: email and password ── */}
      {!mfaRequired && (
        <>
          <AuthHeading title="Sign in" subtitle="Welcome back. Sign in to see your results and fixes." />

          {error && <AuthAlert>{error}</AuthAlert>}

          {verificationRequired && (
            <AuthAlert tone="warning">
              <p className="font-semibold">Confirm your email first</p>
              <p className="mt-1">Open the link we sent to {email.trim() || 'your inbox'}, then sign in.</p>
              {resendDone ? (
                <p className="mt-2 font-semibold">We've sent it again.</p>
              ) : (
                <button type="button" onClick={handleResendVerification} disabled={resendLoading}
                  className="mt-2 font-semibold underline underline-offset-2 disabled:opacity-50">
                  {resendLoading ? 'Sending…' : 'Send the link again'}
                </button>
              )}
            </AuthAlert>
          )}

          {microsoftButton}
          <div className="flex items-center gap-3 my-6" aria-hidden="true">
            <div className="flex-1 h-px bg-rule" />
            <span className="text-[13px] text-graphite">or with email</span>
            <div className="flex-1 h-px bg-rule" />
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <Field id="login-email" label="Email">
              <input id="login-email" type="email" className="input h-12" placeholder="you@example.com"
                value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email" autoFocus />
            </Field>
            <Field id="login-password" label="Password"
              hint={<Link to="/forgot-password" className="text-[13px] font-semibold text-brand-700 hover:underline">Forgot password?</Link>}>
              <input id="login-password" type="password" className="input h-12" placeholder="••••••••"
                value={password} onChange={e => setPassword(e.target.value)} required autoComplete="current-password" />
            </Field>
            <button type="submit" disabled={loading} className="btn-primary btn-lg w-full !mt-8">
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
          <p className="mt-10 pt-6 border-t border-rule text-[15px] text-graphite">
            New to CyberMeters? <Link to="/signup" className="font-semibold text-brand-700 hover:underline">Create an account</Link>
          </p>
        </>
      )}

      {/* ── Step 2: authenticator code ── */}
      {mfaRequired && !showRecovery && (
        <>
          <AuthHeading title="Two-factor authentication" subtitle="Enter the 6-digit code from your authenticator app." />
          {error && <AuthAlert>{error}</AuthAlert>}
          <form onSubmit={handleMfaSubmit} className="space-y-5">
            <Field id="login-mfa" label="Verification code">
              <input id="login-mfa" type="text" inputMode="numeric" pattern="\d{6}" maxLength={6}
                className="input h-14 text-center text-[24px] font-mono tracking-[0.4em]" placeholder="000000"
                value={mfaCode} onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                required autoFocus autoComplete="one-time-code" />
            </Field>
            <button type="submit" disabled={loading || mfaCode.length !== 6} className="btn-primary btn-lg w-full">
              {loading ? 'Verifying…' : 'Verify'}
            </button>
          </form>
          <div className="mt-6 pt-6 border-t border-rule flex items-center justify-between text-[14px]">
            <button type="button" onClick={resetToPassword} className="text-graphite hover:text-ink">Back to sign in</button>
            <button type="button" onClick={() => { setShowRecovery(true); setError(null) }} className="font-semibold text-brand-700 hover:underline">
              Use a recovery code
            </button>
          </div>
        </>
      )}

      {/* ── Step 2b: recovery code ── */}
      {mfaRequired && showRecovery && (
        <>
          <AuthHeading title="Recovery code" subtitle="Enter one of the backup codes you saved when you set up two-factor authentication." />
          {error && <AuthAlert>{error}</AuthAlert>}
          <form onSubmit={handleRecoverySubmit} className="space-y-5">
            <Field id="login-recovery" label="Recovery code">
              <input id="login-recovery" type="text" className="input h-12 font-mono text-center tracking-widest" placeholder="XXXX-XXXX-XXXX"
                value={recoveryCode} onChange={e => setRecoveryCode(e.target.value.toUpperCase())}
                required autoFocus autoComplete="off" spellCheck={false} />
            </Field>
            <button type="submit" disabled={loading || !recoveryCode.trim()} className="btn-primary btn-lg w-full">
              {loading ? 'Verifying…' : 'Verify recovery code'}
            </button>
          </form>
          <div className="mt-6 pt-6 border-t border-rule text-[14px]">
            <button type="button" onClick={() => { setShowRecovery(false); setError(null) }} className="text-graphite hover:text-ink">
              Back to authenticator code
            </button>
          </div>
        </>
      )}
    </AuthShell>
  )
}
