import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import AuthShell, { AuthAlert, AuthHeading, Field, NextStepsAside } from '../components/AuthShell'
import { api } from '../api'
import { persistSignupDomainParam, sanitizeDomainParam } from '../utils/signupDomainHandoff'

function ResendLink({ email }) {
  const [sent,    setSent]    = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleResend() {
    if (loading || sent) return
    setLoading(true)
    try {
      await api.resendVerification(email)
      setSent(true)
    } catch {
      // Silent — resend always succeeds server-side
      setSent(true)
    } finally {
      setLoading(false)
    }
  }

  if (sent) return <span className="text-result-pass font-semibold">we've sent it again.</span>
  return (
    <button
      type="button"
      onClick={handleResend}
      disabled={loading}
      className="text-brand-700 font-semibold underline underline-offset-2 disabled:opacity-50"
    >
      {loading ? 'sending…' : 'send it again'}
    </button>
  )
}

export default function SignupPage() {
  const [name,     setName]     = useState('')
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [error,    setError]    = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [done,     setDone]     = useState(false)

  // Carry the Cyber MOT domain through signup → verify → onboarding.
  const [searchParams] = useSearchParams()
  const pendingDomain = sanitizeDomainParam(searchParams.get('domain'))
  useEffect(() => {
    try { persistSignupDomainParam(searchParams.get('domain')) } catch { /* storage unavailable — ignore */ }
  }, [searchParams])

  async function handleSubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)

    if (password.length < 12) {
      setError('Password must be at least 12 characters.')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      await api.authSignup(email.trim().toLowerCase(), password, name.trim())
      setDone(true)
    } catch (err) {
      setError(err.message || 'Signup failed')
    } finally {
      setLoading(false)
    }
  }

  const passwordLongEnough = password.length >= 12

  if (done) {
    return (
      <AuthShell aside={<NextStepsAside />}>
        <AuthHeading
          title="Check your email"
          subtitle={<>We sent a confirmation link to <span className="font-semibold text-ink">{email}</span>. Open it to activate your account, then sign in.</>}
        />
        <p className="text-[14px] text-graphite">
          Nothing arrived after a few minutes? Check spam, or <ResendLink email={email} />
        </p>
        <Link to="/login" className="btn-secondary btn-lg w-full mt-8">Back to sign in</Link>
      </AuthShell>
    )
  }

  return (
    <AuthShell aside={<NextStepsAside />}>
      <AuthHeading
        title="Create your account"
        subtitle={pendingDomain
          ? <>We'll set up <span className="font-semibold text-ink">{pendingDomain}</span> straight after you sign up.</>
          : 'Free to start. No card needed.'}
      />

      {error && <AuthAlert>{error}</AuthAlert>}

      <form onSubmit={handleSubmit} className="space-y-5" noValidate={false}>
        <Field id="signup-name" label="Your name">
          <input id="signup-name" type="text" className="input h-12" placeholder="Jane Smith"
            value={name} onChange={e => setName(e.target.value)} autoComplete="name" autoFocus />
        </Field>
        <Field id="signup-email" label="Work email">
          <input id="signup-email" type="email" className="input h-12" placeholder="you@example.com"
            value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email" />
        </Field>
        <Field
          id="signup-password"
          label="Password"
          hint={<span className={`text-[13px] ${passwordLongEnough ? 'text-result-pass font-semibold' : 'text-graphite'}`} aria-live="polite">
            {passwordLongEnough ? '12+ characters' : `${password.length}/12 characters`}
          </span>}
        >
          <input id="signup-password" type="password" className="input h-12" placeholder="At least 12 characters"
            value={password} onChange={e => setPassword(e.target.value)} required autoComplete="new-password" />
        </Field>
        <Field id="signup-confirm" label="Confirm password">
          <input id="signup-confirm" type="password" className="input h-12" placeholder="••••••••"
            value={confirm} onChange={e => setConfirm(e.target.value)} required autoComplete="new-password" />
        </Field>

        <button type="submit" disabled={loading} className="btn-primary btn-lg w-full !mt-8">
          {loading ? 'Creating account…' : 'Create account'}
        </button>

        <p className="text-[13px] text-graphite leading-relaxed">
          By creating an account you agree to our{' '}
          <Link to="/terms" className="text-brand-700 underline underline-offset-2">Terms of Service</Link>
          {' '}and{' '}
          <Link to="/privacy" className="text-brand-700 underline underline-offset-2">Privacy Policy</Link>.
        </p>
      </form>
      <p className="mt-10 pt-6 border-t border-rule text-[15px] text-graphite">
        Already have an account? <Link to="/login" className="font-semibold text-brand-700 hover:underline">Sign in</Link>
      </p>
    </AuthShell>
  )
}
