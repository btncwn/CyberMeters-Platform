import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Mail, Lock, User, AlertTriangle, UserPlus, CheckCircle, Globe } from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
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

  if (sent) return <span className="text-green-600 font-medium">Email resent!</span>
  return (
    <button
      type="button"
      onClick={handleResend}
      disabled={loading}
      className="text-brand-600 font-medium hover:underline disabled:opacity-50"
    >
      {loading ? 'Sending…' : 'Resend verification email'}
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

  return (
    <div className="min-h-screen auth-bg flex flex-col items-center justify-center px-4">

      {/* Brand */}
      <CyberMetersLogo size={48} showWordmark animated className="mb-8" />

      {/* ── Success: email sent ── */}
      {done ? (
        <div className="card auth-card text-center">
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 rounded-full bg-green-50 flex items-center justify-center">
              <CheckCircle className="w-6 h-6 text-green-500" />
            </div>
          </div>
          <h1 className="text-xl font-bold text-gray-900 mb-2">Check your email</h1>
          <p className="text-sm text-gray-500 mb-6">
            We sent a verification link to{' '}
            <span className="font-semibold text-gray-700">{email}</span>.
            Click it to activate your account.
          </p>
          <p className="text-xs text-gray-400">
            Didn't receive it?{' '}
            <ResendLink email={email} />
          </p>
          <div className="mt-6">
            <Link to="/login" className="text-sm text-brand-600 font-semibold hover:underline">
              Back to sign in
            </Link>
          </div>
        </div>
      ) : (

      /* ── Signup form ── */
      <div className="card auth-card shadow-card-lg !rounded-[20px]">
        <h1 className="text-xl font-bold text-gray-900 mb-1">Create account</h1>
        <p className="text-sm text-gray-400 mb-6">See your business's external security risks in minutes.</p>

        {pendingDomain && (
          <div className="flex items-center gap-2 px-3 py-2 mb-5 bg-brand-50 border border-brand-100 rounded-xl text-xs text-brand-800">
            <Globe className="w-3.5 h-3.5 flex-shrink-0 text-brand-600" />
            <span>We'll set up <span className="font-semibold">{pendingDomain}</span> right after you sign up.</span>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Name</label>
            <div className="relative">
              <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
              <input
                type="text"
                className="input pl-10"
                placeholder="Jane Smith"
                value={name}
                onChange={e => setName(e.target.value)}
                autoComplete="name"
                autoFocus
              />
            </div>
          </div>

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
                placeholder="At least 12 characters"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                autoComplete="new-password"
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
                placeholder="••••••••"
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
              ? <span className="opacity-70">Creating account…</span>
              : <><UserPlus className="w-4 h-4" /> Create account</>
            }
          </button>

          <p className="text-[11px] text-gray-400 text-center leading-relaxed mt-3">
            By creating an account you agree to our{' '}
            <Link to="/terms"   className="text-brand-600 hover:underline">Terms of Service</Link>
            {' '}and{' '}
            <Link to="/privacy" className="text-brand-600 hover:underline">Privacy Policy</Link>.
          </p>
        </form>
      </div>

      )}

      {!done && (
        <p className="mt-5 text-sm text-gray-400">
          Already have an account?{' '}
          <Link to="/login" className="text-brand-600 font-semibold hover:underline">
            Sign in
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
          © {new Date().getFullYear()} CyberMeters — External Security Monitoring
        </p>
      </div>
    </div>
  )
}
