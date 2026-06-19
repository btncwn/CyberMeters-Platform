import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Mail, Lock, User, AlertTriangle, UserPlus } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { api } from '../api'

export default function SignupPage() {
  const navigate = useNavigate()
  const { login } = useAuth()

  const [name,     setName]     = useState('')
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [error,    setError]    = useState(null)
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (loading) return
    setError(null)

    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      // Create account
      await api.authSignup(email.trim().toLowerCase(), password, name.trim())
      // Auto-login after signup
      const data = await api.authLogin(email.trim().toLowerCase(), password)
      login(data.token, data.user)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err.message || 'Signup failed')
    } finally {
      setLoading(false)
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

      {/* Card */}
      <div className="card w-full max-w-sm p-8">
        <h1 className="text-xl font-bold text-gray-900 mb-1">Create account</h1>
        <p className="text-sm text-gray-400 mb-6">Start monitoring your attack surface.</p>

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
                placeholder="At least 8 characters"
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
        </form>
      </div>

      <p className="mt-5 text-sm text-gray-400">
        Already have an account?{' '}
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
