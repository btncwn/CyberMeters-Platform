/**
 * MicrosoftCallbackPage
 *
 * Landing page for the Microsoft Entra OAuth callback.
 * The backend GET /api/auth/microsoft/callback redirects here with session
 * params in the query string after successfully validating the id_token and
 * creating a session.
 *
 * Query params (set by backend):
 *   token  — raw session bearer token
 *   id     — user ID
 *   email  — user email
 *   name   — display name
 *   plan   — effective plan
 *   ms_error — error message if something went wrong (no token present)
 */
import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Shield, AlertTriangle } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function MicrosoftCallbackPage() {
  const [searchParams]  = useSearchParams()
  const { login }       = useAuth()
  const navigate        = useNavigate()
  const [error, setError] = useState(null)

  useEffect(() => {
    const token   = searchParams.get('token')
    const id      = searchParams.get('id')
    const email   = searchParams.get('email')
    const name    = searchParams.get('name')
    const plan    = searchParams.get('plan')
    const msError = searchParams.get('ms_error')

    if (msError) {
      setError(msError)
      return
    }

    if (!token || !id || !email) {
      setError('Sign-in did not complete. Please try again.')
      return
    }

    login(token, { id, email, name: name || email.split('@')[0], plan: plan || 'free' })
    navigate('/dashboard', { replace: true })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
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
        {error ? (
          <>
            <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600 text-left">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
            <button
              className="btn-primary w-full justify-center"
              onClick={() => navigate('/login', { replace: true })}
            >
              Back to sign in
            </button>
          </>
        ) : (
          <p className="text-sm text-gray-400">Signing you in…</p>
        )}
      </div>
    </div>
  )
}
