/**
 * MicrosoftCallbackPage
 *
 * Landing page for the Microsoft Entra OAuth callback.
 *
 * Security model — two-step handoff (no tokens in URLs):
 *   1. The backend GET /api/auth/microsoft/callback creates a session, then
 *      redirects here with only a short-lived one-time code (OTC) in the URL:
 *        /auth/microsoft/callback?otc=<32-hex-char code>
 *   2. This page reads the OTC, immediately POSTs it to POST /api/auth/exchange,
 *      which validates the OTC (single-use, 30-second TTL), deletes it, and
 *      returns the session bearer token + user metadata in the JSON response body.
 *   3. The bearer token is passed to login() and stored in localStorage.
 *      It never appears in any URL, browser history entry, or log file.
 *
 * Query params received:
 *   otc      — one-time code (short-lived, server-side validated)
 *   ms_error — error message from Microsoft or the backend (no otc present)
 */
import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { useAuth } from '../context/AuthContext'
import { api } from '../api'

export default function MicrosoftCallbackPage() {
  const [searchParams]  = useSearchParams()
  const { login }       = useAuth()
  const navigate        = useNavigate()
  const [error, setError] = useState(null)

  useEffect(() => {
    const otc     = searchParams.get('otc')
    const msError = searchParams.get('ms_error')

    if (msError) {
      setError(msError)
      return
    }

    if (!otc) {
      setError('Sign-in did not complete. Please try again.')
      return
    }

    // Exchange the one-time code for the session token.
    // The token is returned in the response body — it never appears in any URL.
    api.exchangeOAuthCode(otc)
      .then(async data => {
        if (!data.token || !data.id || !data.email) {
          setError('Sign-in did not complete. Please try again.')
          return
        }
        login(data.token, {
          id:    data.id,
          email: data.email,
          name:  data.name || data.email.split('@')[0],
          plan:  data.plan || 'free',
        })
        // New users (no workspaces yet) go to onboarding; existing users to dashboard.
        try {
          const wsData = await api.getWorkspaces()
          if ((wsData?.workspaces?.length ?? 0) === 0) {
            navigate('/onboarding', { replace: true })
            return
          }
        } catch {
          // Workspace check failed — fall through to dashboard.
        }
        navigate('/dashboard', { replace: true })
      })
      .catch(() => {
        setError('Sign-in session expired. Please try again.')
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
      <CyberMetersLogo size={40} showWordmark className="mb-8" />

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
