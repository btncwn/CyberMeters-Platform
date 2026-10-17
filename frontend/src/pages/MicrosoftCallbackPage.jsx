/**
 * MicrosoftCallbackPage
 *
 * Landing page for the Microsoft Entra OAuth callback.
 *
 * Security model — two-step handoff (no tokens in URLs), bound to this browser:
 *   1. The backend GET /api/auth/microsoft/callback redirects here with only a
 *      short-lived one-time code (OTC) in the URL:
 *        /auth/microsoft/callback?otc=<64-hex-char code>
 *   2. This page POSTs the OTC with the verifiers this browser stored when it
 *      started the sign-in. The API releases the result only to the matching
 *      verifier, so a callback link opened in another browser cannot sign it in.
 *   3. The bearer token is passed to login() and stored in localStorage.
 *      It never appears in any URL, browser history entry, or log file.
 *   A failed exchange never touches an existing session in this browser.
 *
 * Query params received:
 *   otc      — one-time code (short-lived, server-side validated)
 *   ms_error — present when sign-in failed (its text is not displayed)
 */
import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { useAuth } from '../context/AuthContext'
import { api } from '../api'
import { forgetMicrosoftLoginVerifier, microsoftLoginVerifiers } from '../lib/microsoftLoginBinding'
import { takeMicrosoftMcpContinuation } from '../lib/mcpLoginContinuation'

export default function MicrosoftCallbackPage() {
  const [searchParams]  = useSearchParams()
  const { login }       = useAuth()
  const navigate        = useNavigate()
  const [error, setError] = useState(null)

  useEffect(() => {
    const otc     = searchParams.get('otc')
    const msError = searchParams.get('ms_error')

    // The URL's wording is never echoed: a link could carry any text.
    if (msError) {
      setError('Microsoft sign-in did not complete. Please try again.')
      return
    }

    if (!otc) {
      setError('Sign-in did not complete. Please try again.')
      return
    }

    // Exchange the one-time code for the session token.
    // The token is returned in the response body — it never appears in any URL.
    const verifiers = microsoftLoginVerifiers()
    if (verifiers.length === 0) {
      setError('This sign-in was started in another browser or has expired. Please sign in again here.')
      return
    }

    api.exchangeOAuthCode(otc, verifiers)
      .then(async data => {
        await forgetMicrosoftLoginVerifier(data?.binding).catch(() => {})
        const mcpDestination = takeMicrosoftMcpContinuation(data?.binding)
        // MFA-enabled account: the backend issued a second-factor challenge instead
        // of a session. Hand the challenge to the login page, which renders the
        // existing MFA step (authenticator code + recovery code) to complete it.
        if (data.mfa_required && data.challenge_token) {
          navigate('/login', { replace: true, state: {
            mfaChallengeToken: data.challenge_token,
            ...(mcpDestination ? { from: {
              pathname: '/mcp/connect', search: mcpDestination.slice('/mcp/connect'.length),
            } } : {}),
          } })
          return
        }
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
        // New users (no workspaces yet) go to onboarding; existing users land on
        // the Services launcher (the standard post-login entry experience).
        try {
          const wsData = await api.getWorkspaces()
          if ((wsData?.workspaces?.length ?? 0) === 0) {
            navigate('/onboarding', { replace: true })
            return
          }
        } catch {
          // Workspace check failed — fall through to the services launcher.
        }
        navigate(mcpDestination || '/services', { replace: true })
      })
      .catch(() => {
        setError('Sign-in could not be completed in this browser. Please sign in again.')
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
      <CyberMetersLogo size={48} showWordmark animated className="mb-8" />

      <div className="card auth-card text-center">
        {error ? (
          <>
            <div className="flex items-center gap-2.5 px-4 py-3 mb-5 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700 text-left">
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
