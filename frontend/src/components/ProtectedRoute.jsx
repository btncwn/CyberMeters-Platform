import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { logoutWithToken } from '../api'
import { useAuth } from '../context/AuthContext'
import { TOKEN_KEY } from '../context/authKeys'
import { returnLocation } from '../lib/urlSecrets'

function SessionUnavailable() {
  const { isRetryingSession, retrySession, logout } = useAuth()
  const navigate = useNavigate()

  function handleLogout() {
    const currentToken = localStorage.getItem(TOKEN_KEY)
    logout()
    if (currentToken) logoutWithToken(currentToken)
    navigate('/login', { replace: true })
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-6">
      <div role="alert" className="max-w-md text-center">
        <h1 className="text-lg font-semibold text-gray-900">We can't confirm your session right now</h1>
        <p className="mt-2 text-sm text-gray-600">
          You have not been signed out. Your account stays closed until we can reach
          CyberMeters. Check your connection and try again.
        </p>
        <div className="mt-5 flex items-center justify-center gap-3">
          <button type="button" onClick={retrySession} disabled={isRetryingSession} className="btn-primary">
            {isRetryingSession ? 'Trying again…' : 'Try again'}
          </button>
          <button type="button" onClick={handleLogout} className="btn-secondary">Sign out</button>
        </div>
      </div>
    </div>
  )
}

/**
 * ProtectedRoute — the app's auth guard. While the session is being validated
 * it holds the screen on a spinner (no premature redirect); once resolved it
 * either renders the protected children or bounces to /login, remembering the
 * original location so login can return the user where they were headed. A
 * session nobody could check renders neither: it holds on a try-again message.
 */
export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading, sessionUnavailable } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-brand-700 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (sessionUnavailable) return <SessionUnavailable />

  if (!isAuthenticated) {
    // The return location is held in router state; a secret the page received
    // (an MCP consent intent) goes with it, never into a URL.
    return <Navigate to="/login" state={{ from: returnLocation(location) }} replace />
  }

  return children
}
