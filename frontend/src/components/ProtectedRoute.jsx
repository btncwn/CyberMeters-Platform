import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { returnLocation } from '../lib/urlSecrets'

/**
 * ProtectedRoute — the app's auth guard. While the session is being validated
 * it holds the screen on a spinner (no premature redirect); once resolved it
 * either renders the protected children or bounces to /login, remembering the
 * original location so login can return the user where they were headed.
 */
export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-brand-700 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!isAuthenticated) {
    // The return location is held in router state; a secret the page received
    // (an MCP consent intent) goes with it, never into a URL.
    return <Navigate to="/login" state={{ from: returnLocation(location) }} replace />
  }

  return children
}
