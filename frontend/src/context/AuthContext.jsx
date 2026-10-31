/**
 * AuthContext — provides authentication state across the app.
 *
 * Token is stored in localStorage under 'cybermeters_auth_token'.
 * User metadata is stored under 'cybermeters_auth_user'.
 *
 * api.js reads the token from localStorage and attaches it to every request
 * as Authorization: Bearer <token>.
 */
import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { registerUnauthorizedHandler, validateSession } from '../api'
import { TOKEN_KEY, USER_KEY } from './authKeys'
import { clearAccountWorkspaceState } from '../lib/activeWorkspace'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY))
  const [user,  setUser]  = useState(() => {
    try {
      const raw = localStorage.getItem(USER_KEY)
      return raw ? JSON.parse(raw) : null
    } catch {
      return null
    }
  })

  // isLoading is true only when a token exists at startup and needs server-side
  // validation. If localStorage is empty we know immediately we're not authenticated.
  const [isLoading, setIsLoading] = useState(() => Boolean(localStorage.getItem(TOKEN_KEY)))

  // True when a stored session could not be checked (API unreachable or failing).
  // The session stays stored but counts as signed out until the server confirms it.
  const [sessionUnavailable, setSessionUnavailable] = useState(false)
  const [isRetryingSession, setIsRetryingSession] = useState(false)

  // Only the latest check may decide; signing in or out outdates any in flight.
  const latestCheck = useRef(0)

  const settleSessionCheck = useCallback(() => {
    latestCheck.current += 1
    setSessionUnavailable(false)
    setIsRetryingSession(false)
    setIsLoading(false)
  }, [])

  const login = useCallback((newToken, newUser) => {
    settleSessionCheck()
    // A different account (or one this browser cannot vouch for) never inherits
    // the previous account's active workspace.
    let previousId = null
    try { previousId = JSON.parse(localStorage.getItem(USER_KEY) || 'null')?.id ?? null } catch { previousId = null }
    if (!previousId || previousId !== newUser?.id) clearAccountWorkspaceState()
    localStorage.setItem(TOKEN_KEY, newToken)
    localStorage.setItem(USER_KEY, JSON.stringify(newUser))
    setToken(newToken)
    setUser(newUser)
  }, [settleSessionCheck])

  const logout = useCallback(() => {
    settleSessionCheck()
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    clearAccountWorkspaceState()
    setToken(null)
    setUser(null)
  }, [settleSessionCheck])

  // Register logout as the handler for 401 responses in api.js.
  // This keeps the React state in sync when the module-level request() helper
  // detects an expired/invalid session and clears localStorage directly.
  useEffect(() => {
    registerUnauthorizedHandler(logout)
  }, [logout])

  // Uses validateSession() which bypasses the auto-logout/hard-redirect handler
  // so ProtectedRoute can do a soft React Router redirect that preserves the
  // intended destination URL in location state.
  const checkSession = useCallback(() => {
    latestCheck.current += 1
    const check = latestCheck.current
    const storedToken = localStorage.getItem(TOKEN_KEY)
    return validateSession().then(userData => {
      if (check !== latestCheck.current) return
      if (!userData) {
        // Token is missing, expired, or invalid — clear all auth state.
        logout()
        return
      }
      // Token is valid — refresh user metadata from server.
      setToken(storedToken)
      setUser(userData)
      localStorage.setItem(USER_KEY, JSON.stringify(userData))
      setSessionUnavailable(false)
      setIsRetryingSession(false)
      setIsLoading(false)
    }, () => {
      if (check !== latestCheck.current) return
      // Nobody could say either way: keep the session, open nothing.
      setSessionUnavailable(true)
      setIsRetryingSession(false)
      setIsLoading(false)
    })
  }, [logout])

  // On mount, validate any stored token against the server.
  useEffect(() => {
    if (!localStorage.getItem(TOKEN_KEY)) {
      setIsLoading(false)
      return
    }
    checkSession()
  }, [checkSession])

  const retrySession = useCallback(() => {
    setIsRetryingSession(true)
    return checkSession()
  }, [checkSession])

  const updateUser = useCallback((patch) => {
    setUser(prev => {
      const next = { ...(prev || {}), ...(patch || {}) }
      localStorage.setItem(USER_KEY, JSON.stringify(next))
      return next
    })
  }, [])

  const isAuthenticated = Boolean(token) && !sessionUnavailable

  return (
    <AuthContext.Provider value={{
      token: sessionUnavailable ? null : token,
      user: sessionUnavailable ? null : user,
      isAuthenticated,
      isLoading,
      sessionUnavailable,
      isRetryingSession,
      retrySession,
      login,
      logout,
      updateUser,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}

// TOKEN_KEY and USER_KEY are exported from ./authKeys
