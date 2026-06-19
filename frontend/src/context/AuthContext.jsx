/**
 * AuthContext — provides authentication state across the app.
 *
 * Token is stored in localStorage under 'cybermeters_auth_token'.
 * User metadata is stored under 'cybermeters_auth_user'.
 *
 * api.js reads the token from localStorage and attaches it to every request
 * as Authorization: Bearer <token>.
 */
import { createContext, useContext, useState, useCallback } from 'react'

const TOKEN_KEY = 'cybermeters_auth_token'
const USER_KEY  = 'cybermeters_auth_user'

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

  const login = useCallback((newToken, newUser) => {
    localStorage.setItem(TOKEN_KEY, newToken)
    localStorage.setItem(USER_KEY, JSON.stringify(newUser))
    setToken(newToken)
    setUser(newUser)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setToken(null)
    setUser(null)
  }, [])

  const updateUser = useCallback((patch) => {
    setUser(prev => {
      const next = { ...(prev || {}), ...(patch || {}) }
      localStorage.setItem(USER_KEY, JSON.stringify(next))
      return next
    })
  }, [])

  const isAuthenticated = Boolean(token)

  return (
    <AuthContext.Provider value={{ token, user, isAuthenticated, login, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}

export { TOKEN_KEY }
