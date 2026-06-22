import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../api'

const WS_ID_KEY   = 'cybermeters_workspace_id'
const WS_NAME_KEY = 'cybermeters_workspace_name'

/**
 * useWorkspace — server-authoritative workspace selection with localStorage cache.
 *
 * On mount (when an auth token exists):
 *   1. Fetches GET /api/workspaces to get the real list.
 *   2. If the list is empty, calls POST /api/account/bootstrap to auto-create
 *      a default workspace — new users are never stranded.
 *   3. Validates the localStorage workspace ID against the returned list.
 *      If stale (deleted, or user lost access), falls back to server default_workspace_id.
 *   4. Writes the validated ID back to localStorage so components that still
 *      read localStorage directly continue to work correctly.
 *
 * localStorage is a cache hint, not the source of truth.
 *
 * Exposes:
 *   wsId         — active workspace ID (null while loading or unauthenticated)
 *   wsName       — active workspace name
 *   workspaces   — full list of accessible workspaces
 *   loading      — true while the initial server fetch is in progress
 *   setWorkspace — (id, name) → switch active workspace
 */
export function useWorkspace() {
  const [wsId,       setWsId]       = useState(() => localStorage.getItem(WS_ID_KEY))
  const [wsName,     setWsName]     = useState(() => localStorage.getItem(WS_NAME_KEY))
  const [workspaces, setWorkspaces] = useState([])
  const [loading,    setLoading]    = useState(true)
  const didFetch = useRef(false)

  const setWorkspace = useCallback((id, name) => {
    if (id) {
      localStorage.setItem(WS_ID_KEY,   id)
      localStorage.setItem(WS_NAME_KEY, name || '')
    } else {
      localStorage.removeItem(WS_ID_KEY)
      localStorage.removeItem(WS_NAME_KEY)
    }
    setWsId(id)
    setWsName(name || '')
  }, [])

  // Server-side validation + bootstrap on mount.
  // Skip if no token exists (unauthenticated) to avoid spurious 401s.
  useEffect(() => {
    const token = localStorage.getItem('cybermeters_auth_token')
    if (!token) {
      setLoading(false)
      return
    }
    if (didFetch.current) return
    didFetch.current = true

    let cancelled = false

    async function validateAndBootstrap() {
      try {
        let data = await api.getWorkspaces()
        let list = data.workspaces ?? []

        // Auto-create a default workspace for users who have none.
        if (list.length === 0) {
          try {
            const bs = await api.bootstrapWorkspace()
            if (bs?.workspace?.id) {
              list = [{ ...bs.workspace, role: 'owner' }]
              data = { workspaces: list, default_workspace_id: bs.workspace.id }
            }
          } catch {
            // Bootstrap failed — non-fatal, user can create workspace manually.
          }
        }

        if (cancelled) return
        setWorkspaces(list)

        if (list.length === 0) {
          setWorkspace(null, null)
          return
        }

        // Validate cached ID against server list.
        const cachedId    = localStorage.getItem(WS_ID_KEY)
        const validCached = cachedId ? list.find(w => w.id === cachedId) : null

        if (validCached) {
          // Still valid — sync name in case it changed server-side.
          setWsName(validCached.name)
          if (validCached.name !== localStorage.getItem(WS_NAME_KEY)) {
            localStorage.setItem(WS_NAME_KEY, validCached.name)
          }
        } else {
          // Stale or absent — fall back to server default.
          const fallback =
            list.find(w => w.id === data.default_workspace_id) ??
            list.find(w => w.role === 'owner') ??
            list[0]
          if (fallback) setWorkspace(fallback.id, fallback.name)
        }
      } catch {
        // Network error — leave existing localStorage values intact.
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    validateAndBootstrap()
    return () => { cancelled = true }
  }, [setWorkspace])

  // Sync when another tab or component switches workspace via localStorage.
  useEffect(() => {
    function sync() {
      setWsId(localStorage.getItem(WS_ID_KEY)    ?? null)
      setWsName(localStorage.getItem(WS_NAME_KEY) ?? '')
    }
    window.addEventListener('storage', sync)
    const id = setInterval(sync, 1500)
    return () => { window.removeEventListener('storage', sync); clearInterval(id) }
  }, [])

  return { wsId, wsName, workspaces, loading, setWorkspace }
}
