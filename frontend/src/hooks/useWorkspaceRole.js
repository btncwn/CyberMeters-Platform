import { useEffect, useState } from 'react'
import { api } from '../api'
import { activeWorkspaceRole, scanAccessFor } from '../lib/workspaceRole'

/**
 * The caller's role on the active workspace, from the workspace list the
 * frontend already receives, and — only for a member who cannot start scans at
 * all, or who was just refused by the API — the owner's display name for the
 * "ask the owner" sentence. scanAccess is 'full', 'rescan' or 'none'.
 */
export function useWorkspaceRole(wsId, { refused = false } = {}) {
  const [state, setState] = useState({ wsId: null, role: null })
  const [ownerName, setOwnerName] = useState(null)

  useEffect(() => {
    if (!wsId) return undefined
    let alive = true
    Promise.resolve().then(() => api.getWorkspaces())
      .then((d) => { if (alive) setState({ wsId, role: activeWorkspaceRole(d?.workspaces, wsId) }) })
      .catch(() => { if (alive) setState({ wsId, role: null }) })
    return () => { alive = false }
  }, [wsId])

  const role = state.wsId === wsId ? state.role : null
  const scanAccess = scanAccessFor(role)
  const needsOwner = scanAccess === 'none' || refused

  useEffect(() => {
    setOwnerName(null)
    if (!wsId || !needsOwner) return undefined
    let alive = true
    Promise.resolve().then(() => api.getWorkspaceMembers(wsId))
      .then((d) => {
        const owner = (d?.members || []).find((m) => m?.role === 'owner')
        if (alive) setOwnerName(owner?.name || null)
      })
      .catch(() => { if (alive) setOwnerName(null) })
    return () => { alive = false }
  }, [wsId, needsOwner])

  return {
    role,
    scanAccess,
    canScanNewDomain: scanAccess === 'full',
    canRescan: scanAccess !== 'none',
    ownerName,
    roleKnown: state.wsId === wsId,
  }
}
