import { useState, useEffect } from 'react'

/**
 * useWorkspace — reads active workspace from localStorage.
 * Layout's WorkspaceSelector writes to the same keys.
 */
export function useWorkspace() {
  const [wsId, setWsId]     = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [wsName, setWsName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))

  // Sync when another tab or component switches workspace
  useEffect(() => {
    function sync() {
      setWsId(localStorage.getItem('cybermeters_workspace_id'))
      setWsName(localStorage.getItem('cybermeters_workspace_name'))
    }
    window.addEventListener('storage', sync)
    // Also poll for same-tab switches (localStorage events don't fire in same tab)
    const id = setInterval(sync, 1000)
    return () => { window.removeEventListener('storage', sync); clearInterval(id) }
  }, [])

  return { wsId, wsName }
}
