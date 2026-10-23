// AreaShell — how an area page and the app shell share the area's tab strip
// (S1-SHELL-V2, founder-approved 22 Oct 2026). The shell's second top-bar row
// holds "<Area> ·" and the tabs; the area page owns the tab state (?tab=) and
// its open-case count. One tab strip per screen, never two:
//   • inside the app, ModuleContract portals its tablist into the row's slot
//     and the row shows nothing else;
//   • on an area's sub-page (no ModuleContract), the row shows the same tabs
//     as links to the area page;
//   • outside the shell (unit tests, isolated renders) there is no context and
//     ModuleContract keeps its tablist inline, as before.
import { createContext, useCallback, useContext, useMemo, useState } from 'react'

const AreaShellContext = createContext(null)

export function AreaShellProvider({ children }) {
  const [slot, setSlot] = useState(null)
  const [toolbarSlot, setToolbarSlot] = useState(null)
  const [claims, setClaims] = useState(0)
  const [openCases, setOpenCases] = useState({})
  const claim = useCallback(() => {
    setClaims((n) => n + 1)
    return () => setClaims((n) => Math.max(0, n - 1))
  }, [])
  const reportOpenCases = useCallback((domainKey, count) => {
    setOpenCases((prev) => (prev[domainKey] === count ? prev : { ...prev, [domainKey]: count }))
  }, [])
  const value = useMemo(() => ({ slot, setSlot, toolbarSlot, setToolbarSlot, claimed: claims > 0, claim, openCases, reportOpenCases }), [slot, toolbarSlot, claims, claim, openCases, reportOpenCases])
  return <AreaShellContext.Provider value={value}>{children}</AreaShellContext.Provider>
}

/** null outside the app shell. */
export function useAreaShell() {
  return useContext(AreaShellContext)
}
