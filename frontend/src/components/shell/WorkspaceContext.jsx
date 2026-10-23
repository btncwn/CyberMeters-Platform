// Workspace context (founder decision, 23 Oct 2026): which workspace and which
// domain the screen is about, stated — never inferred.
//   • useWorkspaceDomains(wsId): the active workspace's domain names, keyed by
//     workspace id, so a switch never shows the previous workspace's list.
//   • useScopedDomain(domain): a page about ONE domain (a case, a scan, a
//     domain's history or verification) reports it; the bar shows it.
//   • ContextBar: the thin row under the main nav —
//       "She.Shire › sheshire.co.uk ▾"   on a page about one domain
//       "She.Shire › All domains (2) ▾"  on a workspace-wide page
//       "Portfolio › 12 workspaces ▾"    on the portfolio pages
//     ▾ is a keyboard-accessible menu: open another domain (its history page),
//     or, in Portfolio, switch workspace. A single-domain workspace shows its
//     domain with no menu.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { api } from '../../api'
import { WORKSPACE_DOMAINS_EVENT, setActiveWorkspace } from '../../lib/activeWorkspace'

const ScopedDomainContext = createContext(null)

export function ScopedDomainProvider({ children }) {
  const [scoped, setScoped] = useState(null)
  const value = useMemo(() => ({ scoped, setScoped }), [scoped])
  return <ScopedDomainContext.Provider value={value}>{children}</ScopedDomainContext.Provider>
}

/**
 * A page about one domain names it, tagged with the workspace its record belongs
 * to when the page knows it (C-47 F02); cleared when the page goes or names none.
 * The bar shows it only while it belongs to the ACTIVE workspace. No-op outside the shell.
 */
export function useScopedDomain(domain, { workspaceId = null } = {}) {
  const ctx = useContext(ScopedDomainContext)
  const set = ctx?.setScoped
  const name = String(domain || '').trim().toLowerCase() || null
  useEffect(() => {
    if (!set) return undefined
    set(name ? { domain: name, workspaceId: workspaceId || null } : null)
    return () => set(null)
  }, [set, name, workspaceId])
}

export function useScopedDomainValue() {
  return useContext(ScopedDomainContext)?.scoped ?? null
}

const nameOf = (d) => String(d?.domain || d?.name || '').trim().toLowerCase()

/** { status: 'loading' | 'ok' | 'error', domains: string[] } for the active workspace only. */
export function useWorkspaceDomains(wsId) {
  const [state, setState] = useState({ wsId: null, status: 'loading', domains: [] })
  // A domain added, removed or verified in this workspace refetches the list (C-47 F04).
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    const bump = () => setRevision((n) => n + 1)
    window.addEventListener(WORKSPACE_DOMAINS_EVENT, bump)
    return () => window.removeEventListener(WORKSPACE_DOMAINS_EVENT, bump)
  }, [])
  useEffect(() => {
    let alive = true
    setState((prev) => (prev.wsId === wsId && revision > 0 ? prev : { wsId, status: 'loading', domains: [] }))
    if (!wsId) return undefined
    Promise.resolve()
      .then(() => api.getWorkspaceDomains(wsId))
      .then((data) => {
        if (!alive) return
        const rows = Array.isArray(data?.domains) ? data.domains : null
        setState({ wsId, status: rows ? 'ok' : 'error', domains: rows ? [...new Set(rows.map(nameOf).filter(Boolean))].sort() : [] })
      })
      .catch(() => { if (alive) setState({ wsId, status: 'error', domains: [] }) })
    return () => { alive = false }
  }, [wsId, revision])
  // A result for another workspace (the moment of a switch) is never shown.
  return state.wsId === wsId ? state : { wsId, status: 'loading', domains: [] }
}

export function domainCountLabel(n) {
  return `${n} domain${n === 1 ? '' : 's'}`
}

function useMenu() {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const buttonRef = useRef(null)
  const close = useCallback((refocus) => { setOpen(false); if (refocus) buttonRef.current?.focus() }, [])
  useEffect(() => {
    if (!open) return undefined
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) close(false) }
    const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); close(true) } }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey) }
  }, [open, close])
  return { open, setOpen, ref, buttonRef, close }
}

function MenuButton({ menu, label, id, children }) {
  return (
    <span className="cm-ctx-menu" ref={menu.ref}>
      <button ref={menu.buttonRef} type="button" className="cm-ctx-trigger" aria-haspopup="menu" aria-expanded={menu.open} aria-controls={id}
        onClick={() => menu.setOpen((v) => !v)} data-testid="context-trigger">
        {label} <span aria-hidden="true">▾</span>
      </button>
      {menu.open && (
        <div id={id} role="menu" aria-label={label} className="cm-popover cm-ctx-popover" data-testid="context-menu">
          {children}
        </div>
      )}
    </span>
  )
}

const ITEM = 'block px-4 py-2 text-[15px] text-gray-800 hover:bg-gray-50'

export default function ContextBar({ wsId, wsName, domainsState }) {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const scoped = useScopedDomainValue()
  const menu = useMenu()
  const portfolio = pathname === '/portfolio' || pathname.startsWith('/portfolio/')
  // null loading · 'error' a failed or malformed read (C-47 F05: never "No workspaces") · array.
  const [workspaces, setWorkspaces] = useState(null)
  useEffect(() => {
    if (!portfolio) return undefined
    let alive = true
    api.getWorkspaces()
      .then((d) => { if (alive) setWorkspaces(Array.isArray(d?.workspaces) ? d.workspaces : 'error') })
      .catch(() => { if (alive) setWorkspaces('error') })
    return () => { alive = false }
  }, [portfolio])
  useEffect(() => { menu.close(false) }, [pathname, wsId]) // eslint-disable-line react-hooks/exhaustive-deps

  if (portfolio) {
    const n = Array.isArray(workspaces) ? workspaces.length : null
    return (
      <nav aria-label="Workspace context" className="cm-ctxbar" data-testid="context-bar">
        <span className="cm-ctx-root">Portfolio</span><span aria-hidden="true" className="cm-ctx-sep">›</span>
        {workspaces === 'error' ? <span>Workspaces not available</span> : n == null ? <span>…</span> : n === 0 ? <span>No workspaces</span> : (
          <MenuButton menu={menu} id="cm-ctx-workspaces" label={`${n} workspace${n === 1 ? '' : 's'}`}>
            {workspaces.map((w) => (
              <button key={w.id} type="button" role="menuitem" className={`${ITEM} w-full text-left`}
                onClick={() => { setActiveWorkspace(w.id, w.name); menu.close(false); navigate('/dashboard') }}>{w.name}</button>
            ))}
          </MenuButton>
        )}
      </nav>
    )
  }

  if (!wsId) return null
  const { status, domains } = domainsState || { status: 'loading', domains: [] }
  const workspace = wsName || 'This workspace'
  // A page's domain is shown only while it belongs to the ACTIVE workspace (its
  // record's workspace when known, and the workspace's own domain list) — after a
  // switch it is never shown under the other workspace's name (C-47 F02).
  const scopedName = scoped && (!scoped.workspaceId || scoped.workspaceId === wsId) && status === 'ok' && domains.includes(scoped.domain)
    ? scoped.domain : null
  let scope
  if (scoped && status === 'loading') {
    scope = <span>…</span>
  } else if (scopedName) {
    const scoped = scopedName
    const others = domains.filter((d) => d !== scoped)
    scope = status === 'ok' && others.length > 0 ? (
      <MenuButton menu={menu} id="cm-ctx-domains" label={scoped}>
        <Link role="menuitem" to="/dashboard" className={ITEM} onClick={() => menu.close(false)}>All domains ({domains.length})</Link>
        {others.map((d) => <Link key={d} role="menuitem" to={`/domain/${encodeURIComponent(d)}/history`} className={ITEM} onClick={() => menu.close(false)}>{d}</Link>)}
      </MenuButton>
    ) : <span className="cm-ctx-current">{scoped}</span>
  } else if (status === 'loading') {
    scope = <span>…</span>
  } else if (status === 'error') {
    scope = <span>Domains not available</span>
  } else if (domains.length === 0) {
    scope = <span>No domains yet</span>
  } else if (domains.length === 1) {
    scope = <span className="cm-ctx-current">{domains[0]}</span>
  } else {
    scope = (
      <MenuButton menu={menu} id="cm-ctx-domains" label={`All domains (${domains.length})`}>
        {domains.map((d) => <Link key={d} role="menuitem" to={`/domain/${encodeURIComponent(d)}/history`} className={ITEM} onClick={() => menu.close(false)}>{d}</Link>)}
      </MenuButton>
    )
  }
  return (
    <nav aria-label="Workspace context" className="cm-ctxbar" data-testid="context-bar">
      <span className="cm-ctx-root">{workspace}</span><span aria-hidden="true" className="cm-ctx-sep">›</span>{scope}
    </nav>
  )
}
