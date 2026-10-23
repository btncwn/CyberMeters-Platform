// AreaSidebar — the always-visible left column of the app shell (S1-SHELL-V2,
// founder-approved design, 22 Oct 2026): the logo (a link to Overview, no
// longer a menu), "Your external posture", and the eight areas in canonical
// order (shared/areas.js). Each row: chevron · name · the area's status chip —
// the SAME word the area header shows (domainStatus → StatusChip), never
// derived here. Selecting an area navigates to it; only the selected area is
// expanded, with its sub-topics (names only) as links into its existing
// sections and sub-pages. Nothing else lives here: no workspace switcher, no
// account links, no icons.
//
// Below 1024px the same component renders inside a drawer (Layout).
import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import CyberMetersLogo from '../CyberMetersLogo'
import StatusChip from '../StatusChip'
import { SERVICES, detectServiceKey, subtopicsForDomainKey } from '../WorkspaceNav'
import { api } from '../../api'
import { domainStatus } from '../../lib/statusVocabulary'

// The eight-domain states for one workspace: loading | error | ok, refetched
// when the workspace changes. With no workspace nothing is fetched.
export function useAreaStates(wsId) {
  const [states, setStates] = useState({ wsId: null, entries: null, request: 'loading' })
  useEffect(() => {
    if (!wsId) { setStates({ wsId: null, entries: [], request: 'ok' }); return undefined }
    let alive = true
    setStates({ wsId, entries: null, request: 'loading' })
    Promise.resolve()
      .then(() => api.getSecurityCheckDomains(wsId))
      .then((data) => {
        if (!alive) return
        const entries = Array.isArray(data?.cyber_mot_domains) ? data.cyber_mot_domains : null
        setStates({ wsId, entries: entries || [], request: entries ? 'ok' : 'error' })
      })
      .catch(() => { if (alive) setStates({ wsId, entries: [], request: 'error' }) })
    return () => { alive = false }
  }, [wsId])
  return states
}

/** The status word for one area, exactly as the area header computes it. */
export function areaStatusKey(entry, request, wsId) {
  if (!wsId) return 'not_assessed'
  return domainStatus(entry, request === 'ok' && !entry ? 'error' : request)
}

function Chevron({ open }) {
  return (
    <svg className={`cm-side-chevron${open ? ' cm-side-chevron-open' : ''}`} width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export default function AreaSidebar({ wsId, stacked = false, onNavigate = null }) {
  const { pathname, search, hash } = useLocation()
  const navigate = useNavigate()
  const { entries, request } = useAreaStates(wsId)
  const current = detectServiceKey(pathname)
  // The selected area is the one the route is in; a click on another area's
  // row selects (and opens) it. Re-clicking the open area collapses it.
  const [open, setOpen] = useState(current)
  useEffect(() => { setOpen(current) }, [current])
  const here = `${pathname}${search}${hash}`

  function selectArea(svc) {
    if (svc.key === current && open === svc.key) { setOpen(null); return }
    setOpen(svc.key)
    if (svc.key !== current) navigate(svc.to)
    onNavigate?.()
  }

  return (
    <nav aria-label="Security areas" className="cm-side" data-testid="area-sidebar">
      <Link to="/dashboard" className="cm-side-logo" aria-label="CyberMeters — Overview" onClick={() => onNavigate?.()}>
        <CyberMetersLogo size={28} />
        <span className="cm-side-word">CyberMeters</span>
      </Link>
      <p className="cm-side-label">Your external posture</p>
      <ul className="cm-side-list">
        {SERVICES.map((svc) => {
          const entry = (entries || []).find((d) => d?.domain_key === svc.domainKey) || null
          const isOpen = open === svc.key
          const subs = isOpen ? subtopicsForDomainKey(svc.domainKey) : []
          return (
            <li key={svc.key}>
              <button
                type="button"
                className={`cm-side-item${svc.key === current ? ' cm-side-item-active' : ''}${stacked ? ' cm-side-item-stacked' : ''}`}
                aria-expanded={isOpen}
                aria-current={svc.key === current && pathname === svc.to ? 'page' : undefined}
                onClick={() => selectArea(svc)}
                data-service-key={svc.key}
              >
                <Chevron open={isOpen} />
                {/* Name and chip share one line when they fit; otherwise the chip wraps under the name (never over it). */}
                <span className="cm-side-text">
                  <span className="cm-side-name">{svc.title}</span>
                  <span className="cm-side-state" data-testid={`area-state-${svc.domainKey}`}>
                    <StatusChip status={areaStatusKey(entry, request, wsId)} />
                  </span>
                </span>
              </button>
              {subs.length > 0 && (
                <ul className="cm-side-subs" aria-label={`${svc.title} topics`}>
                  {subs.map((sub) => (
                    <li key={sub.label}>
                      <Link to={sub.to} className={`cm-side-sub${here === sub.to ? ' cm-side-sub-active' : ''}`} onClick={() => onNavigate?.()}>
                        {sub.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
