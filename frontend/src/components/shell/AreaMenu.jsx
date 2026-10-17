// AreaMenu — the brand button in the top bar and the sheet it opens (founder
// prototype v2, 17 Oct 2026). The eight areas are listed in founder order with
// a 36px icon in a 56px pastel circle, the area name and, under it, the state
// word the backend resolved for the active workspace — exactly as the
// vocabulary maps it, never derived here. Nothing about the areas shows until
// the brand is clicked.
//
// Keyboard: Enter/Space on the brand opens the sheet and focuses the first
// item; arrows move between items (wrapping); Home/End jump; Escape closes and
// returns focus to the brand. aria-haspopup="menu", aria-expanded and
// aria-controls on the button; role="menu" / "menuitem" on the sheet.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import CyberMetersLogo from '../CyberMetersLogo'
import { SERVICES } from '../WorkspaceNav'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import { moduleIcon } from './moduleIcons'
import { api } from '../../api'
import { domainStatus, statusMeta } from '../../lib/statusVocabulary'
import { preloadComponent } from '../../utils/preload'
import { routePreloadMap } from '../../utils/preloadMap'

export const AREA_SHEET_ID = 'cm-area-sheet'

// The eight-domain states for one workspace, fetched when the sheet first
// opens and refreshed when the workspace changes. `request` follows the
// vocabulary: loading | error | ok. With no workspace nothing is fetched and
// every area reads "Not assessed".
export function useAreaStates(wsId, open) {
  const [states, setStates] = useState({ wsId: null, entries: null, request: 'loading' })
  useEffect(() => {
    if (!open) return undefined
    if (!wsId) { setStates({ wsId: null, entries: [], request: 'ok' }); return undefined }
    if (states.wsId === wsId && states.request !== 'loading') return undefined
    let alive = true
    setStates({ wsId, entries: null, request: 'loading' })
    Promise.resolve()
      .then(() => api.getCyberMotDomains(wsId))
      .then((data) => {
        if (!alive) return
        const entries = Array.isArray(data?.cyber_mot_domains) ? data.cyber_mot_domains : null
        setStates({ wsId, entries: entries || [], request: entries ? 'ok' : 'error' })
      })
      .catch(() => { if (alive) setStates({ wsId, entries: [], request: 'error' }) })
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsId, open])
  return states
}

export function areaStateLabel(entry, request, wsId) {
  if (!wsId) return statusMeta('not_assessed').label
  if (request === 'loading') return statusMeta('loading').label
  if (request === 'error') return statusMeta('error').label
  return statusMeta(domainStatus(entry, 'ok')).label
}

export default function AreaMenu({ wsId }) {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const buttonRef = useRef(null)
  const sheetRef = useRef(null)
  const { entries, request } = useAreaStates(wsId, open)

  const close = useCallback(({ refocus } = {}) => {
    setOpen(false)
    if (refocus) buttonRef.current?.focus()
  }, [])

  useEffect(() => {
    if (!open) return undefined
    function onPointerDown(e) {
      if (sheetRef.current?.contains(e.target) || buttonRef.current?.contains(e.target)) return
      close()
    }
    function onKeyDown(e) { if (e.key === 'Escape') { e.preventDefault(); close({ refocus: true }) } }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open, close])

  useEffect(() => {
    if (open) sheetRef.current?.querySelector('[role="menuitem"]')?.focus()
  }, [open])

  function items() { return Array.from(sheetRef.current?.querySelectorAll('[role="menuitem"]') || []) }
  function onSheetKeyDown(e) {
    const list = items()
    if (!list.length) return
    const index = list.indexOf(document.activeElement)
    const move = (next) => { e.preventDefault(); list[(next + list.length) % list.length].focus() }
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') move(index + 1)
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') move(index - 1)
    else if (e.key === 'Home') move(0)
    else if (e.key === 'End') move(list.length - 1)
  }

  function go(svc) {
    close({ refocus: false })
    navigate(svc.to)
  }
  const preload = (svc) => { const loader = routePreloadMap[svc.to]; if (loader) preloadComponent(loader) }

  return (
    <div className="cm-brandwrap">
      <button
        ref={buttonRef}
        type="button"
        className="cm-brandbtn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={AREA_SHEET_ID}
        aria-label="CyberMeters — open areas"
        onClick={() => setOpen((v) => !v)}
        data-testid="brand-button"
      >
        <CyberMetersLogo size={34} animated />
        <span className="cm-brand-word">CyberMeters</span>
        <svg className="cm-brand-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
      </button>

      {open && (
        <div
          id={AREA_SHEET_ID}
          ref={sheetRef}
          role="menu"
          aria-label="Areas"
          className="cm-sheet"
          onKeyDown={onSheetKeyDown}
          data-testid="area-sheet"
        >
          <h4 className="cm-sheet-title">Your external posture</h4>
          <div className="cm-sheet-grid">
            {SERVICES.map((svc) => {
              const t = SERVICE_COLORS[svc.key]
              const Icon = moduleIcon(svc.key)
              const entry = (entries || []).find((d) => d?.domain_key === svc.domainKey) || null
              const label = areaStateLabel(entry, request, wsId)
              return (
                <button
                  key={svc.key}
                  type="button"
                  role="menuitem"
                  className="cm-mrow"
                  onClick={() => go(svc)}
                  onMouseEnter={() => preload(svc)}
                  onFocus={() => preload(svc)}
                  data-service-key={svc.key}
                >
                  <span className="cm-mrow-icon" style={{ backgroundColor: `${t.chip}66` }} aria-hidden="true">
                    <Icon style={{ width: 36, height: 36, color: t.icon }} strokeWidth={1.6} />
                  </span>
                  <span className="min-w-0">
                    <b className="cm-mrow-name">{svc.title}</b>
                    <span className="cm-mrow-state" data-testid={`area-state-${svc.domainKey}`}>{label}</span>
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
