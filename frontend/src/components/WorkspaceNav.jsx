import { useState, useEffect, useRef } from 'react'
import { NavLink, Link, useNavigate, useLocation } from 'react-router-dom'
import { Check, ChevronDown, ChevronRight } from 'lucide-react'
import { api } from '../api'
import { preloadComponent } from '../utils/preload'
import { routePreloadMap } from '../utils/preloadMap'
import { SERVICE_COLORS } from '../theme/serviceColors'
import { guideSlugForColourKey } from '../data/fieldGuide'

// ── Sea-glass palette — from the shared single source of truth ──────────────────
// The sidebar maps the shared per-domain colours onto the field names it uses
// (bg = active-item background = the shared `chip`; accent = `icon`). Inline
// styles keep the themes dynamic without touching tailwind.config (no purge risk).
const THEME = Object.fromEntries(
  Object.entries(SERVICE_COLORS).map(([key, c]) => [
    key,
    { icon: c.icon, text: c.text, bg: c.chip, accent: c.icon, tint: c.tint },
  ])
)

// ── Canonical Cyber MOT domains — the primary sections in the sidebar ─────────
// Founder order (14 Oct): strongest evidence first, down to the readiness area.
// The area name itself opens its overview, so no sub-item repeats that
// destination: every visible link in the sidebar goes somewhere different.
const SERVICES = [
  {
    key: 'email', domainKey: 'email_protection', title: 'Email Protection', to: '/ws/email-protection',
    match: p => p.startsWith('/ws/email-protection'),
    items: [
      { hash: '#dmarc-setup',       label: 'DMARC Setup' },
      { hash: '#sender-inventory',  label: 'Sender Inventory' },
      { hash: '#auth-detail',       label: 'Authentication Detail' },
    ],
  },
  {
    key: 'surface', domainKey: 'attack_surface', title: 'Attack Surface', to: '/assets',
    match: p => p.startsWith('/assets') || p.startsWith('/exposure') || p.startsWith('/ws/admin-surfaces')
      || p.startsWith('/ws/cloud-assets') || p.startsWith('/scans') || p.startsWith('/schedules'),
    items: [
      { to: '/exposure',          label: 'Timeline' },
      { to: '/scans',             label: 'Scans' },
      { to: '/schedules',         label: 'Schedules' },
      { to: '/ws/admin-surfaces', label: 'Admin Surfaces' },
      { to: '/ws/cloud-assets',   label: 'Cloud Assets' },
    ],
  },
  {
    key: 'website', domainKey: 'website_security', title: 'Website Security', to: '/ws/website-security',
    match: p => p.startsWith('/ws/website-security'),
    items: [],
  },
  {
    key: 'identity', domainKey: 'identity_exposure', title: 'Identity Exposure', to: '/ws/identity-exposure',
    match: p => p.startsWith('/ws/identity-exposure'),
    items: [],
  },
  {
    key: 'shadow_it', domainKey: 'shadow_it_unmanaged_technology', title: 'Shadow IT & Unmanaged Technology', to: '/ws/shadow-it',
    match: p => p.startsWith('/ws/shadow-it') || p.startsWith('/ws/saas-exposure') || p.startsWith('/ws/third-party'),
    items: [
      { to: '/ws/saas-exposure',   label: 'SaaS Exposure' },
      { to: '/ws/third-party',     label: 'Third-Party' },
    ],
  },
  {
    key: 'certs', domainKey: 'certificates_trust', title: 'Certificates & Trust', to: '/ws/certificates',
    match: p => p.startsWith('/ws/certificates'),
    items: [
      { to: '/ws/certificates/lifecycle', label: 'Managed Lifecycle' },
      { hash: '#cert-inventory', label: 'Inventory' },
      { hash: '#cert-expiry',    label: 'Expiry Risk' },
      { hash: '#cert-actions',   label: 'Recommended Actions' },
      { hash: '#cert-trust',     label: 'Trust Posture' },
    ],
  },
  {
    key: 'brand', domainKey: 'brand_protection', title: 'Brand Protection', to: '/ws/brand-monitoring',
    match: p => p.startsWith('/ws/brand-monitoring'),
    items: [
      { hash: '#typosquats',        label: 'Typosquat Candidates' },
      { hash: '#brand-summary',     label: 'Brand Findings' },
    ],
  },
  {
    key: 'cyber_essentials', domainKey: 'cyber_essentials_readiness', title: 'Cyber Essentials Readiness', to: '/ws/cyber-essentials',
    match: p => p.startsWith('/ws/cyber-essentials'),
    items: [],
  },
]

// Secondary workspace/admin links — tucked into the WORKSPACE section at the
// foot of the sidebar so they never dominate the coloured service suite.
// Founder decision (16 Oct 2026): switching, managing and clearing the
// workspace live here too (they left the top bar), under the active
// workspace's name, so one control appears in one place.
const WORKSPACE_TOOLS = [
  { to: '/ws/dashboard',           label: 'Administration' },
  { to: '/ws/scorecard',           label: 'Scorecard'    },
  { to: '/ws/executive-dashboard', label: 'Executive dashboard' },
  { to: '/ws/cases',               label: 'Operations' },
  { to: '/ws/related-changes',     label: 'Related Changes' },
  { to: '/ws/audit-log',           label: 'Audit Log'    },
  { to: '/ws/members',             label: 'Team Members' },
  { to: '/ws/alerts',              label: 'Alert Channels' },
  { to: '/ws/retention',           label: 'Usage & retention' },
  { to: '/settings',               label: 'Settings'     },
]

// Exported: Layout uses this to wash the routed content column in the active
// domain's `surface` colour — route→domain mapping stays defined ONCE, here.
export function detectServiceKey(pathname) {
  const s = SERVICES.find(svc => svc.match(pathname))
  return s ? s.key : null
}

export default function WorkspaceNav({ wsId: wsIdProp, wsName }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const activeKey = detectServiceKey(pathname)
  const [toolsOpen, setToolsOpen] = useState(false)
  const wsId = wsIdProp ?? localStorage.getItem('cybermeters_workspace_id')
  const [workspaces, setWorkspaces] = useState(null)   // null = not read yet
  const [wsLoading, setWsLoading] = useState(false)

  // The workspace list is read once, the first time the section opens.
  async function toggleTools() {
    const opening = !toolsOpen
    setToolsOpen(opening)
    if (opening && workspaces === null && !wsLoading) {
      setWsLoading(true)
      try {
        const data = await api.getWorkspaces()
        setWorkspaces(Array.isArray(data?.workspaces) ? data.workspaces : [])
      } catch { setWorkspaces([]) }
      finally { setWsLoading(false) }
    }
  }

  // Selecting writes the same keys the rest of the app reads and tells Layout
  // at once (it listens for `storage`), so the rail and pages follow immediately.
  function selectWorkspace(ws) {
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
    window.dispatchEvent(new Event('storage'))
    setToolsOpen(false)
    navigate('/ws/dashboard')
  }

  function clearWorkspace() {
    localStorage.removeItem('cybermeters_workspace_id')
    localStorage.removeItem('cybermeters_workspace_name')
    window.dispatchEvent(new Event('storage'))
    setToolsOpen(false)
    // The /ws/... pages belong to the workspace just cleared, so leave them.
    navigate('/workspaces')
  }
  const [hoverKey, setHoverKey] = useState(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const mobileToggle = useRef(null)
  useEffect(() => { setMobileOpen(false) }, [pathname])
  // Sub-items behave as a manual accordion: the active service opens by default,
  // but a click toggles it closed (and open again) without waiting for a route change.
  const [expandedKey, setExpandedKey] = useState(activeKey)
  useEffect(() => { setExpandedKey(activeKey) }, [activeKey])

  const handlePreload = (to) => {
    const loader = routePreloadMap[to]
    if (loader) preloadComponent(loader)
  }


  return (
    <aside className="w-full lg:w-[20%] lg:max-w-[280px] lg:min-w-[236px] shrink-0 bg-white border-b lg:border-b-0 lg:border-r border-gray-200 xl:sticky xl:top-[144px] xl:h-[calc(100vh-144px)] xl:overflow-y-auto flex flex-col" onKeyDown={event => { if (event.key === 'Escape' && mobileOpen) { setMobileOpen(false); mobileToggle.current?.focus() } }}>
      <button ref={mobileToggle} type="button" aria-label="Workspace navigation" aria-expanded={mobileOpen} aria-controls="workspace-service-navigation" onClick={() => setMobileOpen(value => !value)} className="lg:hidden flex items-center justify-between gap-3 px-4 py-3 text-sm font-semibold text-gray-800">
        <span className="min-w-0 truncate">{wsName || 'Workspace'} · Services</span>
        <ChevronDown className={`w-4 h-4 shrink-0 transition-transform ${mobileOpen ? 'rotate-180' : ''}`} />
      </button>
      <div id="workspace-service-navigation" className={`${mobileOpen ? 'flex' : 'hidden'} lg:flex flex-col flex-1`}>

      {/* ── Cyber MOT domains — the sidebar starts here ── */}
      <nav aria-label="Modules" className="flex-1 px-2.5 py-4 space-y-1.5">
        {SERVICES.map(svc => {
          const active = activeKey === svc.key
          const expanded = expandedKey === svc.key
          const hovered = hoverKey === svc.key
          const t = THEME[svc.key]
          return (
            <div key={svc.key}>
              {/* The row is two controls: the name opens the area; the chevron
                  only expands or collapses its sub-navigation. */}
              <div
                onMouseEnter={() => { setHoverKey(svc.key); handlePreload(svc.to) }}
                onMouseLeave={() => setHoverKey(null)}
                style={active
                  ? { backgroundColor: t.bg, borderLeftColor: t.accent }
                  : hovered ? { backgroundColor: t.tint, borderLeftColor: 'transparent' } : { borderLeftColor: 'transparent' }}
                className={`flex items-center gap-2 pl-3 pr-1.5 rounded-xl border-l-[3px] transition-colors ${
                  active ? 'font-semibold' : 'font-medium text-black'
                }`}
              >
                <Link
                  to={svc.to}
                  onFocus={() => handlePreload(svc.to)}
                  className="flex-1 min-w-0 py-2.5 text-[18px] leading-snug"
                  style={{ color: active ? t.text : '#000000' }}
                >
                  {svc.title}
                </Link>
                <button
                  type="button"
                  onClick={() => setExpandedKey(prev => prev === svc.key ? null : svc.key)}
                  aria-expanded={expanded}
                  aria-controls={`ws-nav-${svc.key}`}
                  aria-label={`${expanded ? 'Collapse' : 'Expand'} ${svc.title}`}
                  className="w-9 h-9 flex items-center justify-center rounded-lg hover:bg-black/5 shrink-0"
                >
                  {expanded
                    ? <ChevronDown className="w-4 h-4" style={{ color: t.accent }} />
                    : <ChevronRight className="w-4 h-4 text-gray-500" />}
                </button>
              </div>

              {/* The expanded service reveals its coloured sub-items */}
              {expanded && (
                <div
                  id={`ws-nav-${svc.key}`}
                  className="ml-3 mt-1 mb-1.5 pl-3.5 space-y-0.5 border-l-2"
                  style={{ borderColor: t.bg }}
                >
                  {[...svc.items, { to: `/ws/cases?domain_key=${svc.domainKey}`, label: 'Operations' }, { to: `/guide/${guideSlugForColourKey(svc.key)}`, label: 'Field Guide' }].map((item, i) => item.hash ? (
                    <a key={i} href={item.hash}
                      style={{ color: t.text }}
                      className="block px-2.5 py-1.5 rounded-lg text-[17px] font-medium opacity-80 hover:opacity-100 transition-opacity">
                      {item.label}
                    </a>
                  ) : (
                    <NavLink key={i} to={item.to} end={item.end}
                      onMouseEnter={() => handlePreload(item.to)}
                      onFocus={() => handlePreload(item.to)}
                      style={({ isActive }) => isActive ? { color: t.text, backgroundColor: t.bg } : { color: t.text }}
                      className={({ isActive }) =>
                        `block px-2.5 py-1.5 rounded-lg text-[17px] transition-all ${
                          isActive ? 'font-semibold' : 'font-medium opacity-80 hover:opacity-100'
                        }`
                      }>
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* ── WORKSPACE: active workspace, switch / manage / clear, admin links ── */}
      <section className="px-2.5 py-2.5 border-t border-gray-100" aria-label="Workspace" data-testid="workspace-section">
        <button
          type="button"
          onClick={toggleTools}
          aria-expanded={toolsOpen}
          aria-controls="workspace-section-body"
          className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-[15px] font-bold text-coral uppercase tracking-widest hover:bg-coral-50 transition-colors"
        >
          <span className="flex-1 text-left">Workspace</span>
          <ChevronDown className={`w-3.5 h-3.5 transition-transform ${toolsOpen ? 'rotate-180' : ''}`} />
        </button>
        <p className="px-2.5 pb-1 text-[17px] font-semibold text-gray-900 truncate" data-testid="active-workspace-name">
          {wsName || 'No workspace selected'}
        </p>
        {toolsOpen && (
          <div id="workspace-section-body" className="mt-1 space-y-0.5">
            <div className="px-2.5 pt-2 pb-1 text-xs font-semibold text-gray-400 uppercase tracking-wider">Switch workspace</div>
            {wsLoading && <div className="px-2.5 py-1.5 text-[16px] text-gray-400">Loading…</div>}
            {!wsLoading && Array.isArray(workspaces) && workspaces.length === 0 && (
              <div className="px-2.5 py-1.5 text-[16px] text-gray-400">No workspaces yet</div>
            )}
            {Array.isArray(workspaces) && workspaces.map(ws => (
              <button
                key={ws.id}
                type="button"
                onClick={() => selectWorkspace(ws)}
                aria-current={ws.id === wsId ? 'true' : undefined}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[16px] text-left transition-colors ${ws.id === wsId ? 'font-semibold text-gray-900 bg-gray-100' : 'text-gray-700 hover:bg-gray-50'}`}
              >
                <span className="flex-1 truncate">{ws.name}</span>
                {ws.id === wsId && <Check className="w-3.5 h-3.5 text-brand-600 shrink-0" aria-hidden="true" />}
              </button>
            ))}
            <NavLink
              to="/workspaces"
              end
              onMouseEnter={() => handlePreload('/workspaces')}
              className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[16px] font-semibold text-brand-700 hover:bg-brand-50 transition-colors"
            >
              Manage workspaces
            </NavLink>
            {wsId && (
              <button
                type="button"
                onClick={clearWorkspace}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[16px] text-gray-500 hover:bg-gray-50 transition-colors text-left"
              >
                Clear selection
              </button>
            )}
            <div className="border-t border-gray-100 my-1" />
            {WORKSPACE_TOOLS.map(({ to, label }) => (
              <NavLink
                key={to}
                to={to}
                end
                onMouseEnter={() => handlePreload(to)}
                onFocus={() => handlePreload(to)}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[18px] transition-colors ${
                    isActive ? 'text-amber-brand bg-gray-100 font-bold' : 'text-black hover:text-amber-brand hover:bg-gray-50 font-semibold'
                  }`
                }
              >
                {label}
              </NavLink>
            ))}
          </div>
        )}
      </section>
      </div>
    </aside>
  )
}
