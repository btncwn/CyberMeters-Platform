// WorkspaceNav — the 72px module rail of the app shell: one icon per area in
// founder order (lib/moduleRegistry.js order, SERVICE_COLORS key), a dark
// tooltip on hover/focus, the active area on a light tinted ground, and the
// workspace button with its popover at the foot. Below the lg breakpoint the
// rail becomes a bottom bar. The wide sidebar it replaces is gone; each
// area's sub-pages are now the tiles on the area page (MODULE_SUBPAGES).
import { NavLink, useLocation } from 'react-router-dom'
import { preloadComponent } from '../utils/preload'
import { routePreloadMap } from '../utils/preloadMap'
import { SERVICE_COLORS } from '../theme/serviceColors'
import { moduleIcon } from './shell/moduleIcons'
import WorkspaceMenu from './shell/WorkspaceMenu'

// ── Canonical Cyber MOT domains — the areas on the rail ─────────────────────
// Founder order (14 Oct): strongest evidence first, down to the readiness area.
// `items` are the area's sub-pages (route or in-page anchor), shown as tiles on
// the area page; the area name itself opens its overview.
export const SERVICES = [
  {
    key: 'email', domainKey: 'email_protection', title: 'Email Protection', to: '/ws/email-protection',
    match: p => p.startsWith('/ws/email-protection'),
    items: [
      { hash: '#dmarc-setup',       label: 'DMARC Setup',          desc: 'Policy, alignment and the hosted record' },
      { hash: '#sender-inventory',  label: 'Sender Inventory',     desc: 'Every source seen sending as your domain' },
      { hash: '#auth-detail',       label: 'Authentication Detail', desc: 'SPF, DKIM and DMARC as observed' },
    ],
  },
  {
    key: 'surface', domainKey: 'attack_surface', title: 'Attack Surface', to: '/assets',
    match: p => p.startsWith('/assets') || p.startsWith('/exposure') || p.startsWith('/ws/admin-surfaces')
      || p.startsWith('/ws/cloud-assets') || p.startsWith('/scans') || p.startsWith('/schedules'),
    items: [
      { to: '/exposure',          label: 'Timeline',       desc: 'What appeared, changed or disappeared' },
      { to: '/scans',             label: 'Scans',          desc: 'Every assessment run and its result' },
      { to: '/schedules',         label: 'Schedules',      desc: 'When the next assessments run' },
      { to: '/ws/admin-surfaces', label: 'Admin Surfaces', desc: 'Login and admin pages reachable from outside' },
      { to: '/ws/cloud-assets',   label: 'Cloud Assets',   desc: 'Storage and cloud endpoints observed' },
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
      { to: '/ws/saas-exposure',   label: 'SaaS Exposure', desc: 'Portals and tenants observed for your domain' },
      { to: '/ws/third-party',     label: 'Third-Party',   desc: 'Suppliers and services seen in your pages' },
    ],
  },
  {
    key: 'certs', domainKey: 'certificates_trust', title: 'Certificates & Trust', to: '/ws/certificates',
    match: p => p.startsWith('/ws/certificates'),
    items: [
      { to: '/ws/certificates/lifecycle', label: 'Managed Lifecycle', desc: 'Renewals, replacements and follow-up' },
      { hash: '#cert-inventory', label: 'Inventory',           desc: 'Certificates observed on your hostnames' },
      { hash: '#cert-expiry',    label: 'Expiry Risk',         desc: 'What expires soon' },
      { hash: '#cert-actions',   label: 'Recommended Actions', desc: 'What to do, from the registry' },
      { hash: '#cert-trust',     label: 'Trust Posture',       desc: 'What the trust path shows' },
    ],
  },
  {
    key: 'brand', domainKey: 'brand_protection', title: 'Brand Protection', to: '/ws/brand-monitoring',
    match: p => p.startsWith('/ws/brand-monitoring'),
    items: [
      { hash: '#typosquats',        label: 'Typosquat Candidates', desc: 'Lookalike domains observed' },
      { hash: '#brand-summary',     label: 'Brand Findings',       desc: 'What the brand checks established' },
    ],
  },
  {
    key: 'cyber_essentials', domainKey: 'cyber_essentials_readiness', title: 'Cyber Essentials Readiness', to: '/ws/cyber-essentials',
    match: p => p.startsWith('/ws/cyber-essentials'),
    items: [],
  },
]

// Exported: Layout and the area pages use this to find the active area —
// route→domain mapping stays defined ONCE, here.
export function detectServiceKey(pathname) {
  const s = SERVICES.find(svc => svc.match(pathname))
  return s ? s.key : null
}

/** The sub-page tiles of one area, each with an absolute `to` (anchors resolve against the area page). */
export function subpagesForDomainKey(domainKey) {
  const svc = SERVICES.find((s) => s.domainKey === domainKey)
  if (!svc) return []
  return svc.items.map((item) => ({
    label: item.label,
    desc: item.desc || '',
    to: item.to || `${svc.to}${item.hash}`,
    anchor: Boolean(item.hash),
  }))
}

export const MODULE_SUBPAGES = Object.freeze(Object.fromEntries(SERVICES.map((s) => [s.domainKey, subpagesForDomainKey(s.domainKey)])))

function RailItem({ svc, active }) {
  const t = SERVICE_COLORS[svc.key]
  const Icon = moduleIcon(svc.key)
  const preload = () => { const loader = routePreloadMap[svc.to]; if (loader) preloadComponent(loader) }
  return (
    <li>
      <NavLink
        to={svc.to}
        aria-label={svc.title}
        aria-current={active ? 'page' : undefined}
        onMouseEnter={preload}
        onFocus={preload}
        className={`cm-rail-item ${active ? 'cm-rail-item-active' : ''}`}
        style={active ? { backgroundColor: t.chip, color: t.text } : { color: t.icon }}
        data-service-key={svc.key}
      >
        <Icon className="w-5 h-5" aria-hidden="true" />
        <span className="cm-tip" aria-hidden="true">{svc.title}</span>
      </NavLink>
    </li>
  )
}

export default function WorkspaceNav({ wsId, wsName }) {
  const { pathname } = useLocation()
  const activeKey = detectServiceKey(pathname)
  return (
    <nav aria-label="Modules" className="cm-rail" data-testid="module-rail">
      <ul className="cm-rail-list">
        {SERVICES.map((svc) => <RailItem key={svc.key} svc={svc} active={activeKey === svc.key} />)}
      </ul>
      <div className="cm-rail-foot">
        <WorkspaceMenu wsId={wsId} wsName={wsName} placement="up" />
      </div>
    </nav>
  )
}
