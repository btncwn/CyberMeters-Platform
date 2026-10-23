// WorkspaceNav — the canonical area list of the app shell: one entry per area
// in founder order (lib/moduleRegistry.js order, SERVICE_COLORS key) with the
// route it opens and its sub-pages. The 72px rail that once rendered this list
// is gone (founder prototype v2, 17 Oct 2026): the areas now show only in the
// sidebar (shell/AreaSidebar.jsx, S1-SHELL-V2) and as tiles on each area
// page. This file is the data; it renders nothing.
// ── Canonical security domains — the areas ─────────────────────
// Founder order (14 Oct): strongest evidence first, down to the readiness area.
// `items` are the area's sub-pages (route or in-page anchor), shown as tiles on
// the area page; the area name itself opens its overview. An anchor opens the
// Findings tab unless `tab: 'overview'` says the block is a summary that lives
// on Overview (statistic cards, coverage honesty).
import { sortByAreaOrder } from '../../../shared/areas.js'
const SERVICE_DEFINITIONS = [
  {
    key: 'email', domainKey: 'email_protection', title: 'Email Protection', to: '/ws/email-protection',
    match: p => p.startsWith('/ws/email-protection'),
    // Sidebar sub-topics (S1-SHELL-V2, founder-approved 22 Oct 2026): names only,
    // in order of importance; each opens an existing section or sub-page.
    subtopics: [
      { label: 'DMARC policy',            hash: '#auth-dmarc' },
      { label: 'SPF',                     hash: '#auth-spf' },
      { label: 'DKIM',                    hash: '#auth-dkim' },
      { label: 'MTA-STS & TLS reporting', hash: '#mta-sts-setup', tab: 'settings' },
      { label: 'Aggregate reports',       hash: '#report-history' },
      // The module checks STARTTLS on each mail server; DANE (TLSA) is not checked, so the label never claims it.
      { label: 'Mail transport encryption', hash: '#mail-transport' },
    ],
    items: [
      // Configuration lives on the Settings tab of the area template (18 Oct 2026).
      { hash: '#dmarc-setup',       label: 'DMARC Setup',          desc: 'Policy, alignment and the hosted record', tab: 'settings' },
      { hash: '#sender-inventory',  label: 'Sender Inventory',     desc: 'Every source seen sending as your domain' },
      { hash: '#auth-detail',       label: 'Authentication Detail', desc: 'SPF, DKIM and DMARC as observed' },
      { hash: '#connect-reporting', label: 'Connect reporting', desc: 'Set up DMARC report delivery', tab: 'settings' },
      { hash: '#lifecycle-history', label: 'Lifecycle history', desc: 'Changes to reporting and senders' },
    ],
  },
  {
    key: 'surface', domainKey: 'attack_surface', title: 'Attack Surface', to: '/assets',
    match: p => p.startsWith('/assets') || p.startsWith('/exposure') || p.startsWith('/ws/admin-surfaces')
      || p.startsWith('/ws/cloud-assets') || p.startsWith('/scans') || p.startsWith('/schedules') || p.startsWith('/intelligence'),
    subtopics: [
      // Each sub-topic opens its OWN named section (C-38 S28: no aliases).
      { label: 'Hostnames',      hash: '#asset-inventory' },
      // The inventory with the Exposed Service filter selected (its own named view).
      { label: 'Exposed services', to: '/assets?type=exposed_service#asset-inventory' },
      { label: 'Admin surfaces', to: '/ws/admin-surfaces' },
      { label: 'Cloud assets',   to: '/ws/cloud-assets' },
      { label: 'Network assets', hash: '#network-assets' },
      { label: 'Timeline',       to: '/exposure' },
    ],
    items: [
      { to: '/exposure',          label: 'Timeline',       desc: 'What appeared, changed or disappeared' },
      { to: '/scans',             label: 'Scans',          desc: 'Every assessment run and its result' },
      { to: '/schedules',         label: 'Schedules',      desc: 'When the next assessments run' },
      { to: '/ws/admin-surfaces', label: 'Admin Surfaces', desc: 'Login and admin pages reachable from outside' },
      { to: '/ws/cloud-assets',   label: 'Cloud Assets',   desc: 'Storage and cloud endpoints observed' },
      // Network/port evidence (NetworkAssetsPanel) lives on the Findings tab; since
      // #650 nothing led to it, so the founder thought it was gone.
      { hash: '#network-assets',  label: 'Network assets', desc: 'Open ports and services on addresses you are authorised to test' },
      // The scan-level intelligence page was reachable from nowhere. It carries the
      // score history, what changed between scans and the remediation plan, and it
      // states the check pack's position on outside vulnerability data.
      { to: '/intelligence',      label: 'Intelligence',   desc: 'Score history, changes between scans and the remediation plan' },
    ],
  },
  {
    key: 'website', domainKey: 'website_security', title: 'Website Security', to: '/ws/website-security',
    match: p => p.startsWith('/ws/website-security'),
    subtopics: [
      // Each opens its own "What we observed" figure (S1-SHELL-V2b).
      { label: 'HTTPS & HSTS',            hash: '#website-hsts', tab: 'overview' },
      { label: 'Security headers',        hash: '#website-security-headers', tab: 'overview' },
      { label: 'Content Security Policy', hash: '#website-csp', tab: 'overview' },
      { label: 'Signed-in scanning',      hash: '#sign-in-settings', tab: 'settings' },
      { label: 'Pages checked',           hash: '#pages-checked' },
    ],
    items: [
      { hash: '#website-observations', label: 'Observations', desc: 'HTTPS, headers and cookies from the latest scan', tab: 'overview' },
      { hash: '#exposure-checks', label: 'Exposure checks', desc: 'Public content and management surfaces checked', tab: 'overview' },
      { hash: '#pages-checked', label: 'Pages checked', desc: 'Public pages observed on your site' },
      { hash: '#sign-in-settings', label: 'Sign-in settings', desc: 'Set up and review signed-in checks', tab: 'settings' },
    ],
  },
  {
    key: 'identity', domainKey: 'identity_exposure', title: 'Identity Exposure', to: '/ws/identity-exposure',
    match: p => p.startsWith('/ws/identity-exposure') || p.startsWith('/ws/identity-assets'),
    subtopics: [
      { label: 'Provider relationships',    to: '/ws/identity-assets#identity-providers' },
      { label: 'Identity-facing hostnames', to: '/ws/identity-assets#identity-hostnames' },
    ],
    items: [
      { to: '/ws/identity-assets', label: 'People & evidence', desc: 'Accounts and identity evidence' },
      { to: '/ws/identity-assets#workforce-response', label: 'Workforce response', desc: 'Account observations and recorded responses' },
      { to: '/ws/identity-assets#public-sources', label: 'Public sources', desc: 'Checks of public web files' },
    ],
  },
  {
    key: 'shadow_it', domainKey: 'shadow_it_unmanaged_technology', title: 'Shadow IT & Unmanaged Technology', to: '/ws/shadow-it',
    match: p => p.startsWith('/ws/shadow-it') || p.startsWith('/ws/saas-exposure') || p.startsWith('/ws/third-parties')
      || p.startsWith('/ws/third-party') || p.startsWith('/ws/vendors') || p.startsWith('/ws/supply-chain'),
    subtopics: [
      { label: 'Observed technology', hash: '#shadow-it-inventory' },
      // The inventory with Approved selected (C-38 S27), not the all-items view.
      { label: 'Approved inventory',  to: '/ws/shadow-it?filter=approved#shadow-it-inventory' },
    ],
    items: [
      { to: '/ws/saas-exposure',   label: 'SaaS Exposure', desc: 'Portals and tenants observed for your domain' },
      // One home for third parties (founder, 17 Oct 2026): the services seen in
      // your pages, the providers behind your domain and their concentration.
      { to: '/ws/third-parties',   label: 'Third parties', desc: 'Services, providers and dependencies observed for your domain' },
    ],
  },
  {
    key: 'certs', domainKey: 'certificates_trust', title: 'Certificates & Trust', to: '/ws/certificates',
    match: p => p.startsWith('/ws/certificates'),
    subtopics: [
      { label: 'Expiry',        hash: '#cert-expiry', tab: 'overview' },
      { label: 'Chain & trust', hash: '#cert-trust' },
      { label: 'Hostname match',        hash: '#cert-hostname-match' },
      { label: 'Issuance policy (CAA)', hash: '#cert-caa' },
      { label: 'Lifecycle',     to: '/ws/certificates/lifecycle' },
    ],
    items: [
      { to: '/ws/certificates/lifecycle', label: 'Managed Lifecycle', desc: 'Renewals, replacements and follow-up' },
      { hash: '#cert-inventory', label: 'Inventory',           desc: 'Certificates observed on your hostnames' },
      { hash: '#cert-expiry',    label: 'Expiry Risk',         desc: 'What expires soon', tab: 'overview' },
      { hash: '#cert-actions',   label: 'Recommended Actions', desc: 'What to do, from the registry' },
      { hash: '#cert-trust',     label: 'Trust Posture',       desc: 'What the trust path shows' },
    ],
  },
  {
    key: 'brand', domainKey: 'brand_protection', title: 'Brand Protection', to: '/ws/brand-monitoring',
    match: p => p.startsWith('/ws/brand-monitoring'),
    subtopics: [
      { label: 'Lookalike domains', hash: '#typosquats' },
      { label: 'Watchlist',         hash: '#protected-brand', tab: 'settings' },
      { label: 'Takedown tracking', hash: '#managed-brand-cases' },
    ],
    items: [
      { hash: '#typosquats',        label: 'Typosquat Candidates', desc: 'Lookalike domains observed' },
      // The brand counts are the template's always-visible figures; the editor lives on Settings (18 Oct 2026).
      { hash: '#protected-brand',   label: 'Protected brand',      desc: 'The brand names and domains the checks run against', tab: 'settings' },
    ],
  },
  {
    key: 'cyber_essentials', domainKey: 'cyber_essentials_readiness', title: 'Cyber Essentials Readiness', to: '/ws/cyber-essentials',
    match: p => p.startsWith('/ws/cyber-essentials'),
    subtopics: [
      { label: 'Questionnaire',      hash: '#questionnaire' },
      { label: 'External indicator', hash: '#ce-indicator', tab: 'overview' },
      { label: 'Controls',           hash: '#ce-observed-controls', tab: 'overview' },
    ],
    items: [],
  },
]

// Founder order lives in ONE place (shared/areas.js); the area sheet, the Overview
// list and the Field Guide all derive from it.
export const SERVICES = Object.freeze(sortByAreaOrder(SERVICE_DEFINITIONS))

// Exported: Layout and the area pages use this to find the active area —
// route→domain mapping stays defined ONCE, here.
export function detectServiceKey(pathname) {
  const s = SERVICES.find(svc => svc.match(pathname))
  return s ? s.key : null
}

/**
 * The sub-page tiles of one area, each with an absolute `to` (anchors resolve
 * against the area page; an Overview anchor carries `?tab=overview` so the
 * contract opens the tab that holds it).
 */
export function subpagesForDomainKey(domainKey) {
  const svc = SERVICES.find((s) => s.domainKey === domainKey)
  if (!svc) return []
  return svc.items.map((item) => ({
    label: item.label,
    desc: item.desc || '',
    // A tile names the tab that holds its section when that is not Findings (the anchor default).
    to: item.to || `${svc.to}${item.tab ? `?tab=${item.tab}` : ''}${item.hash}`,
    anchor: Boolean(item.hash),
  }))
}

/** The sidebar sub-topics of one area, each with an absolute `to` (same rule as the tiles). */
export function subtopicsForDomainKey(domainKey) {
  const svc = SERVICES.find((s) => s.domainKey === domainKey)
  if (!svc) return []
  return (svc.subtopics || []).map((item) => ({
    label: item.label,
    to: item.to || `${svc.to}${item.tab ? `?tab=${item.tab}` : ''}${item.hash}`,
  }))
}

export const MODULE_SUBPAGES = Object.freeze(Object.fromEntries(SERVICES.map((s) => [s.domainKey, subpagesForDomainKey(s.domainKey)])))
