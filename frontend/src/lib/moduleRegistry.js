// Module registry — the eight customer-facing areas as the app shell knows
// them: founder order, the colour key every surface shares, the route the
// sidebar opens, the Field Guide area, and the display copy a card shows when
// the backend has not yet said anything about the area. Presentation only: no
// state, no evidence, no verdict lives here.
//
// Founder order (14 Oct 2026): strongest evidence first, readiness last — the
// same order as the service sidebar and the eight-domain display helpers.
import { SERVICE_COLORS } from '../theme/serviceColors'
import { sortByAreaOrder } from '../../../shared/areas.js'
import { guideAreaForDomainKey } from '../data/fieldGuide'

const MODULE_DEFINITIONS = Object.freeze([
  {
    domainKey: 'email_protection', colourKey: 'email', title: 'Email Protection', to: '/ws/email-protection',
    cta: 'Open Email Protection',
    fallback: 'Connect DMARC reporting to measure impersonation exposure.',
  },
  {
    domainKey: 'attack_surface', colourKey: 'surface', title: 'Attack Surface', to: '/assets',
    cta: 'Review Attack Surface',
    fallback: 'Run your first external scan to discover exposed assets.',
  },
  {
    domainKey: 'website_security', colourKey: 'website', title: 'Website Security', to: '/ws/website-security',
    cta: 'Review Website Security',
    fallback: 'Review HTTPS, redirects, headers and cookie flag evidence.',
  },
  {
    domainKey: 'identity_exposure', colourKey: 'identity', title: 'Identity Exposure', to: '/ws/identity-exposure',
    cta: 'Review Identity Exposure',
    fallback: 'Review observed identity-provider relationships and identity-facing hostnames. Endpoint reachability is shown only with HTTP evidence.',
  },
  {
    domainKey: 'shadow_it_unmanaged_technology', colourKey: 'shadow_it', title: 'Shadow IT & Unmanaged Technology', to: '/ws/shadow-it',
    cta: 'Review Shadow IT',
    fallback: 'Review SaaS, vendor, script and unmanaged technology observations.',
  },
  {
    domainKey: 'certificates_trust', colourKey: 'certs', title: 'Certificates & Trust', to: '/ws/certificates',
    cta: 'Review Certificates',
    fallback: 'Review certificate expiry and HTTPS trust posture.',
  },
  {
    domainKey: 'brand_protection', colourKey: 'brand', title: 'Brand Protection', to: '/ws/brand-monitoring',
    cta: 'Review Brand Protection',
    fallback: 'Add a protected brand profile to monitor lookalike domains.',
  },
  {
    domainKey: 'cyber_essentials_readiness', colourKey: 'cyber_essentials', title: 'Cyber Essentials Readiness', to: '/ws/cyber-essentials',
    cta: 'Review Readiness',
    fallback: 'Review readiness evidence and saved questionnaire answers.',
  },
])

// Founder order from shared/areas.js — the same constant the area sheet and the Field Guide use.
export const MODULES = Object.freeze(sortByAreaOrder(MODULE_DEFINITIONS))

export const MODULE_DOMAIN_KEYS = Object.freeze(MODULES.map((m) => m.domainKey))

const BY_KEY = new Map(MODULES.map((m) => [m.domainKey, m]))

export function moduleForDomainKey(domainKey) {
  return BY_KEY.get(domainKey) || null
}

export function moduleTheme(domainKey) {
  const m = moduleForDomainKey(domainKey)
  return (m && SERVICE_COLORS[m.colourKey]) || null
}

/** `/guide/<slug>` for an area, through the Field Guide's own mapping; null when no area exists. */
export function guidePathForDomainKey(domainKey) {
  const area = guideAreaForDomainKey(domainKey)
  return area?.key ? `/guide/${area.key}` : null
}

/** The Operations view, filtered to one area. */
export function casesPathForDomainKey(domainKey) {
  return `/ws/cases?domain_key=${encodeURIComponent(domainKey)}`
}
