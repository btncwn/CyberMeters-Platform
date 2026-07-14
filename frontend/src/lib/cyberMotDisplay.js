// Cyber MOT display helper — PRESENTATION SAFETY ONLY.
// The eight domain STATES are always resolved server-side. This helper exists solely
// so the UI can never render FEWER than eight domains: if the server data is absent,
// malformed, or the request failed, it falls back to the eight canonical domain NAMES
// with a fixed, honest, NON-healthy "unavailable" state. It never derives a state
// from evidence and never invents a healthy verdict.

// Canonical domain names + order (display copy only — no evidence, no derived state).
export const CYBER_MOT_DISPLAY_ORDER = [
  { domain_key: 'email_protection',               display_name: 'Email Protection' },
  { domain_key: 'brand_protection',               display_name: 'Brand Protection' },
  { domain_key: 'attack_surface',                 display_name: 'Attack Surface' },
  { domain_key: 'certificates_trust',             display_name: 'Certificates & Trust' },
  { domain_key: 'cyber_essentials_readiness',     display_name: 'Cyber Essentials Readiness' },
  { domain_key: 'website_security',               display_name: 'Website Security' },
  { domain_key: 'identity_exposure',              display_name: 'Identity Exposure' },
  { domain_key: 'shadow_it_unmanaged_technology', display_name: 'Shadow IT & Unmanaged Technology' },
]

const isValidDomainEntry = (d) => d && typeof d === 'object' && typeof d.domain_key === 'string' && typeof d.state === 'string'

// resolveDisplayDomains — returns the array of exactly eight domains to render.
// Passes server-resolved states straight through when they are a valid eight-entry
// set; otherwise returns the eight-domain "unavailable" skeleton (never healthy,
// never fewer than eight).
export function resolveDisplayDomains(domains) {
  if (Array.isArray(domains) && domains.length === 8 && domains.every(isValidDomainEntry)) {
    return domains
  }
  return CYBER_MOT_DISPLAY_ORDER.map((d) => ({
    ...d,
    state: 'unavailable',
    coverage: null,
    summary: 'Coverage temporarily unavailable — refresh to reassess.',
    finding_count: 0,
    limitations: [],
  }))
}
