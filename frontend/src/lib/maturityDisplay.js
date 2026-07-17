// Maturity display helper — PRESENTATION SAFETY ONLY (M5.f).
// The maturity STAGE for each of the eight domains is always decided server-side by the
// canonical maturity ledger (engines/domain-maturity.js). This helper exists solely so the
// UI can never render FEWER than eight domains: if the server data is absent, malformed, or
// the request failed, it falls back to the eight canonical domain NAMES with a fixed,
// honest "not_established" stage. It NEVER derives a stage from evidence and never invents a
// mature verdict — maturity is not computed in the frontend.

// Canonical domain names + order (display copy only — no evidence, no derived stage).
export const MATURITY_DISPLAY_ORDER = [
  { domain_key: 'email_protection',               display_name: 'Email Protection' },
  { domain_key: 'brand_protection',               display_name: 'Brand Protection' },
  { domain_key: 'attack_surface',                 display_name: 'Attack Surface' },
  { domain_key: 'certificates_trust',             display_name: 'Certificates & Trust' },
  { domain_key: 'cyber_essentials_readiness',     display_name: 'Cyber Essentials Readiness' },
  { domain_key: 'website_security',               display_name: 'Website Security' },
  { domain_key: 'identity_exposure',              display_name: 'Identity Exposure' },
  { domain_key: 'shadow_it_unmanaged_technology', display_name: 'Shadow IT & Unmanaged Technology' },
]

// Stage → { label, tone }. Presentation mapping only. Mirrors the backend
// MATURITY_STAGE_META labels; the SOURCE of the stage is always the server.
export const STAGE_META = {
  not_established: { label: 'Not established',        tone: 'gray' },
  observed:        { label: 'Observed',               tone: 'blue' },
  managed:         { label: 'Under management',       tone: 'indigo' },
  verified:        { label: 'Verified by CyberMeters', tone: 'green' },
  monitored:       { label: 'Verified & monitored',  tone: 'green' },
}

const isValidMaturityEntry = (d) =>
  d && typeof d === 'object' && typeof d.domain_key === 'string' && typeof d.maturity_stage === 'string'

// resolveDisplayMaturity — returns the array of exactly eight maturity rows to render.
// Passes server-resolved rows straight through when they are a valid eight-entry set;
// otherwise returns the eight-domain "not_established" skeleton (never mature, never fewer
// than eight).
export function resolveDisplayMaturity(domains) {
  if (Array.isArray(domains) && domains.length === 8 && domains.every(isValidMaturityEntry)) {
    return domains
  }
  return MATURITY_DISPLAY_ORDER.map((d) => ({
    ...d,
    maturity_stage: 'not_established',
    stage_label: STAGE_META.not_established.label,
    stage_description: 'Maturity temporarily unavailable — refresh to reassess.',
    capability_ceiling: null,
    reason_code: 'unavailable',
    previous_stage: null,
    flags: { attested: false, regressed: false, has_unmanaged_issue: false },
    established: false,
  }))
}
