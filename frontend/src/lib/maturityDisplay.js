import { sortDisplayDomains } from './cyberMotDisplay.js'

// Maturity display helper — PRESENTATION SAFETY ONLY (M5.f).
// The maturity STAGE for each of the eight domains is always decided server-side by the
// canonical maturity ledger (engines/domain-maturity.js). This helper exists solely so the
// UI can never render FEWER than eight domains: if the server data is absent, malformed, or
// the request failed, it falls back to the eight canonical domain NAMES with a fixed,
// honest "not_established" stage. It NEVER derives a stage from evidence and never invents a
// mature verdict — maturity is not computed in the frontend.

// Canonical domain names in customer presentation order (display copy only — no evidence, no derived stage).
export const MATURITY_DISPLAY_ORDER = [
  { domain_key: 'identity_exposure',              display_name: 'Identity Exposure' },
  { domain_key: 'attack_surface',                 display_name: 'Attack Surface' },
  { domain_key: 'email_protection',               display_name: 'Email Protection' },
  { domain_key: 'website_security',               display_name: 'Website Security' },
  { domain_key: 'shadow_it_unmanaged_technology', display_name: 'Shadow IT & Unmanaged Technology' },
  { domain_key: 'certificates_trust',             display_name: 'Certificates & Trust' },
  { domain_key: 'brand_protection',               display_name: 'Brand Protection' },
  { domain_key: 'cyber_essentials_readiness',     display_name: 'Cyber Essentials Readiness' },
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
    return sortDisplayDomains(domains)
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

// ── Maturity history (presentation only) ────────────────────────────────────
// Words for the server's reason codes. The code itself — and the stage — come
// from the canonical ledger; an unknown code is shown as-is, never guessed.
export const MATURITY_REASON_TEXT = Object.freeze({
  monitored_recurrence_watch: 'Fixed, re-observed by CyberMeters, and watched for recurrence',
  verified_by_observation: 'Fix re-observed by CyberMeters',
  live_issue_managed: 'An issue is currently observed; it has an owner',
  issue_unmanaged: 'An observed issue has no owner yet',
  recurrence_reopened: 'An issue came back; its case was reopened',
  capability_capped: 'Managed — CyberMeters cannot re-observe this domain to verify it',
  attested_not_verified: 'Customer attested the fix; not externally verified',
  managed_owned: 'Issues have owners',
  observed_clean: 'Assessed; nothing to manage',
  observed_monitoring: 'Assessed; monitoring only',
  customer_input_required: 'Needs customer input before it can be assessed',
  domain_not_observed: 'The domain’s evidence was not obtained on that scan',
})

export function maturityReasonText(code) {
  return MATURITY_REASON_TEXT[code] || (code ? String(code).replace(/_/g, ' ') : null)
}

/** History rows (newest first) with "changed" marking where the stage moved. */
export function maturityHistoryRows(history) {
  const list = Array.isArray(history) ? history.filter((h) => h && typeof h.maturity_stage === 'string') : []
  return list.map((h, i) => {
    const older = list[i + 1]
    return {
      key: `${h.assessed_at || i}-${i}`,
      assessed_at: h.assessed_at || null,
      stage: h.maturity_stage,
      label: STAGE_META[h.maturity_stage]?.label || h.stage_label || h.maturity_stage,
      tone: STAGE_META[h.maturity_stage]?.tone || 'gray',
      reason: maturityReasonText(h.reason_code),
      changed: !older || older.maturity_stage !== h.maturity_stage,
      regressed: Boolean(h.flags?.regressed),
      attested: Boolean(h.flags?.attested),
      unmanaged: Boolean(h.flags?.has_unmanaged_issue),
    }
  })
}
