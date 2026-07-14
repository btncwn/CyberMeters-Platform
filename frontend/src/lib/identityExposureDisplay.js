// Shared presentation for the Identity Exposure Managed Workflow. Maps server-
// owned classification / risk / ownership / verification / monitoring states into
// a display label + tone. The frontend NEVER decides risk, verification, or which
// actions are allowed — those come from the backend lifecycle service; screens
// only display state and POST an action the server validates. It never softens
// the honesty: a publicly visible identity surface is not automatically a
// vulnerability, and a customer-recorded change is not verified until CyberMeters
// re-observes it externally.

// Customer classification (a decision, separate from observation).
export const CLASSIFICATION_META = {
  unreviewed:  { label: 'Unreviewed',  tone: 'slate' },
  expected:    { label: 'Expected',    tone: 'green' },
  unexpected:  { label: 'Unexpected',  tone: 'red'   },
  investigate: { label: 'Investigate', tone: 'amber' },
  exception:   { label: 'Exception',   tone: 'amber' },
  retired:     { label: 'Retired',     tone: 'slate' },
}

// Externally-observable risk (explainable, not alarmist).
export const RISK_META = {
  ok:        { label: 'OK',        tone: 'green' },
  low:       { label: 'Low',       tone: 'blue'  },
  attention: { label: 'Attention', tone: 'amber' },
  elevated:  { label: 'Elevated',  tone: 'amber' },
  high:      { label: 'High',      tone: 'red'   },
}

// Server-derived ownership status (business/technical/identity roles).
export const OWNERSHIP_META = {
  known:   { label: 'Owned',         tone: 'green' },
  partial: { label: 'Partial owner', tone: 'amber' },
  missing: { label: 'Owner missing', tone: 'red'   },
}

// Verification — external-observation only. Only 'verified' means CyberMeters
// actually re-observed the expected change.
export const VERIFICATION_META = {
  not_verified: { label: 'Not verified', tone: 'slate' },
  verified:     { label: 'Verified',     tone: 'green' },
  failed:       { label: 'Failed',       tone: 'red'   },
  inconclusive: { label: 'Inconclusive', tone: 'amber' },
  unsupported:  { label: 'Unsupported',  tone: 'slate' },
  pending:      { label: 'Pending',      tone: 'slate' },
}

// Surface type → readable label.
export const SURFACE_META = {
  identity_provider: { label: 'Identity provider' },
  sso_portal:        { label: 'SSO portal' },
  saml_federation:   { label: 'SAML federation' },
  login_portal:      { label: 'Login portal' },
  admin_login:       { label: 'Admin login' },
  vpn_portal:        { label: 'VPN portal' },
  oauth_endpoint:    { label: 'OAuth endpoint' },
}

export const TONE_CLASS = {
  slate: 'bg-slate-50 text-slate-600 border-slate-200',
  blue:  'bg-blue-50 text-blue-700 border-blue-200',
  green: 'bg-green-50 text-green-700 border-green-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  red:   'bg-red-50 text-red-700 border-red-200',
}

const humanize = (s) => s ? String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : '—'

export function classificationMeta(c) { return CLASSIFICATION_META[c] || { label: humanize(c), tone: 'slate' } }
export function riskMeta(s) { return RISK_META[s] || { label: humanize(s), tone: 'slate' } }
export function ownershipMeta(s) { return OWNERSHIP_META[s] || { label: humanize(s), tone: 'slate' } }
export function verificationMeta(s) { return VERIFICATION_META[s] || { label: humanize(s), tone: 'slate' } }
export function surfaceLabel(s) { return (SURFACE_META[s] && SURFACE_META[s].label) || humanize(s) }
export function toneClass(tone) { return TONE_CLASS[tone] || TONE_CLASS.slate }

// A customer-recorded change/removal that CyberMeters has not yet re-observed.
export function isAwaitingVerification(item) {
  return item?.remediation_status === 'customer_actioned' && item?.verification_status === 'not_verified'
}

export const IDENTITY_SCOPE_NOTE =
  'Externally observed identity and login surfaces only. A publicly visible identity entry point is not automatically a vulnerability. CyberMeters does not see leaked or breached credentials, dark-web data, MFA enrolment, Conditional Access or internal identity policy — those remain unknown. Your classification is a decision; a recorded change or removal is not verified until CyberMeters re-observes it externally.'
