// Shared presentation for the Certificates Managed Lifecycle. Maps server-owned
// renewal readiness / lifecycle state / coverage / ownership / verification into
// a display label + tone. The frontend NEVER decides readiness, verification, or
// which actions are allowed — those come from the backend lifecycle service;
// screens only display state and POST an action the server validates. It also
// never softens the honesty: a recorded renewal is shown as customer-asserted,
// not verified, until the server observes a distinct new certificate.

// Renewal readiness bands (must match backend certificate-policy CERT_RENEWAL_BANDS).
export const READINESS_META = {
  monitoring:  { label: 'Monitoring',    tone: 'green' },
  planning:    { label: 'Plan renewal',  tone: 'blue'  },
  preparation: { label: 'Prepare',       tone: 'amber' },
  high:        { label: 'Renew soon',    tone: 'amber' },
  critical:    { label: 'Renew now',     tone: 'red'   },
  expired:     { label: 'Expired',       tone: 'red'   },
  unknown:     { label: 'Expiry unknown',tone: 'slate' },
}

// Coverage status (expected vs observed). "unknown" = nothing declared yet.
export const COVERAGE_META = {
  complete:   { label: 'Complete',        tone: 'green' },
  partial:    { label: 'Partial',         tone: 'amber' },
  missing:    { label: 'Not covered',     tone: 'red'   },
  unexpected: { label: 'Unexpected SANs',  tone: 'amber' },
  unknown:    { label: 'Not assessed',    tone: 'slate' },
}

// Server-derived ownership status (business/technical/renewal roles).
export const OWNERSHIP_META = {
  known:   { label: 'Owned',         tone: 'green' },
  partial: { label: 'Partial owner', tone: 'amber' },
  missing: { label: 'Owner missing', tone: 'red'   },
}

// Verification status — external-observation only. verified_replaced is the ONLY
// state that means the product actually saw the new certificate.
export const VERIFICATION_META = {
  not_verified:     { label: 'Not verified',      tone: 'slate' },
  verified_replaced:{ label: 'Verified',          tone: 'green' },
  failed:           { label: 'Verification failed', tone: 'red' },
  inconclusive:     { label: 'Inconclusive',      tone: 'amber' },
}

export const TONE_CLASS = {
  slate: 'bg-slate-50 text-slate-600 border-slate-200',
  blue:  'bg-blue-50 text-blue-700 border-blue-200',
  green: 'bg-green-50 text-green-700 border-green-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  red:   'bg-red-50 text-red-700 border-red-200',
}

const humanize = (s) => s ? String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : '—'

export function readinessMeta(s) { return READINESS_META[s] || { label: humanize(s), tone: 'slate' } }
export function coverageMeta(s) { return COVERAGE_META[s] || { label: humanize(s), tone: 'slate' } }
export function ownershipMeta(s) { return OWNERSHIP_META[s] || { label: humanize(s), tone: 'slate' } }
export function verificationMeta(s) { return VERIFICATION_META[s] || { label: humanize(s), tone: 'slate' } }
export function toneClass(tone) { return TONE_CLASS[tone] || TONE_CLASS.slate }

// Human phrase for the days-remaining number (never claims safety it can't see).
export function daysRemainingLabel(days) {
  if (days == null) return 'Expiry unknown'
  if (days < 0) return `Expired ${Math.abs(days)}d ago`
  if (days === 0) return 'Expires today'
  return `${days}d remaining`
}

// Whether a customer "recorded replacement" is still awaiting external proof.
export function isAwaitingVerification(item) {
  return item?.renewal_status === 'awaiting_verification' && item?.verification_status !== 'verified_replaced'
}

export const CERT_LIFECYCLE_SCOPE_NOTE =
  'Externally observed certificates only — no live TLS handshake, and chain, root, OCSP, revocation and private-key status are not checked and remain unknown. An unexpired certificate is not the same as fully trusted. A recorded renewal is not verified until CyberMeters observes a distinct new certificate on the expected hostnames with a later expiry.'
