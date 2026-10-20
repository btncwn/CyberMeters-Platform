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

// Server-derived ownership status of the CERTIFICATE (its business, technical
// and renewal owner roles on the lifecycle record). This is a different field
// from the linked case's owner, so the label names whose owner it is: a case
// can have an owner while the certificate's own roles are still unset
// (founder, 20 Oct 2026).
export const OWNERSHIP_META = {
  known:   { label: 'Certificate owners set',       tone: 'green' },
  partial: { label: 'Some certificate owners set',  tone: 'amber' },
  missing: { label: 'Certificate owner not set',    tone: 'red'   },
}
export const CERT_OWNER_ROLES_NOTE = 'Business, technical and renewal owners of the certificate. The owner of a linked case is recorded separately on the case.'

// Recurrence reasons shown on a row, in plain words. Unknown reasons fall back
// to the backend code with spaces, never a guess.
const RECURRENCE_TEXT = { owner_missing: 'certificate owner not set' }
export function recurrenceText(code) { return code ? (RECURRENCE_TEXT[code] || String(code).replace(/_/g, ' ')) : null }

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
  green: 'bg-brand-200 text-brand-900 border-brand-200',
  amber: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700',
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

export function certificateRelationshipMessage(item) {
  return item?.certificate_assurance?.relationship?.customer_message || null
}

export const CERT_LIFECYCLE_SCOPE_NOTE =
  'Externally observed certificate evidence only. Live leaf, presented chain, root acceptance, OCSP/revocation, hostname match and declared trust-store validation are separate signals and may remain unknown or unavailable. An unexpired certificate is not the same as a fully trusted result. A recorded renewal is not verified until CyberMeters later re-observes method-appropriate evidence.'
