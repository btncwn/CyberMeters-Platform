// Case History words for events whose generic "<action> — moved to <status>"
// reading contradicts itself (KALAN 10c, founder 23 Oct 2026: "Resolution
// observed — moved to detected"). An improvement CyberMeters observed is never a
// verification on its own; the event's recorded reason says why not.
// Presentation of the backend's recorded event only.
//
// One entry per observed-improvement event the case engines write:
//   resolution_observed[_not_verifying]   website-security-cases.js
//   recovery_observed[_not_verifying]     cyber-essentials-cases.js, email-protection-cases.js
//   replacement_observed[_not_verifying]  certificate-lifecycle.js

const STAYS_OPEN = 'The case stays open until you submit it for verification.'
// A case already closed keeps no "stays open" promise: certificate replacements
// are noted on a linked case in any phase (certificate-lifecycle.js), so the
// event's own status decides (R1 02:15).
const TERMINAL_STATUSES = new Set(['closed', 'closed_no_action', 'false_positive', 'rejected', 'resolved', 'verified', 'superseded', 'accepted_risk', 'risk_accepted'])
const OUTSIDE = 'it cannot verify this fix from outside.'

// Null-prototype tables: an event or reason key such as "toString" is never a
// table entry (R1 02:15).
const table = (entries) => Object.freeze(Object.assign(Object.create(null), entries))
const OBSERVED_EVENTS = table({
  resolution_observed: {
    observed: 'CyberMeters no longer observes this condition.',
    lead: 'CyberMeters did not see the condition',
    reasons: table({
      detecting_module_not_proven_complete: 'but the check that detects it did not complete, so this does not count as a fix.',
      registry_method_is_not_externally_observable: `but ${OUTSIDE}`,
    }),
  },
  recovery_observed: {
    observed: 'CyberMeters observed an improvement.',
    lead: 'CyberMeters observed an improvement',
    reasons: table({
      external_evidence_incomplete: 'but some of the external evidence was not collected, so this does not count as a fix.',
      registry_method_is_not_externally_observable: `but ${OUTSIDE}`,
    }),
  },
  replacement_observed: {
    observed: 'CyberMeters observed a replacement certificate.',
    lead: 'CyberMeters observed a replacement certificate',
    reasons: table({
      registry_method_is_not_externally_observable_for_this_finding: `but ${OUTSIDE}`,
    }),
  },
})

function detailOf(ev) {
  if (ev?.detail && typeof ev.detail === 'object') return ev.detail
  if (typeof ev?.detail_json !== 'string') return {}
  try { const parsed = JSON.parse(ev.detail_json); return parsed && typeof parsed === 'object' ? parsed : {} } catch { return {} }
}

/** The plain sentence for an observed-improvement event, or null for any other event. */
export function resolutionEventWords(ev) {
  const action = typeof ev?.action === 'string' ? ev.action : ''
  const notVerifying = action.endsWith('_not_verifying')
  const key = notVerifying ? action.slice(0, -'_not_verifying'.length) : action
  const entry = Object.hasOwn(OBSERVED_EVENTS, key) ? OBSERVED_EVENTS[key] : null
  if (!entry) return null
  if (!notVerifying) {
    const closed = TERMINAL_STATUSES.has(ev?.to_status) || TERMINAL_STATUSES.has(ev?.from_status)
    return closed ? entry.observed : `${entry.observed} ${STAYS_OPEN}`
  }
  const reason = detailOf(ev).reason
  const why = typeof reason === 'string' && Object.hasOwn(entry.reasons, reason) ? entry.reasons[reason] : null
  return `${entry.lead}, ${why || 'but this does not verify the fix.'}`
}
