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
const OUTSIDE = 'it cannot verify this fix from outside.'

const OBSERVED_EVENTS = Object.freeze({
  resolution_observed: {
    observed: `CyberMeters no longer observes this condition. ${STAYS_OPEN}`,
    lead: 'CyberMeters did not see the condition',
    reasons: {
      detecting_module_not_proven_complete: 'but the check that detects it did not complete, so this does not count as a fix.',
      registry_method_is_not_externally_observable: `but ${OUTSIDE}`,
    },
  },
  recovery_observed: {
    observed: `CyberMeters observed this condition recover. ${STAYS_OPEN}`,
    lead: 'CyberMeters observed a recovery',
    reasons: {
      external_evidence_incomplete: 'but some of the external evidence was not collected, so this does not count as a fix.',
      registry_method_is_not_externally_observable: `but ${OUTSIDE}`,
    },
  },
  replacement_observed: {
    observed: `CyberMeters observed a replacement certificate. ${STAYS_OPEN}`,
    lead: 'CyberMeters observed a replacement certificate',
    reasons: {
      registry_method_is_not_externally_observable_for_this_finding: `but ${OUTSIDE}`,
    },
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
  const entry = OBSERVED_EVENTS[notVerifying ? action.slice(0, -'_not_verifying'.length) : action]
  if (!entry) return null
  if (!notVerifying) return entry.observed
  const why = entry.reasons[detailOf(ev).reason]
  return `${entry.lead}, ${why || 'but this does not verify the fix.'}`
}
