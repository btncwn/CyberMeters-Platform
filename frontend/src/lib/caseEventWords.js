// Case History words for events whose generic "<action> — moved to <status>"
// reading contradicts itself (KALAN 10c, founder 23 Oct 2026: "Resolution
// observed — moved to detected"). A resolution CyberMeters observed is never a
// verification on its own; the event's recorded reason says why not.
// Presentation of the backend's recorded event only.

const NOT_VERIFYING_REASONS = Object.freeze({
  detecting_module_not_proven_complete:
    'CyberMeters did not see the condition, but the check that detects it did not complete, so this does not count as a fix.',
  registry_method_is_not_externally_observable:
    'CyberMeters did not see the condition, but it cannot verify this fix from outside.',
})

function detailOf(ev) {
  if (ev?.detail && typeof ev.detail === 'object') return ev.detail
  if (typeof ev?.detail_json !== 'string') return {}
  try { const parsed = JSON.parse(ev.detail_json); return parsed && typeof parsed === 'object' ? parsed : {} } catch { return {} }
}

/** The plain sentence for a resolution event, or null for any other event. */
export function resolutionEventWords(ev) {
  if (ev?.action === 'resolution_observed') {
    return 'CyberMeters no longer observes this condition. The case stays open until you submit it for verification.'
  }
  if (ev?.action === 'resolution_observed_not_verifying') {
    return NOT_VERIFYING_REASONS[detailOf(ev).reason]
      || 'CyberMeters did not see the condition, but this does not verify the fix.'
  }
  return null
}
