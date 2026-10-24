// One sentence per status word (founder, 23 Oct 2026: "what does Provisional /
// Evidence insufficient / Established mean"). ONE source: every StatusChip's
// tooltip and accessible description, and the Field Guide's status table,
// read these. Keys are statusVocabulary's STATUS_KEYS; presentation only —
// the backend still decides which word applies.
import { STATUS_KEYS, statusMeta } from './statusVocabulary.js'

export const STATUS_EXPLANATIONS = Object.freeze({
  loading: 'CyberMeters is still loading this.',
  error: 'This could not be loaded. It is not a result.',
  not_assessed: 'Not evaluated for this workspace yet.',
  evidence_insufficient: 'Required evidence could not be collected, so this is not assessed. It is never treated as healthy.',
  provisional: 'No issue was observed, but coverage was incomplete.',
  // The vocabulary's own meaning (statusVocabulary.js): an authoritative
  // assessment exists — not "healthy". Shadow IT's monitoring_only maps here
  // too, and the backend defines that as monitoring only, never a verdict (R1 21:00).
  established: 'An authoritative assessment exists for this area; the summary beside it says what was concluded.',
  stale: 'The evidence is older than expected. The next complete scan refreshes it.',
  action_required: 'An issue was observed and needs action.',
  customer_input: 'Needs information only you can give.',
  in_progress: 'Work on this has started.',
  ready_to_verify: 'Marked as fixed and waiting to be verified.',
  verified: 'CyberMeters observed that the fix holds.',
  recurring: 'The issue was observed again after it was fixed, so the case reopened.',
  attested: 'You attested this. CyberMeters cannot verify it from outside.',
  external: 'Needs evidence from an independent third party.',
  closed: 'This case is closed.',
})

/** The sentence for a status key; an unknown key reads as Error's. */
export function statusExplanation(key) {
  return STATUS_EXPLANATIONS[key] || STATUS_EXPLANATIONS.error
}

/** [key, label, sentence] rows for the Field Guide, in vocabulary order. */
export function statusExplanationRows() {
  return STATUS_KEYS.filter((key) => key !== 'loading').map((key) => [key, statusMeta(key).label, STATUS_EXPLANATIONS[key]])
}
