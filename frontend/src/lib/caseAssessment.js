// The case's chip word where it is shown (case rows, case page). A CE case in a
// workspace whose readiness is not assessed carries the backend's `assessment`
// (#921); its chip reads "Not assessed" instead of "Action required". Lanes,
// counts and the case's own status are unchanged: they still use caseStatus.
import { caseStatus } from './statusVocabulary'

export function caseChipStatus(caseRecord) {
  return caseRecord?.assessment?.state === 'not_assessed' ? 'not_assessed' : caseStatus(caseRecord)
}

/** The backend's one-line assessment note for the case, or null. */
export function caseAssessmentMessage(caseRecord) {
  const a = caseRecord?.assessment
  return a?.state === 'not_assessed' && typeof a.message === 'string' && a.message ? a.message : null
}
