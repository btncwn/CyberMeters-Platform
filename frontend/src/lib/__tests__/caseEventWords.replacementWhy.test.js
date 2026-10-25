import { describe, expect, it } from 'vitest'
import { resolutionEventWords } from '../caseEventWords'

// Executive 25 Oct 03:52: a certificate replacement that did not verify the case
// says WHY, from the verification-evidence code certificate-lifecycle.js records
// (managed-case-model.js validateVerificationEvidence). Free-text errors stay on
// the generic sentence and are never shown raw.
const ev = (reason) => ({ action: 'replacement_observed_not_verifying', detail_json: JSON.stringify({ code: 'evidence_invalid', reason }) })
const LEAD = 'CyberMeters observed a replacement certificate, '

describe('replacement_observed_not_verifying reasons', () => {
  it.each([
    ['verification_evidence_missing', 'but no verification evidence was recorded, so this does not count as a fix.'],
    ['scan_completion_not_verification', 'but a completed scan alone does not verify a fix.'],
    ['note_not_verification', 'but a note alone does not verify a fix.'],
    ['verification_unsupported', 'but this finding cannot be verified this way.'],
    ['verification_result_invalid', 'but the verification result was not recorded in a usable form, so this does not count as a fix.'],
    ['verification_not_positive', 'but the check did not confirm the fix.'],
    ['evidence_type_missing', 'but the evidence did not say what was checked, so this does not count as a fix.'],
    ['observed_at_missing', 'but the evidence did not record when it was observed, so this does not count as a fix.'],
    ['observation_missing', 'but no observation was recorded with it, so this does not count as a fix.'],
    ['attestation_required', 'but this finding needs your attestation before it can be verified.'],
    ['attestation_actor_required', 'but the attestation did not record who made it, so this does not count as a fix.'],
    ['automated_observation_required', 'but the automatic check recorded no observation, so this does not count as a fix.'],
  ])('%s says why', (reason, why) => {
    expect(resolutionEventWords(ev(reason))).toBe(`${LEAD}${why}`)
  })
  it('no sentence over-claims a fix or verification', () => {
    for (const reason of ['verification_evidence_missing', 'verification_not_positive', 'attestation_required', 'observation_missing']) {
      expect(resolutionEventWords(ev(reason))).not.toMatch(/\b(fixed|resolved|is verified|was verified)\b/i)
    }
  })
  it('a free-text error or unknown code stays on the generic sentence, never raw', () => {
    for (const reason of ['D1_ERROR: no such column x', 'Transition not allowed from detected', 'some_new_code', 'toString', null]) {
      const words = resolutionEventWords(ev(reason))
      expect(words).toBe(`${LEAD}but this does not verify the fix.`)
      if (reason) expect(words).not.toContain(reason)
    }
  })
})
