import { describe, expect, it } from 'vitest'
import {
  isPhase5EvidenceAvailable,
  phase5KnownCount,
} from '../phase5EvidencePresentation'

describe('Phase-5 evidence presentation', () => {
  it('renders backend-marked non-publishable evidence as unavailable', () => {
    const deferred = {
      executed: false,
      incomplete: true,
      outcome: 'deadline_exceeded',
      evidence_publishable: false,
      critical_count: 0,
    }
    expect(isPhase5EvidenceAvailable(deferred)).toBe(false)
    expect(phase5KnownCount(deferred, deferred.critical_count)).toBeNull()
  })

  it('retains a genuine completed measured zero', () => {
    const completed = { evidence_publishable: true, critical_count: 0 }
    expect(isPhase5EvidenceAvailable(completed)).toBe(true)
    expect(phase5KnownCount(completed, completed.critical_count)).toBe(0)
  })

  it('retains completed positive evidence', () => {
    const completed = { evidence_publishable: true, critical_count: 2 }
    expect(phase5KnownCount(completed, completed.critical_count)).toBe(2)
  })
})
