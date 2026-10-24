import { describe, expect, it } from 'vitest'
import { scanProgressCopy } from '../scanDuration'

// F1 (D, Executive 24 Oct 2026): a scan stays 'queued' while its exposure job runs
// first. With progress.exposure_checks pending/running it is working, not waiting.
describe('Preparing checks', () => {
  it.each([
    ['running', 'CyberMeters is checking the domain’s exposed services and certificates first. Results appear here automatically.'],
    // Not picked up yet: preparing, never "is checking" (R1 16:50).
    ['pending', 'CyberMeters is preparing the domain’s service and certificate checks. Results appear here automatically.'],
  ])('exposure job %s → "Preparing checks", a running timer, its own sentence', (state, detail) => {
    const c = scanProgressCopy({ status: 'queued', elapsedMs: 362000, progress: { exposure_checks: state } })
    expect(c.heading).toBe('Preparing checks')
    expect(c.timer).toBe('Running for 6 min 02 s')
    expect(c.detail).toBe(detail)
  })
  it('real queueing (no exposure job, or a finished one) keeps "Scan queued"', () => {
    for (const progress of [null, {}, { exposure_checks: null }, { exposure_checks: 'complete' }]) {
      const c = scanProgressCopy({ status: 'queued', elapsedMs: 40000, progress })
      expect(c.heading).toBe('Scan queued')
      expect(c.timer).toBe('Queued for 40 s')
    }
  })
  it('a running scan is unchanged', () => {
    expect(scanProgressCopy({ status: 'running', elapsedMs: 40000, progress: { exposure_checks: 'running' } }).heading).toBe('Scan in progress')
  })
})
