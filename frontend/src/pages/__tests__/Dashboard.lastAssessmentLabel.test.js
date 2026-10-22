import { describe, expect, it } from 'vitest'
import { lastAssessmentLabel, overviewAssessmentLine } from '../Dashboard'
import { formatDate } from '../../utils/dates'

describe('home assessment date', () => {
  it('shows a consistent absolute date rather than relative time', () => {
    const created_at = '2026-10-17T19:21:00Z'
    expect(lastAssessmentLabel({ domain: 'example.com', created_at }))
      .toBe(`Last assessment of example.com · ${formatDate(created_at)}`)
    expect(lastAssessmentLabel({ domain: 'example.com', created_at })).not.toMatch(/ago|just now/)
  })

  it('does not invent a date for missing or invalid timestamps', () => {
    for (const created_at of [null, '', 'not-a-date']) {
      expect(lastAssessmentLabel({ domain: 'example.com', created_at })).toBe('Last assessment of example.com')
    }
    expect(lastAssessmentLabel(null)).toBe('No assessment has been recorded in this workspace yet.')
  })
})

// Founder, 22 Oct 2026: "Last assessment … 10:07" named a scan that FAILED.
describe('the Overview names the last COMPLETED scan, never a failed one', () => {
  const done = { id: 's1', domain: 'example.com', status: 'completed', scan_quality: 'complete', created_at: '2026-10-22T09:00:00Z' }
  const partial = { ...done, id: 's2', scan_quality: 'partial', created_at: '2026-10-22T09:30:00Z' }
  const failed = { id: 's3', domain: 'example.com', status: 'failed', created_at: '2026-10-22T10:07:00Z' }
  const running = { id: 's4', domain: 'example.com', status: 'running', created_at: '2026-10-22T10:30:00Z' }

  it('a newer failed attempt is said separately; the assessment is the completed scan', () => {
    expect(overviewAssessmentLine([failed, done]))
      .toBe(`Last assessment of example.com · ${formatDate(done.created_at)} The last attempt (${formatDate(failed.created_at)}) did not finish.`)
  })
  it('a completed scan with partial evidence is still the last assessment', () => {
    expect(overviewAssessmentLine([partial, done])).toBe(`Last assessment of example.com · ${formatDate(partial.created_at)}`)
  })
  it('a scan still running is neither an assessment nor a failure', () => {
    expect(overviewAssessmentLine([running, done])).toBe(`Last assessment of example.com · ${formatDate(done.created_at)}`)
    expect(overviewAssessmentLine([running, failed, done])).toMatch(/The last attempt .* did not finish\.$/)
  })
  it('only failed attempts: no assessment is claimed', () => {
    expect(overviewAssessmentLine([failed])).toBe(`No completed assessment yet. The last attempt (${formatDate(failed.created_at)}) did not finish.`)
  })
  it('no scans at all keeps the honest empty line', () => {
    expect(overviewAssessmentLine([])).toBe('No assessment has been recorded in this workspace yet.')
  })
})
