import { describe, expect, it } from 'vitest'
import { lastAssessmentLabel } from '../Dashboard'
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
