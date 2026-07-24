import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import ExecutiveReportV2 from '../ExecutiveReportV2'
import { CYBER_MOT_DISPLAY_ORDER } from '../../lib/cyberMotDisplay'

const evidence = {
  grade: 'L1',
  source_type: 'product_policy',
  basis: 'CyberMeters product-policy assessment over frozen RFC 7208 scan evidence.',
  limits: ['External RFC 7208 observation only.'],
  repeat_confirmed: false,
}

describe('ExecutiveReportV2 Evidence-Grade pilot', () => {
  it('renders an honest, neutral state for a completed pre-snapshot scan', () => {
    render(
      <ExecutiveReportV2
        report={{
          report_availability: {
            status: 'historical_scan_no_canonical_snapshot',
            available_from: '2026-07-17',
            message:
              'This scan predates the canonical report snapshot; a full evidence-graded report is available for scans from 17 July 2026 onward.',
          },
        }}
      />
    )

    expect(screen.getByRole('status')).toHaveTextContent('Historical scan report')
    expect(screen.getByRole('status')).toHaveTextContent('predates the canonical report snapshot')
    expect(screen.getByRole('status')).toHaveTextContent('reporting-format boundary, not data loss')
    expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('explains evidence strength once, keeps bases before conclusions, and labels the band honestly', () => {
    const { container } = render(
      <ExecutiveReportV2
        report={{
          domain: { name: 'example.com' },
          assessed_at: '2026-07-24T12:00:00.000Z',
          cyber_metrics_score: {
            value: 85,
            rating: 'good',
            evidence_grade: evidence,
          },
          business_risk_indicator: {
            band: 'low',
            explanation: 'No major gaps in the evidence available.',
            evidence_grade: evidence,
          },
          executive_summary: {
            summary: 'Eight-domain summary.',
            evidence_grade: { ...evidence, grade: 'L0' },
            priority_actions: [],
          },
          cyber_mot_domains: CYBER_MOT_DISPLAY_ORDER.map((domain) => ({
            ...domain,
            state: 'evidence_insufficient',
            coverage: 'partial',
            summary: 'Further evidence is required.',
            finding_count: 0,
            evidence_grade: evidence,
          })),
          observed_findings: [],
          observations: [],
          remediation_actions: [],
          limitations: [],
        }}
      />
    )

    const text = container.textContent
    expect(screen.getByText('How to read this report')).toBeInTheDocument()
    expect(screen.getByText(/Evidence strength shows how strongly/)).toHaveTextContent(
      'A domain we could not fully assess is shown as evidence-insufficient, not as low-risk.'
    )
    expect(text.indexOf('Evidence strength: Limited')).toBeLessThan(text.indexOf('85'))
    expect(screen.getAllByText('Evidence strength: Limited')).toHaveLength(9)
    expect(text.indexOf('Score basis:')).toBeLessThan(text.indexOf('85'))
    expect(text).toContain('Business Risk Indicator basis:')
    expect(text).toContain('Eight-domain summary basis:')
    expect(text).not.toContain('Evidence confidence:')
    expect(text).not.toContain('RFC 7208')
    expect(screen.getByText('CyberMeters assessment band')).toBeInTheDocument()
    expect(screen.queryByText(/Security Rating/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/\bL[0-5]\b/)).not.toBeInTheDocument()
  })
})
