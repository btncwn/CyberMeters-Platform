import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ExecutiveReportV2 from '../ExecutiveReportV2'

// The Assessment Score section never shows a withheld / provisional score as the
// headline ring: the backend's explanation reads first, without a number.

const base = {
  version: '3.0', report_type: 'executive_scan_report', domain: { name: 'cybermeters.com' }, assessed_at: '2026-10-16T09:00:00Z',
  executive_summary: { summary: 'Summary.', priority_actions: [] }, observed_findings: [], observations: [], remediation_actions: [],
  cyber_mot_domains: [], business_risk_indicator: { band: null, explanation: null }, methodology: {}, evidence_completeness: null,
}

const renderReport = (cms, evidenceCompleteness = null) => render(<MemoryRouter><ExecutiveReportV2 report={{ ...base, cyber_metrics_score: cms, evidence_completeness: evidenceCompleteness }} /></MemoryRouter>)

describe('ExecutiveReportV2 — score honesty', () => {
  it('partial + withheld: explanation first, no numeric score', () => {
    renderReport({ value: 100, rating: null, provisional: true, quality: 'partial', message: 'Attack surface did not complete, so the score is provisional.' })
    const block = screen.getByTestId('executive-score-withheld')
    expect(block.firstElementChild).toHaveTextContent('Attack surface did not complete, so the score is provisional.')
    expect(block).toHaveTextContent('Score available after a complete scan')
    expect(block).not.toHaveTextContent('100 / 100')
    expect(screen.queryByText('/ 100')).toBeNull()
    expect(screen.queryByText('100')).toBeNull()
    expect(screen.queryByText('CyberMeters assessment band')).toBeNull()
  })
  it('withholds an apparently final CMS value when the report scan quality is partial', () => {
    renderReport({ value: 100, rating: 'excellent', provisional: false, quality: 'complete' }, { scan_quality: 'partial' })
    expect(screen.getByTestId('executive-score-withheld')).toHaveTextContent('Score available after a complete scan')
    expect(screen.queryByText('100')).toBeNull()
  })
  it('a withheld band with no provisional flag is still not a headline', () => {
    renderReport({ value: 100, rating: null, provisional: false, quality: 'complete', message: null })
    expect(screen.getByTestId('executive-score-withheld')).toHaveTextContent('Score withheld: some checks did not complete.')
    expect(screen.queryByText('/ 100')).toBeNull()
  })
  it('an established score keeps the ring and the band', () => {
    renderReport({ value: 85, rating: 'good', provisional: false, quality: 'complete', message: null })
    expect(screen.getByText('85')).toBeInTheDocument()
    expect(screen.getByText('/ 100')).toBeInTheDocument()
    expect(screen.getByText('CyberMeters assessment band')).toBeInTheDocument()
    expect(screen.queryByTestId('executive-score-withheld')).toBeNull()
  })
})
