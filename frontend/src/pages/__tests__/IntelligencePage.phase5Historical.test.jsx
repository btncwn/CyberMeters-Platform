import React from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import IntelligencePage from '../IntelligencePage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getWorkspaceScans: vi.fn(),
    getScanReport: vi.fn(),
  },
}))

const PARTIAL_ASSESSMENT = Object.freeze({
  display_score: null,
  display_rating: null,
  quality: 'partial',
  provisional: true,
  authoritative: false,
  comparable: false,
  message: 'Some checks were not completed. This score is provisional.',
})

const COMPLETE_ASSESSMENT = Object.freeze({
  display_score: 82,
  display_rating: 'good',
  quality: 'complete',
  provisional: false,
  authoritative: true,
  comparable: true,
  message: null,
})

const unavailable = source => ({
  executed: false,
  incomplete: true,
  outcome: 'unavailable',
  reason: 'historical_module_evidence_missing',
  source,
  evidence_publishable: false,
})

const scanFixture = (overrides = {}) => ({
  id: 'scan-intelligence',
  domain: 'intelligence.example',
  status: 'completed',
  score: 99,
  rating: 'excellent',
  created_at: '2026-07-20T10:00:00Z',
  ...overrides,
})

const historicalChanges = (overrides = {}) => ({
  has_previous: true,
  previous_scan_id: 'scan-previous',
  previous_score: 70,
  current_score: 85,
  score_change: 15,
  comparable: false,
  new_subdomains: [],
  removed_subdomains: [],
  new_findings: [{ title: 'Claimed New Finding' }],
  resolved_findings: [{ title: 'Claimed Resolved Finding' }],
  new_takeover_risks: [],
  new_exposed_assets: [],
  ...overrides,
})

const observedFinding = Object.freeze({
  id: 'trusted-sibling',
  title: 'Trustworthy sibling header finding',
  severity: 'high',
  business_impact: 'Observed by a completed sibling module.',
})

const reportFixture = (overrides = {}) => {
  const base = {
    scan_id: 'scan-intelligence',
    domain: 'intelligence.example',
    status: 'completed',
    cyber_metrics_score: 99,
    risk_level: 'excellent',
    assessment: PARTIAL_ASSESSMENT,
    scan_quality: {
      status: 'partial',
      modules_skipped: ['headers'],
      warnings: [],
    },
    modules: {
      cve_intelligence: unavailable('cve_intelligence'),
      known_exploited_vulnerabilities: unavailable('known_exploited_vulnerabilities'),
      email_security_intelligence: unavailable('email_security_intelligence'),
      historical_changes: historicalChanges(),
      risk_intelligence: {
        overall_risk_level: null,
        narrative: null,
        incomplete: true,
        finding_counts: { critical: 0, high: 1, medium: 0, low: 0 },
        risk_categories: { 'Web Security': [observedFinding] },
      },
      remediation_plan: {
        incomplete: true,
        summary: { p1_count: 0, p2_count: 0, p3_count: 0 },
        immediate_actions: [],
        short_term_actions: [],
        strategic_actions: [],
      },
    },
  }
  return {
    ...base,
    ...overrides,
    modules: { ...base.modules, ...(overrides.modules || {}) },
  }
}

function cardForHeading(heading) {
  const headingNode = screen.getByText(heading)
  const card = headingNode.closest('.card')
  expect(card).not.toBeNull()
  return card
}

function summaryMetric(label) {
  const labelNode = screen.getByText(label)
  const metric = labelNode.closest('.bg-white')
  expect(metric).not.toBeNull()
  return metric
}

function expectRawStoredAssessmentHidden() {
  expect(screen.queryByText(/^99\s*\/\s*100$/i)).not.toBeInTheDocument()
  expect(screen.queryByText(/^excellent$/i)).not.toBeInTheDocument()
}

async function renderFixture({ scan = scanFixture(), report = reportFixture() } = {}) {
  api.getWorkspaceScans.mockResolvedValue({ scans: [scan] })
  api.getScanReport.mockResolvedValue(report)
  render(<MemoryRouter><IntelligencePage /></MemoryRouter>)
  await screen.findByText('Full Report')
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalledWith(scan.id))
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws-intelligence')
  localStorage.setItem('cybermeters_workspace_name', 'Intelligence Workspace')
})

describe('IntelligencePage canonical assessment and history presentation', () => {
  it('A: partial raw excellent/99 with null canonical rating and score fails closed', async () => {
    await renderFixture()

    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0)
    expect(screen.getByText('Score —/100')).toBeInTheDocument()
    expect(within(summaryMetric('Provisional Score')).getByText('—')).toBeInTheDocument()
    expectRawStoredAssessmentHidden()
    expect(screen.queryByText('99')).not.toBeInTheDocument()
  })

  it('B: partial canonical provisional score remains visible with an explicit label', async () => {
    const report = reportFixture({
      assessment: { ...PARTIAL_ASSESSMENT, display_score: 85 },
    })
    await renderFixture({ report })

    expect(screen.getByText('Provisional score 85/100')).toBeInTheDocument()
    expect(within(summaryMetric('Provisional Score')).getByText('85')).toBeInTheDocument()
    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0)
    expectRawStoredAssessmentHidden()
  })

  it('C: complete authoritative canonical good assessment remains visible', async () => {
    const report = reportFixture({
      assessment: COMPLETE_ASSESSMENT,
      scan_quality: { status: 'complete', modules_skipped: [], warnings: [] },
      modules: {
        historical_changes: historicalChanges({ comparable: true }),
      },
    })
    await renderFixture({ report })

    expect(screen.getByText('Score 82/100')).toBeInTheDocument()
    expect(within(summaryMetric('Cyber Metrics Score')).getByText('82')).toBeInTheDocument()
    expect(screen.getAllByText('Good').length).toBeGreaterThan(0)
    expect(screen.queryByText('Provisional Score')).not.toBeInTheDocument()
    expectRawStoredAssessmentHidden()
  })

  it('D: comparable true exposes canonical score and finding history', async () => {
    const report = reportFixture({
      assessment: COMPLETE_ASSESSMENT,
      modules: {
        historical_changes: historicalChanges({
          comparable: true,
          previous_score: 75,
          current_score: 82,
          score_change: 7,
          new_findings: [{ title: 'New comparable finding' }],
          resolved_findings: [{ title: 'Resolved comparable finding' }],
          removed_subdomains: ['old.intelligence.example'],
        }),
      },
    })
    await renderFixture({ report })

    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText('Score Comparison')).toBeInTheDocument()
    expect(within(history).getByText('+7', { exact: false })).toBeInTheDocument()
    expect(within(history).getByText('New comparable finding')).toBeInTheDocument()
    expect(within(history).getByText('Resolved comparable finding')).toBeInTheDocument()
    expect(within(history).getByText('old.intelligence.example')).toBeInTheDocument()
  })

  it('E: comparable false suppresses every historical claim', async () => {
    await renderFixture()

    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText('Not comparable')).toBeInTheDocument()
    expect(within(history).queryByText('Score Comparison')).not.toBeInTheDocument()
    expect(within(history).queryByText('New Findings')).not.toBeInTheDocument()
    expect(within(history).queryByText('Resolved Findings')).not.toBeInTheDocument()
    expect(within(history).queryByText(/No changes detected/i)).not.toBeInTheDocument()
  })

  it('F1: null comparable fails closed', async () => {
    const report = reportFixture({
      modules: { historical_changes: historicalChanges({ comparable: null }) },
    })
    await renderFixture({ report })

    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText('Not comparable')).toBeInTheDocument()
    expect(within(history).queryByText('Score Comparison')).not.toBeInTheDocument()
  })

  it('F2: missing comparable fails closed', async () => {
    const changes = historicalChanges()
    delete changes.comparable
    const report = reportFixture({ modules: { historical_changes: changes } })
    await renderFixture({ report })

    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText('Not comparable')).toBeInTheDocument()
    expect(within(history).queryByText('New Findings')).not.toBeInTheDocument()
  })

  it('F3: unknown comparable fails closed', async () => {
    const report = reportFixture({
      modules: { historical_changes: historicalChanges({ comparable: 'true' }) },
    })
    await renderFixture({ report })

    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText('Not comparable')).toBeInTheDocument()
    expect(within(history).queryByText('Resolved Findings')).not.toBeInTheDocument()
  })

  it('G: backend non-comparable message is rendered verbatim without frontend causality', async () => {
    const message = 'Backend canonical comparison warning — retain this sentence exactly.'
    const report = reportFixture({
      assessment: { ...PARTIAL_ASSESSMENT, message },
      scan_quality: {
        status: 'partial',
        modules_skipped: ['headers'],
        warnings: ['Lower-priority backend warning.'],
      },
    })
    await renderFixture({ report })

    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText(message)).toBeInTheDocument()
    expect(within(history).queryByText(/Headers evidence did not complete/i)).not.toBeInTheDocument()
    expect(within(history).queryByText(/because headers/i)).not.toBeInTheDocument()
  })

  it('H: positive observed finding remains visible without a new or resolved claim', async () => {
    const report = reportFixture({
      modules: {
        historical_changes: historicalChanges({
          comparable: false,
          new_findings: [{ title: observedFinding.title }],
          resolved_findings: [{ title: 'False resolution claim' }],
        }),
      },
    })
    await renderFixture({ report })

    expect(screen.getByText(observedFinding.title)).toBeInTheDocument()
    const history = cardForHeading('Changes Since Last Scan')
    expect(within(history).getByText('Not comparable')).toBeInTheDocument()
    expect(within(history).queryByText('New Findings')).not.toBeInTheDocument()
    expect(within(history).queryByText('Resolved Findings')).not.toBeInTheDocument()
    expect(within(history).queryByText(observedFinding.title)).not.toBeInTheDocument()
    expect(within(history).queryByText('False resolution claim')).not.toBeInTheDocument()
  })

  it('I: missing canonical assessment never falls back to raw report or stored values', async () => {
    const report = reportFixture({ assessment: undefined })
    await renderFixture({ report })

    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0)
    expect(screen.getByText('Score —/100')).toBeInTheDocument()
    expect(screen.queryByText('99')).not.toBeInTheDocument()
    expectRawStoredAssessmentHidden()
  })

  it('J: unknown rating and non-finite canonical score fail closed', async () => {
    const report = reportFixture({
      assessment: {
        ...COMPLETE_ASSESSMENT,
        display_score: Number.POSITIVE_INFINITY,
        display_rating: 'surprising-new-band',
      },
      modules: {
        risk_intelligence: {
          overall_risk_level: 'Surprising',
          narrative: null,
          incomplete: false,
          finding_counts: { critical: 0, high: 0, medium: 0, low: 0 },
          risk_categories: {},
        },
      },
    })
    await renderFixture({ report })

    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0)
    expect(screen.getByText('Score —/100')).toBeInTheDocument()
    expect(screen.queryByText('surprising-new-band')).not.toBeInTheDocument()
    expect(screen.queryByText('Surprising Risk')).not.toBeInTheDocument()
    expectRawStoredAssessmentHidden()
  })
})
