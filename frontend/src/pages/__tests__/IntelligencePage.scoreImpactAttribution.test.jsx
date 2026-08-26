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

// Item 19 PR-D: the backend already attributes the applied KEV/CVE score impact
// onto the risk-intelligence notes (score_impact mirrors score_impact_applied,
// stamped once by the scoring owner). This page is the ONLY consumer that
// receives those notes — and the Item 19 measurement showed it rendered
// score_impact ZERO times. These tests pin the render (red-first against that
// measurement) and its honesty boundaries: zero/absent stays neutral, and
// incomplete evidence never renders a deduction.

const scanFixture = () => ({
  id: 'scan-impact',
  domain: 'impact.example',
  status: 'completed',
  score: 55,
  rating: 'fair',
  created_at: '2026-08-26T10:00:00Z',
})

const kevNote = (overrides = {}) => ({
  id: 'kev_active_exploitation',
  severity: 'critical',
  title: '1 CISA Known Exploited Vulnerability detected in technology stack',
  business_impact: 'Active exploitation confirmed.',
  risk_category: 'Data Security',
  score_impact: -30,
  ...overrides,
})

const cveNote = (overrides = {}) => ({
  id: 'cve_high_severity_detected',
  severity: 'high',
  title: '3 known CVEs matched in completed technology checks',
  business_impact: 'Known vulnerabilities in deployed technologies.',
  risk_category: 'Data Security',
  score_impact: -15,
  ...overrides,
})

const completeModules = (riskIntelligence) => ({
  cve_intelligence: {
    technologies_checked: ['nginx'],
    lookup_statuses: { nginx: { status: 'complete' } },
    total_cves: 3,
    cve_coverage: 'complete',
    evidence_publishable: true,
  },
  known_exploited_vulnerabilities: { matches: [{ cveID: 'CVE-2024-0001' }], evidence_publishable: true },
  email_security_intelligence: { email_security_score: 100, evidence_publishable: true },
  historical_changes: { has_previous: false },
  risk_intelligence: riskIntelligence,
  remediation_plan: {
    summary: { p1_count: 1, p2_count: 0, p3_count: 0 },
    immediate_actions: [],
    short_term_actions: [],
    strategic_actions: [],
  },
})

const reportFixture = (riskIntelligence) => ({
  scan_id: 'scan-impact',
  domain: 'impact.example',
  status: 'completed',
  cyber_metrics_score: 55,
  risk_level: 'fair',
  assessment: {
    display_score: 55,
    display_rating: 'fair',
    quality: 'complete',
    provisional: false,
    authoritative: true,
    comparable: true,
    message: null,
  },
  scan_quality: { status: 'complete', modules_skipped: [], warnings: [] },
  modules: completeModules(riskIntelligence),
})

async function renderReport(report) {
  api.getWorkspaceScans.mockResolvedValue({ scans: [scanFixture()] })
  api.getScanReport.mockResolvedValue(report)
  render(<MemoryRouter><IntelligencePage /></MemoryRouter>)
  await screen.findByText('Full Report')
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalledWith('scan-impact'))
}

function riskCard() {
  const headingNode = screen.getByText('Risk Intelligence')
  const card = headingNode.closest('.card')
  expect(card).not.toBeNull()
  return card
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws-impact')
  localStorage.setItem('cybermeters_workspace_name', 'Impact Workspace')
})

describe('IntelligencePage renders the attributed KEV/CVE score impact', () => {
  it('A: applied negative score_impact on KEV and CVE notes is customer-visible', async () => {
    await renderReport(reportFixture({
      overall_risk_level: 'High',
      narrative: 'Active exploitation risk present.',
      incomplete: false,
      finding_counts: { critical: 1, high: 1, medium: 0, low: 0 },
      risk_categories: { 'Data Security': [kevNote(), cveNote()] },
    }))
    const card = riskCard()
    expect(within(card).getByText('-30 pts')).toBeInTheDocument()
    expect(within(card).getByText('-15 pts')).toBeInTheDocument()
  })

  it('B: zero and absent score_impact stay NEUTRAL — never shown as a deduction', async () => {
    await renderReport(reportFixture({
      overall_risk_level: 'Medium',
      narrative: null,
      incomplete: false,
      finding_counts: { critical: 0, high: 1, medium: 0, low: 0 },
      risk_categories: {
        'Data Security': [
          kevNote({ score_impact: 0 }),
          cveNote({ score_impact: undefined }),
        ],
      },
    }))
    const card = riskCard()
    // The notes themselves render; no impact chip may exist for 0 or absent.
    expect(within(card).getByText(/CISA Known Exploited/)).toBeInTheDocument()
    expect(within(card).queryByText(/-?\d+\s*pts/)).not.toBeInTheDocument()
    expect(within(card).queryByText('0 pts')).not.toBeInTheDocument()
  })

  it('C: incomplete evidence NEVER renders a deduction, even if a stale impact value is present', async () => {
    // Fail-closed at the consumer: when the risk projection says incomplete,
    // a carried score_impact must not be presented as an applied deduction —
    // the unavailable-evidence -> no-false-signal law at this surface.
    await renderReport(reportFixture({
      overall_risk_level: null,
      narrative: null,
      incomplete: true,
      finding_counts: { critical: 1, high: 0, medium: 0, low: 0 },
      risk_categories: { 'Data Security': [kevNote({ score_impact: -30 })] },
    }))
    const card = riskCard()
    expect(within(card).getByText(/CISA Known Exploited/)).toBeInTheDocument()
    expect(within(card).queryByText(/-?\d+\s*pts/)).not.toBeInTheDocument()
  })
})
