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

const incompleteMessage =
  'Partial scan — some checks did not complete this run; results may be incomplete.'

const unavailable = (source) => ({
  executed: false,
  incomplete: true,
  outcome: 'unavailable',
  reason: 'historical_module_evidence_missing',
  source,
  evidence_publishable: false,
})

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws-historical')
  localStorage.setItem('cybermeters_workspace_name', 'Historical Workspace')
})

describe('IntelligencePage historical Phase-5 customer projection', () => {
  it('uses the projected report assessment, fails closed for missing modules, and retains sibling findings', async () => {
    api.getWorkspaceScans.mockResolvedValue({
      scans: [{
        id: 'scan-historical',
        domain: 'historical.example',
        status: 'completed',
        score: 100,
        rating: 'excellent',
        created_at: '2026-07-20T10:00:00Z',
      }],
    })
    api.getScanReport.mockResolvedValue({
      scan_id: 'scan-historical',
      domain: 'historical.example',
      status: 'completed',
      cyber_metrics_score: null,
      risk_level: null,
      assessment: {
        display_score: null,
        display_rating: null,
        quality: 'partial',
        provisional: true,
        authoritative: false,
        message: incompleteMessage,
      },
      modules: {
        cve_intelligence: unavailable('cve_intelligence'),
        known_exploited_vulnerabilities: unavailable('known_exploited_vulnerabilities'),
        email_security_intelligence: unavailable('email_security_intelligence'),
        risk_intelligence: {
          overall_risk_level: null,
          narrative: null,
          incomplete: true,
          finding_counts: { critical: 0, high: 1, medium: 0, low: 0 },
          risk_categories: {
            'Web Security': [{
              id: 'trusted-sibling',
              title: 'Trustworthy sibling header finding',
              severity: 'high',
              business_impact: 'Observed by a completed sibling module.',
            }],
          },
        },
        remediation_plan: {
          incomplete: true,
          summary: { p1_count: 0, p2_count: 0, p3_count: 0 },
          immediate_actions: [],
          short_term_actions: [],
          strategic_actions: [],
        },
      },
    })

    render(<MemoryRouter><IntelligencePage /></MemoryRouter>)

    await screen.findByText('Trustworthy sibling header finding')
    expect(screen.getAllByText(incompleteMessage).length).toBeGreaterThan(0)
    expect(screen.getByText('Score —/100')).toBeInTheDocument()
    expect(screen.queryByText('Score 100/100')).toBeNull()
    expect(screen.queryByText('excellent')).toBeNull()
    expect(screen.queryByText('Low Risk')).toBeNull()
    expect(screen.queryByText(/No critical or high-severity issues detected/)).toBeNull()
    const cveKevCard = screen.getByText('CVE / KEV').parentElement
    expect(within(cveKevCard).getByText('—')).toBeInTheDocument()
    expect(within(cveKevCard).queryByText('0')).toBeNull()
    await waitFor(() => expect(api.getScanReport).toHaveBeenCalledWith('scan-historical'))
  })
})
