import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceBusinessRiskPage from '../WorkspaceBusinessRiskPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: { getWorkspaceBusinessRisk: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws', wsName: 'Founder Workspace' }),
}))

const renderPage = async (payload) => {
  api.getWorkspaceBusinessRisk.mockResolvedValue(payload)
  render(<MemoryRouter><WorkspaceBusinessRiskPage /></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspaceBusinessRisk).toHaveBeenCalledWith('ws'))
}

const partialPayload = {
  workspace_name: 'Founder Workspace',
  state: 'latest_incomplete',
  state_reason:
    'The latest assessment was partial, so a current Business Risk Score is unavailable. The last complete score is shown separately as historical evidence.',
  score: null,
  brs: null,
  band: null,
  grade: null,
  categories: null,
  current_assessment: {
    scan_id: 'scan-partial',
    status: 'completed',
    scan_quality: 'partial',
    assessed_at: '2026-07-28T10:01:00.000Z',
    brs_assessed: false,
  },
  last_complete_assessment: {
    score: 70,
    grade: 'B',
    risk_band: 'medium',
    historical: true,
    stale: true,
    basis_scan: {
      scan_id: 'scan-complete',
      scan_quality: 'complete',
      assessed_at: '2026-07-28T09:01:00.000Z',
    },
  },
  trend: [{
    date: '2026-07-28T09:01:00.000Z',
    brs_score: 70,
    asm_score: 70,
    basis_scan_id: 'scan-complete',
    scan_quality: 'complete',
  }],
}

beforeEach(() => vi.clearAllMocks())

describe('WorkspaceBusinessRiskPage partial-scan honesty', () => {
  it('renders latest partial as unavailable and the older score only as historical', async () => {
    await renderPage(partialPayload)
    await waitFor(() => expect(screen.getByText('Business Risk Score unavailable')).toBeInTheDocument())
    expect(screen.getByText('Last complete Business Risk Score')).toBeInTheDocument()
    expect(screen.getByText(/Historical\/stale/)).toBeInTheDocument()
    expect(document.body.textContent).toContain('scan-partial')
    expect(document.body.textContent).toContain('scan-complete')
  })

  it('does not render the historical B/medium result as the current grade or band', async () => {
    await renderPage(partialPayload)
    await waitFor(() => expect(screen.getByText('No current grade or risk band is shown.')).toBeInTheDocument())
    expect(screen.queryByText('Category Breakdown')).not.toBeInTheDocument()
    expect(screen.queryByText('No issues detected')).not.toBeInTheDocument()
    expect(screen.getByText(/Historical\/stale/)).toBeInTheDocument()
  })

  it('preserves the complete positive control', async () => {
    await renderPage({
      state: 'assessed',
      state_reason: null,
      score: 70,
      brs: 70,
      band: 'medium',
      grade: 'B',
      summary: 'Persisted complete assessment.',
      categories: {
        email_trust: { score: 70, label: 'Needs attention', issues: ['DMARC missing'] },
      },
      current_assessment: {
        scan_id: 'scan-complete',
        status: 'completed',
        scan_quality: 'complete',
        assessed_at: '2026-07-28T09:01:00.000Z',
        brs_assessed: true,
      },
      last_complete_assessment: {
        score: 70,
        grade: 'B',
        risk_band: 'medium',
        historical: false,
        stale: false,
        basis_scan: { scan_id: 'scan-complete', scan_quality: 'complete' },
      },
      trend: [],
    })
    await waitFor(() => expect(screen.getByText('B')).toBeInTheDocument())
    expect(screen.getAllByText('70').length).toBeGreaterThan(0)
    expect(screen.getByText('Category Breakdown')).toBeInTheDocument()
    expect(screen.queryByText('Business Risk Score unavailable')).not.toBeInTheDocument()
  })
})
