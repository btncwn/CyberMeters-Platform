import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceDetailPage from '../WorkspaceDetailPage'
import { api } from '../../api'

// Founder, 22 Oct 2026 (She.Shire, 2 domains): the Cyber Score tile read
// "75 · Good" — the workspace's last COMPLETE assessment — while the newest
// assessment was incomplete and the domain row said "Score available after a
// complete scan". One page, one number.

vi.mock('../../api', () => ({ api: { getWorkspace: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceAssetsSummary: vi.fn() } }))

function setup(latest) {
  api.getWorkspace.mockResolvedValue({
    workspace: { id: 'ws1', name: 'She.Shire', created_at: '2026-10-01T00:00:00Z', role: 'owner' },
    stats: { total_domains: 2, total_scans: 9, cyber_score_average: null, latest_scan: latest,
      posture_established: true, posture_score: 75, posture_rating: 'good', posture_message: null },
  })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  api.getWorkspaceAssetsSummary.mockResolvedValue(null)
  render(<MemoryRouter initialEntries={['/workspaces/ws1']}><Routes><Route path="/workspaces/:id" element={<WorkspaceDetailPage />} /></Routes></MemoryRouter>)
}
beforeEach(() => vi.clearAllMocks())

describe('Cyber Score tile', () => {
  it('the newest assessment is incomplete: "No score yet", the 75 only as the labelled last complete assessment', async () => {
    setup({ id: 's9', domain: 'sheshire.co.uk', status: 'completed', scan_quality: 'partial', score: null, created_at: '2026-10-22T11:16:00Z' })
    expect(await screen.findByText('No score yet')).toBeInTheDocument()
    expect(screen.getByText('Latest assessment incomplete · last complete assessment: 75 · Good')).toBeInTheDocument()
    expect(screen.queryByText('75')).toBeNull()
  })
  it('the newest assessment is complete: the score is the headline', async () => {
    setup({ id: 's9', domain: 'sheshire.co.uk', status: 'completed', scan_quality: 'complete', score: 75, created_at: '2026-10-22T11:16:00Z' })
    expect(await screen.findByText('75')).toBeInTheDocument()
    expect(screen.getByText('Good')).toBeInTheDocument()
  })
  it('a scan still running or failed is not an assessment: the last complete score stays', async () => {
    setup({ id: 's9', domain: 'sheshire.co.uk', status: 'failed', scan_quality: null, score: null, created_at: '2026-10-22T11:16:00Z' })
    expect(await screen.findByText('75')).toBeInTheDocument()
  })
})
