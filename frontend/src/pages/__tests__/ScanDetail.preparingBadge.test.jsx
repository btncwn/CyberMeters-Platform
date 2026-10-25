import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'
import { scanProgress } from '../../../../workers/scan-api/src/routes/scans.js'

// F1 (D), R1 15:50: the header badge follows the backend's progress — a queued
// scan whose exposure job is live reads Running; real queueing reads Queued.
vi.mock('../../api', () => ({
  api: { getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(), getWorkspaceScans: vi.fn(), getScans: vi.fn() },
}))
const NOW = Date.now()
const scan = { id: 's_prep', domain: 'example.com', status: 'queued', created_at: new Date(NOW - 6 * 60_000).toISOString() }
beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceScans.mockResolvedValue({ scans: [] }); api.getScans.mockResolvedValue({ scans: [] })
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
})
const open = () => render(<MemoryRouter initialEntries={['/scans/s_prep']}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
const headerBadge = () => screen.getByRole('heading', { level: 1 }).parentElement

it('a live exposure job: the badge reads Running beside "Preparing checks"', async () => {
  const job = { state: 'running', created_ms: NOW - 6 * 60_000, deadline_ms: NOW + 20 * 60_000, lease_until: NOW + 60_000 }
  api.getScan.mockResolvedValue({ scan, progress: scanProgress(scan, NOW, { exposureJob: job }) })
  open()
  await screen.findByText('Preparing checks')
  await waitFor(() => expect(headerBadge()).toHaveTextContent(/Running/))
  expect(headerBadge()).not.toHaveTextContent(/Queued/)
})

it('real queueing: the badge reads Queued', async () => {
  api.getScan.mockResolvedValue({ scan, progress: scanProgress(scan, NOW, { exposureJob: null }) })
  open()
  await screen.findByText('Scan queued')
  expect(headerBadge()).toHaveTextContent(/Queued/)
})
