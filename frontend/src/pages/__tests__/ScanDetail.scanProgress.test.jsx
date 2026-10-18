import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'

// A queued or running scan has ONE status block: no banner above it, no second
// "in progress" card. Queued and running use different words, the elapsed time
// counts up, and the expectation comes from the workspace's own completed scans.

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(), getWorkspaceScans: vi.fn(),
  },
}))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))

const iso = (msAgo) => new Date(Date.now() - msAgo).toISOString()
const active = (status, msAgo) => ({ id: 'scan_active_1234567890abcdef', domain: 'cybermeters.com', status, score: null, rating: null, scan_quality: null, created_at: iso(msAgo) })
const history = (n, domain = 'cybermeters.com') => Array.from({ length: n }, (_, i) => ({ id: `scan_h${i}`, domain, status: 'completed', score: 80, rating: 'good', scan_quality: 'complete', created_at: `2026-10-${String(10 + i).padStart(2, '0')}T08:00:00Z` }))

function renderPage(scan) {
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'scan_in_progress', retryable: false } })
  return render(
    <MemoryRouter initialEntries={[`/scans/${scan.id}`]}>
      <Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  localStorage.setItem('cybermeters_workspace_id', 'ws1')
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
})

describe('ScanDetail — active scan status block', () => {
  it('queued: one block, queued wording, a count-up, and the domain-based expectation', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [active('queued', 40000), ...history(4)] })
    api.getScanReport.mockImplementation(async (id) => ({ scan_id: id, started_at: '2026-10-10T08:00:00Z', completed_at: '2026-10-10T08:02:00Z' }))
    renderPage(active('queued', 40000))
    const block = await screen.findByTestId('scan-progress')
    expect(block).toHaveAttribute('data-status', 'queued')
    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(screen.getByText('Scan queued')).toBeInTheDocument()
    expect(screen.queryByText('Scan in progress')).toBeNull()
    expect(screen.queryByText(/auto-refreshing/)).toBeNull()
    expect(screen.getByTestId('scan-progress-timer')).toHaveTextContent(/^Queued for 4\d s$/)
    await waitFor(() => expect(screen.getByTestId('scan-progress-expectation')).toHaveTextContent('Usually takes about 2 min, based on your last 4 scans of this domain.'))
    // Only the other, completed scans' reports were read — never the active scan's.
    expect(api.getScanReport).toHaveBeenCalledTimes(4)
    expect(api.getScanReport.mock.calls.map(([id]) => id)).not.toContain('scan_active_1234567890abcdef')
    expect(screen.queryByTestId('scan-progress-long')).toBeNull()
  })

  it('running: running wording, workspace fallback under three domain samples, and the long-running note past twice the median', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [active('running', 5 * 60000), ...history(2), ...history(3, 'other.example')] })
    api.getScanReport.mockImplementation(async () => ({ started_at: '2026-10-10T08:00:00Z', completed_at: '2026-10-10T08:01:30Z' }))
    renderPage(active('running', 5 * 60000))
    await screen.findByTestId('scan-progress')
    expect(screen.getByText('Scan in progress')).toBeInTheDocument()
    expect(screen.queryByText('Scan queued')).toBeNull()
    expect(screen.getByTestId('scan-progress-timer')).toHaveTextContent(/^Running for 5 min 0\d s$/)
    await waitFor(() => expect(screen.getByTestId('scan-progress-expectation')).toHaveTextContent('Usually takes about 2 min, based on your last 5 scans.'))
    expect(screen.getByTestId('scan-progress-long')).toHaveTextContent('Taking longer than usual; it is still running.')
  })

  it('no history: says first scan and invents no number', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [active('running', 10000)] })
    renderPage(active('running', 10000))
    await screen.findByTestId('scan-progress')
    await waitFor(() => expect(screen.getByTestId('scan-progress-expectation')).toHaveTextContent('First scan of cybermeters.com; usually a few minutes.'))
    expect(screen.getByTestId('scan-progress-expectation').textContent).not.toMatch(/\d/)
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it('the header carries the domain and the status chip but never the raw scan id', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [] })
    renderPage(active('queued', 1000))
    await screen.findByTestId('scan-progress')
    expect(screen.queryByText('scan_active_1234567890abcdef')).toBeNull()
    expect(screen.getByTestId('scan-id-short')).toHaveTextContent('scan_acti…cdef')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('cybermeters.com')
  })
})
