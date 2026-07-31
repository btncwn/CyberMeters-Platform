import React from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'
import {
  REPORT_PREPARING_DELAYS_MS,
  REPORT_PREPARING_MAX_ATTEMPTS,
} from '../../lib/reportAvailability'

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(),
    getScanReport: vi.fn(),
    getExecutiveReportV2: vi.fn(),
    getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(),
    waiveFinding: vi.fn(),
    unwaiveFinding: vi.fn(),
  },
}))

vi.mock('../../components/ExecutiveReportV2', () => ({
  default: ({ report }) => <div>Executive report {report?.marker}</div>,
}))

const completedScan = {
  id: 'scan-a1',
  domain: 'a1.example',
  status: 'completed',
  score: 82,
  rating: 'good',
  scan_quality: 'complete',
  created_at: '2026-07-30T10:00:00Z',
}

const preparing = {
  status: 'report_preparing',
  code: 'report_preparing',
  message: 'Your assessment is complete. CyberMeters is preparing the report.',
  retryable: true,
  retry_after_ms: 1,
}

const ready = {
  status: 'report_ready',
  retryable: false,
  snapshot_id: 'snap-a1',
}

function renderPage(id = 'scan-a1') {
  function RouteControls() {
    const navigate = useNavigate()
    return (
      <button type="button" onClick={() => navigate('/scans/scan-b')}>
        Open scan B
      </button>
    )
  }

  return render(
    <MemoryRouter initialEntries={[`/scans/${id}`]}>
      <RouteControls />
      <Routes>
        <Route path="/scans/:id" element={<ScanDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

async function advance(ms) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.getScanReport.mockResolvedValue({
    scan_id: 'scan-a1',
    domain: 'a1.example',
    status: 'completed',
    findings: [],
    modules: {},
  })
  api.getExecutiveReportV2.mockResolvedValue({ marker: 'ready' })
})

afterEach(() => {
  vi.useRealTimers()
})

describe('ScanDetail canonical report availability', () => {
  it('preserves active-scan presentation and never calls a report route', async () => {
    api.getScan.mockResolvedValue({
      scan: { ...completedScan, status: 'running' },
      report_availability: {
        status: 'scan_in_progress',
        retryable: false,
        message: 'The assessment is still in progress.',
      },
    })

    renderPage()

    expect(await screen.findByText('Scan in progress')).toBeInTheDocument()
    expect(screen.queryByText(/report is being prepared/i)).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()
    expect(api.getExecutiveReportV2).not.toHaveBeenCalled()
  })

  it('renders a completed report only after authoritative report_ready', async () => {
    api.getScan.mockResolvedValue({
      scan: completedScan,
      report_availability: ready,
    })

    renderPage()

    expect(await screen.findByText('Executive report ready')).toBeInTheDocument()
    expect(api.getScanReport).toHaveBeenCalledTimes(1)
    expect(api.getExecutiveReportV2).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: /Download PDF/i })).toBeInTheDocument()
  })

  it('keeps rolling-deploy compatibility by accepting a successful real renderer response', async () => {
    api.getScan.mockResolvedValue({ scan: completedScan })

    renderPage()

    expect(await screen.findByText('Executive report ready')).toBeInTheDocument()
    expect(api.getScanReport).toHaveBeenCalledTimes(1)
    expect(api.getExecutiveReportV2).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: /Download PDF/i })).toBeInTheDocument()
  })

  it('shows preparation, polls once at a time, then transitions to ready', async () => {
    vi.useFakeTimers()
    let releasePoll
    api.getScan
      .mockResolvedValueOnce({
        scan: completedScan,
        report_availability: preparing,
      })
      .mockImplementationOnce(() => new Promise((resolve) => { releasePoll = resolve }))

    renderPage()
    await act(async () => {})

    expect(screen.getByText('Your report is being prepared')).toBeInTheDocument()
    expect(screen.queryByText('Something went wrong')).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()

    await advance(REPORT_PREPARING_DELAYS_MS[0])
    expect(api.getScan).toHaveBeenCalledTimes(2)
    await advance(REPORT_PREPARING_DELAYS_MS[1] * 2)
    expect(api.getScan).toHaveBeenCalledTimes(2)

    await act(async () => {
      releasePoll({
        scan: completedScan,
        report_availability: ready,
      })
    })
    await act(async () => {})
    expect(screen.getByText('Executive report ready')).toBeInTheDocument()
    expect(api.getScanReport).toHaveBeenCalledTimes(1)
    expect(api.getExecutiveReportV2).toHaveBeenCalledTimes(1)
  })

  it('surfaces a terminal report error and never relabels it preparing', async () => {
    api.getScan.mockResolvedValue({
      scan: completedScan,
      report_availability: {
        status: 'report_unavailable',
        code: 'report_integrity_error',
        message: 'The report is unavailable because its integrity could not be verified.',
        retryable: false,
        manual_retry_available: false,
      },
    })

    renderPage()

    expect(await screen.findByText('Report unavailable')).toBeInTheDocument()
    expect(screen.getByText(/integrity could not be verified/i)).toBeInTheDocument()
    expect(screen.queryByText('Your report is being prepared')).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it.each([
    ['cross-tenant/nonexistent', 403, 'You don’t have access to this scan'],
    ['soft-deleted workspace', 403, 'You don’t have access to this scan'],
  ])('stops immediately for %s authorization boundaries', async (_label, status, title) => {
    const error = Object.assign(new Error('You don’t have access to this.'), { status })
    api.getScan.mockRejectedValue(error)

    renderPage()

    expect(await screen.findByText(title)).toBeInTheDocument()
    expect(api.getScan).toHaveBeenCalledTimes(1)
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it('stops after the finite preparation bound and offers an explicit retry', async () => {
    vi.useFakeTimers()
    api.getScan.mockImplementation(async () => ({
      scan: { ...completedScan },
      report_availability: { ...preparing },
    }))

    renderPage()
    await act(async () => {})
    for (const delay of REPORT_PREPARING_DELAYS_MS) {
      await advance(delay)
    }
    await act(async () => {})

    expect(api.getScan).toHaveBeenCalledTimes(REPORT_PREPARING_MAX_ATTEMPTS + 1)
    expect(screen.getByText('Report preparation is taking longer than expected'))
      .toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Check again' })).toBeInTheDocument()
    expect(screen.queryByText('Something went wrong')).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it('cancels preparation polling when the page unmounts', async () => {
    vi.useFakeTimers()
    api.getScan.mockResolvedValue({
      scan: completedScan,
      report_availability: preparing,
    })
    const view = renderPage()
    await act(async () => {})
    expect(api.getScan).toHaveBeenCalledTimes(1)

    view.unmount()
    await advance(REPORT_PREPARING_DELAYS_MS.reduce((sum, delay) => sum + delay, 0))
    expect(api.getScan).toHaveBeenCalledTimes(1)
  })

  it('aborts the pending request on unmount without rendering a network error or polling again', async () => {
    vi.useFakeTimers()
    let requestSignal
    api.getScan.mockImplementation((_id, options) => {
      requestSignal = options.signal
      return new Promise(() => {})
    })

    const view = renderPage()
    await act(async () => {})
    expect(requestSignal).toBeInstanceOf(AbortSignal)
    expect(requestSignal.aborted).toBe(false)

    view.unmount()
    expect(requestSignal.aborted).toBe(true)
    await advance(REPORT_PREPARING_DELAYS_MS.reduce((sum, delay) => sum + delay, 0))
    expect(api.getScan).toHaveBeenCalledTimes(1)
    expect(screen.queryByText(/couldn't reach CyberMeters/i)).toBeNull()
  })

  it('keeps Scan B state when an aborted Scan A request resolves last', async () => {
    let resolveA
    let resolveB
    let signalA
    api.getScan.mockImplementation((scanId, options) => new Promise((resolve) => {
      if (scanId === 'scan-a1') {
        resolveA = resolve
        signalA = options.signal
      } else if (scanId === 'scan-b') {
        resolveB = resolve
      }
    }))

    renderPage()
    await waitFor(() => expect(resolveA).toBeTypeOf('function'))
    fireEvent.click(screen.getByRole('button', { name: 'Open scan B' }))
    await waitFor(() => expect(resolveB).toBeTypeOf('function'))
    expect(signalA.aborted).toBe(true)

    await act(async () => {
      resolveB({
        scan: {
          ...completedScan,
          id: 'scan-b',
          domain: 'b.example',
        },
        report_availability: {
          ...preparing,
          message: 'Preparing Scan B report.',
        },
      })
    })
    expect(await screen.findByRole('heading', { name: 'b.example', level: 1 }))
      .toBeInTheDocument()
    expect(screen.getByText('Preparing Scan B report.')).toBeInTheDocument()

    // The mock deliberately ignores AbortSignal and resolves anyway. The
    // id/generation guard must still reject this obsolete response.
    await act(async () => {
      resolveA({
        scan: {
          ...completedScan,
          id: 'scan-a1',
          domain: 'a1.example',
        },
        report_availability: ready,
      })
    })
    expect(screen.getByRole('heading', { name: 'b.example', level: 1 }))
      .toBeInTheDocument()
    expect(screen.getByText('Preparing Scan B report.')).toBeInTheDocument()
    expect(screen.queryByText('a1.example')).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()
    expect(api.getExecutiveReportV2).not.toHaveBeenCalled()
  })
})
