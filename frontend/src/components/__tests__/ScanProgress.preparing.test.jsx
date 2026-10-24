import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ScanProgress from '../ScanProgress'
import { scanProgress } from '../../../../workers/scan-api/src/routes/scans.js'

// F1 (D), R1 15:50: the real API shape (the backend's scanProgress) drives the
// copy; "Preparing checks" never lasts forever; the clock never resets.
vi.mock('../../lib/scanDuration', async (orig) => ({ ...(await orig()), collectSamples: vi.fn().mockResolvedValue([]) }))

const NOW = Date.parse('2026-10-24T10:06:00Z')
const created = '2026-10-24T10:00:00Z'
const job = (over) => ({ state: 'running', created_ms: Date.parse(created), deadline_ms: NOW + 20 * 60_000, lease_until: NOW + 60_000, ...over })
beforeEach(() => { vi.useFakeTimers({ shouldAdvanceTime: false }); vi.setSystemTime(NOW) })
afterEach(() => vi.useRealTimers())

describe('real API shape → copy', () => {
  it('a live exposure job → "Preparing checks · Running for 6 min 00 s"', async () => {
    const progress = scanProgress({ status: 'queued' }, NOW, { exposureJob: job() })
    render(<ScanProgress scan={{ id: 's1', status: 'queued', domain: 'example.com', created_at: created }} progress={progress} />)
    await act(async () => {})
    expect(screen.getByText('Preparing checks')).toBeInTheDocument()
    expect(screen.getByTestId('scan-progress-timer')).toHaveTextContent('Running for 6 min 00 s')
  })
  it('past the job\'s deadline → "Scan queued" plus the gone-quiet sentence, never "Preparing" forever', async () => {
    const progress = scanProgress({ status: 'queued' }, NOW, { exposureJob: job({ deadline_ms: NOW - 1 }) })
    render(<ScanProgress scan={{ id: 's1', status: 'queued', domain: 'example.com', created_at: created }} progress={progress} />)
    await act(async () => {})
    expect(screen.queryByText('Preparing checks')).toBeNull()
    expect(screen.getByTestId('scan-progress-stale')).toHaveTextContent('This check has gone quiet.')
  })
  it('no job → real queueing, "Scan queued"', async () => {
    render(<ScanProgress scan={{ id: 's1', status: 'queued', domain: 'example.com', created_at: created }} progress={scanProgress({ status: 'queued' }, NOW, { exposureJob: null })} />)
    await act(async () => {})
    expect(screen.getByText('Scan queued')).toBeInTheDocument()
    expect(screen.getByTestId('scan-progress-timer')).toHaveTextContent('Queued for 6 min 00 s')
  })
})

it('the clock keeps running across queued (preparing) → running', async () => {
  const scan = { id: 's1', status: 'queued', domain: 'example.com', created_at: created }
  const { rerender } = render(<ScanProgress scan={scan} progress={scanProgress({ status: 'queued' }, NOW, { exposureJob: job() })} />)
  await act(async () => {})
  expect(screen.getByTestId('scan-progress-timer')).toHaveTextContent('Running for 6 min 00 s')
  vi.setSystemTime(NOW + 5000)
  rerender(<ScanProgress scan={{ ...scan, status: 'running' }} progress={scanProgress({ status: 'running', last_heartbeat_at: new Date(NOW).toISOString() }, NOW + 5000)} />)
  await act(async () => { vi.advanceTimersByTime(1000) })
  expect(screen.getByTestId('scan-progress-timer')).toHaveTextContent(/Running for 6 min 0[5-6] s/)
})
