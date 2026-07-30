import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { TOKEN_KEY } from '../context/authKeys'

const availability = {
  status: 'report_preparing',
  code: 'report_preparing',
  message: 'Your assessment is complete. CyberMeters is preparing the report.',
  retryable: true,
  retry_after_ms: 2000,
}

function preparingResponse() {
  return new Response(JSON.stringify({
    error: availability.message,
    code: 'report_preparing',
    report_availability: availability,
  }), {
    status: 409,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  localStorage.setItem(TOKEN_KEY, 'a1-token')
})

afterEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
})

describe('API report availability error context', () => {
  it('preserves canonical preparation state on JSON report reads', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(preparingResponse()))

    const error = await api.getScanReport('scan-a1').catch((caught) => caught)

    expect(error.message).toBe(availability.message)
    expect(error.status).toBe(409)
    expect(error.code).toBe('report_preparing')
    expect(error.report_availability).toEqual(availability)
  })

  it('preserves canonical preparation state on PDF reads', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(preparingResponse()))

    const error = await api.getScanReportPdf('scan-a1').catch((caught) => caught)

    expect(error.message).toBe(availability.message)
    expect(error.status).toBe(409)
    expect(error.code).toBe('report_preparing')
    expect(error.report_availability).toEqual(availability)
  })

  it('requests failed-build repair only for an explicit customer retry', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      scan: { id: 'scan-a1', status: 'completed' },
      report_availability: { status: 'report_ready' },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await api.getScan('scan-a1', { retryReport: true })

    expect(fetchMock.mock.calls[0][0]).toBe(
      'http://localhost/api/scans/scan-a1?retry_report=1',
    )
  })
})
