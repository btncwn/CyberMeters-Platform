import { act, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import StatusPage from '../StatusPage'

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function installProbeFetch({
  health = { status: 'ok', version: 'test-version', maintenance: false },
  ready = { status: 'ready', checks: { d1: true, r2: true } },
  readyStatus = 200,
  rejectHealth = false,
  rejectReady = false,
} = {}) {
  const fetchMock = vi.fn(async (url) => {
    if (String(url).endsWith('/health')) {
      if (rejectHealth) throw new TypeError('Failed to fetch')
      return jsonResponse(health)
    }
    if (String(url).endsWith('/ready')) {
      if (rejectReady) throw new TypeError('Failed to fetch')
      return jsonResponse(ready, readyStatus)
    }
    throw new Error(`unexpected status-page request: ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function renderStatus() {
  return render(<MemoryRouter><StatusPage /></MemoryRouter>)
}

async function flushProbePromises() {
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
  })
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('StatusPage', () => {
  it('maps /ready 200 with d1/r2 true to operational', async () => {
    installProbeFetch()
    renderStatus()

    expect(await screen.findByText('All systems operational')).toBeInTheDocument()
    expect(screen.getAllByText('Operational')).toHaveLength(3)
  })

  it('maps a real /ready failure to degraded', async () => {
    installProbeFetch({
      ready: { status: 'degraded', checks: { d1: false, r2: true } },
      readyStatus: 503,
    })
    renderStatus()

    expect(await screen.findByText('Partial service disruption')).toBeInTheDocument()
    expect(screen.getByText('Degraded')).toBeInTheDocument()
  })

  it('maps a network/CORS failure alone to unavailable with unknown dependency state', async () => {
    installProbeFetch({ rejectReady: true })
    renderStatus()

    expect(await screen.findByText('Unable to reach the service')).toBeInTheDocument()
    expect(screen.getAllByText('Unknown')).toHaveLength(2)
  })

  it('uses the same /health + /ready request path for mount, manual refresh and 30-second refresh', async () => {
    vi.useFakeTimers()
    const fetchMock = installProbeFetch()
    renderStatus()

    await flushProbePromises()
    expect(fetchMock).toHaveBeenCalledTimes(2)

    const refresh = screen.getByRole('button', { name: 'Refresh' })
    expect(refresh).not.toBeDisabled()
    fireEvent.click(refresh)
    await flushProbePromises()
    expect(fetchMock).toHaveBeenCalledTimes(4)

    act(() => vi.advanceTimersByTime(30000))
    await flushProbePromises()

    expect(fetchMock).toHaveBeenCalledTimes(6)
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      'http://localhost/health', 'http://localhost/ready',
      'http://localhost/health', 'http://localhost/ready',
      'http://localhost/health', 'http://localhost/ready',
    ])
    for (const [, options] of fetchMock.mock.calls) {
      expect(options).toEqual({ cache: 'no-store' })
    }
  })
})
