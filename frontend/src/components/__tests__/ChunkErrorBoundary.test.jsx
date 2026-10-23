import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ChunkErrorBoundary, {
  isChunkLoadError,
  reloadForFreshAssets,
  clearReloadBudget,
} from '../ChunkErrorBoundary'

import { freshReload } from '../../lib/freshReload'

const RELOAD_FLAG = 'cybermeters_chunk_reload_at'

// Every reload goes through lib/freshReload (S1-RELOAD: a plain location.reload
// read a poisoned cached chunk back and looped). Its own behaviour is tested in
// lib/__tests__/freshReload.test.js; here we pin WHEN the boundary reloads.
vi.mock('../../lib/freshReload', () => ({ freshReload: vi.fn() }))
const reloadSpy = freshReload
beforeEach(() => {
  freshReload.mockClear()
  sessionStorage.clear()
})

function Boom({ message, name }) {
  const err = new Error(message)
  if (name) err.name = name
  throw err
}

function renderWithBoundary(child) {
  return render(
    <MemoryRouter>
      <ChunkErrorBoundary>{child}</ChunkErrorBoundary>
    </MemoryRouter>,
  )
}

describe('isChunkLoadError', () => {
  it('recognises the browser-specific stale-chunk messages', () => {
    expect(isChunkLoadError(new Error('Failed to fetch dynamically imported module: /assets/x.js'))).toBe(true)
    expect(isChunkLoadError(new Error("'text/html' is not a valid JavaScript MIME type"))).toBe(true)
    expect(isChunkLoadError(new Error('Loading chunk 42 failed'))).toBe(true)
    const named = new Error('anything')
    named.name = 'ChunkLoadError'
    expect(isChunkLoadError(named)).toBe(true)
  })

  it('does not classify ordinary render errors as chunk failures', () => {
    expect(isChunkLoadError(new Error('Cannot read properties of undefined'))).toBe(false)
    expect(isChunkLoadError(null)).toBe(false)
  })
})

describe('ChunkErrorBoundary recovery', () => {
  it('auto-reloads ONCE on a stale-chunk error and shows the loading state, not an error card', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    renderWithBoundary(<Boom message="Failed to fetch dynamically imported module: /assets/Page.js" />)
    expect(reloadSpy).toHaveBeenCalledTimes(1)
    expect(sessionStorage.getItem(RELOAD_FLAG)).not.toBeNull()
    expect(screen.getByText("We've just updated CyberMeters. Reloading…")).toBeInTheDocument()
    expect(reloadSpy.mock.calls[0][0]?.message).toMatch(/\/assets\/Page\.js/)
    expect(screen.queryByText(/something went wrong/i)).not.toBeInTheDocument()
    spy.mockRestore()
  })

  it('refuses a second auto-reload inside the window and falls back to the customer-safe card', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    sessionStorage.setItem(RELOAD_FLAG, String(Date.now())) // a reload just happened
    renderWithBoundary(<Boom message="Loading chunk 7 failed" />)
    expect(reloadSpy).not.toHaveBeenCalled()
    expect(screen.getByText("We've just updated CyberMeters")).toBeInTheDocument()
    // A deliberate click must always work — the budget only limits automatic reloads.
    fireEvent.click(screen.getByRole('button', { name: /reload page/i }))
    expect(reloadSpy).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Reloading…' })).toBeDisabled()
    spy.mockRestore()
  })

  it('shows the generic customer-safe card for non-chunk render errors (no raw error text)', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    renderWithBoundary(<Boom message="secret internal stack detail" />)
    expect(reloadSpy).not.toHaveBeenCalled()
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
    expect(screen.queryByText(/secret internal stack detail/i)).not.toBeInTheDocument()
    spy.mockRestore()
  })

  it('clearReloadBudget restores the auto-reload budget after a healthy boot', () => {
    sessionStorage.setItem(RELOAD_FLAG, String(Date.now()))
    expect(reloadForFreshAssets()).toBe(false) // budget spent
    clearReloadBudget()
    expect(reloadForFreshAssets()).toBe(true)  // budget restored
    expect(reloadSpy).toHaveBeenCalledTimes(1)
  })
})
