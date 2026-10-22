import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import SecurityPage from '../SecurityPage'

// Design standard §3/§4 (22 Oct 2026): a read that failed says so in words and
// states no empty list or count beside the error; the server's message never
// reaches the screen.

vi.mock('../../api', () => ({ api: { getLoginHistory: vi.fn(), getActiveSessions: vi.fn(), revokeSession: vi.fn() } }))

const renderPage = () => render(<MemoryRouter><SecurityPage embedded /></MemoryRouter>)

beforeEach(() => { vi.clearAllMocks() })

describe('SecurityPage failed reads', () => {
  it('shows the error only: no "No active sessions", no "0 sign-in events", no server text', async () => {
    api.getLoginHistory.mockRejectedValue(new Error('D1_ERROR: no such table'))
    api.getActiveSessions.mockRejectedValue(new Error('D1_ERROR: no such table'))
    renderPage()
    expect(await screen.findByText('Sessions could not be loaded. Use Reload sessions to try again.')).toBeInTheDocument()
    expect(await screen.findByText('Sign-in history could not be loaded. Use Reload history to try again.')).toBeInTheDocument()
    expect(screen.queryByText('No active sessions.')).toBeNull()
    expect(screen.queryByText('No sign-in events recorded yet.')).toBeNull()
    expect(document.body.textContent).not.toMatch(/Showing the last 0|D1_ERROR/)
  })
  it('an empty read still says it is empty', async () => {
    api.getLoginHistory.mockResolvedValue({ events: [] })
    api.getActiveSessions.mockResolvedValue({ sessions: [] })
    renderPage()
    expect(await screen.findByText('No active sessions.')).toBeInTheDocument()
    expect(await screen.findByText('No sign-in events recorded yet.')).toBeInTheDocument()
    expect(screen.getByText(/Showing the last 0 sign-in events\./)).toBeInTheDocument()
  })
})
