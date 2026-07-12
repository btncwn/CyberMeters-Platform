import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../api'
import RecentChangesCard from '../RecentChangesCard'

vi.mock('../../api', () => ({ api: { getExposureFeed: vi.fn() } }))

const renderCard = (wsId = 'ws1') =>
  render(<MemoryRouter><RecentChangesCard workspaceId={wsId} /></MemoryRouter>)

beforeEach(() => api.getExposureFeed.mockReset())

describe('RecentChangesCard', () => {
  it('renders the latest changes with a link to the full timeline', async () => {
    api.getExposureFeed.mockResolvedValue({
      events: [{ id: 'e1', category: 'email', severity: 'high', title: 'DMARC policy changed', created_at: '2026-03-20T09:12:00Z' }],
      pagination: { total: 1 },
    })
    renderCard()
    expect(await screen.findByText('DMARC policy changed')).toBeInTheDocument()
    expect(screen.getByText(/View timeline/i)).toBeInTheDocument()
    expect(api.getExposureFeed).toHaveBeenCalledWith('ws1', { limit: 5 })
  })

  it('renders nothing when there are no recent changes', async () => {
    api.getExposureFeed.mockResolvedValue({ events: [], pagination: { total: 0 } })
    const { container } = renderCard()
    await waitFor(() => expect(api.getExposureFeed).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })
})
