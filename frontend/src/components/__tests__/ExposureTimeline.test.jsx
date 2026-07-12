import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../api'
import ExposureTimeline from '../ExposureTimeline'

vi.mock('../../api', () => ({
  api: { getExposureFeed: vi.fn() },
}))

const evt = (over = {}) => ({
  id: 'evt_1', created_at: '2026-03-20T09:12:00Z', event_type: 'email_dmarc_policy_changed',
  category: 'email', severity: 'high', hostname: 'acme.co.uk',
  title: 'DMARC policy changed', description: 'DMARC policy changed: reject → none', ...over,
})
const feed = (events, over = {}) => ({
  workspace_id: 'ws1', events,
  pagination: { limit: 50, offset: 0, total: events.length, has_more: false, ...over },
})

beforeEach(() => { api.getExposureFeed.mockReset() })

describe('ExposureTimeline', () => {
  it('renders enriched events with title, description and severity badge', async () => {
    api.getExposureFeed.mockResolvedValue(feed([evt(), evt({ id: 'evt_2', title: 'New subdomain', category: 'asset', severity: 'info', description: 'New asset discovered: shop.acme.co.uk' })]))
    render(<ExposureTimeline workspaceId="ws1" />)
    expect(await screen.findByText('DMARC policy changed')).toBeInTheDocument()
    expect(screen.getByText('DMARC policy changed: reject → none')).toBeInTheDocument()
    expect(screen.getByText('New subdomain')).toBeInTheDocument()
    // severity badge text present
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('shows the first-run empty state when there are no changes', async () => {
    api.getExposureFeed.mockResolvedValue(feed([]))
    render(<ExposureTimeline workspaceId="ws1" />)
    expect(await screen.findByText(/No changes recorded yet/i)).toBeInTheDocument()
    expect(screen.getByText(/builds as we re-scan/i)).toBeInTheDocument()
  })

  it('sends the category filter to the API when a chip is clicked', async () => {
    api.getExposureFeed.mockResolvedValue(feed([evt()]))
    render(<ExposureTimeline workspaceId="ws1" />)
    await screen.findByText('DMARC policy changed')
    await userEvent.click(screen.getByRole('button', { name: 'Email' }))
    await waitFor(() =>
      expect(api.getExposureFeed).toHaveBeenLastCalledWith('ws1', expect.objectContaining({ category: 'email' })),
    )
  })

  it('paginates: shows Load more and fetches the next page on click', async () => {
    api.getExposureFeed
      .mockResolvedValueOnce(feed([evt({ id: 'p1' })], { has_more: true, total: 2 }))
      .mockResolvedValueOnce(feed([evt({ id: 'p2', title: 'IP address changed', category: 'dns' })], { has_more: false, total: 2 }))
    render(<ExposureTimeline workspaceId="ws1" />)
    await screen.findByText('DMARC policy changed')
    const more = screen.getByRole('button', { name: /Load more/i })
    await userEvent.click(more)
    await waitFor(() =>
      expect(api.getExposureFeed).toHaveBeenLastCalledWith('ws1', expect.objectContaining({ offset: 1 })),
    )
    expect(await screen.findByText('IP address changed')).toBeInTheDocument()
  })
})
