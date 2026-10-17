import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import ActivityTimeline from '../ActivityTimeline'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getWorkspaceActivity: vi.fn() } }))
beforeEach(() => vi.resetAllMocks())

it('shows one filter per alert family and keeps internal event IDs out of primary text', async () => {
  api.getWorkspaceActivity.mockResolvedValue({ events: [{
    id: 'event-1', entity_id: 'mcpconn_abcd1234', event_type: 'scan_completed',
    description: 'Scan completed', created_at: '2026-10-17T19:21:00Z',
  }] })
  render(<ActivityTimeline workspaceId="ws-1" />)
  expect(await screen.findByText('Scan completed')).toBeInTheDocument()
  const options = screen.getAllByRole('option').map(option => option.textContent)
  expect(options.filter(label => label.includes('Cyber Essentials'))).toEqual(['Cyber Essentials alerts'])
  expect(options.filter(label => label.includes('Shadow IT'))).toEqual(['Shadow IT alerts'])
  expect(screen.queryByText('mcpconn_abcd1234')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Copy activity reference ID' })).toHaveAttribute('title', 'mcpconn_abcd1234')
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'shadow_it_alerts' } })
  await waitFor(() => expect(api.getWorkspaceActivity).toHaveBeenLastCalledWith('ws-1', { limit: 25, offset: 0, event_type: 'shadow_it_alerts' }))
})
