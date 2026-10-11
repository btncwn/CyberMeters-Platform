import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ReportSnapshotHistory from '../ReportSnapshotHistory'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getReportSnapshots: vi.fn(), getWorkspaceDomains: vi.fn() } }))
beforeEach(() => { vi.resetAllMocks() })
const view = () => render(<MemoryRouter><ReportSnapshotHistory wsId="ws1" /></MemoryRouter>)

describe('ReportSnapshotHistory', () => {
  it('loads only when opened and lists snapshots read-only', async () => {
    api.getReportSnapshots.mockResolvedValue({ snapshots: [
      { id: 's2', scan_id: 'scan2', domain_id: 'd1', assessed_at: '2026-10-10T10:00:00Z', scan_quality: 'complete', superseded_by: null },
      { id: 's1', scan_id: 'scan1', domain_id: 'd1', assessed_at: '2026-10-01T10:00:00Z', scan_quality: 'complete', superseded_by: 's2' },
    ], pagination: { has_more: false } })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain_id: 'd1', domain: 'acme.test' }] })
    view()
    expect(api.getReportSnapshots).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Show history' }))
    expect(await screen.findByText('Latest for this domain')).toBeInTheDocument()
    expect(screen.getByText('Superseded by a later scan')).toBeInTheDocument()
    expect(screen.getAllByText('acme.test')).toHaveLength(2)
    expect(screen.getAllByRole('link', { name: 'Scan details' })[0]).toHaveAttribute('href', '/scans/scan2')
    expect(screen.queryByRole('button', { name: /delete|regenerate/i })).toBeNull()
  })

  it('a failed read is shown as an error', async () => {
    api.getReportSnapshots.mockRejectedValue(new Error('500'))
    api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
    view()
    fireEvent.click(screen.getByRole('button', { name: 'Show history' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Snapshot history could not be loaded.')
  })

  it('no snapshots says when one appears', async () => {
    api.getReportSnapshots.mockResolvedValue({ snapshots: [], pagination: { has_more: false } })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
    view()
    fireEvent.click(screen.getByRole('button', { name: 'Show history' }))
    expect(await screen.findByText(/One is recorded after each completed scan/)).toBeInTheDocument()
  })
})
