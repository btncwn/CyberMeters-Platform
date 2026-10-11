import React from 'react'
import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceUsageCard from '../WorkspaceUsageCard'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getWorkspaceUsage: vi.fn() } }))
beforeEach(() => { vi.resetAllMocks() })

describe('WorkspaceUsageCard', () => {
  it('shows this month for the workspace with shared allowances', async () => {
    api.getWorkspaceUsage.mockResolvedValue({
      period_start: '2026-10-01T00:00:00.000Z',
      current_period: { scans_used: 12, scans_completed: 10, reports_generated: 3, scheduled_reports_generated: 1, active_assets: 40, workspace_report_count: 2, storage_bytes: 500000, storage_estimated: true },
      limits: { scans_per_month: 100, reports_per_month: 50 },
    })
    render(<WorkspaceUsageCard workspaceId="ws1" />)
    expect(await screen.findByText('12')).toBeInTheDocument()
    expect(api.getWorkspaceUsage).toHaveBeenCalledWith('ws1')
    expect(screen.getByText('Plan: 100 scans a month (shared)')).toBeInTheDocument()
    expect(screen.getByText(/shared by all workspaces/)).toBeInTheDocument()
    expect(screen.getByText('2 stored reports, about 500 KB (estimated).')).toBeInTheDocument()
  })

  it('a load failure is shown, not zeros', async () => {
    api.getWorkspaceUsage.mockRejectedValue(new Error('500'))
    render(<WorkspaceUsageCard workspaceId="ws1" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Usage could not be loaded.')
    expect(screen.queryByText('0')).toBeNull()
  })
})
