import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import WorkspaceRetentionPage from '../WorkspaceRetentionPage'
import { api } from '../../../api'

vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws-1', wsName: 'Example' }) }))
vi.mock('../../../components/WorkspaceUsageCard', () => ({ default: () => <div>Current plan usage</div> }))
vi.mock('../../../api', () => ({ api: { getWorkspaceStorage: vi.fn(), getWorkspaceRetention: vi.fn() } }))
beforeEach(() => vi.resetAllMocks())

it('uses Professional and omits empty metric tiles and filler storage content', async () => {
  api.getWorkspaceStorage.mockResolvedValue({ report_count: 4, storage_mb: 2.5, retention_days: null, auto_cleanup: null })
  api.getWorkspaceRetention.mockResolvedValue({ plan: 'professional', retention_days: 365, auto_cleanup: false })
  render(<MemoryRouter><WorkspaceRetentionPage /></MemoryRouter>)
  expect(await screen.findByText('4')).toBeInTheDocument()
  expect(screen.getByRole('cell', { name: 'Professional' })).toBeInTheDocument()
  expect(screen.queryByRole('cell', { name: 'Pro' })).toBeNull()
  expect(screen.queryByText('Storage insights')).toBeNull()
  const storageCard = screen.getByText('Storage Usage').closest('.card')
  expect(within(storageCard).queryByText('—')).toBeNull()
  expect(within(storageCard).queryByText('Auto cleanup')).toBeNull()
})
