import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import WorkspaceExecutiveDashboard from '../WorkspaceExecutiveDashboard'
import { api } from '../../../api'

vi.mock('../../../api', () => ({ api: { getExecutiveDashboard: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'workspace-a', wsName: 'Test workspace' }),
}))

function Location() {
  return <span data-testid="location">{useLocation().pathname}</span>
}
function renderPage() {
  render(<MemoryRouter initialEntries={['/ws/executive-dashboard']}>
    <WorkspaceExecutiveDashboard />
    <Location />
  </MemoryRouter>)
}
const dashboard = { summary: { security_score: 82, domains: 1 }, score_trend: [], top_risks: [] }

beforeEach(() => vi.resetAllMocks())

describe('Executive Dashboard plan response', () => {
  it.each(['error', 'code'])('shows a plan action instead of a broken-page retry for the %s contract', async field => {
    const user = userEvent.setup()
    api.getExecutiveDashboard.mockRejectedValue(Object.assign(
      new Error('Feature requires upgrade: executive_dashboard'),
      { [field]: 'plan_feature_required', feature: 'executive_dashboard', required_plan: 'professional' },
    ))
    renderPage()

    expect(await screen.findByRole('heading', { name: 'Executive Dashboard requires an upgrade' })).toBeInTheDocument()
    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
    expect(screen.queryByText(/Feature requires upgrade:/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(screen.queryByText('Security Score')).not.toBeInTheDocument()
    expect(api.getExecutiveDashboard).toHaveBeenCalledWith('workspace-a')

    await user.click(screen.getByRole('button', { name: 'Upgrade to Professional' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/billing')
  })

  it('keeps a real service failure retryable and restores the dashboard after retry', async () => {
    const user = userEvent.setup()
    api.getExecutiveDashboard.mockRejectedValueOnce(new Error('Service unavailable')).mockResolvedValue(dashboard)
    renderPage()

    expect(await screen.findByText('Service unavailable')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Upgrade to Professional' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('82')).toBeInTheDocument()
    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
    expect(api.getExecutiveDashboard).toHaveBeenCalledTimes(2)
  })

  it('renders entitled responses without a plan prompt', async () => {
    api.getExecutiveDashboard.mockResolvedValue(dashboard)
    renderPage()
    expect(await screen.findByText('82')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Executive Dashboard' })).toBeInTheDocument()
    expect(screen.queryByText(/requires an upgrade/)).not.toBeInTheDocument()
  })
})
