import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { PlanGate } from '../PlanUsageCard'

// Billing-state rendering: the frontend half of the contract the backend
// pipeline test proves server-side (403 {error:'plan_feature_required',
// required_plan:'professional'} on gated endpoints).

function renderGate(error) {
  return render(
    <MemoryRouter>
      <PlanGate error={error}>
        <p>normal page content</p>
      </PlanGate>
    </MemoryRouter>,
  )
}

describe('PlanGate (billing state rendering)', () => {
  it('renders the upgrade wall for a plan_feature_required API error', () => {
    renderGate({ error: 'plan_feature_required', feature: 'audit_logs', required_plan: 'professional' })
    expect(screen.getByText(/requires an upgrade/i)).toBeInTheDocument()
    // "Professional" appears in both the plan sentence and the feature box.
    expect(screen.getAllByText(/professional/i).length).toBeGreaterThan(0)
    expect(screen.queryByText('normal page content')).not.toBeInTheDocument()
  })

  it('falls through to the page for any other error', () => {
    renderGate({ error: 'server_error' })
    expect(screen.getByText('normal page content')).toBeInTheDocument()
    expect(screen.queryByText(/requires an upgrade/i)).not.toBeInTheDocument()
  })

  it('renders the page normally when there is no error at all', () => {
    renderGate(null)
    expect(screen.getByText('normal page content')).toBeInTheDocument()
  })
})
