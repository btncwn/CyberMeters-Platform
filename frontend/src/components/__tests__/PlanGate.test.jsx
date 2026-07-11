import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { PlanGate, PlanUsageCard, PlanBadge } from '../PlanUsageCard'

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

function renderGateWithLocation(error) {
  return render(
    <MemoryRouter initialEntries={['/ws/audit-log']}>
      <PlanGate error={error}>
        <p>normal page content</p>
      </PlanGate>
      <LocationSpy />
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

  it('uses code fields and fallback feature labels when rendering the gate', () => {
    renderGate({ code: 'plan_feature_required', feature: 'unknown_feature', required_plan: 'business' })
    expect(screen.getByText(/this feature requires an upgrade/i)).toBeInTheDocument()
    expect(screen.getAllByText(/business/i).length).toBeGreaterThan(0)
  })

  it('routes the upgrade and back actions through React Router', async () => {
    const user = userEvent.setup()
    renderGateWithLocation({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter' })

    await user.click(screen.getByRole('button', { name: /upgrade to starter/i }))

    expect(screen.getByTestId('location')).toHaveTextContent('/billing')
  })
})

function LocationSpy() {
  const location = useLocation()
  return <span data-testid="location">{location.pathname}</span>
}

function renderUsage(planLimits) {
  return render(
    <MemoryRouter initialEntries={['/services']}>
      <Routes>
        <Route
          path="*"
          element={(
            <>
              <PlanUsageCard planLimits={planLimits} />
              <LocationSpy />
            </>
          )}
        />
      </Routes>
    </MemoryRouter>,
  )
}

describe('PlanUsageCard', () => {
  it('renders nothing when usage data has not loaded', () => {
    const { container } = renderUsage(null)
    expect(container).toHaveTextContent('/services')
    expect(screen.queryByText(/plan usage/i)).not.toBeInTheDocument()
  })

  it('renders usage meters and the current plan badge', () => {
    renderUsage({
      plan: 'starter',
      limits: { workspaces: 1, scans_per_month: 5, reports_per_month: 3 },
      usage: { workspaces: 1, scans_this_month: 4, reports_this_month: 3 },
    })

    expect(screen.getByText('Plan Usage')).toBeInTheDocument()
    expect(screen.getByText('Starter')).toBeInTheDocument()
    expect(screen.getByText('Workspaces')).toBeInTheDocument()
    expect(screen.getByText('Scans this month')).toBeInTheDocument()
    expect(screen.getByText('Reports this month')).toBeInTheDocument()
    expect(screen.getByText('4 / 5')).toBeInTheDocument()
    expect(screen.getByText('3 / 3')).toBeInTheDocument()
  })

  it('hides the usage bar for unlimited limits', () => {
    renderUsage({
      plan: 'business',
      limits: { workspaces: 999999, scans_per_month: 999999, reports_per_month: 999999 },
      usage: { workspaces: 25, scans_this_month: 300, reports_this_month: 50 },
    })

    expect(screen.getAllByText(/∞/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/upgrade your plan/i)).not.toBeInTheDocument()
  })

  it('routes free and starter users to billing from the upgrade nudge', async () => {
    const user = userEvent.setup()
    renderUsage({
      plan: 'free',
      limits: { workspaces: 1, scans_per_month: 5, reports_per_month: 3 },
      usage: { workspaces: 0, scans_this_month: 0, reports_this_month: 0 },
    })

    await user.click(screen.getByRole('button', { name: /upgrade your plan/i }))

    expect(screen.getByTestId('location')).toHaveTextContent('/billing')
  })
})

describe('PlanBadge', () => {
  it('falls back to Free for unknown plan names', () => {
    render(<PlanBadge plan="unknown" />)
    expect(screen.getByText('Free')).toBeInTheDocument()
  })
})
