import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getPlanLimits } from '../../../../workers/scan-api/src/engines/plan-usage.js'

// S1-BILLING-UPGRADE (founder, 22 Oct 2026): a Professional trial could only
// "Upgrade to Business" — there was no way to buy the plan the trial is on.

vi.mock('../../api', () => ({
  api: { getWorkspaceSubscription: vi.fn(), getBillingPlans: vi.fn(), startWorkspaceCheckout: vi.fn(), openWorkspaceBillingPortal: vi.fn() },
}))
import { api } from '../../api'
import SubscriptionPage from '../SubscriptionPage'

const PLANS = { plans: [
  { key: 'starter', monthly_gbp: 9.99 }, { key: 'professional', monthly_gbp: 19.99 }, { key: 'business', monthly_gbp: 49.99 },
] }
function setup(sub, plans = PLANS) {
  localStorage.setItem('cybermeters_workspace_id', 'ws_test')
  api.getBillingPlans.mockResolvedValue(plans)
  api.startWorkspaceCheckout.mockResolvedValue({ url: null })
  api.getWorkspaceSubscription.mockResolvedValue({
    status: 'active', subscription_active: true, trial_active: false, billing_interval: 'monthly',
    cancel_at_period_end: false, grace_period_active: false, features: [], limits: getPlanLimits(sub.plan), ...sub,
  })
  return render(<MemoryRouter initialEntries={['/billing']}><SubscriptionPage /></MemoryRouter>)
}
afterEach(() => { vi.clearAllMocks(); localStorage.clear() })

describe('the plan card offers the purchase that fits', () => {
  it('a Professional trial: "Subscribe to Professional — £19.99/month" first, Business as a secondary choice', async () => {
    setup({ plan: 'professional', status: 'trialing', trial_active: true, subscription_active: true, trial_end: '2026-11-04T12:00:00Z' })
    const primary = await screen.findByTestId('plan-primary-action')
    await waitFor(() => expect(primary).toHaveTextContent('Subscribe to Professional — £19.99/month'))
    expect(screen.getByTestId('plan-secondary-action')).toHaveTextContent('Upgrade to Business instead')
    fireEvent.click(primary)
    await waitFor(() => expect(api.startWorkspaceCheckout).toHaveBeenCalledWith('ws_test', 'professional', 'monthly'))
  })
  it('the trial banner\'s "Upgrade now" starts the same Professional checkout', async () => {
    setup({ plan: 'professional', status: 'trialing', trial_active: true, subscription_active: true, trial_end: '2026-11-04T12:00:00Z' })
    fireEvent.click(await screen.findByRole('button', { name: /Upgrade now/ }))
    await waitFor(() => expect(api.startWorkspaceCheckout).toHaveBeenCalledWith('ws_test', 'professional', 'monthly'))
  })
  it('a paid Professional plan offers the Business upgrade only', async () => {
    setup({ plan: 'professional' })
    expect(await screen.findByTestId('plan-primary-action')).toHaveTextContent('Upgrade to Business')
    expect(screen.queryByTestId('plan-secondary-action')).toBeNull()
    expect(screen.queryByText(/Subscribe to Professional/)).toBeNull()
  })
  it('Starter: Professional first, Business as the secondary choice', async () => {
    setup({ plan: 'starter' })
    const primary = await screen.findByTestId('plan-primary-action')
    expect(primary).toHaveTextContent('Upgrade to Professional')
    const secondary = screen.getByTestId('plan-secondary-action')
    expect(secondary).toHaveTextContent('Upgrade to Business instead')
    fireEvent.click(secondary)
    await waitFor(() => expect(api.startWorkspaceCheckout).toHaveBeenCalledWith('ws_test', 'business', 'monthly'))
  })
  it('without live plan prices, no price is stated (never a stale number)', async () => {
    setup({ plan: 'professional', status: 'trialing', trial_active: true, subscription_active: true }, { plans: [] })
    const primary = await screen.findByTestId('plan-primary-action')
    await waitFor(() => expect(api.getBillingPlans).toHaveBeenCalled())
    expect(primary).toHaveTextContent(/^Subscribe to Professional$/)
    expect(primary.textContent).not.toMatch(/£/)
  })
})
