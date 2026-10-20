import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { getPlanLimits, getPlanRetentionDays, retentionDaysToPolicy } from '../../../../workers/scan-api/src/engines/plan-usage.js'
import { BILLING_PLAN_METADATA } from '../../../../workers/scan-api/src/engines/entitlements.js'

// Pricing truth (founder, 20 Oct 2026). Report history has one source: the
// plan card, the retention the Worker enforces and the report_retention label
// must agree. Business shows its 10 included domains and offers no overage
// while per-domain billing is not wired to Stripe.

vi.mock('../../api', () => ({
  api: {
    getWorkspaceSubscription: vi.fn(),
    getBillingPlans: vi.fn(),
    startWorkspaceCheckout: vi.fn(),
    openWorkspaceBillingPortal: vi.fn(),
  },
}))

import { api } from '../../api'
import SubscriptionPage from '../../pages/SubscriptionPage'

const EXPECTED = { starter: 90, professional: 365, business: 730, enterprise: null }

afterEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
})

describe('report history: one source of truth', () => {
  it.each(Object.entries(EXPECTED))('%s keeps reports for the days the founder set', (plan, days) => {
    expect(getPlanRetentionDays(plan)).toBe(days)
    expect(getPlanLimits(plan).report_retention).toBe(retentionDaysToPolicy(days))
  })

  it('no plan label claims longer than reports are kept', () => {
    expect(getPlanLimits('professional').report_retention).toBe('1_year')
    expect(getPlanLimits('business').report_retention).toBe('2_years')
    expect(getPlanLimits('enterprise').report_retention).toBe('forever')
  })

  it.each(Object.entries(EXPECTED))('the %s plan card shows the retention the code enforces', async (plan, days) => {
    localStorage.setItem('cybermeters_workspace_id', 'ws_test')
    api.getBillingPlans.mockResolvedValue({ plans: [] })
    api.getWorkspaceSubscription.mockResolvedValue({
      plan, status: 'active', subscription_active: true, trial_active: false, billing_interval: 'monthly',
      cancel_at_period_end: false, grace_period_active: false, features: [],
      limits: getPlanLimits(plan),
    })
    render(<MemoryRouter initialEntries={['/billing']}><SubscriptionPage /></MemoryRouter>)
    const label = await waitFor(() => screen.getByText('Report history (days)'))
    expect(label.nextElementSibling.textContent).toBe(days === null ? 'Unlimited' : days.toLocaleString('en-GB'))
  })
})

describe('Business domains', () => {
  it('the plan API offers no per-domain overage while it cannot be billed', () => {
    const business = BILLING_PLAN_METADATA.business
    expect(business.pricing_model.included_domains).toBe(10)
    expect(business.pricing_model).not.toHaveProperty('additional_domain_monthly_gbp')
    expect(business.pricing_model).not.toHaveProperty('domain_hard_cap')
    expect(business.description).not.toMatch(/25|expand/i)
    expect(getPlanLimits('business').domains).toBe(10)
  })
})
