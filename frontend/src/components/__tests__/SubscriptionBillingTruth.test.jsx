import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Billing-surface truth (M7 acceptance findings):
//  P2 — the Subscription card must reflect the subscription's ACTUAL billing
//       interval. An annual subscriber is charged the annual price; showing the
//       plan's monthly headline ("£49.99/mo" for a £499.90/year subscription)
//       mis-states what they pay. If the annual figure is unavailable, show NO
//       price — never the monthly number an annual customer is not charged.
//  P3 — the retired "Vendor Risk Intelligence" / "Vendor Risk Analysis" /
//       "Supply Chain Intelligence" claims must not be advertised on billing
//       or upgrade surfaces.

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
import { PlanGate } from '../PlanUsageCard'

const CANONICAL_PLANS = [
  { key: 'starter', name: 'Starter', monthly_gbp: 9.99, annual_gbp: 99.9, annual_equivalent_monthly_gbp: 8.33, checkout_enabled: true, pricing_model: { included_domains: 1 } },
  { key: 'professional', name: 'Professional', monthly_gbp: 19.99, annual_gbp: 199.9, annual_equivalent_monthly_gbp: 16.66, checkout_enabled: true, pricing_model: { included_domains: 3 } },
  { key: 'business', name: 'Business', monthly_gbp: 49.99, annual_gbp: 499.9, annual_equivalent_monthly_gbp: 41.66, checkout_enabled: true, pricing_model: { included_domains: 10 } },
  { key: 'enterprise', name: 'MSP', monthly_gbp: null, annual_gbp: null, annual_equivalent_monthly_gbp: null, checkout_enabled: false, pricing_model: { included_domains: 0, floor_monthly_gbp: 129.99, floor_annual_gbp: 1299.9 } },
]

function subFixture(overrides = {}) {
  return {
    plan: 'business',
    status: 'active',
    subscription_active: true,
    trial_active: false,
    trial_remaining_days: 0,
    trial_start: null,
    trial_end: null,
    current_period_start: '2026-07-20 00:00:00',
    current_period_end: '2027-07-20 00:00:00',
    billing_interval: 'monthly',
    cancel_at_period_end: false,
    cancelled_at: null,
    grace_period_active: false,
    grace_period_ends_at: null,
    stripe_subscription_id: 'sub_test_123',
    limits: { domains: 10, users: 10, history_days: 365 },
    features: ['scheduled_scans', 'alerts', 'pdf_reports', 'business_risk_score', 'cyber_essentials', 'vendor_risk', 'executive_dashboard', 'audit_logs', 'portfolio_monitoring', 'white_label'],
    ...overrides,
  }
}

function renderPage() {
  return render(
    <MemoryRouter>
      <SubscriptionPage />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  localStorage.setItem('cybermeters_workspace_id', 'ws_test')
})

afterEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
})

// ── P2: billing-interval truth ───────────────────────────────────────────────

test('ANNUAL subscription renders the annual price, never the monthly headline', async () => {
  api.getWorkspaceSubscription.mockResolvedValue(subFixture({ billing_interval: 'annual' }))
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  renderPage()
  await waitFor(() => expect(screen.getByText('£499.90')).toBeInTheDocument())
  expect(screen.getByText('/ year')).toBeInTheDocument()
  expect(screen.getByText(/≈ £41\.66\/mo · billed annually/)).toBeInTheDocument()
  // The founder-confirmed defect: the monthly headline for an annual sub.
  expect(screen.queryByText('£49.99')).not.toBeInTheDocument()
  expect(screen.queryByText('/ month')).not.toBeInTheDocument()
})

test('ANNUAL Professional subscription renders £199.90/year, not £19.99/mo', async () => {
  api.getWorkspaceSubscription.mockResolvedValue(subFixture({ plan: 'professional', billing_interval: 'annual', limits: { domains: 3, users: 5, history_days: 365 } }))
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  renderPage()
  await waitFor(() => expect(screen.getByText('£199.90')).toBeInTheDocument())
  expect(screen.getByText('/ year')).toBeInTheDocument()
  expect(screen.queryByText('£19.99')).not.toBeInTheDocument()
})

test('MONTHLY subscription still renders the monthly price', async () => {
  api.getWorkspaceSubscription.mockResolvedValue(subFixture({ billing_interval: 'monthly' }))
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  renderPage()
  await waitFor(() => expect(screen.getByText('£49.99')).toBeInTheDocument())
  expect(screen.getByText('/ month')).toBeInTheDocument()
  expect(screen.queryByText('/ year')).not.toBeInTheDocument()
})

test('annual sub with NO live annual figure shows NO price — never the monthly fallback', async () => {
  const plansWithoutAnnual = CANONICAL_PLANS.map((p) =>
    p.key === 'business' ? { ...p, annual_gbp: null, annual_equivalent_monthly_gbp: null } : p,
  )
  api.getWorkspaceSubscription.mockResolvedValue(subFixture({ billing_interval: 'annual' }))
  api.getBillingPlans.mockResolvedValue({ plans: plansWithoutAnnual })
  const { container } = renderPage()
  await waitFor(() => expect(screen.getByText('Business')).toBeInTheDocument())
  // Fail honest: no amount at all rather than an amount the customer is not charged.
  expect(container.textContent).not.toMatch(/£\s?\d/)
})

test('trial (not a paid annual sub) keeps the prospective monthly display', async () => {
  api.getWorkspaceSubscription.mockResolvedValue(subFixture({
    plan: 'professional', status: 'trialing', trial_active: true, trial_remaining_days: 10,
    trial_end: '2026-07-31 00:00:00', billing_interval: 'monthly', stripe_subscription_id: null,
    limits: { domains: 1, users: 5, history_days: 365 },
  }))
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  renderPage()
  await waitFor(() => expect(screen.getByText('£19.99')).toBeInTheDocument())
  expect(screen.getByText('/ month')).toBeInTheDocument()
})

// ── P3: retired claims are not advertised on billing surfaces ────────────────

test('billing page advertises no retired Vendor Risk / Supply Chain Intelligence claim', async () => {
  api.getWorkspaceSubscription.mockResolvedValue(subFixture({ plan: 'professional', billing_interval: 'monthly' }))
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  const { container } = renderPage()
  await waitFor(() => expect(screen.getByText('£19.99')).toBeInTheDocument())
  expect(container.textContent).not.toMatch(/Vendor Risk/i)
  expect(container.textContent).not.toMatch(/Supply Chain Intelligence/i)
  // The gated feature is still advertised — under its honest label.
  expect(screen.getByText('Third-party technology detection')).toBeInTheDocument()
})

test('PlanGate upgrade wall for vendor_risk uses the honest label, no retired claims', () => {
  const { container } = render(
    <MemoryRouter>
      <PlanGate error={{ error: 'plan_feature_required', feature: 'vendor_risk', required_plan: 'professional' }}>
        <div>content</div>
      </PlanGate>
    </MemoryRouter>,
  )
  expect(screen.getByText(/Third-party technology detection requires an upgrade/)).toBeInTheDocument()
  expect(container.textContent).not.toMatch(/Vendor Risk/i)
  expect(container.textContent).not.toMatch(/Supply Chain Intelligence/i)
})

// ── Source guard: the retired claims must not reappear in billing sources ────

test('no billing-surface source file carries a retired Vendor Risk claim', () => {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const src = (rel) => fs.readFileSync(path.resolve(here, rel), 'utf8')
  const files = {
    'SubscriptionPage.jsx': src('../../pages/SubscriptionPage.jsx'),
    'PlanUsageCard.jsx': src('../PlanUsageCard.jsx'),
  }
  for (const [name, content] of Object.entries(files)) {
    expect(content, `${name} advertises a retired claim`).not.toMatch(/Vendor Risk (Intelligence|Analysis)/)
    expect(content, `${name} advertises a retired claim`).not.toMatch(/Supply Chain Intelligence/)
    expect(content, `${name} advertises a retired claim`).not.toMatch(/Vendor & Supply Chain Risk/)
  }
})
