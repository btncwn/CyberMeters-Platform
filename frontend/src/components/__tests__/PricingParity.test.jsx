import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Pricing parity: the frontend must never carry its own price ladder. Prices
// come exclusively from the canonical plan API (backed by the locked pricing
// policy), and an unreachable API renders an honest unavailable state — never
// a stale fallback figure the backend would refuse to charge.

vi.mock('../../api', () => ({
  api: {
    getBillingPlans: vi.fn(),
    startCheckout: vi.fn(),
  },
}))
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({ isAuthenticated: false }),
}))

import { api } from '../../api'
import PricingPage from '../../pages/PricingPage'

const CANONICAL_PLANS = [
  { key: 'free', name: '14-Day Full Trial', description: 'Full Cyber MOT for 14 days.', monthly_gbp: 0, annual_gbp: 0, checkout_enabled: false, pricing_model: { included_domains: 1, trial: { duration_days: 14, domains: 1, card_required: false } } },
  { key: 'starter', name: 'Starter', description: 'Full Cyber MOT for 1 monitored domain.', monthly_gbp: 9.99, annual_gbp: 99.9, checkout_enabled: true, pricing_model: { included_domains: 1 } },
  { key: 'professional', name: 'Professional', description: 'Up to 3 monitored domains.', monthly_gbp: 19.99, annual_gbp: 199.9, checkout_enabled: true, pricing_model: { included_domains: 3 } },
  { key: 'business', name: 'Business', description: '10 domains included.', monthly_gbp: 49.99, annual_gbp: 499.9, checkout_enabled: true, pricing_model: { included_domains: 10, additional_domain_monthly_gbp: 3, domain_hard_cap: 25 } },
  { key: 'enterprise', name: 'MSP', description: 'Base fee plus per-domain pricing.', monthly_gbp: null, annual_gbp: null, checkout_enabled: false, pricing_model: { included_domains: 0, base_monthly_gbp: 99.99, per_domain_monthly_gbp: 3, min_billed_domains: 10, floor_monthly_gbp: 129.99, floor_annual_gbp: 1299.9 } },
]

function renderPage() {
  return render(
    <MemoryRouter>
      <PricingPage />
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
})

test('renders the canonical ladder from live API data', async () => {
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  renderPage()
  await waitFor(() => expect(screen.getByText('£9.99/mo')).toBeInTheDocument())
  expect(screen.getByText('£19.99/mo')).toBeInTheDocument()
  expect(screen.getByText('£49.99/mo')).toBeInTheDocument()
  expect(screen.getByText('from £129.99/mo')).toBeInTheDocument()
  expect(screen.getByText('14-Day Full Trial')).toBeInTheDocument()
  // Business overage model is stated from API data
  expect(screen.getByText(/Add domains at £3\/month each \(up to 25\)/)).toBeInTheDocument()
})

test('annual toggle shows the exact ×10 annual figures', async () => {
  localStorage.setItem('cm_billing_interval', 'annual')
  api.getBillingPlans.mockResolvedValue({ plans: CANONICAL_PLANS })
  renderPage()
  await waitFor(() => expect(screen.getByText('£99.90/yr')).toBeInTheDocument())
  expect(screen.getByText('£199.90/yr')).toBeInTheDocument()
  expect(screen.getByText('£499.90/yr')).toBeInTheDocument()
})

test('API failure renders an honest unavailable state with NO prices', async () => {
  api.getBillingPlans.mockRejectedValue(new Error('network down'))
  const { container } = renderPage()
  await waitFor(() =>
    expect(screen.getByText(/Live pricing is temporarily unavailable/)).toBeInTheDocument(),
  )
  // No £ amount is rendered anywhere — a stale fallback ladder must not exist.
  expect(container.textContent).not.toMatch(/£\s?\d/)
})

test('no frontend source file carries a hard-coded price ladder', () => {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const src = (rel) => fs.readFileSync(path.resolve(here, rel), 'utf8')
  const files = {
    'PricingPage.jsx': src('../../pages/PricingPage.jsx'),
    'SubscriptionPage.jsx': src('../../pages/SubscriptionPage.jsx'),
    'PlanUsageCard.jsx': src('../PlanUsageCard.jsx'),
  }
  for (const [name, content] of Object.entries(files)) {
    // The discredited legacy ladder must never reappear…
    expect(content, `${name} carries a legacy price`).not.toMatch(/£\s?(29|149|399|276|1428|3828)\b/)
    // …and no price table may be defined locally at all (prices are API-only).
    expect(content, `${name} defines local monthly_gbp price data`).not.toMatch(/monthly_gbp:\s*\d/)
    // Stale domain-count claims from the pre-policy tiers.
    expect(content, `${name} claims the stale 5/20 domain tiers`).not.toMatch(/Up to (5|20) monitored domains/)
  }
})
