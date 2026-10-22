import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Found live on 19 Oct 2026 on a Professional trial: the plan card promised
// 3 domains while the trial limit was 1, the countdown showed "14 days left"
// beside "Day 0 of 14", "Upgrade now" looked disabled, a workspace used at its
// limit painted a red danger bar, and new API tokens defaulted to never expire.

vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'owner-a', email: 'owner@example.test', name: 'Owner', plan: 'professional' }, updateUser: vi.fn() }) }))
vi.mock('../../api', () => ({
  api: {
    getWorkspaceSubscription: vi.fn(), getBillingPlans: vi.fn(), startWorkspaceCheckout: vi.fn(), openWorkspaceBillingPortal: vi.fn(),
    getAccountProfile: vi.fn(), getCompanyProfile: vi.fn(), getSubscription: vi.fn(), getApiTokens: vi.fn(), createApiToken: vi.fn(), getAccountUsage: vi.fn(), getMfaStatus: vi.fn(),
    updateAccountProfile: vi.fn(), updateCompanyProfile: vi.fn(), getBrandingProfiles: vi.fn(), getNotificationPreferences: vi.fn(), updateNotificationPreferences: vi.fn(),
  },
}))
vi.mock('../SecurityPage', () => ({ default: () => <div /> }))
vi.mock('../AccountPrivacyPage', () => ({ default: () => <div /> }))

import { api } from '../../api'
import SubscriptionPage, { planCardDescription } from '../SubscriptionPage'
import AccountPage from '../AccountPage'
import { PlanUsageCard } from '../../components/PlanUsageCard'

const PLANS = [
  { key: 'starter', name: 'Starter', monthly_gbp: 9.99, annual_gbp: 99.9, checkout_enabled: true, pricing_model: { included_domains: 1 } },
  { key: 'professional', name: 'Professional', monthly_gbp: 19.99, annual_gbp: 199.9, checkout_enabled: true, pricing_model: { included_domains: 3 } },
]

function trialSub(overrides = {}) {
  return {
    plan: 'professional', status: 'trialing', subscription_active: true, trial_active: true,
    trial_remaining_days: 14, trial_start: '2026-10-19 09:00:00', trial_end: '2026-11-02 09:00:00',
    billing_interval: 'monthly', cancel_at_period_end: false,
    limits: { domains: 1, users: 3, history_days: 90 }, features: ['scheduled_scans'],
    ...overrides,
  }
}

beforeEach(() => {
  vi.resetAllMocks()
  localStorage.clear()
  localStorage.setItem('cybermeters_workspace_id', 'ws1')
  api.getBillingPlans.mockResolvedValue({ plans: PLANS })
})

describe('Subscription page during the trial', () => {
  it('says what applies now and what the plan gives after the trial', async () => {
    api.getWorkspaceSubscription.mockResolvedValue(trialSub())
    render(<MemoryRouter><SubscriptionPage /></MemoryRouter>)
    const description = await screen.findByTestId('plan-card-description')
    expect(description).toHaveTextContent(/^During the trial: 1 monitored domain\. On Professional: up to 3 monitored domains/)
  })

  it('keeps the plan description unchanged outside the trial', () => {
    const meta = { label: 'Professional', description: 'Up to 3 monitored domains, plus more.' }
    expect(planCardDescription(meta, { trialActive: false, trialDomains: 1 })).toBe('Up to 3 monitored domains, plus more.')
    expect(planCardDescription(meta, { trialActive: true, trialDomains: null })).toBe('Up to 3 monitored domains, plus more.')
    expect(planCardDescription(meta, { trialActive: true, trialDomains: 2 })).toBe('During the trial: 2 monitored domains. On Professional: up to 3 monitored domains, plus more.')
  })

  it('shows one day count and an active Upgrade now button', async () => {
    api.getWorkspaceSubscription.mockResolvedValue(trialSub())
    render(<MemoryRouter><SubscriptionPage /></MemoryRouter>)
    await screen.findByText('14 days left in your 14-day full trial')
    expect(screen.queryByText(/Day \d+ of 14/)).not.toBeInTheDocument()
    expect(screen.queryByText(/days remaining/)).not.toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: 'Trial time used' })).toHaveAttribute('aria-valuetext', '14 of 14 days left')
    const upgrade = screen.getByRole('button', { name: 'Upgrade now' })
    expect(upgrade).toBeEnabled()
    expect(upgrade.className).toContain('bg-brand-700')
    expect(upgrade.className).not.toContain('bg-brand-200')
  })
})

describe('Usage bars', () => {
  it('use a neutral colour at the limit and red only over it', () => {
    const { rerender } = render(<MemoryRouter><PlanUsageCard planLimits={{ plan: 'professional', limits: { workspaces: 1, scans_per_month: 10, reports_per_month: 10 }, usage: { workspaces: 1 } }} /></MemoryRouter>)
    const atLimit = document.querySelector('[data-usage="at-limit"]')
    expect(atLimit.className).toContain('bg-brand-700')
    expect(document.querySelector('.bg-red-500')).toBeNull()
    rerender(<MemoryRouter><PlanUsageCard planLimits={{ plan: 'professional', limits: { workspaces: 1, scans_per_month: 10, reports_per_month: 10 }, usage: { workspaces: 2 } }} /></MemoryRouter>)
    expect(document.querySelector('[data-usage="over"]').className).toContain('bg-red-500')
  })
})

function renderAccount(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path="/account/*" element={<AccountPage />} /><Route path="/account" element={<AccountPage />} /></Routes>
    </MemoryRouter>,
  )
}

describe('Account page', () => {
  beforeEach(() => {
    api.getAccountProfile.mockResolvedValue({ user: { name: 'Owner' }, profile: { company_name: 'Acme' } })
    api.getCompanyProfile.mockResolvedValue({ company: { company_name: 'Acme' } })
    api.getSubscription.mockResolvedValue({ subscription: { plan: 'professional', status: 'trialing', billing_provider: 'stripe' } })
    api.getApiTokens.mockResolvedValue({ tokens: [] })
    api.getAccountUsage.mockResolvedValue({ plan: 'professional', usage: { workspaces: 1 }, limits: { workspaces: 1, domains: 3, users: 3, history_days: 90 } })
    api.getMfaStatus.mockResolvedValue({ mfa_enabled: false })
    api.getBrandingProfiles.mockResolvedValue({ profiles: [], white_label_available: false })
    api.getNotificationPreferences.mockResolvedValue({})
  })

  it('Billing: Workspaces 1 / 1 is normal use, not a red danger bar', async () => {
    renderAccount('/account/billing')
    await screen.findByText('1 / 1')
    expect(document.querySelector('[data-usage="at-limit"]').className).toContain('bg-brand-700')
    expect(screen.getByText('1 / 1').className).not.toContain('text-red-700')
    expect(document.querySelector('.bg-red-500')).toBeNull()
  })

  it('API tokens default to 90 days, with Never still an explicit choice', async () => {
    api.createApiToken.mockResolvedValue({ token: 'cm_test_token' })
    renderAccount('/account/security')
    await screen.findByText('API Tokens')
    const expires = screen.getAllByRole('combobox').find((el) => within(el).queryByRole('option', { name: 'Never' }))
    expect(expires).toHaveValue('90')
    fireEvent.change(screen.getByPlaceholderText('e.g. CI pipeline'), { target: { value: 'CI' } })
    const before = Date.now()
    fireEvent.click(screen.getByRole('button', { name: 'Generate token' }))
    await waitFor(() => expect(api.createApiToken).toHaveBeenCalledTimes(1))
    const { expires_at } = api.createApiToken.mock.calls[0][0]
    const days = (Date.parse(expires_at) - before) / 86_400_000
    expect(days).toBeGreaterThan(89)
    expect(days).toBeLessThan(91.1)
    await waitFor(() => expect(expires).toHaveValue('90'))
    fireEvent.change(expires, { target: { value: 'never' } })
    expect(expires).toHaveValue('never')
  })
})
