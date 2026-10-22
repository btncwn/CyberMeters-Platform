import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import AccountPage from '../AccountPage'

// Founder, 22 Oct 2026: a 14-day trial read "Professional plan". The billing tab
// uses the account menu's wording, from the same session fields.
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u1', email: 'owner@example.test', name: 'Owner', plan: 'professional', is_trial: true, trial_end: '2026-11-04T12:00:00.000Z' }, updateUser: vi.fn() }),
}))
vi.mock('../../api', () => ({
  api: {
    getAccountProfile: vi.fn().mockResolvedValue({}), getCompanyProfile: vi.fn().mockResolvedValue({ company: {} }),
    getSubscription: vi.fn().mockResolvedValue({ subscription: { plan: 'professional', status: 'trialing', billing_provider: 'stripe', trial_ends_at: '2026-11-04T12:00:00.000Z' } }),
    getApiTokens: vi.fn().mockResolvedValue({ tokens: [] }), getAccountUsage: vi.fn().mockResolvedValue(null), getMfaStatus: vi.fn().mockResolvedValue({ mfa_enabled: false }),
    getWorkspaces: vi.fn().mockResolvedValue({ workspaces: [] }), getNotificationPreferences: vi.fn().mockResolvedValue({}),
  },
}))

describe('billing tab during a trial', () => {
  it('reads "Professional trial · ends 4 Nov", never "Professional plan"', async () => {
    render(<MemoryRouter initialEntries={['/account/billing']}><Routes><Route path="/account/:tab" element={<AccountPage />} /></Routes></MemoryRouter>)
    expect(await screen.findByTestId('trial-plan-label')).toHaveTextContent('Professional trial · ends 4 Nov')
    expect(screen.queryByText('Professional plan')).toBeNull()
    expect(api.getSubscription).toHaveBeenCalled()
  })
})
