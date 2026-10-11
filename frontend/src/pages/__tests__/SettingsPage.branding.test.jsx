import React from 'react'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import SettingsPage from '../SettingsPage'
import { api } from '../../api'
vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'owner-a', email: 'owner@example.test', plan: 'free' }, updateUser: vi.fn() }) }))
vi.mock('../../api', () => ({ api: { getAccountProfile: vi.fn(), getCompanyProfile: vi.fn(), getSubscription: vi.fn(), getAccountUsage: vi.fn(), getBrandingProfiles: vi.fn() } }))
beforeEach(() => {
  vi.resetAllMocks(); api.getAccountProfile.mockResolvedValue({ user: { name: 'Owner' }, subscription: null }); api.getCompanyProfile.mockResolvedValue({ company: {} })
  api.getSubscription.mockResolvedValue({ subscription: { plan: 'business', status: 'trialing', billing_provider: 'stripe' } }); api.getAccountUsage.mockResolvedValue({ plan: 'business', usage: { workspaces: 2 }, limits: { workspaces: 5, domains: 10, users: 5, history_days: 90 } })
  api.getBrandingProfiles.mockResolvedValue({ profiles: [], white_label_available: true })
})
describe('Settings current billing and agency branding', () => {
  it('mounts real V2 profiles and displays current API plan instead of stale auth plan', async () => {
    render(<MemoryRouter><SettingsPage /></MemoryRouter>); await screen.findByText('No agency profiles saved.')
    expect(screen.getByText('business')).toBeInTheDocument(); expect(screen.getByTestId('subscription-status')).toHaveTextContent('Trial'); expect(screen.queryByText('Active')).not.toBeInTheDocument(); expect(screen.queryByText('free')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Manage billing' })).toHaveAttribute('href', '/billing'); expect(screen.queryByText(/Payment integration is not enabled/)).not.toBeInTheDocument(); expect(screen.queryByText('Upgrade coming soon')).not.toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Agency report branding' })).getByRole('button', { name: 'Add agency profile' })).toBeEnabled()
  })
  it('does not fabricate free, active or a payment provider when billing data is missing', async () => {
    api.getSubscription.mockResolvedValue({}); api.getAccountUsage.mockResolvedValue(null)
    render(<MemoryRouter><SettingsPage /></MemoryRouter>); await screen.findByText('No agency profiles saved.')
    expect(screen.getAllByText('Unavailable')).toHaveLength(3); expect(screen.queryByText('active')).not.toBeInTheDocument(); expect(screen.queryByText('free')).not.toBeInTheDocument(); expect(screen.queryByText('manual')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Manage billing' })).toBeInTheDocument()
  })
})

describe('Settings subscription status honesty', () => {
  it('shows Unavailable, not a free/active state, when the subscription cannot be read', async () => {
    api.getSubscription.mockRejectedValue(new Error('boom'))
    render(<MemoryRouter><SettingsPage /></MemoryRouter>); await screen.findByText('No agency profiles saved.')
    expect(screen.getByTestId('subscription-status')).toHaveTextContent('Unavailable')
    expect(screen.queryByText('Active')).not.toBeInTheDocument()
  })
  it('an unrecognised backend status reads Unknown, never Active', async () => {
    api.getSubscription.mockResolvedValue({ subscription: { plan: 'starter', status: 'incomplete_expired', billing_provider: 'stripe' } })
    render(<MemoryRouter><SettingsPage /></MemoryRouter>); await screen.findByText('No agency profiles saved.')
    expect(screen.getByTestId('subscription-status')).toHaveTextContent('Unknown')
    expect(screen.queryByText('Active')).not.toBeInTheDocument()
  })
  it('a trial that has ended reads Trial ended', async () => {
    api.getSubscription.mockResolvedValue({ subscription: { plan: 'free', status: 'trial_expired', billing_provider: 'cybermeters' } })
    render(<MemoryRouter><SettingsPage /></MemoryRouter>); await screen.findByText('No agency profiles saved.')
    expect(screen.getByTestId('subscription-status')).toHaveTextContent('Trial ended')
  })
})
