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
    expect(screen.getByText('business')).toBeInTheDocument(); expect(screen.getByText('trialing')).toBeInTheDocument(); expect(screen.queryByText('free')).not.toBeInTheDocument()
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
