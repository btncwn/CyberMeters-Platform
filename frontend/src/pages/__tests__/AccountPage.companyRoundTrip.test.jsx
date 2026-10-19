import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// P1 found live on 19 Oct 2026: the company form said "Profile saved
// successfully" and a reload showed empty fields. The page read `profile`
// from GET /api/account/profile, which returns the record as `company`, and
// country was never persisted. This drives a stateful server double with the
// real route shapes: save, reload, and every field must come back.

vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'owner-a', email: 'owner@example.test', name: 'Owner' }, updateUser: vi.fn() }) }))
vi.mock('../../api', () => ({
  api: {
    getAccountProfile: vi.fn(), getCompanyProfile: vi.fn(), updateCompanyProfile: vi.fn(), updateAccountProfile: vi.fn(),
    getSubscription: vi.fn(), getApiTokens: vi.fn(), getAccountUsage: vi.fn(), getMfaStatus: vi.fn(),
    getBrandingProfiles: vi.fn(), getNotificationPreferences: vi.fn(), updateNotificationPreferences: vi.fn(),
  },
}))
vi.mock('../SecurityPage', () => ({ default: () => <div /> }))
vi.mock('../AccountPrivacyPage', () => ({ default: () => <div /> }))

import { api } from '../../api'
import AccountPage from '../AccountPage'

// Server double for customer_profiles: PUT /api/account/company upserts, keeps
// country when the body does not send it, and both reads return `company`.
let stored = null
function serverPut(body) {
  const next = { ...(stored || {}) }
  for (const key of ['company_name', 'website', 'industry', 'company_size', 'contact_name']) next[key] = (body[key] || '').trim() || null
  next.contact_email = (body.contact_email || '').trim().toLowerCase() || null
  if (Object.hasOwn(body, 'country')) next.country = (body.country || '').trim() || null
  stored = next
  return { company: { ...stored } }
}

function renderCompany() {
  return render(
    <MemoryRouter initialEntries={['/account/company']}>
      <Routes><Route path="/account/*" element={<AccountPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.resetAllMocks()
  stored = null
  localStorage.clear()
  api.getAccountProfile.mockImplementation(async () => ({ user: { name: 'Owner' }, company: stored && { ...stored }, subscription: { plan: 'professional', status: 'trialing' } }))
  api.getCompanyProfile.mockImplementation(async () => ({ company: stored && { ...stored } }))
  // Like the real PATCH: the response carries no profile.
  api.updateCompanyProfile.mockImplementation(async (body) => serverPut(body))
  api.updateAccountProfile.mockResolvedValue({ user: { name: 'Owner' } })
  api.getSubscription.mockResolvedValue({ subscription: { plan: 'professional', status: 'trialing' } })
  api.getApiTokens.mockResolvedValue({ tokens: [] })
  api.getAccountUsage.mockResolvedValue({ plan: 'professional', usage: {}, limits: {} })
  api.getMfaStatus.mockResolvedValue({ mfa_enabled: false })
  api.getBrandingProfiles.mockResolvedValue({ profiles: [] })
  api.getNotificationPreferences.mockResolvedValue({})
})

const typed = {
  company_name: 'SheShire Ltd', website: 'https://sheshire.example', country: 'United Kingdom',
  contact_name: 'Sam Security', contact_email: 'security@sheshire.example',
}

describe('Account → Company round trip', () => {
  it('save, reload: every field comes back, country and the security contact included', async () => {
    const first = renderCompany()
    const panel = await screen.findByTestId('account-panel-company')
    for (const [name, value] of Object.entries(typed)) {
      fireEvent.change(panel.querySelector(`[name="${name}"]`), { target: { value } })
    }
    fireEvent.change(panel.querySelector('[name="industry"]'), { target: { value: 'Legal' } })
    fireEvent.change(panel.querySelector('[name="company_size"]'), { target: { value: '11-50' } })
    fireEvent.click(within(panel).getByRole('button', { name: 'Save changes' }))
    await screen.findByText('Profile saved successfully.')
    expect(stored).toMatchObject({ ...typed, industry: 'Legal', company_size: '11-50' })
    first.unmount()

    renderCompany()
    const reloaded = await screen.findByTestId('account-panel-company')
    await waitFor(() => expect(reloaded.querySelector('[name="company_name"]')).toHaveValue('SheShire Ltd'))
    for (const [name, value] of Object.entries(typed)) {
      expect(reloaded.querySelector(`[name="${name}"]`)).toHaveValue(value)
    }
    expect(reloaded.querySelector('[name="industry"]')).toHaveValue('Legal')
    expect(reloaded.querySelector('[name="company_size"]')).toHaveValue('11-50')
  })

  it('after saving, the form shows what the server holds, not what it sent', async () => {
    api.updateCompanyProfile.mockImplementation(async (body) => serverPut({ ...body, contact_email: ' Security@SheShire.example ' }))
    renderCompany()
    const panel = await screen.findByTestId('account-panel-company')
    fireEvent.change(panel.querySelector('[name="company_name"]'), { target: { value: 'SheShire Ltd' } })
    fireEvent.click(within(panel).getByRole('button', { name: 'Save changes' }))
    await screen.findByText('Profile saved successfully.')
    expect(panel.querySelector('[name="contact_email"]')).toHaveValue('security@sheshire.example')
  })
})
