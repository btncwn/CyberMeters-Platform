import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AccountPage, { ACCOUNT_TABS, accountTabForPath } from '../AccountPage'
import { api } from '../../api'

// /settings merged into /account (founder, 17 Oct 2026): one page with
// sub-tabs — Profile · Company · Security · Notifications · Billing ·
// Privacy & data — one company form with the richer industry and size lists
// plus the security contact, and the billing honesty the Settings page proved.

vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'owner-a', email: 'owner@example.test', name: 'Owner', plan: 'free' }, updateUser: vi.fn() }) }))
vi.mock('../../api', () => ({
  api: {
    getAccountProfile: vi.fn(), getCompanyProfile: vi.fn(), getSubscription: vi.fn(), getApiTokens: vi.fn(), getAccountUsage: vi.fn(), getMfaStatus: vi.fn(),
    updateAccountProfile: vi.fn(), updateCompanyProfile: vi.fn(), getBrandingProfiles: vi.fn(), getNotificationPreferences: vi.fn(), updateNotificationPreferences: vi.fn(),
  },
}))
vi.mock('../SecurityPage', () => ({ default: ({ embedded }) => <div data-testid="security-embedded">{String(embedded)}</div> }))
vi.mock('../AccountPrivacyPage', () => ({ default: ({ embedded }) => <div data-testid="privacy-embedded">{String(embedded)}</div> }))

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path="/account/*" element={<AccountPage />} /><Route path="/account" element={<AccountPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.resetAllMocks()
  localStorage.clear()
  localStorage.setItem('cybermeters_workspace_id', 'ws1')
  // The real route shapes: GET /api/account/profile returns the record as
  // `company` (never `profile`); GET /api/account/company returns `company`.
  const company = { company_name: 'Acme', website: 'https://acme.test', industry: 'Legal', company_size: '11-50', country: 'United Kingdom', contact_name: 'Sam Security', contact_email: 'security@acme.test' }
  api.getAccountProfile.mockResolvedValue({ user: { name: 'Owner' }, company })
  api.getCompanyProfile.mockResolvedValue({ company })
  api.getSubscription.mockResolvedValue({ subscription: { plan: 'business', status: 'trialing', billing_provider: 'stripe' } })
  api.getApiTokens.mockResolvedValue({ tokens: [] })
  api.getAccountUsage.mockResolvedValue({ plan: 'business', usage: { workspaces: 2 }, limits: { workspaces: 5, domains: 10, users: 5, history_days: 365 } })
  api.getMfaStatus.mockResolvedValue({ mfa_enabled: false })
  api.getBrandingProfiles.mockResolvedValue({ profiles: [], white_label_available: true })
  api.getNotificationPreferences.mockResolvedValue({ email_frequency: 'critical_only' })
  api.updateAccountProfile.mockResolvedValue({ user: { name: 'Owner' } })
  api.updateCompanyProfile.mockResolvedValue({ company: {} })
})

describe('accountTabForPath', () => {
  it('maps /account and its sub-paths to tabs, unknown to profile', () => {
    expect(accountTabForPath('/account')).toBe('profile')
    expect(accountTabForPath('/account/company')).toBe('company')
    expect(accountTabForPath('/account/privacy/')).toBe('privacy')
    expect(accountTabForPath('/account/nope')).toBe('profile')
    expect(ACCOUNT_TABS.map((t) => t.label)).toEqual(['Profile', 'Company', 'Security', 'Notifications', 'Billing', 'Privacy & data'])
  })
})

describe('AccountPage tabs', () => {
  it('renders the six tabs with the current one selected and Profile by default', async () => {
    renderAt('/account')
    await screen.findByTestId('account-panel-profile')
    const tabs = screen.getAllByRole('tab')
    expect(tabs.map((t) => t.textContent)).toEqual(['Profile', 'Company', 'Security', 'Notifications', 'Billing', 'Privacy & data'])
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[1]).toHaveAttribute('href', '/account/company')
    expect(screen.getByDisplayValue('Owner')).toBeInTheDocument()
    expect(screen.queryByText('Company')).toBeInTheDocument() // the tab only
    expect(screen.queryByDisplayValue('Acme')).toBeNull()
  })

  it('Company: one form with the richer industry and size lists and the security contact; saving writes the company record and re-reads it', async () => {
    renderAt('/account/company')
    const panel = await screen.findByTestId('account-panel-company')
    expect(screen.getByTestId('account-tab-company')).toHaveAttribute('aria-selected', 'true')
    expect(panel.querySelectorAll('form')).toHaveLength(1)
    const industry = within(panel).getByDisplayValue('Legal')
    expect(within(industry).getByRole('option', { name: 'Financial Services' })).toBeInTheDocument()
    const size = within(panel).getByDisplayValue('11–50 employees')
    expect(within(size).getByRole('option', { name: '1,000+ employees' })).toBeInTheDocument()
    expect(within(panel).getByDisplayValue('Sam Security')).toBeInTheDocument()
    expect(within(panel).getByDisplayValue('security@acme.test')).toBeInTheDocument()
    fireEvent.click(within(panel).getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(api.updateCompanyProfile).toHaveBeenCalledTimes(1))
    expect(api.updateCompanyProfile).toHaveBeenCalledWith(expect.objectContaining({ company_name: 'Acme', industry: 'Legal', company_size: '11-50', country: 'United Kingdom', contact_name: 'Sam Security', contact_email: 'security@acme.test' }))
    await waitFor(() => expect(api.getCompanyProfile).toHaveBeenCalledTimes(2))
    expect(api.updateAccountProfile).not.toHaveBeenCalled()
  })

  it('Security: MFA, API tokens and the embedded sessions/login history', async () => {
    renderAt('/account/security')
    await screen.findByTestId('account-panel-security')
    expect(screen.getByText('Two-step sign-in')).toBeInTheDocument()
    expect(screen.getByText('Works with any authenticator app.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Turn on two-step sign-in' })).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/Two-Factor|\bMFA\b|Google Authenticator|Authy|1Password|Bitwarden/)
    expect(screen.getByPlaceholderText('e.g. CI pipeline')).toBeInTheDocument()
    expect(screen.getByText('API tokens')).toBeInTheDocument()
    expect(screen.getByTestId('security-embedded')).toHaveTextContent('true')
  })

  it('Notifications: the email-frequency card and the link to the workspace alert channels', async () => {
    renderAt('/account/notifications')
    await screen.findByTestId('account-panel-notifications')
    await waitFor(() => expect(screen.getByRole('radio', { name: /Critical only/ })).toBeChecked())
    expect(screen.getByRole('link', { name: 'Alert channels' })).toHaveAttribute('href', '/ws/alerts')
  })

  it('Billing: current plan, honest status, agency report branding and the billing link', async () => {
    renderAt('/account/billing')
    await screen.findByText('No agency profiles saved.')
    expect(screen.getByText('Trial')).toBeInTheDocument()
    expect(screen.queryByText('Active')).toBeNull()
    expect(screen.getByRole('link', { name: 'Manage billing' })).toHaveAttribute('href', '/billing')
    expect(within(screen.getByRole('region', { name: 'Agency report branding' })).getByRole('button', { name: 'Add agency profile' })).toBeEnabled()
    expect(screen.queryByText(/upcoming release/)).toBeNull()
  })

  it('Billing honesty: a failed subscription read is Unavailable, an unknown status is Unknown, an ended trial is Trial ended — never Active', async () => {
    api.getSubscription.mockRejectedValue(new Error('boom'))
    const { unmount } = renderAt('/account/billing')
    await screen.findByText('No agency profiles saved.')
    expect(screen.getByText('Unavailable')).toBeInTheDocument()
    expect(screen.queryByText('Active')).toBeNull()
    unmount()
    api.getSubscription.mockResolvedValue({ subscription: { plan: 'starter', status: 'incomplete_expired', billing_provider: 'stripe' } })
    const second = renderAt('/account/billing')
    await screen.findByText('No agency profiles saved.')
    expect(screen.getByText('Unknown')).toBeInTheDocument()
    expect(screen.queryByText('Active')).toBeNull()
    second.unmount()
    api.getSubscription.mockResolvedValue({ subscription: { plan: 'free', status: 'trial_expired', billing_provider: 'cybermeters' } })
    renderAt('/account/billing')
    await screen.findByText('No agency profiles saved.')
    expect(screen.getByText('Trial ended')).toBeInTheDocument()
  })

  it('Privacy & data embeds the privacy page without its own header, even when the account profile cannot be read', async () => {
    api.getAccountProfile.mockRejectedValue(new Error('profile unavailable'))
    renderAt('/account/privacy')
    await screen.findByTestId('account-panel-privacy')
    expect(screen.getByTestId('privacy-embedded')).toHaveTextContent('true')
    expect(screen.queryByText('profile unavailable')).toBeNull()
  })

  it('Notifications renders without waiting on the account load; Profile still reports a failed read', async () => {
    api.getAccountProfile.mockRejectedValue(new Error('profile unavailable'))
    const first = renderAt('/account/notifications')
    await screen.findByTestId('account-panel-notifications')
    first.unmount()
    const second = renderAt('/account')
    expect(await screen.findByRole('alert')).toHaveTextContent('Your profile could not be loaded. Reload the page to try again.')
    expect(screen.queryByText('profile unavailable')).toBeNull()
    second.unmount()
  })

  // Design standard §3 (22 Oct 2026): a failed profile read blocks only Profile.
  it('a failed profile read does not hide Security, Company or Billing', async () => {
    api.getAccountProfile.mockRejectedValue(new Error('profile unavailable'))
    for (const [route, panel] of [['/account/security', 'security'], ['/account/company', 'company'], ['/account/billing', 'billing']]) {
      const view = renderAt(route)
      expect(await screen.findByTestId(`account-panel-${panel}`)).toBeInTheDocument()
      expect(screen.queryByText(/profile could not be loaded/)).toBeNull()
      view.unmount()
    }
  })
})
