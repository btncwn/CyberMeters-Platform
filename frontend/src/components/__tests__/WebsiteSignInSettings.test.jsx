import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WebsiteSignInSettings from '../WebsiteSignInSettings'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getWebsiteSignIn: vi.fn(), saveWebsiteSignIn: vi.fn(), deleteWebsiteSignIn: vi.fn(), testWebsiteSignIn: vi.fn() } }))

const profile = {
  id: 'wsip_1', method: 'form', login_url: 'https://acme.test/login', start_url: 'https://acme.test/account', signed_in_text: null,
  credential_hint: 'j•••@acme.test', status: 'active', paused_reason: null, last_signed_in_at: null, consecutive_failures: 0,
}
const listing = (over = {}) => ({ can_manage: true, can_use: true, reason: null, scope_note: 'Read-only requests.', domains: [{ domain_id: 'd1', domain: 'acme.test', profile: null, recent_attempts: [] }], ...over })

beforeEach(() => { vi.resetAllMocks() })

describe('WebsiteSignInSettings', () => {
  it('sets up a profile only after the authorization is confirmed, and sends the password only on save', async () => {
    api.getWebsiteSignIn.mockResolvedValue(listing())
    api.saveWebsiteSignIn.mockResolvedValue({ ok: true, status: 201, body: { profile } })
    render(<WebsiteSignInSettings workspaceId="ws1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Set up' }))
    fireEvent.change(screen.getByLabelText('Test account username or email'), { target: { value: 'jane@acme.test' } })
    fireEvent.change(screen.getByLabelText('Test account password'), { target: { value: 'pw' } })
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(save)
    await waitFor(() => expect(api.saveWebsiteSignIn).toHaveBeenCalledTimes(1))
    const [ws, domain, body] = api.saveWebsiteSignIn.mock.calls[0]
    expect([ws, domain]).toEqual(['ws1', 'acme.test'])
    expect(body).toMatchObject({ method: 'form', login_url: 'https://acme.test/login', username: 'jane@acme.test', password: 'pw', authorization_confirmed: true })
    expect(await screen.findByText(/Use “Test sign-in” to check it now/)).toBeInTheDocument()
  })

  it('editing keeps the saved password unless a new one is typed', async () => {
    api.getWebsiteSignIn.mockResolvedValue(listing({ domains: [{ domain_id: 'd1', domain: 'acme.test', profile, recent_attempts: [] }] }))
    api.saveWebsiteSignIn.mockResolvedValue({ ok: true, status: 200, body: { profile } })
    render(<WebsiteSignInSettings workspaceId="ws1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    expect(screen.getByLabelText('Test account password')).toHaveAttribute('placeholder', 'Saved — leave blank to keep')
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.saveWebsiteSignIn).toHaveBeenCalled())
    expect(api.saveWebsiteSignIn.mock.calls[0][2]).not.toHaveProperty('password')
  })

  it('shows a test result with what to do, and session facts without values', async () => {
    api.getWebsiteSignIn.mockResolvedValue(listing({ domains: [{ domain_id: 'd1', domain: 'acme.test', profile, recent_attempts: [] }] }))
    api.testWebsiteSignIn.mockResolvedValue({ ok: true, status: 200, body: { outcome: 'signed_in', detail: { basis: 'anonymous_refused', cookies_at_sign_in: [{ name: 'sid', secure: true, httponly: false }], session_cookie_renewed: 'renewed' } } })
    render(<WebsiteSignInSettings workspaceId="ws1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Test sign-in' }))
    expect(await screen.findByText('Signed in')).toBeInTheDocument()
    expect(screen.getByText(/refused a request without it/)).toBeInTheDocument()
    expect(screen.getByText('Cookie sid set at sign-in without HttpOnly')).toBeInTheDocument()
  })

  it('a refused sign-in explains itself; a paused profile says why', async () => {
    api.getWebsiteSignIn.mockResolvedValue(listing({ domains: [{ domain_id: 'd1', domain: 'acme.test', profile: { ...profile, status: 'paused', paused_reason: 'repeated_sign_in_failures' },
      recent_attempts: [{ id: 'a1', source: 'scan', outcome: 'sign_in_redirects_offsite', detail: {}, created_at: '2026-10-11T00:00:00Z' }] }] }))
    render(<WebsiteSignInSettings workspaceId="ws1" />)
    expect(await screen.findByText(/Paused after 3 refused sign-ins/)).toBeInTheDocument()
    expect(screen.getByText('Sign-in continues on another site')).toBeInTheDocument()
    expect(screen.getByText(/use the header or cookie method/)).toBeInTheDocument()
  })

  it('viewers see status but no controls; plan and load failures are explicit', async () => {
    api.getWebsiteSignIn.mockResolvedValue(listing({ can_manage: false, can_use: false, reason: 'session_role_required' }))
    const { unmount } = render(<WebsiteSignInSettings workspaceId="ws1" />)
    expect(await screen.findByText('Only a workspace owner or admin can set this up.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Set up' })).toBeNull()
    unmount()
    api.getWebsiteSignIn.mockRejectedValue(new Error('503'))
    render(<WebsiteSignInSettings workspaceId="ws1" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
  })

  it('a rate-limited test is shown in place, not as a global error', async () => {
    api.getWebsiteSignIn.mockResolvedValue(listing({ domains: [{ domain_id: 'd1', domain: 'acme.test', profile, recent_attempts: [] }] }))
    api.testWebsiteSignIn.mockResolvedValue({ ok: false, status: 429, body: { code: 'rate_limit_exceeded' } })
    render(<WebsiteSignInSettings workspaceId="ws1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Test sign-in' }))
    expect(await screen.findByText(/Try again in an hour/)).toBeInTheDocument()
  })
})
