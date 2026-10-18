import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import OnboardingPage from '../OnboardingPage'
import { api } from '../../api'
import { PENDING_SIGNUP_DOMAIN_KEY } from '../../utils/signupDomainHandoff'
import {
  RECORD_PREPARE_FAILED, VERIFY_NOT_FOUND_YET, VERIFY_RECORD_REFRESHED, VERIFY_VALUE_MISMATCH,
} from '../../lib/onboardingCopy'

// getDomain (the legacy per-user row) is deliberately absent: onboarding must
// never read verification state from it.
vi.mock('../../api', () => ({ api: {
  getWorkspaces: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceScans: vi.fn(), getScan: vi.fn(),
  addDomainToWorkspace: vi.fn(), generateDomainVerification: vi.fn(), verifyDomain: vi.fn(),
} }))
vi.mock('../../hooks/useDomainConnectOffer', () => ({ useDomainConnectOffer: () => null }))
vi.mock('../../components/OneClickDnsButton', () => ({ default: () => null }))

const TOKEN = 'a1'.repeat(24)
const TOKEN_2 = 'b2'.repeat(24)
const SERVER_TEXT = 'No verification token found. Call POST /api/domains/:id/verification first.'

let link // the workspace's link row as the server holds it
function linkRow() { return { domain_id: 'dom-1', domain: 'sheshire.co.uk', ...link } }

function issue(token) {
  return () => {
    link = { verification_status: 'pending', verification_token: token }
    return Promise.resolve({
      domain: 'sheshire.co.uk', domain_id: 'dom-1', workspace_id: 'ws-1', verification_status: 'pending', token,
      dns: { record_type: 'TXT', host: '_cybermeters.sheshire.co.uk', value: `cybermeters-verification=${token}` },
    })
  }
}

function apiError(status, body) {
  return Object.assign(new Error(body.error), { status, ...(body.code ? { code: body.code } : {}), ...(body.outcome ? { outcome: body.outcome } : {}) })
}

// The guard: no route path or server instruction ever reaches the page.
function expectNoServerText() {
  expect(document.body.textContent).not.toMatch(/\/api\/|Call POST/)
}

function step3() {
  return screen.getByRole('heading', { name: 'Verify Domain' }).closest('section')
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  link = { verification_status: 'unverified', verification_token: null }
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws-1', name: 'Sheshire' }] })
  api.getWorkspaceDomains.mockImplementation(() => Promise.resolve({ domains: [linkRow()] }))
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
  api.generateDomainVerification.mockImplementation(issue(TOKEN))
})

it('fresh signup: the free-check domain is added, its record is issued automatically and shown, and verify fails politely then succeeds', async () => {
  localStorage.setItem(PENDING_SIGNUP_DOMAIN_KEY, 'sheshire.co.uk')
  let added = false
  api.getWorkspaceDomains.mockImplementation(() => Promise.resolve({ domains: added ? [linkRow()] : [] }))
  api.addDomainToWorkspace.mockImplementation(() => { added = true; return Promise.resolve({ domain: { domain_id: 'dom-1', domain: 'sheshire.co.uk', workspace_id: 'ws-1' } }) })
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)

  const input = await screen.findByPlaceholderText('example.com')
  expect(input).toHaveValue('sheshire.co.uk')
  fireEvent.click(screen.getByRole('button', { name: 'Add Domain' }))

  // Step 3 opened with no record on the link: it is issued for THIS workspace without a click.
  await waitFor(() => expect(api.generateDomainVerification).toHaveBeenCalledWith('dom-1', 'ws-1'))
  const record = await within(step3()).findByTestId('onboarding-dns-record')
  expect(within(record).getByText(`cybermeters-verification=${TOKEN}`)).toBeInTheDocument()
  expect(within(record).getByText('_cybermeters.sheshire.co.uk')).toBeInTheDocument()
  expect(api.generateDomainVerification).toHaveBeenCalledTimes(1)

  // One primary action; no "Get DNS Record"; Advanced verification is a link.
  expect(screen.queryByRole('button', { name: /get dns record/i })).toBeNull()
  expect(within(step3()).getByRole('link', { name: 'Advanced verification' })).toHaveAttribute('href', '/domains/dom-1/verify')
  const verify = within(step3()).getByRole('button', { name: 'Verify ownership' })

  api.verifyDomain.mockResolvedValueOnce({ success: false, outcome: 'dns_not_found', message: 'Verification not confirmed yet — server words' })
  fireEvent.click(verify)
  expect(await within(step3()).findByText(VERIFY_NOT_FOUND_YET)).toBeInTheDocument()
  expect(api.verifyDomain).toHaveBeenCalledWith('dom-1', 'ws-1')
  expect(screen.queryByText(/server words/)).toBeNull()
  expect(within(step3()).getByTestId('onboarding-verify-note').className).not.toMatch(/brand/)
  expectNoServerText()

  // The record is now published: the next attempt verifies.
  api.verifyDomain.mockImplementationOnce(() => { link = { verification_status: 'verified', verification_token: TOKEN }; return Promise.resolve({ success: true, outcome: 'verified_dns_txt' }) })
  fireEvent.click(within(step3()).getByRole('button', { name: 'Verify ownership' }))
  expect(await within(step3()).findByText('Domain ownership is verified.')).toBeInTheDocument()
  expectNoServerText()
})

it('shows the token already on the workspace link and does not issue a new one', async () => {
  link = { verification_status: 'pending', verification_token: TOKEN }
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  expect(await screen.findByText(`cybermeters-verification=${TOKEN}`)).toBeInTheDocument()
  expect(api.generateDomainVerification).not.toHaveBeenCalled()
})

it('a no-token refusal prepares a fresh record and says so in plain words, never the server text', async () => {
  // The page shows a record, but the server has none for this link (the live incident).
  link = { verification_status: 'pending', verification_token: TOKEN }
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  await screen.findByText(`cybermeters-verification=${TOKEN}`)
  api.generateDomainVerification.mockImplementation(issue(TOKEN_2))
  api.verifyDomain.mockRejectedValueOnce(apiError(400, { error: SERVER_TEXT, outcome: 'no_token' }))

  fireEvent.click(within(step3()).getByRole('button', { name: 'Verify ownership' }))
  expect(await within(step3()).findByText(VERIFY_RECORD_REFRESHED)).toBeInTheDocument()
  expect(api.generateDomainVerification).toHaveBeenCalledWith('dom-1', 'ws-1')
  expect(await screen.findByText(`cybermeters-verification=${TOKEN_2}`)).toBeInTheDocument()
  expect(screen.queryByText(`cybermeters-verification=${TOKEN}`)).toBeNull()
  expectNoServerText()
})

it('maps a wrong value and an unknown refusal to plain copy', async () => {
  link = { verification_status: 'pending', verification_token: TOKEN }
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  await screen.findByText(`cybermeters-verification=${TOKEN}`)
  api.verifyDomain.mockResolvedValueOnce({ success: false, outcome: 'dns_mismatch', message: 'raw mismatch text' })
  fireEvent.click(within(step3()).getByRole('button', { name: 'Verify ownership' }))
  expect(await within(step3()).findByText(VERIFY_VALUE_MISMATCH)).toBeInTheDocument()

  api.verifyDomain.mockRejectedValueOnce(apiError(500, { error: 'D1_ERROR: no such column — see /api/debug' }))
  fireEvent.click(within(step3()).getByRole('button', { name: 'Verify ownership' }))
  expect(await within(step3()).findByText('We couldn’t finish the check just now. Please try again.')).toBeInTheDocument()
  expect(screen.queryByText(/D1_ERROR|raw mismatch/)).toBeNull()
  expectNoServerText()
})

it('when the record cannot be prepared it says so plainly and offers to try again', async () => {
  api.generateDomainVerification.mockRejectedValueOnce(apiError(500, { error: 'Call POST /api/domains/:id/verification — internal' }))
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  expect(await within(await screen.findByTestId('onboarding-verify')).findByText(RECORD_PREPARE_FAILED)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Verify ownership' })).toBeNull()
  expectNoServerText()

  fireEvent.click(within(step3()).getByRole('button', { name: 'Try again' }))
  expect(await screen.findByText(`cybermeters-verification=${TOKEN}`)).toBeInTheDocument()
  expect(within(step3()).getByRole('button', { name: 'Verify ownership' })).toBeInTheDocument()
})

it('never renders server text for a failed domain add', async () => {
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  api.addDomainToWorkspace.mockRejectedValueOnce(apiError(400, { error: 'domain is required — POST /api/workspaces/:id/domains' }))
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  fireEvent.change(await screen.findByPlaceholderText('example.com'), { target: { value: 'not a domain' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add Domain' }))
  expect(await screen.findByText('Enter a domain like example.com — no https:// or www.')).toBeInTheDocument()
  expectNoServerText()
})
