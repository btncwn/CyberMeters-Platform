import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import NewScan from '../NewScan'
import { api } from '../../api'

// Integration test for the P1 production deadlock.
//
// Observed live: a valid domain showed "Valid domain format…", Start Scan was
// disabled, the helper said "Verify domain ownership to enable scanning" — and NO
// verification CTA existed anywhere. The panel was only reachable from the
// createScan error path, which a disabled button can never trigger. The customer
// had a valid domain and no way forward.
//
// The unit suite passed throughout, because it tested the state helpers in
// isolation and nobody drove the real page. This test drives the page.

vi.mock('../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws_turhan', wsName: 'Turhan Workspace', workspaces: [], loading: false, setWorkspace: () => {} }),
}))

const DOMAIN = 'cybermeters.com'
const DOMAIN_ID = 'domain_31d8ebf3'

const dnsResponse = {
  domain: DOMAIN,
  domain_id: DOMAIN_ID,
  workspace_id: 'ws_turhan',
  verification_status: 'pending',
  token: 'abc123def456',
  dns: {
    record_type: 'TXT',
    host: `_cybermeters.${DOMAIN}`,
    value: 'cybermeters-verification=abc123def456',
  },
}

function renderPage() {
  return render(<MemoryRouter><NewScan /></MemoryRouter>)
}
const typeDomain = (u) => u.type(screen.getByRole('textbox'), DOMAIN)
const startScanBtn = () => screen.getByRole('button', { name: /Start Scan/i })

beforeEach(() => {
  vi.restoreAllMocks()
  // The domain is linked to this workspace but NOT verified — the live state.
  vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({
    workspace_id: 'ws_turhan',
    domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'unverified' }],
  })
  vi.spyOn(api, 'generateDomainVerification').mockResolvedValue(dnsResponse)
  vi.spyOn(api, 'verifyDomain').mockResolvedValue({ verified: true, verification_status: 'verified' })
  vi.spyOn(api, 'createScan').mockResolvedValue({ scan: { id: 'scan_1' } })
})

describe('REGRESSION: the production deadlock state', () => {
  it('a valid unverified domain offers "Verify domain ownership" — never a dead end', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    // This is the exact screenshot state: valid syntax, unverified, no instructions.
    await waitFor(() => expect(screen.getByRole('button', { name: /Verify domain ownership/i })).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
    expect(screen.queryByText(/ready to scan/i)).toBeNull()
  })

  it('does NOT require a failed scan to discover the record', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(screen.getByRole('button', { name: /Verify domain ownership/i })).toBeInTheDocument())
    // Resolution happens through the workspace-scoped lookup, on its own (debounced).
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalledWith('ws_turhan'))
    // The deadlock existed because the record was only learned from a failed scan.
    expect(api.createScan).not.toHaveBeenCalled()
  })
})

describe('the CTA drives the canonical flow', () => {
  it('calls the canonical initiation route with the resolved record', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalled())
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await waitFor(() =>
      // Exact record from the workspace-scoped lookup — never guessed by hostname.
      expect(api.generateDomainVerification).toHaveBeenCalledWith(DOMAIN_ID, 'ws_turhan'))
  })

  it('shows the TXT instructions returned by the backend', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalled())
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    expect(await screen.findByText(`_cybermeters.${DOMAIN}`)).toBeInTheDocument()
    expect(screen.getByText('cybermeters-verification=abc123def456')).toBeInTheDocument()
    expect(screen.getByText('TXT')).toBeInTheDocument()
    expect(screen.getByText(/Cloudflare: DNS/)).toBeInTheDocument()
    expect(screen.getByLabelText('Copy host')).toBeInTheDocument()
    expect(screen.getByLabelText('Copy value')).toBeInTheDocument()
  })

  it('keeps Start Scan disabled while instructions are shown', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalled())
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await screen.findByText(`_cybermeters.${DOMAIN}`)
    expect(startScanBtn()).toBeDisabled()
  })

  it('successful verification enables Start Scan', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalled())
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText('Domain ownership verified')).toBeInTheDocument())
    expect(startScanBtn()).toBeEnabled()
  })
})

describe('already-verified domains skip setup', () => {
  it('enables Start Scan with no CTA', async () => {
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified' }],
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(startScanBtn()).toBeEnabled())
    expect(screen.queryByRole('button', { name: /Verify domain ownership/i })).toBeNull()
  })

  it('fails closed when the lookup errors — never claims verified', async () => {
    api.getWorkspaceDomains.mockRejectedValue(new Error('network'))
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await waitFor(() => expect(screen.getByRole('button', { name: /Verify domain ownership/i })).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })
})

describe('never leaks a machine code', () => {
  it('renders no raw backend identifier on the gate path', async () => {
    const u = userEvent.setup()
    const { container } = renderPage()
    await typeDomain(u)
    await screen.findByRole('button', { name: /Verify domain ownership/i })
    expect(container.textContent).not.toMatch(/domain_verification_required/)
  })
})
