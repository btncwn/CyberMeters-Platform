import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
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
  vi.spyOn(api, 'addDomainToWorkspace').mockResolvedValue({ domain: { id: DOMAIN_ID } })
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

// ── P1: the inert Verify button ─────────────────────────────────────────────
// Production: the TXT record was published and correct, yet clicking
// "I've added the DNS record — Verify domain" did nothing at all — no request, no
// spinner, no error. handleVerify opened with `if (!gated) return`, and for an
// ALREADY-LINKED domain handleStartVerification only assigned a local `record`
// without calling setGated. So gated stayed null and the click returned silently.
//
// The earlier suite missed this because it awaited getWorkspaceDomains before
// clicking, which pre-warmed gated via the debounced effect — arranging away the
// exact precondition that breaks. These tests do NOT pre-warm.
describe('REGRESSION: Verify must never be inert', () => {
  it('clicking Verify without pre-warming the lookup still calls verifyDomain', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    // Deliberately NOT waiting for the debounced resolve.
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(api.verifyDomain).toHaveBeenCalledWith(DOMAIN_ID, 'ws_turhan'))
  })

  it('gated is populated for an existing linked domain (no add-domain call)', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await screen.findByText(`_cybermeters.${DOMAIN}`)
    // Already linked => resolved, never re-linked.
    expect(api.addDomainToWorkspace).not.toHaveBeenCalled()
    await u.click(screen.getByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(api.verifyDomain).toHaveBeenCalledWith(DOMAIN_ID, 'ws_turhan'))
  })

  it('reuses the existing token — no second initiation on verify', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await screen.findByText(`_cybermeters.${DOMAIN}`)
    expect(api.generateDomainVerification).toHaveBeenCalledTimes(1)
    await u.click(screen.getByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(api.verifyDomain).toHaveBeenCalled())
    // A published TXT record must stay valid across retries.
    expect(api.generateDomainVerification).toHaveBeenCalledTimes(1)
  })

  it('a rejected promise cannot leave the UI unchanged', async () => {
    api.verifyDomain.mockRejectedValue(new Error('network'))
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    // Something visible MUST appear — silence is the bug.
    await waitFor(() => expect(screen.getByText(/could not check the DNS record|try again/i)).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /added the DNS record/i })).toBeEnabled()   // restored
  })

  it('DNS-not-found renders actionable propagation guidance, keeping the record on screen', async () => {
    api.verifyDomain.mockResolvedValue({
      success: false, verification_status: 'failed',
      checks: { dns_txt: { checked: true, result: 'not_found', error: null } },
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/not visible yet/i)).toBeInTheDocument())
    expect(screen.getByText(/propagate/i)).toBeInTheDocument()
    expect(screen.getByText(`_cybermeters.${DOMAIN}`)).toBeInTheDocument()   // never stranded
    expect(startScanBtn()).toBeDisabled()
  })

  it('a value mismatch says so, rather than blaming propagation', async () => {
    api.verifyDomain.mockResolvedValue({
      success: false, verification_status: 'failed',
      checks: { dns_txt: { checked: true, result: 'found', error: null } },
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/does not match/i)).toBeInTheDocument())
  })

  it('success enables Start Scan and does not auto-start the scan', async () => {
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText('Domain ownership verified')).toBeInTheDocument())
    expect(startScanBtn()).toBeEnabled()
    expect(api.createScan).not.toHaveBeenCalled()   // never scans on our own initiative
  })

  it('www.cybermeters.com and cybermeters.com do not share stale gated state', async () => {
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [
        { domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified' },
        { domain_id: 'domain_www', domain: `www.${DOMAIN}`, verification_status: 'unverified' },
      ],
    })
    const u = userEvent.setup()
    renderPage()
    const input = screen.getByRole('textbox')
    await u.type(input, DOMAIN)
    await waitFor(() => expect(startScanBtn()).toBeEnabled())        // verified
    await u.clear(input)
    await u.type(input, `www.${DOMAIN}`)
    // The unverified sibling must NOT inherit the verified state.
    await waitFor(() => expect(screen.getByRole('button', { name: /Verify domain ownership/i })).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })
})

// ── Structural guard ────────────────────────────────────────────────────────
// Both defects were shapes, not values: a silent early return, and a resolution
// path that updated a local variable instead of state. Assert the shapes are gone.
describe('STRUCTURAL: the defect shapes cannot return', () => {
  // vitest transforms import.meta.url to a non-file scheme, so resolve from cwd
  // (the frontend package root) instead.
  const src = readFileSync(resolve(process.cwd(), 'src/pages/NewScan.jsx'), 'utf8')
  const code = src.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
  const handleVerify = code.slice(code.indexOf('async function handleVerify'), code.indexOf('async function handleSubmit'))

  it('handleVerify has no silent return when gated is absent', () => {
    expect(handleVerify).not.toMatch(/if\s*\(\s*!gated\s*\)\s*return/)
  })

  it('every early return in handleVerify sets a visible state first', () => {
    // A bare `return` is only legal after setCheckNote/setState — never as a guard.
    const bareGuards = handleVerify.match(/^\s*if\s*\([^)]*\)\s*return\s*$/gm) || []
    expect(bareGuards).toEqual([])
  })

  it('the existing-domain resolution path sets gated', () => {
    const start = code.indexOf('async function handleStartVerification')
    const startFn = code.slice(start, code.indexOf('async function handleVerify'))
    // The `existing` branch must call setGated, not just assign a local.
    // The branch must call setGated — assigning only a local `record` is the bug.
    const branch = startFn.slice(startFn.indexOf('if (existing)'), startFn.indexOf('if (!record?.domain_id)', startFn.indexOf('if (existing)')))
    expect(branch).toContain('setGated(')
  })
})
