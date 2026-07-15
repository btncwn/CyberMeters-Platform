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
  const unverifiedRow = { domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'unverified', verified_at: null }
  const verifiedRow   = { domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified', verified_at: '2026-07-15T10:50:00Z' }

  vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ workspace_id: 'ws_turhan', domains: [unverifiedRow] })
  vi.spyOn(api, 'generateDomainVerification').mockResolvedValue(dnsResponse)
  vi.spyOn(api, 'createScan').mockResolvedValue({ scan: { id: 'scan_1' } })
  vi.spyOn(api, 'addDomainToWorkspace').mockResolvedValue({ domain: { id: DOMAIN_ID } })

  // Model production: verifyDomain PERSISTS the row, so the authoritative reread
  // that follows sees verified + verified_at. A verify that does NOT persist is the
  // false-success case — covered explicitly in the TRUST suite below.
  vi.spyOn(api, 'verifyDomain').mockImplementation(async () => {
    api.getWorkspaceDomains.mockResolvedValue({ workspace_id: 'ws_turhan', domains: [verifiedRow] })
    return { success: true, verification_status: 'verified', verification_method: 'dns_txt' }
  })
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
      domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified', verified_at: '2026-07-15T10:50:00Z' }],
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
        { domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified', verified_at: '2026-07-15T10:50:00Z' },
        { domain_id: 'domain_www', domain: `www.${DOMAIN}`, verification_status: 'unverified', verified_at: null },
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

// ── P1 TRUST BUG: verified shown while the record was pending ───────────────
// Production: the UI reported "Domain ownership verified" and enabled Start Scan
// while workspace_domains was verification_status='pending', verified_at=NULL, with
// no domain_verified notification and no audit event. The UI trusted the verify
// response's own success field, then refreshed authoritative state but was barred
// from downgrading — so a false success became permanent on screen.
//
// A "verified" claim must come from persisted server state for the EXACT record.
describe('TRUST: verified is only ever derived from authoritative persisted state', () => {
  it('a verify response claiming success CANNOT show verified when the record stays pending', async () => {
    // Server says success; the persisted row disagrees. The row wins.
    api.verifyDomain.mockResolvedValue({ success: true, verification_status: 'verified' })
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'pending', verified_at: null }],
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument())
    expect(screen.queryByText('Domain ownership verified')).toBeNull()
    expect(startScanBtn()).toBeDisabled()          // the exact production bug
  })

  it('generic success:true alone cannot set verified', async () => {
    api.verifyDomain.mockResolvedValue({ success: true })   // no status, no verified_at
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'pending', verified_at: null }],
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })

  it('verified WITHOUT verified_at cannot set verified', async () => {
    api.verifyDomain.mockResolvedValue({ success: true, verification_status: 'verified' })
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified', verified_at: null }],
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })

  it('a verified row for a DIFFERENT domain_id cannot set verified', async () => {
    api.verifyDomain.mockResolvedValue({ success: true, verification_status: 'verified' })
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [
        { domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'pending', verified_at: null },
        { domain_id: 'domain_other', domain: 'other.com', verification_status: 'verified', verified_at: '2026-07-15T00:00:00Z' },
      ],
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })

  it('an unreadable reread cannot set verified', async () => {
    api.verifyDomain.mockResolvedValue({ success: true, verification_status: 'verified' })
    let calls = 0
    api.getWorkspaceDomains.mockImplementation(async () => {
      calls += 1
      if (calls === 1) return { workspace_id: 'ws_turhan', domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'pending', verified_at: null }] }
      throw new Error('network')   // the reread fails
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })

  it('the initiation response cannot set verified on its own', async () => {
    // already_verified is a claim about a record we must still re-read.
    api.generateDomainVerification.mockResolvedValue({ already_verified: true, verification_status: 'verified' })
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'pending', verified_at: null }],
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await waitFor(() => expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument())
    expect(startScanBtn()).toBeDisabled()
  })

  it('ONLY an authoritative verified reread enables Start Scan', async () => {
    api.verifyDomain.mockResolvedValue({ success: true, verification_status: 'verified' })
    let calls = 0
    api.getWorkspaceDomains.mockImplementation(async () => {
      calls += 1
      const status = calls === 1 ? { verification_status: 'pending', verified_at: null }
                                 : { verification_status: 'verified', verified_at: '2026-07-15T10:50:00Z' }
      return { workspace_id: 'ws_turhan', domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, ...status }] }
    })
    const u = userEvent.setup()
    renderPage()
    await typeDomain(u)
    await u.click(await screen.findByRole('button', { name: /Verify domain ownership/i }))
    await u.click(await screen.findByRole('button', { name: /added the DNS record/i }))
    await waitFor(() => expect(screen.getByText('Domain ownership verified')).toBeInTheDocument())
    expect(startScanBtn()).toBeEnabled()
  })

  it('stale verified state cannot leak to another domain', async () => {
    api.getWorkspaceDomains.mockResolvedValue({
      workspace_id: 'ws_turhan',
      domains: [
        { domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified', verified_at: '2026-07-15T00:00:00Z' },
        { domain_id: 'domain_www', domain: `www.${DOMAIN}`, verification_status: 'pending', verified_at: null },
      ],
    })
    const u = userEvent.setup()
    renderPage()
    const input = screen.getByRole('textbox')
    await u.type(input, DOMAIN)
    await waitFor(() => expect(startScanBtn()).toBeEnabled())
    await u.clear(input)
    await u.type(input, `www.${DOMAIN}`)
    await waitFor(() => expect(startScanBtn()).toBeDisabled())
    expect(screen.queryByText('Domain ownership verified')).toBeNull()
  })
})

// ── Structural trust guard ──────────────────────────────────────────────────
describe('STRUCTURAL: no optimistic verified state may exist', () => {
  const src = readFileSync(resolve(process.cwd(), 'src/pages/NewScan.jsx'), 'utf8')
  const code = src.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')

  it("setState('verified') exists in exactly one place — the authoritative confirmer", () => {
    const hits = code.match(/setState\('verified'\)/g) || []
    expect(hits.length).toBe(1)
    const confirm = code.slice(code.indexOf('async function confirmVerifiedOrExplain'), code.indexOf('async function resolveGatedRecord'))
    expect(confirm).toMatch(/setState\('verified'\)/)
    expect(confirm).toMatch(/isAuthoritativeVerified\(/)
  })

  it('every verified transition is gated by isAuthoritativeVerified', () => {
    // Any ternary/assignment producing 'verified' must sit behind the contract.
    const ternary = code.match(/setState\([^)]*\?\s*'verified'/g) || []
    for (const t of ternary) expect(t).toMatch(/isAuthoritativeVerified/)
  })

  it('the verify response fields are never trusted directly for a verified transition', () => {
    const handler = code.slice(code.indexOf('async function handleVerify'), code.indexOf('async function handleSubmit'))
    // It may CALL verifyResponseClaimsSuccess, but must not setState('verified') itself.
    expect(handler).not.toMatch(/setState\('verified'\)/)
    expect(handler).toMatch(/confirmVerifiedOrExplain\(/)
  })
})
