import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import NewScan from '../NewScan'
import { api } from '../../api'

// Live finding (18 Oct 2026): an analyst typed a domain on /scans/new and got a
// red "Something went wrong · Forbidden — admin role required to add domains"
// with a Retry, beside a "Verify domain ownership" button they cannot use. The
// page now reads the role: an analyst rescans the workspace's verified domains,
// a viewer reads one calm sentence; any role refusal lands there too.

vi.mock('../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws_bbb', wsName: 'Black Bull Barbers', workspaces: [], loading: false, setWorkspace: () => {} }),
}))

const SENTENCE = 'Only workspace admins can add domains and start scans. Ask Taylor Owner if you need one scanned.'
const AREAS = ['Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness']
const renderPage = () => render(<MemoryRouter><NewScan /></MemoryRouter>)
const noRawText = () => expect(document.body.textContent).not.toMatch(/Something went wrong|Forbidden|admin role required|Retry/)

beforeEach(() => {
  vi.restoreAllMocks()
  vi.spyOn(api, 'getWorkspaceMembers').mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner' }, { role: 'analyst', name: 'Casey Analyst' }] })
  vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [] })
})

const RESCAN = 'Only workspace admins can add new domains. You can rescan domains this workspace has already verified.'
const VERIFIED = { domain_id: 'd1', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }
const PENDING = { domain_id: 'd2', domain: 'bbb-bookings.co.uk', verification_status: 'pending', verified_at: null }
const renderAt = (url) => render(<MemoryRouter initialEntries={[url]}><Routes><Route path="/scans/new" element={<NewScan />} /><Route path="/scans/:id" element={<p>scan page</p>} /></Routes></MemoryRouter>)

describe('an analyst rescans verified domains (decision, 18 Oct 2026)', () => {
  beforeEach(() => {
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'analyst' }] })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [PENDING, VERIFIED] })
  })
  it('no add-domain input or verify; the verified domains each offer Rescan', async () => {
    renderPage()
    const panel = await screen.findByTestId('scan-rescan-only')
    expect(panel).toHaveTextContent(RESCAN)
    const list = await screen.findByTestId('rescan-domains')
    expect(within(list).getAllByRole('listitem').map((li) => li.querySelector('span').textContent)).toEqual(['blackbullbarbers.co.uk'])
    expect(within(list).getByRole('button', { name: 'Rescan blackbullbarbers.co.uk' })).toBeEnabled()
    expect(screen.getByRole('link', { name: 'See all domains in this workspace' })).toHaveAttribute('href', '/workspaces/ws_bbb')
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.queryByRole('button', { name: /Verify domain ownership/ })).toBeNull()
    expect(screen.queryByTestId('scan-not-permitted')).toBeNull()
    expect(api.getWorkspaceMembers).not.toHaveBeenCalled()
    noRawText()
  })
  it('Rescan starts the scan on that domain and opens it', async () => {
    vi.spyOn(api, 'createScan').mockResolvedValue({ scan_id: 'scan_9', status: 'running' })
    renderAt('/scans/new')
    fireEvent.click(await screen.findByRole('button', { name: 'Rescan blackbullbarbers.co.uk' }))
    expect(await screen.findByText('scan page')).toBeInTheDocument()
    expect(api.createScan).toHaveBeenCalledWith('blackbullbarbers.co.uk', 'ws_bbb')
  })
  it('a domain named in the link (?domain=) is listed first', async () => {
    const other = { ...VERIFIED, domain_id: 'd3', domain: 'aaa-example.co.uk' }
    api.getWorkspaceDomains.mockResolvedValue({ domains: [other, VERIFIED] })
    renderAt('/scans/new?domain=blackbullbarbers.co.uk')
    const list = await screen.findByTestId('rescan-domains')
    expect(within(list).getAllByRole('listitem')[0]).toHaveTextContent('blackbullbarbers.co.uk')
  })
  it('a domain that needs verifying again says so plainly, no red error', async () => {
    vi.spyOn(api, 'createScan').mockRejectedValue(Object.assign(new Error('Verify domain ownership before starting an external security check.'), { status: 403, code: 'domain_verification_required' }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Rescan blackbullbarbers.co.uk' }))
    expect(await screen.findByText('A workspace admin needs to verify this domain again before it can be scanned.')).toBeInTheDocument()
    expect(screen.getByTestId('scan-rescan-only')).toBeInTheDocument()
    noRawText()
  })
  it('a role refusal on Rescan lands on the ask-the-owner sentence', async () => {
    vi.spyOn(api, 'createScan').mockRejectedValue(Object.assign(new Error('Forbidden — analyst role required to create scans'), { status: 403 }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Rescan blackbullbarbers.co.uk' }))
    const panel = await screen.findByTestId('scan-not-permitted')
    await waitFor(() => expect(panel).toHaveTextContent(SENTENCE))
    noRawText()
  })
  it('no verified domain yet: says who adds them', async () => {
    api.getWorkspaceDomains.mockResolvedValue({ domains: [PENDING] })
    renderPage()
    expect(await screen.findByTestId('rescan-none')).toHaveTextContent('No domain in this workspace has been verified yet.')
  })
})

describe('a viewer has no scan actions', () => {
  it.each(['viewer'])('%s: calm read-only state, no input, no verify button, no error', async (role) => {
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role }] })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [VERIFIED] })
    renderPage()
    const panel = await screen.findByTestId('scan-not-permitted')
    await waitFor(() => expect(panel).toHaveTextContent(SENTENCE))
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.queryByRole('button', { name: /Verify domain ownership/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Start Scan/ })).toBeNull()
    expect(screen.queryByText('Example Domains')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByRole('button', { name: /Rescan/ })).toBeNull()
    noRawText()
  })
})

describe('owner and admin unchanged', () => {
  it.each(['owner', 'admin'])('%s sees the domain form', async (role) => {
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role }] })
    renderPage()
    await waitFor(() => expect(api.getWorkspaces).toHaveBeenCalled())
    expect(screen.getByRole('textbox')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Start Scan/ })).toBeInTheDocument()
    expect(screen.queryByTestId('scan-not-permitted')).toBeNull()
    expect(screen.queryByTestId('scan-rescan-only')).toBeNull()
    expect(api.getWorkspaceMembers).not.toHaveBeenCalled()
  })
})

describe('a remaining 403 maps to the same sentence', () => {
  it('adding the domain is refused → the calm state, never raw server text', async () => {
    // A stale role (e.g. demoted since the list was read): the form shows, the API refuses.
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'admin' }] })
    vi.spyOn(api, 'addDomainToWorkspace').mockRejectedValue(Object.assign(new Error('Forbidden — admin role required to add domains'), { status: 403 }))
    renderPage()
    const u = userEvent.setup()
    await u.type(screen.getByRole('textbox'), 'blackbullbarbers.co.uk')
    fireEvent.click(await screen.findByRole('button', { name: /Verify domain ownership/ }))
    const panel = await screen.findByTestId('scan-not-permitted')
    await waitFor(() => expect(panel).toHaveTextContent(SENTENCE))
    expect(screen.queryByRole('button', { name: /Verify domain ownership/ })).toBeNull()
    noRawText()
  })
  it('starting the scan is refused → the same sentence', async () => {
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'owner' }] })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [{ domain_id: 'd1', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
    vi.spyOn(api, 'createScan').mockRejectedValue(Object.assign(new Error('Forbidden'), { status: 403 }))
    renderPage()
    const u = userEvent.setup()
    await u.type(screen.getByRole('textbox'), 'blackbullbarbers.co.uk')
    const start = screen.getByRole('button', { name: /Start Scan/ })
    await waitFor(() => expect(start).toBeEnabled())
    fireEvent.click(start)
    const panel = await screen.findByTestId('scan-not-permitted')
    await waitFor(() => expect(panel).toHaveTextContent(SENTENCE))
    noRawText()
  })
})

describe('a verification-required refusal is not a role refusal', () => {
  it('owner: the gate falls back to verification, not the ask-the-owner sentence', async () => {
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'owner' }] })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [VERIFIED] })
    vi.spyOn(api, 'createScan').mockRejectedValue(Object.assign(new Error('Verify domain ownership before starting an external security check.'), { status: 403, code: 'domain_verification_required', domain_id: 'd1', workspace_id: 'ws_bbb' }))
    renderPage()
    const u = userEvent.setup()
    await u.type(screen.getByRole('textbox'), 'blackbullbarbers.co.uk')
    const start = screen.getByRole('button', { name: /Start Scan/ })
    await waitFor(() => expect(start).toBeEnabled())
    fireEvent.click(start)
    expect(await screen.findByRole('button', { name: /Verify domain ownership/ })).toBeInTheDocument()
    expect(screen.queryByTestId('scan-not-permitted')).toBeNull()
  })
})

describe('right panel', () => {
  it('names the eight canonical areas, not the old engine list', async () => {
    vi.spyOn(api, 'getWorkspaces').mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'owner' }] })
    renderPage()
    const list = await screen.findByTestId('scan-areas')
    expect(within(list).getAllByRole('listitem').map((li) => li.querySelector('p').textContent)).toEqual(AREAS)
    expect(document.body.textContent).not.toMatch(/Attack Surface Intelligence|Business Email Intelligence|Brand Intelligence|Executive Intelligence/)
  })
})
