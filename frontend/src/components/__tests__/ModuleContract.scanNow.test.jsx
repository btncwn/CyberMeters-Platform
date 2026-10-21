import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ModuleContract from '../module/ModuleContract'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'

// Founder, 21 Oct 2026: module pages had no way to start a scan — the only
// header control was an icon that reloaded the list. Every area page now shows
// a labelled "Scan now" that starts a scan for the domain the page is showing.

vi.mock('../../api', () => ({
  api: {
    getSecurityCheckDomains: vi.fn(), getCases: vi.fn(), getWorkspaces: vi.fn(), getWorkspaceMembers: vi.fn(),
    getWorkspaceDomains: vi.fn(), createScan: vi.fn(), getScan: vi.fn(),
  },
}))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

const verified = (domain, i = 1) => ({ domain, domain_id: `d${i}`, verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' })

function show(domainKey, props = {}) {
  return render(
    <MemoryRouter>
      <ModuleContract domainKey={domainKey} workspaceId="ws1" workspaceName="Example Ltd" {...props}>
        <p>page body</p>
      </ModuleContract>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: [] })
  api.getCases.mockResolvedValue({ cases: [] })
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1', name: 'Example Ltd', role: 'owner' }] })
  api.getWorkspaceMembers.mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner' }] })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [verified('example.com')] })
  api.createScan.mockResolvedValue({ scan: { id: 'scan_1', status: 'queued' } })
  api.getScan.mockResolvedValue({ scan: { id: 'scan_1', status: 'running' } })
})

describe('Scan now on every area page', () => {
  it.each(MODULES.map((m) => m.domainKey))('%s: a labelled Scan now starts a scan for the verified domain', async (key) => {
    show(key)
    const button = await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('example.com', 'ws1'))
    expect(await screen.findByRole('status')).toHaveTextContent('Scan started — results in about 2–3 minutes.')
    expect(screen.getByRole('link', { name: 'Follow progress' })).toHaveAttribute('href', '/scans/scan_1')
  })

  it('scans the domain the page is showing when the workspace has several', async () => {
    api.getWorkspaceDomains.mockResolvedValue({ domains: [verified('a.example', 1), verified('b.example', 2)] })
    show('email_protection', { scanDomain: 'b.example' })
    const button = await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('b.example', 'ws1'))
  })

  it('asks which domain when the page shows none and several are verified', async () => {
    api.getWorkspaceDomains.mockResolvedValue({ domains: [verified('a.example', 1), verified('b.example', 2)] })
    show('website_security')
    const picker = await screen.findByRole('combobox', { name: 'Domain to scan' })
    const button = screen.getByRole('button', { name: 'Scan now' })
    expect(button).toBeDisabled()
    expect(button).toHaveAccessibleDescription('Choose the domain to scan.')
    fireEvent.change(picker, { target: { value: 'a.example' } })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith('a.example', 'ws1'))
  })

  it('stays visible but disabled, with the reason, for a role that cannot scan', async () => {
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1', name: 'Example Ltd', role: 'viewer' }] })
    show('certificates_trust')
    const button = await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(button).toHaveAccessibleDescription(/cannot start scans\. Ask Taylor Owner/))
    expect(button).toBeDisabled()
    expect(api.createScan).not.toHaveBeenCalled()
  })

  it('says so when no domain is verified yet', async () => {
    api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'new.example', domain_id: 'd9', verification_status: 'pending' }] })
    show('attack_surface')
    const button = await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(button).toHaveAccessibleDescription(/No domain in this workspace is verified yet/))
    expect(button).toBeDisabled()
  })

  it('a plan limit is said in words and starts nothing', async () => {
    api.createScan.mockRejectedValue(Object.assign(new Error('limit'), { status: 402, code: 'plan_limit_exceeded' }))
    show('brand_protection')
    const button = await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    expect(await screen.findByRole('alert')).toHaveTextContent(/did not start/)
  })
})
