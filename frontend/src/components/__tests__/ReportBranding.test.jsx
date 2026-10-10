import React, { StrictMode } from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgencyReportBranding, WorkspaceReportBranding } from '../ReportBranding'
import { api } from '../../api'
vi.mock('../../api', () => ({ api: {
  getBrandingProfiles: vi.fn(), getBrandingProfile: vi.fn(), createBrandingProfile: vi.fn(), updateBrandingProfile: vi.fn(), deleteBrandingProfile: vi.fn(),
  getWorkspaceBranding: vi.fn(), getWorkspaceBrandingLogo: vi.fn(), updateWorkspaceBranding: vi.fn(), updateWorkspaceBrandingLogo: vi.fn(), deleteWorkspaceBrandingLogo: vi.fn(),
} }))
const PNG = 'data:image/png;base64,aGVsbG8='
const profile = (id = 'profile-a') => ({ id, name: `Agency ${id}`, accent: '#123456', mode: 'white_label', is_default: 1, logo_sha256: 'a'.repeat(64) })
const meta = (overrides = {}) => ({ profiles: [profile()], white_label_available: true, ...overrides })
const workspace = (overrides = {}) => ({ can_manage: true, has_logo: true, logo: { display_name: 'Client A' }, effective_mode: 'co_brand', effective_display_name: 'Client A', effective_attribution: 'full', ...overrides })
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }
const wrap = node => <MemoryRouter>{node}</MemoryRouter>
const mountAgency = id => render(wrap(<AgencyReportBranding accountId={id || 'account-a'} />))
const mountWorkspace = id => render(wrap(<WorkspaceReportBranding workspaceId={id || 'workspace-a'} />))
const click = name => fireEvent.click(screen.getByRole('button', { name }))
const fill = (name, value) => fireEvent.change(screen.getByLabelText(name), { target: { value } })
async function newProfile() {
  // Finish the initial revision-reset effect before opening the editor.
  await act(async () => {})
  click('Add agency profile'); fill('Agency name', 'New Agency')
}
beforeEach(() => {
  vi.resetAllMocks()
  api.getBrandingProfiles.mockResolvedValue(meta())
  api.getBrandingProfile.mockImplementation(async id => ({ profile: profile(id), logo_data_uri: PNG, white_label_available: true }))
  api.getWorkspaceBranding.mockResolvedValue(workspace()); api.getWorkspaceBrandingLogo.mockResolvedValue({ logo_data_uri: PNG })
  for (const name of ['createBrandingProfile', 'updateBrandingProfile', 'deleteBrandingProfile', 'updateWorkspaceBranding', 'updateWorkspaceBrandingLogo', 'deleteWorkspaceBrandingLogo']) api[name].mockResolvedValue({ ok: true })
})
describe('Agency branding profiles', () => {
  it('loads real server availability without automatically writing, retains attribution and history explanation', async () => {
    mountAgency(); await screen.findByText('Agency profile-a')
    expect(screen.getByText(/Powered by CyberMeters/)).toBeInTheDocument(); expect(screen.getByText(/Already saved PDF branding stays unchanged/)).toBeInTheDocument()
    expect(api.createBrandingProfile).not.toHaveBeenCalled(); expect(api.updateBrandingProfile).not.toHaveBeenCalled(); expect(api.getBrandingProfile).not.toHaveBeenCalled()
  })
  it.each([false, undefined, 'true'])('does not invent entitled edits from truthy or missing plan capability (%s)', async white_label_available => {
    api.getBrandingProfiles.mockResolvedValue(meta({ white_label_available }))
    // Finish the initial read and its revision-reset effect before interacting.
    // A DOM-only wait can see the profile before React has flushed that effect.
    await act(async () => { mountAgency() }); await screen.findByText('Agency profile-a')
    expect(screen.queryByRole('button', { name: 'Add agency profile' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /Edit Agency/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View billing' })).toHaveAttribute('href', '/billing')
    click('Delete Agency profile-a'); expect(api.deleteBrandingProfile).not.toHaveBeenCalled(); click('Confirm profile deletion')
    await waitFor(() => expect(api.deleteBrandingProfile).toHaveBeenCalledWith('profile-a', expect.any(Object)))
  })
  it('keeps failed loading distinct from empty profiles and retries explicitly', async () => {
    api.getBrandingProfiles.mockRejectedValueOnce(new Error('private')); mountAgency()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded'); expect(screen.queryByText('No agency profiles saved.')).not.toBeInTheDocument()
    api.getBrandingProfiles.mockResolvedValue(meta({ profiles: [] })); click('Refresh branding settings'); await screen.findByText('No agency profiles saved.')
  })
  it('submits exactly one explicit agency profile, preserving optional logo and chosen default', async () => {
    const pending = deferred(); api.createBrandingProfile.mockReturnValue(pending.promise); mountAgency(); await screen.findByText('Agency profile-a'); await newProfile()
    fill('Accent colour', '#aabbcc'); fireEvent.click(screen.getByRole('checkbox', { name: 'Use as my default agency profile' }))
    click('Save agency profile'); fireEvent.submit(screen.getByRole('button', { name: 'Save agency profile' }).closest('form'))
    expect(api.createBrandingProfile).toHaveBeenCalledTimes(1)
    expect(api.createBrandingProfile.mock.calls[0][0]).toEqual({ name: 'New Agency', accent: '#aabbcc', mode: 'white_label', is_default: true })
    await act(async () => pending.resolve({ ok: true })); await screen.findByText('Agency profile saved.')
  })
  it('edits the scoped saved logo and changes default with only the intended body', async () => {
    api.getBrandingProfiles.mockResolvedValue(meta({ profiles: [{ ...profile(), is_default: 0 }] })); await act(async () => { mountAgency() }); await screen.findByText('Agency profile-a')
    click('Make Agency profile-a default'); await screen.findByText('Default agency profile saved.')
    // The save reload bumps `revision`, and a passive effect then closes any open
    // editor. The notice can be in the DOM before that effect has flushed, so an
    // immediate Edit click could be wiped by it. Flush effects before interacting.
    await act(async () => {})
    expect(api.updateBrandingProfile.mock.calls[0][0]).toBe('profile-a'); expect(api.updateBrandingProfile.mock.calls[0][1]).toEqual({ is_default: true })
    click('Edit Agency profile-a'); await screen.findByDisplayValue('Agency profile-a')
    expect(api.getBrandingProfile).toHaveBeenCalledWith('profile-a', expect.objectContaining({ signal: expect.any(AbortSignal) })); expect(screen.getByAltText('Report logo preview')).toHaveAttribute('src', PNG)
    fill('Agency name', 'Renamed'); click('Remove logo on save'); click('Save agency profile'); await screen.findByText('Agency profile saved.')
    expect(api.updateBrandingProfile.mock.calls[1][1]).toEqual({ name: 'Renamed', accent: '#123456', mode: 'white_label', is_default: true, logo: null })
  })
  it('does not display another returned profile or allow edit after a fresh downgrade', async () => {
    api.getBrandingProfile.mockResolvedValue({ profile: profile('foreign'), logo_data_uri: PNG, white_label_available: false }); await act(async () => { mountAgency() }); await screen.findByText('Agency profile-a'); click('Edit Agency profile-a')
    expect(await screen.findByRole('alert')).toHaveTextContent('cannot currently be edited'); expect(screen.queryByLabelText('Agency name')).not.toBeInTheDocument(); expect(screen.queryByText('Agency foreign')).not.toBeInTheDocument()
  })
  it('rejects unsupported image types/oversize before reading and accepts explicit PNG only on save', async () => {
    mountAgency(); await screen.findByText('Agency profile-a'); await newProfile()
    const upload = file => fireEvent.change(screen.getByLabelText('Logo image'), { target: { files: [file] } })
    upload(new File(['<svg onload="bad"/>'], 'unsafe.svg', { type: 'image/svg+xml' })); expect(screen.getByRole('alert')).toHaveTextContent('PNG or JPEG')
    upload(new File([new Uint8Array(512 * 1024 + 1)], 'big.png', { type: 'image/png' })); expect(screen.getByRole('alert')).toHaveTextContent('512 KB')
    upload(new File(['hello'], 'small.png', { type: 'image/png' })); await screen.findByAltText('Report logo preview'); expect(api.createBrandingProfile).not.toHaveBeenCalled()
    click('Save agency profile'); await screen.findByText('Agency profile saved.'); expect(api.createBrandingProfile.mock.calls[0][0].logo).toBe(PNG)
  })
  it('does not silently save without a selected image while its local read is pending', async () => {
    const original = globalThis.FileReader; let reader
    class PendingReader { constructor() { this.readyState = 1; reader = this } readAsDataURL() {} abort() { this.readyState = 2 } }
    globalThis.FileReader = PendingReader
    try {
      mountAgency(); await screen.findByText('Agency profile-a'); await newProfile()
      fireEvent.change(screen.getByLabelText('Logo image'), { target: { files: [new File(['hello'], 'small.png', { type: 'image/png' })] } })
      expect(screen.getByRole('button', { name: 'Save agency profile' })).toBeDisabled(); fireEvent.submit(screen.getByLabelText('Agency name').closest('form')); expect(api.createBrandingProfile).not.toHaveBeenCalled()
      await act(async () => { reader.result = PNG; reader.onload() }); expect(screen.getByRole('button', { name: 'Save agency profile' })).toBeEnabled()
    } finally { globalThis.FileReader = original }
  })
  it('does not label an unused legacy co-brand profile as the effective agency default', async () => {
    api.getBrandingProfiles.mockResolvedValue(meta({ profiles: [{ ...profile(), mode: 'co_brand' }] })); mountAgency(); await screen.findByText('Agency profile-a')
    expect(screen.getByText(/Legacy co-brand profile/)).toBeInTheDocument(); expect(screen.queryByText('Default')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /Make .* default/ })).not.toBeInTheDocument()
  })
  it('refuses an invalid colour before a write', async () => {
    await act(async () => { mountAgency() }); await screen.findByText('Agency profile-a'); await newProfile(); fill('Accent colour', 'red')
    expect(screen.getByRole('button', { name: 'Save agency profile' })).toBeDisabled(); fireEvent.submit(screen.getByLabelText('Agency name').closest('form')); expect(api.createBrandingProfile).not.toHaveBeenCalled()
  })
  it('locks writes after lost response, never claims save or echoes errors, and reconciles by refresh', async () => {
    api.createBrandingProfile.mockRejectedValue(new Error('private-customer-data')); mountAgency(); await screen.findByText('Agency profile-a'); await newProfile(); click('Save agency profile')
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be confirmed'); expect(screen.queryByText('Agency profile saved.')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('private-customer-data')
    expect(screen.getByRole('button', { name: 'Save agency profile' })).toBeDisabled(); click('Refresh branding settings'); await waitFor(() => expect(screen.getByRole('button', { name: 'Add agency profile' })).toBeEnabled())
  })
  it('aborts account-scoped reads and discards late detail on account switch', async () => {
    const late = deferred(); api.getBrandingProfile.mockReturnValue(late.promise); const view = mountAgency(); await screen.findByText('Agency profile-a'); click('Edit Agency profile-a')
    const signal = api.getBrandingProfile.mock.calls[0][1].signal
    api.getBrandingProfiles.mockResolvedValue(meta({ profiles: [profile('profile-b')] })); view.rerender(wrap(<AgencyReportBranding accountId="account-b" />)); await screen.findByText('Agency profile-b'); expect(signal.aborted).toBe(true)
    await act(async () => late.resolve({ profile: profile('old-private'), logo_data_uri: PNG, white_label_available: true })); expect(screen.queryByLabelText('Agency name')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('old-private')
  })
})
describe('Client workspace branding', () => {
  it('reads current server identity and saves a name without reuploading its saved logo', async () => {
    mountWorkspace(); await screen.findByDisplayValue('Client A'); expect(screen.getByAltText('Report logo preview')).toHaveAttribute('src', PNG)
    fill('Client report name', 'New client'); click('Save client branding'); await screen.findByText('Client report branding saved.')
    expect(api.updateWorkspaceBranding).toHaveBeenCalledWith('workspace-a', { display_name: 'New client' }, expect.any(Object)); expect(api.updateWorkspaceBrandingLogo).not.toHaveBeenCalled()
  })
  it.each([false, 'true', undefined])('only exposes management controls with exact capability (%s)', async can_manage => {
    api.getWorkspaceBranding.mockResolvedValue(workspace({ can_manage })); mountWorkspace(); await screen.findByText('Client A')
    expect(screen.queryByLabelText('Client report name')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Logo image')).not.toBeInTheDocument(); expect(api.updateWorkspaceBranding).not.toHaveBeenCalled()
  })
  it('replaces and removes a logo through the workspace-specific routes, with no data persisted in browser storage', async () => {
    const storage = vi.spyOn(Object.getPrototypeOf(localStorage), 'setItem'); mountWorkspace(); await screen.findByDisplayValue('Client A')
    fireEvent.change(screen.getByLabelText('Logo image'), { target: { files: [new File(['hello'], 'client.png', { type: 'image/png' })] } }); await screen.findByRole('button', { name: 'Discard logo change' }); click('Save client branding')
    await screen.findByText('Client report branding saved.'); expect(api.updateWorkspaceBrandingLogo).toHaveBeenCalledWith('workspace-a', { display_name: 'Client A', logo: PNG }, expect.any(Object))
    click('Remove client logo'); await screen.findByText('Client logo removed; saved PDF branding is retained.'); expect(api.deleteWorkspaceBrandingLogo).toHaveBeenCalledWith('workspace-a', expect.any(Object)); expect(storage).not.toHaveBeenCalled(); storage.mockRestore()
  })
  it('never treats a failed saved-logo preview as absence and never loads an arbitrary URL', async () => {
    api.getWorkspaceBrandingLogo.mockResolvedValue({ logo_data_uri: 'https://external.example/track' }); mountWorkspace(); await screen.findByDisplayValue('Client A')
    expect(screen.queryByRole('img')).not.toBeInTheDocument(); expect(screen.getByText('Saved logo; preview is unavailable.')).toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Remove client logo' })).toBeEnabled()
  })
  it('clears draft and cancels/ignores an in-flight save across workspace A→B→A', async () => {
    const late = deferred(); api.updateWorkspaceBranding.mockReturnValue(late.promise); const view = mountWorkspace(); await screen.findByDisplayValue('Client A'); fill('Client report name', 'Old draft'); click('Save client branding')
    const signal = api.updateWorkspaceBranding.mock.calls[0][2].signal; api.getWorkspaceBranding.mockResolvedValue(workspace({ logo: { display_name: 'Client B' }, effective_display_name: 'Client B' }))
    view.rerender(wrap(<WorkspaceReportBranding workspaceId="workspace-b" />)); await screen.findByDisplayValue('Client B'); expect(signal.aborted).toBe(true)
    api.getWorkspaceBranding.mockResolvedValue(workspace()); view.rerender(wrap(<WorkspaceReportBranding workspaceId="workspace-a" />)); await screen.findByDisplayValue('Client A')
    await act(async () => late.resolve({ ok: true })); expect(screen.queryByDisplayValue('Old draft')).not.toBeInTheDocument(); expect(screen.queryByText('Client report branding saved.')).not.toBeInTheDocument()
  })
  it('supports StrictMode effect replay without displaying stale workspace metadata', async () => {
    const late = deferred(); api.getWorkspaceBranding.mockReturnValueOnce(late.promise).mockResolvedValue(workspace())
    render(<StrictMode>{wrap(<WorkspaceReportBranding workspaceId="workspace-a" />)}</StrictMode>); await screen.findByDisplayValue('Client A'); expect(api.getWorkspaceBranding.mock.calls[0][1].signal.aborted).toBe(true)
    await act(async () => late.resolve(workspace({ effective_display_name: 'Stale secret name' }))); expect(document.body.textContent).not.toContain('Stale secret name')
  })
})
