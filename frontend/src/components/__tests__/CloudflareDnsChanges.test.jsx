import { StrictMode } from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import CloudflareDnsChanges from '../CloudflareDnsChanges'
import { api } from '../../api'
vi.mock('../../api', () => ({ api: {
  getDnsConnections: vi.fn(), getDnsConnection: vi.fn(), connectDns: vi.fn(), disconnectDns: vi.fn(),
  previewDnsChange: vi.fn(), getDnsChange: vi.fn(), applyDnsChange: vi.fn(), verifyDnsChange: vi.fn(), rollbackDnsChange: vi.fn(),
} }))
const meta = () => ({ can_manage: true, can_apply: true, domains: [{ id: 'a', domain: 'example.com' }, { id: 'b', domain: 'other.test' }], supported_actions: ['spf_publish', 'dmarc_reporting', 'tls_rpt'].map(id => ({ id })), scope_note: 'Only supported changes on your verified domain.' })
const conn = () => ({ can_manage: true, can_apply: true, reporting_ready: true, connection: { id: 'connection-a', zone_id: 'a'.repeat(32), zone_name: 'example.com' }, changes: [] })
const preview = () => ({ id: 'change-a', action_id: 'spf_publish', status: 'preview', before: [], after: { name: 'example.com', type: 'TXT', content: 'v=spf1 -all', ttl: 1 }, created_at: '2026-10-09T00:00:00Z', expires_at: '2026-10-09T00:15:00Z', can_apply: true, can_verify: false, can_rollback: false, verification: { state: 'not_checked' } })
const accepted = () => ({ ...preview(), status: 'provider_accepted', can_apply: false, can_verify: true, can_rollback: true })
const deferred = () => { let resolve; let reject; const promise = new Promise((a, b) => { resolve = a; reject = b }); return { promise, resolve, reject } }
const change = (label, value) => fireEvent.change(screen.getByLabelText(label), { target: { value } })
const click = name => fireEvent.click(screen.getByRole('button', { name }))
const consent = name => fireEvent.click(screen.getByRole('checkbox', { name }))
const mount = () => render(<CloudflareDnsChanges workspaceId="workspace-a" />)
async function select(domain = 'example.com') {
  await screen.findByLabelText('Domain for this DNS change'); change('Domain for this DNS change', domain)
  await waitFor(() => expect(screen.queryByText('Loading this domain’s connection…')).not.toBeInTheDocument())
}
async function noMail() {
  await select(); change('Supported correction', 'spf_publish'); change('Does this domain send email?', 'no_mail')
  consent(/I confirm this domain sends no email/); click('Preview exact DNS change'); await screen.findByText('Preview only — not applied')
}
async function saved(item = accepted()) {
  api.getDnsConnection.mockResolvedValue({ ...conn(), changes: [item] }); api.getDnsChange.mockResolvedValue({ change: item })
  await select(); click(/Publish missing SPF ·/); await screen.findByText('Before')
}
beforeEach(() => {
  vi.resetAllMocks()
  api.getDnsConnections.mockResolvedValue(meta()); api.getDnsConnection.mockResolvedValue(conn())
  api.connectDns.mockResolvedValue(conn()); api.disconnectDns.mockResolvedValue({ ok: true })
  api.previewDnsChange.mockResolvedValue({ change: preview() }); api.getDnsChange.mockResolvedValue({ change: preview() })
  api.applyDnsChange.mockResolvedValue({ change: accepted() })
  api.verifyDnsChange.mockResolvedValue({ change: { ...accepted(), status: 'dns_verified', verification: { state: 'observed', checked_at: '2026-10-09T00:01:00Z' } } })
  api.rollbackDnsChange.mockResolvedValue({ change: { ...accepted(), status: 'rolled_back', can_rollback: false } })
})
describe('Explicit Cloudflare DNS corrections', () => {
  it('never connects, previews or writes on mount or while typing', async () => {
    api.getDnsConnection.mockResolvedValue({ ...conn(), connection: null }); mount()
    expect(await screen.findByLabelText('Domain for this DNS change')).toHaveValue(''); expect(api.getDnsConnection).not.toHaveBeenCalled()
    await select(); change('Restricted Cloudflare API token', 'synthetic-token'); change('Cloudflare zone ID', 'a'.repeat(32))
    expect(screen.getByRole('button', { name: 'Connect Cloudflare' })).toBeDisabled()
    expect(screen.getByRole('link', { name: 'Cloudflare API tokens' })).toHaveAttribute('href', 'https://dash.cloudflare.com/profile/api-tokens')
    expect(screen.getByText(/cannot prove the token has no wider permissions/)).toBeInTheDocument()
    for (const name of ['connectDns', 'previewDnsChange', 'applyDnsChange', 'verifyDnsChange', 'rollbackDnsChange']) expect(api[name]).not.toHaveBeenCalled()
  })
  it('explicitly sends once, clears token immediately, never stores or echoes even secret-bearing errors', async () => {
    api.getDnsConnection.mockResolvedValue({ ...conn(), connection: null }); const pending = deferred(); api.connectDns.mockReturnValue(pending.promise)
    const storage = vi.spyOn(Storage.prototype, 'setItem'); mount(); await select()
    change('Cloudflare zone ID', 'A'.repeat(32)); change('Restricted Cloudflare API token', 'synthetic-token-private'); consent(/I control this zone/)
    const button = screen.getByRole('button', { name: 'Connect Cloudflare' }); fireEvent.click(button); fireEvent.submit(button.closest('form'))
    expect(api.connectDns).toHaveBeenCalledTimes(1)
    expect(api.connectDns).toHaveBeenCalledWith('workspace-a', 'example.com', { zone_id: 'a'.repeat(32), token: 'synthetic-token-private' }, expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(screen.getByLabelText('Restricted Cloudflare API token')).toHaveValue(''); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(storage).not.toHaveBeenCalled()
    await act(async () => pending.reject(new Error('echo synthetic-token-private')))
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be confirmed'); expect(document.body.textContent).not.toContain('synthetic-token-private')
    expect(screen.getByLabelText('Restricted Cloudflare API token')).toHaveValue(''); storage.mockRestore()
  })
  it.each([false, 'true', undefined])('hides all controls without exact owner/admin capability (%s)', async can_manage => {
    api.getDnsConnections.mockResolvedValue({ ...meta(), can_manage }); mount()
    await waitFor(() => expect(screen.queryByText('Loading DNS connection options…')).not.toBeInTheDocument())
    expect(screen.queryByRole('heading')).not.toBeInTheDocument(); expect(api.getDnsConnection).not.toHaveBeenCalled()
  })
  it('distinguishes failed loading from no verified domains, without requiring a scan', async () => {
    api.getDnsConnections.mockRejectedValueOnce(new Error('private')); mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be confirmed'); expect(screen.queryByText(/Verify a domain/)).not.toBeInTheDocument()
    api.getDnsConnections.mockResolvedValue({ ...meta(), domains: [] }); click('Load DNS connection options')
    expect(await screen.findByText(/A completed scan is not required/)).toBeInTheDocument(); expect(screen.queryByLabelText('Restricted Cloudflare API token')).not.toBeInTheDocument()
  })
  it('survives StrictMode effect replay and ignores canceled read results', async () => {
    const old = deferred(); api.getDnsConnections.mockReturnValueOnce(old.promise).mockResolvedValue(meta())
    render(<StrictMode><CloudflareDnsChanges workspaceId="workspace-a" /></StrictMode>); await screen.findByLabelText('Domain for this DNS change')
    expect(api.getDnsConnections.mock.calls[0][1].signal.aborted).toBe(true)
    await act(async () => old.resolve({ ...meta(), domains: [{ id: 'stale', domain: 'stale.test' }] }))
    expect(screen.queryByRole('option', { name: 'stale.test' })).not.toBeInTheDocument()
  })
  it('clears token and ignores a late connection across workspace A→B→A', async () => {
    api.getDnsConnection.mockResolvedValue({ ...conn(), connection: null }); const pending = deferred(); api.connectDns.mockReturnValue(pending.promise)
    const view = mount(); await select(); change('Cloudflare zone ID', 'a'.repeat(32)); change('Restricted Cloudflare API token', 'synthetic-token'); consent(/I control this zone/); click('Connect Cloudflare')
    const signal = api.connectDns.mock.calls[0][3].signal
    view.rerender(<CloudflareDnsChanges workspaceId="workspace-b" />); await screen.findByLabelText('Domain for this DNS change'); expect(signal.aborted).toBe(true)
    view.rerender(<CloudflareDnsChanges workspaceId="workspace-a" />); await select()
    await act(async () => pending.resolve({ ...conn(), connection: { zone_name: 'stale-private-zone' } }))
    expect(screen.queryByText('stale-private-zone')).not.toBeInTheDocument(); expect(screen.getByLabelText('Restricted Cloudflare API token')).toHaveValue(''); expect(screen.getByRole('checkbox')).not.toBeChecked()
  })
  it('requires explicit no-mail confirmation and shows a preview without applying', async () => {
    mount(); await select(); expect(screen.getByLabelText('Supported correction')).toHaveValue('')
    change('Supported correction', 'spf_publish'); expect(screen.getByLabelText('Does this domain send email?')).toHaveValue(''); change('Does this domain send email?', 'no_mail')
    expect(screen.getByRole('button', { name: 'Preview exact DNS change' })).toBeDisabled()
    consent(/I confirm this domain sends no email/); click('Preview exact DNS change'); await screen.findByText('Preview only — not applied')
    expect(api.previewDnsChange).toHaveBeenCalledWith('workspace-a', 'example.com', { action_id: 'spf_publish', request_id: expect.stringMatching(/^[0-9a-f-]{36}$/), inputs: { mail_mode: 'no_mail', no_mail_confirmed: true } }, expect.any(Object))
    expect(api.applyDnsChange).not.toHaveBeenCalled(); expect(screen.getByText('No matching record')).toBeInTheDocument(); expect(screen.getByText('v=spf1 -all')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Apply this exact change' })).toBeDisabled()
  })
  it('requires specific SPF senders and chosen policy; edits invalidate the earlier approval', async () => {
    mount(); await select(); change('Supported correction', 'spf_publish'); change('Does this domain send email?', 'senders'); expect(screen.getByLabelText('Other senders')).toHaveValue('')
    change('SPF include domains', '_spf.example.net, relay.example.net'); change('Authorised IPv4 addresses or ranges', '192.0.2.1'); consent(/I confirm these are/)
    expect(screen.getByRole('button', { name: 'Preview exact DNS change' })).toBeDisabled(); change('Other senders', '~all'); expect(screen.getByRole('checkbox', { name: /I confirm these are/ })).not.toBeChecked()
    consent(/I confirm these are/); click('Preview exact DNS change'); await screen.findByText('Preview only — not applied')
    expect(api.previewDnsChange.mock.calls[0][2].inputs).toEqual({ mail_mode: 'senders', includes: ['_spf.example.net', 'relay.example.net'], ip4: ['192.0.2.1'], ip6: [], all: '~all', senders_confirmed: true })
    consent(/reviewed this exact/); change('SPF include domains', 'different.example.net'); expect(screen.queryByRole('button', { name: 'Apply this exact change' })).not.toBeInTheDocument(); expect(api.applyDnsChange).not.toHaveBeenCalled()
  })
  it.each(['dmarc_reporting', 'tls_rpt'])('requires reporting activation for %s and sends no invented input', async actionId => {
    api.getDnsConnection.mockResolvedValueOnce({ ...conn(), reporting_ready: false }); mount(); await select(); change('Supported correction', actionId)
    expect(screen.getByRole('button', { name: 'Preview exact DNS change' })).toBeDisabled(); expect(screen.getByText(/Activate DMARC reporting below/)).toBeInTheDocument()
    click('Refresh connection and history'); await waitFor(() => expect(screen.getByRole('button', { name: 'Preview exact DNS change' })).toBeEnabled())
    click('Preview exact DNS change'); await screen.findByText('Preview only — not applied'); expect(api.previewDnsChange.mock.calls[0][2]).toMatchObject({ action_id: actionId, inputs: {} })
  })
  it('escapes exact before/after evidence and keeps provider acceptance separate from public DNS and case closure', async () => {
    api.previewDnsChange.mockResolvedValue({ change: { ...preview(), before: [{ id: 'dns-a', type: 'TXT', name: 'example.com', content: 'v=spf1 include:<script>bad()</script> -all', ttl: 300 }], after: { name: 'example.com', type: 'TXT', content: 'v=spf1 -all', ttl: 300 } } })
    mount(); await noMail(); expect(screen.getByText('v=spf1 include:<script>bad()</script> -all')).toBeInTheDocument(); expect(document.querySelector('script')).toBeNull(); expect(screen.getAllByText('TTL: 300')).toHaveLength(2)
    consent(/reviewed this exact/); click('Apply this exact change'); expect(await screen.findByText('Accepted by Cloudflare — public DNS not yet confirmed')).toBeInTheDocument(); expect(screen.getByText('Public DNS: not checked')).toBeInTheDocument()
    expect(api.applyDnsChange).toHaveBeenCalledWith('workspace-a', 'example.com', 'change-a', { request_id: expect.any(String), confirm: true }, expect.any(Object))
    expect(screen.getByText(/does not prove mail delivery or close a security case/)).toBeInTheDocument(); click('Check public DNS and saved outcome')
    expect(await screen.findByText('Record observed in public DNS')).toBeInTheDocument(); expect(screen.getByText(/^Public DNS: record observed/)).toBeInTheDocument()
    expect(api.verifyDnsChange.mock.calls[0][3]).not.toHaveProperty('confirm'); expect(screen.queryByText(/case closed|issue fixed/i)).not.toBeInTheDocument()
  })
  it('refuses apply without full record evidence even if an inconsistent response says can_apply', async () => {
    api.previewDnsChange.mockResolvedValue({ change: { ...preview(), after: null } }); mount(); await noMail()
    expect(screen.getByText('Record evidence unavailable')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Apply this exact change' })).not.toBeInTheDocument()
  })
  it('does not treat uncertain, unavailable, pending or unknown outcomes as verified', async () => {
    mount(); await saved({ ...accepted(), status: 'uncertain', can_rollback: false, verification: { state: 'unavailable' } })
    expect(screen.getByText('Provider outcome uncertain')).toBeInTheDocument(); expect(screen.getByText('Public DNS: check unavailable')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Undo this change' })).not.toBeInTheDocument()
    api.verifyDnsChange.mockResolvedValue({ change: { ...accepted(), status: 'unknown', verification: { state: 'pending' } } }); click('Check public DNS and saved outcome')
    expect(await screen.findByText('Outcome not established')).toBeInTheDocument(); expect(screen.getByText('Public DNS: not observed yet')).toBeInTheDocument(); expect(screen.queryByText('Record observed in public DNS')).not.toBeInTheDocument()
  })
  it('locks writes after an unconfirmed apply until saved state is explicitly refreshed', async () => {
    api.applyDnsChange.mockRejectedValue(Object.assign(new Error('private'), { code: 'record_drift' })); mount(); await noMail(); consent(/reviewed this exact/); click('Apply this exact change')
    expect(await screen.findByRole('alert')).toHaveTextContent('record has changed'); expect(screen.getByText('Provider outcome uncertain')).toBeInTheDocument(); expect(screen.queryByText('Preview only — not applied')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Apply this exact change' })).not.toBeInTheDocument(); expect(api.applyDnsChange).toHaveBeenCalledTimes(1)
    api.getDnsChange.mockResolvedValue({ change: { ...preview(), status: 'conflict', can_apply: false } }); click('Refresh this change')
    expect(await screen.findByText('Record changed — action refused')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Apply this exact change' })).not.toBeInTheDocument()
  })
  it('permits preview but not apply without plan; retains explicit undo and check after downgrade', async () => {
    api.getDnsConnections.mockResolvedValue({ ...meta(), can_apply: false }); api.getDnsConnection.mockResolvedValue({ ...conn(), can_apply: false, reason: 'plan_required' }); mount(); await noMail()
    expect(screen.queryByRole('button', { name: 'Apply this exact change' })).not.toBeInTheDocument(); expect(screen.getByText(/eligible paid plan or trial/)).toBeInTheDocument()
    api.getDnsChange.mockResolvedValue({ change: accepted() }); click('Refresh this change'); await screen.findByText('Accepted by Cloudflare — public DNS not yet confirmed')
    expect(screen.getByRole('button', { name: 'Check public DNS and saved outcome' })).toBeEnabled(); expect(screen.getByRole('button', { name: 'Undo this change' })).toBeDisabled()
    consent(/approve undoing/); click('Undo this change'); expect(await screen.findByText('Undo accepted by Cloudflare')).toBeInTheDocument()
    expect(api.rollbackDnsChange.mock.calls[0].slice(0, 3)).toEqual(['workspace-a', 'example.com', 'change-a']); expect(api.rollbackDnsChange.mock.calls[0][3].confirm).toBe(true); expect(screen.getByText('Public DNS: not checked')).toBeInTheDocument()
  })
  it('cancels and discards an in-flight preview when selected domain changes', async () => {
    const pending = deferred(); api.previewDnsChange.mockReturnValue(pending.promise); mount(); await select(); change('Supported correction', 'dmarc_reporting'); click('Preview exact DNS change')
    const signal = api.previewDnsChange.mock.calls[0][3].signal; await select('other.test'); expect(signal.aborted).toBe(true)
    await act(async () => pending.resolve({ change: preview() })); expect(screen.queryByText('Preview only — not applied')).not.toBeInTheDocument(); expect(screen.getByLabelText('Supported correction')).toHaveValue('')
  })
})
