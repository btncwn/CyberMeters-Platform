import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import IdentityBreachChecks from '../IdentityBreachChecks'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getIdentityBreachChecks: vi.fn(), createIdentityBreachCheck: vi.fn(), deleteIdentityBreachCheck: vi.fn(),
} }))

const empty = () => ({ can_check: true, consent_version: '2026-10-09', domains: [{ id: 'domain-a', domain: 'example.com' }, { id: 'domain-b', domain: 'other.test' }], items: [], scope_note: 'Checks only the address you submit against LeakCheck Public sources. This is not domain-wide, dark-web or password monitoring. A match does not prove current account compromise; no match does not prove the address is safe.' })
const item = (status = 'sources_found') => ({ id: 'check-a', domain_id: 'domain-a', masked_address: 'a***@example.com', status, found_count: status === 'sources_found' ? 2 : null, fields: ['email', 'password'], sources: [{ name: 'Recorded source', date: '2023-01' }], checked_at: '2026-10-09T00:00:00Z', expires_at: '2026-11-08T00:00:00Z' })
const deferred = () => { let resolve; let reject; const promise = new Promise((a, b) => { resolve = a; reject = b }); return { promise, resolve, reject } }
const mount = () => render(<IdentityBreachChecks workspaceId="workspace-a" />)
async function prepare(address = 'alice@example.com') {
  await screen.findByRole('heading', { name: 'Known address breach check' })
  fireEvent.change(screen.getByLabelText('Verified domain'), { target: { value: 'domain-a' } })
  fireEvent.change(screen.getByLabelText('Known corporate email address'), { target: { value: address } })
}
beforeEach(() => {
  vi.resetAllMocks()
  api.getIdentityBreachChecks.mockResolvedValue(empty())
  api.createIdentityBreachCheck.mockResolvedValue({ item: item() })
  api.deleteIdentityBreachCheck.mockResolvedValue({ ok: true })
})

describe('Manual identity breach checks', () => {
  it('never queries an address on load or while typing, and starts without suggestions or consent', async () => {
    mount()
    await screen.findByRole('heading', { name: 'Known address breach check' })
    expect(screen.getByLabelText('Known corporate email address')).toHaveValue('')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    await prepare()
    expect(api.createIdentityBreachCheck).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Check this address' })).toBeDisabled()
    expect(screen.getByRole('checkbox')).toHaveAccessibleName(/pseudonymous, not anonymous/)
    expect(screen.getByRole('link', { name: 'Powered by LeakCheck' })).toHaveAttribute('href', 'https://leakcheck.io')
    expect(screen.getByText(/not domain-wide, dark-web or password monitoring/)).toBeInTheDocument()
  })

  it('submits exact consent and scope once, clears raw input immediately, and saves no browser data', async () => {
    const pending = deferred()
    api.createIdentityBreachCheck.mockReturnValue(pending.promise)
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    mount()
    await prepare()
    fireEvent.click(screen.getByRole('checkbox'))
    const button = screen.getByRole('button', { name: 'Check this address' })
    fireEvent.click(button)
    fireEvent.submit(button.closest('form'))
    expect(api.createIdentityBreachCheck).toHaveBeenCalledTimes(1)
    expect(api.createIdentityBreachCheck).toHaveBeenCalledWith('workspace-a', {
      domain_id: 'domain-a', email: 'alice@example.com', consent: true, consent_version: '2026-10-09', request_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
    }, expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(screen.getByLabelText('Known corporate email address')).toHaveValue('')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(storage).not.toHaveBeenCalled()
    await act(async () => pending.resolve({ item: item() }))
    expect(screen.getByText('a***@example.com')).toBeInTheDocument()
    expect(screen.queryByText('alice@example.com')).not.toBeInTheDocument()
    storage.mockRestore()
  })

  it('requires the selected verified domain and resets consent when the target changes', async () => {
    mount()
    await prepare('person@unverified.test')
    fireEvent.click(screen.getByRole('checkbox'))
    expect(screen.getByRole('button', { name: 'Check this address' })).toBeDisabled()
    expect(screen.getByText('Use an address on the selected verified domain.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Known corporate email address'), { target: { value: 'person@example.com' } })
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    fireEvent.click(screen.getByRole('checkbox'))
    expect(screen.getByRole('button', { name: 'Check this address' })).toBeEnabled()
    fireEvent.change(screen.getByLabelText('Verified domain'), { target: { value: 'domain-b' } })
    expect(screen.getByLabelText('Known corporate email address')).toHaveValue('')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(api.createIdentityBreachCheck).not.toHaveBeenCalled()
  })

  it.each([false, 'true', undefined])('hides both controls and unexpected results unless can_check is strictly true (%s)', async can_check => {
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), can_check, items: [item()] })
    mount()
    await waitFor(() => expect(screen.queryByText('Loading saved address checks…')).not.toBeInTheDocument())
    expect(screen.queryByText('a***@example.com')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check this address' })).not.toBeInTheDocument()
  })

  it('refuses unavailable verification and unrecognised consent text without calling the provider', async () => {
    api.getIdentityBreachChecks.mockResolvedValueOnce({ ...empty(), domains: [] })
    const view = mount()
    expect(await screen.findByText(/Verify a domain in this workspace/)).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), consent_version: 'different' })
    view.rerender(<IdentityBreachChecks workspaceId="workspace-b" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('consent notice has changed')
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(api.createIdentityBreachCheck).not.toHaveBeenCalled()
  })

  it('distinguishes no matches, provider failures, rate limits and pending without safe or zero-finding claims', async () => {
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), items: ['no_matches', 'unavailable', 'rate_limited', 'pending', 'unknown_status'].map((status, index) => ({ ...item(status), id: `check-${index}`, sources: [], fields: [] })) })
    mount()
    expect(await screen.findByText('No matches returned')).toBeInTheDocument()
    expect(screen.getByText(/Other sources and later disclosures may differ/)).toBeInTheDocument()
    expect(screen.getByText('Check rate limited')).toBeInTheDocument()
    expect(screen.getAllByText('Check unavailable')).toHaveLength(2)
    expect(screen.getByText(/No conclusion yet/)).toBeInTheDocument()
    expect(screen.getAllByText(/No conclusion about exposure is available/)).toHaveLength(3)
    expect(screen.queryByText(/0 matching records/)).not.toBeInTheDocument()
  })

  it('shows source names, dates and field types as escaped text, never as password values or source links', async () => {
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), items: [{ ...item(), sources: [{ name: '<img src=x onerror=alert(1)>', date: '2023-01' }] }] })
    const view = mount()
    expect(await screen.findByText(/2 matching records reported/)).toBeInTheDocument()
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument()
    expect(view.container.querySelector('article img')).toBeNull()
    expect(view.container.querySelector('article a')).toBeNull()
    expect(screen.getByText(/Values and passwords are not shown/)).toBeInTheDocument()
    expect(screen.getByText(/Saved until:/)).toBeInTheDocument()
  })

  it('distinguishes matching records from source count and collapses long saved source lists', async () => {
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), items: [{ ...item(), found_count: 2036, sources: Array.from({ length: 316 }, (_, i) => ({ name: `Synthetic source ${i + 1}`, date: null })) }] })
    const view = mount()
    expect(await screen.findByText(/2036 matching records reported/)).toHaveTextContent('not a count of unique breaches')
    expect(screen.getByText('Source names in this saved result: 316')).toBeInTheDocument()
    const details = view.container.querySelector('article details')
    expect(details.open).toBe(false)
    expect(details.querySelectorAll('li')).toHaveLength(10)
    fireEvent.click(screen.getByText('Show all 316 saved source names'))
    expect(details.querySelectorAll('li')).toHaveLength(316)
    fireEvent.click(screen.getByText('Show first 10 source names'))
    expect(details.querySelectorAll('li')).toHaveLength(10)
  })

  it('distinguishes disabled automatic expiry from a missing observation timestamp', async () => {
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), items: [{ ...item(), checked_at: null, expires_at: null }] })
    mount()
    expect(await screen.findByText('Checked: Not recorded · No automatic expiry')).toBeInTheDocument()
    expect(screen.queryByText(/Saved until: Not recorded/)).not.toBeInTheDocument()
  })

  it('does not echo error payloads or restore a raw email when submission fails', async () => {
    api.createIdentityBreachCheck.mockRejectedValue(new Error('provider echoed alice@example.com'))
    mount()
    await prepare()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Check this address' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('This is not a no-match result')
    expect(screen.queryByText(/provider echoed/)).not.toBeInTheDocument()
    expect(screen.getByLabelText('Known corporate email address')).toHaveValue('')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
  })

  it('ignores late results and clears inputs across workspace changes, including A → B → A', async () => {
    const pending = deferred()
    api.createIdentityBreachCheck.mockReturnValue(pending.promise)
    const view = mount()
    await prepare()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Check this address' }))
    const requestSignal = api.createIdentityBreachCheck.mock.calls[0][2].signal
    view.rerender(<IdentityBreachChecks workspaceId="workspace-b" />)
    await screen.findByRole('heading', { name: 'Known address breach check' })
    expect(requestSignal.aborted).toBe(true)
    expect(screen.getByLabelText('Known corporate email address')).toHaveValue('')
    view.rerender(<IdentityBreachChecks workspaceId="workspace-a" />)
    await screen.findByRole('heading', { name: 'Known address breach check' })
    await act(async () => pending.resolve({ item: item() }))
    expect(screen.queryByText('a***@example.com')).not.toBeInTheDocument()
    expect(screen.getByText(/No saved checks/)).toBeInTheDocument()
  })

  it('rejects late initial loads from another workspace and sends no read before workspace resolution', async () => {
    const pending = deferred()
    api.getIdentityBreachChecks.mockReturnValueOnce(pending.promise).mockResolvedValue(empty())
    const view = render(<IdentityBreachChecks workspaceId={null} />)
    expect(api.getIdentityBreachChecks).not.toHaveBeenCalled()
    view.rerender(<IdentityBreachChecks workspaceId="workspace-a" />)
    const signal = api.getIdentityBreachChecks.mock.calls[0][1].signal
    view.rerender(<IdentityBreachChecks workspaceId="workspace-b" />)
    await screen.findByRole('heading', { name: 'Known address breach check' })
    await act(async () => pending.resolve({ ...empty(), items: [item()] }))
    expect(signal.aborted).toBe(true)
    expect(screen.queryByText('a***@example.com')).not.toBeInTheDocument()
  })

  it('deletes only the chosen saved result and retains it when deletion fails', async () => {
    api.getIdentityBreachChecks.mockResolvedValue({ ...empty(), items: [item(), { ...item('no_matches'), id: 'check-b', masked_address: 'b***@example.com' }] })
    api.deleteIdentityBreachCheck.mockRejectedValueOnce(new Error('failure')).mockResolvedValue({ ok: true })
    mount()
    const remove = await screen.findByRole('button', { name: 'Delete result for a***@example.com' })
    fireEvent.click(remove)
    expect(await screen.findByRole('alert')).toHaveTextContent('remains in the list')
    expect(screen.getByText('a***@example.com')).toBeInTheDocument()
    await waitFor(() => expect(remove).toBeEnabled())
    fireEvent.click(remove)
    await waitFor(() => expect(screen.queryByText('a***@example.com')).not.toBeInTheDocument())
    expect(screen.getByText('b***@example.com')).toBeInTheDocument()
    expect(api.deleteIdentityBreachCheck).toHaveBeenLastCalledWith('workspace-a', 'check-a', expect.objectContaining({ signal: expect.any(AbortSignal) }))
  })

  it('shows failed history loading as unavailable rather than an empty no-match result', async () => {
    api.getIdentityBreachChecks.mockRejectedValue(new Error('network'))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    expect(screen.queryByText(/No saved checks/)).not.toBeInTheDocument()
    expect(screen.queryByText('No matches returned')).not.toBeInTheDocument()
  })
})
