import React from 'react'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import HostnameListPanel, { importSummaryLines } from '../HostnameListPanel'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getHostnameLists: vi.fn(), saveHostnameList: vi.fn(), clearHostnameList: vi.fn() } }))

const list = {
  format: 'list', hostnames: ['portal.acme.test', 'vpn.acme.test'], hostname_count: 2, entries_examined: 3,
  out_of_scope: 1, rejected: 0, truncated: false, rejected_reasons: [], saved_at: '2026-10-11T09:00:00Z',
}
const listing = (over = {}) => ({
  can_manage: true, formats: ['list', 'csv', 'zone'], limits: { max_hostnames: 200, max_bytes: 262144 },
  scope_note: 'Each scan asks DNS about each name.', domains: [{ domain: 'acme.test', list: null }], ...over,
})

beforeEach(() => { vi.resetAllMocks() })

describe('HostnameListPanel', () => {
  it('saves a pasted list in the chosen format and reports what the backend kept', async () => {
    api.getHostnameLists.mockResolvedValueOnce(listing()).mockResolvedValueOnce(listing({ domains: [{ domain: 'acme.test', list }] }))
    api.saveHostnameList.mockResolvedValue({ ok: true, status: 200, body: { list, result: { accepted: 2, out_of_scope: 1, rejected: 0, truncated: false } } })
    render(<HostnameListPanel workspaceId="ws1" />)
    expect(await screen.findByText('Each scan asks DNS about each name.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Add list' }))
    const save = screen.getByRole('button', { name: 'Save list' })
    expect(save).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Hostnames under acme.test'), { target: { value: 'portal.acme.test\nvpn.acme.test\nother.test' } })
    fireEvent.click(save)
    await waitFor(() => expect(api.saveHostnameList).toHaveBeenCalledTimes(1))
    expect(api.saveHostnameList.mock.calls[0]).toEqual(['ws1', 'acme.test', { format: 'list', text: 'portal.acme.test\nvpn.acme.test\nother.test' }])
    expect(await screen.findByText('2 hostnames saved.')).toBeInTheDocument()
    expect(screen.getByText('1 entry outside acme.test was ignored.')).toBeInTheDocument()
    expect(screen.getByText('The next scan asks DNS about each name.')).toBeInTheDocument()
    expect(await screen.findByText(/2 hostnames listed/)).toBeInTheDocument()
  })

  it('shows the backend refusal and its reasons when nothing in the list is under the domain', async () => {
    api.getHostnameLists.mockResolvedValue(listing())
    api.saveHostnameList.mockResolvedValue({ ok: false, status: 422, body: { code: 'no_hostnames_accepted', result: { accepted: 0, out_of_scope: 2, rejected: 1, truncated: false } } })
    render(<HostnameListPanel workspaceId="ws1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Add list' }))
    fireEvent.change(screen.getByLabelText('Hostnames under acme.test'), { target: { value: 'a.other.test\nb.other.test\n???' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save list' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('No hostname under this domain was found in the list.')
    expect(screen.getByText('2 entries outside acme.test were ignored.')).toBeInTheDocument()
    expect(screen.getByText('1 entry could not be read as a hostname.')).toBeInTheDocument()
  })

  it('lists saved names and removes a list only after confirmation', async () => {
    api.getHostnameLists.mockResolvedValue(listing({ domains: [{ domain: 'acme.test', list }] }))
    api.clearHostnameList.mockResolvedValue({ ok: true, status: 200, body: { domain: 'acme.test', cleared: true } })
    render(<HostnameListPanel workspaceId="ws1" />)
    const names = await screen.findByLabelText('Hostnames listed for acme.test')
    expect(within(names).getAllByRole('listitem').map((item) => item.textContent)).toEqual(['portal.acme.test', 'vpn.acme.test'])
    fireEvent.click(screen.getByRole('button', { name: 'Remove list' }))
    expect(api.clearHostnameList).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm remove' }))
    await waitFor(() => expect(api.clearHostnameList).toHaveBeenCalledWith('ws1', 'acme.test'))
    expect(await screen.findByText('List removed. Scans no longer check these names.')).toBeInTheDocument()
  })

  it('viewers see lists without controls; load failures and empty workspaces are explicit', async () => {
    api.getHostnameLists.mockResolvedValue(listing({ can_manage: false, domains: [{ domain: 'acme.test', list }] }))
    const { unmount } = render(<HostnameListPanel workspaceId="ws1" />)
    expect(await screen.findByText('Only a workspace owner or admin can change hostname lists.')).toBeInTheDocument()
    for (const name of ['Add list', 'Replace list', 'Remove list']) expect(screen.queryByRole('button', { name })).toBeNull()
    unmount()
    api.getHostnameLists.mockResolvedValue(listing({ domains: [] }))
    const second = render(<HostnameListPanel workspaceId="ws1" />)
    expect(await screen.findByText('Verify a domain in this workspace to list hostnames for it.')).toBeInTheDocument()
    second.unmount()
    api.getHostnameLists.mockRejectedValue(new Error('503'))
    render(<HostnameListPanel workspaceId="ws1" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Hostname lists could not be loaded.')
  })

  it('summarises only facts the backend reported', () => {
    expect(importSummaryLines(null, 'acme.test')).toEqual([])
    expect(importSummaryLines({ accepted: 1, out_of_scope: 0, rejected: 2, truncated: true }, 'acme.test')).toEqual([
      '1 hostname saved.',
      '2 entries could not be read as a hostname.',
      'The list was longer than the limit; only the first names were kept.',
    ])
  })
})
