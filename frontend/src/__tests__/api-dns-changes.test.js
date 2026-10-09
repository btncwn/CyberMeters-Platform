import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { TOKEN_KEY } from '../context/authKeys'
beforeEach(() => { localStorage.setItem(TOKEN_KEY, 'synthetic-session') })
afterEach(() => { vi.unstubAllGlobals(); localStorage.clear() })
const response = () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } })
describe('DNS correction API transport', () => {
  it('uses existing authenticated no-store cancellation and encoded scope', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => response()); vi.stubGlobal('fetch', fetchMock); const signal = new AbortController().signal
    await api.getDnsConnections('ws/a', { signal }); await api.getDnsConnection('ws/a', 'example.com/path', { signal }); await api.getDnsChange('ws/a', 'example.com/path', 'change/a', { signal })
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual(['http://localhost/api/workspaces/ws%2Fa/dns-connections', 'http://localhost/api/workspaces/ws%2Fa/domains/example.com%2Fpath/dns-connection', 'http://localhost/api/workspaces/ws%2Fa/domains/example.com%2Fpath/dns-changes/change%2Fa'])
    for (const [, options] of fetchMock.mock.calls) { expect(options.signal).toBe(signal); expect(options.cache).toBe('no-store'); expect(options.headers.Authorization).toBe('Bearer synthetic-session') }
  })
  it('sends token only in explicit PUT body, never in disconnect or URL', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => response()); vi.stubGlobal('fetch', fetchMock); const body = { zone_id: 'a'.repeat(32), token: 'synthetic-token' }
    await api.connectDns('ws-a', 'example.com', body); await api.disconnectDns('ws-a', 'example.com')
    expect(fetchMock.mock.calls[0][0]).not.toContain('synthetic-token'); expect(fetchMock.mock.calls[0][1].method).toBe('PUT'); expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(body)
    expect(fetchMock.mock.calls[1][1].method).toBe('DELETE'); expect(fetchMock.mock.calls[1][1].body).toBeUndefined()
  })
  it('keeps preview, apply, verify and rollback separate and forwards exact approval', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => response()); vi.stubGlobal('fetch', fetchMock); const body = { request_id: 'test-request', confirm: true }; const signal = new AbortController().signal
    await api.previewDnsChange('ws-a', 'example.com', { action_id: 'tls_rpt', inputs: {}, request_id: 'test-preview' }, { signal })
    for (const method of ['applyDnsChange', 'verifyDnsChange', 'rollbackDnsChange']) await api[method]('ws-a', 'example.com', 'change/a', body, { signal })
    expect(fetchMock.mock.calls.map(([url]) => url.split('/dns-changes/')[1])).toEqual(['preview', 'change%2Fa/apply', 'change%2Fa/verify', 'change%2Fa/rollback'])
    for (const [, options] of fetchMock.mock.calls) { expect(options.method).toBe('POST'); expect(options.signal).toBe(signal) }
    for (const [, options] of fetchMock.mock.calls.slice(1)) expect(JSON.parse(options.body)).toEqual(body)
  })
})
