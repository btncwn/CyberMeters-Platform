import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { TOKEN_KEY } from '../context/authKeys'

beforeEach(() => { localStorage.setItem(TOKEN_KEY, 'synthetic-session') })
afterEach(() => { vi.unstubAllGlobals(); localStorage.clear() })
const response = data => new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } })

describe('Known-address check API transport', () => {
  it('uses the existing authenticated no-store transport and forwards read cancellation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ can_check: false }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()
    await api.getIdentityBreachChecks('ws/scope', { signal: controller.signal })
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('http://localhost/api/workspaces/ws%2Fscope/identity-breach-checks')
    expect(options.signal).toBe(controller.signal)
    expect(options.headers.Authorization).toBe('Bearer synthetic-session')
    expect(options.cache).toBe('no-store')
  })

  it('sends an address only in the POST body, with explicit versioned consent and cancellation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ item: { id: 'check-a' } }))
    vi.stubGlobal('fetch', fetchMock)
    const body = { domain_id: 'domain-a', email: 'alice@example.com', consent: true, consent_version: '2026-10-09', request_id: 'synthetic-request' }
    const controller = new AbortController()
    await api.createIdentityBreachCheck('workspace-a', body, { signal: controller.signal })
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('http://localhost/api/workspaces/workspace-a/identity-breach-checks')
    expect(url).not.toContain('alice')
    expect(options.method).toBe('POST')
    expect(JSON.parse(options.body)).toEqual(body)
    expect(options.signal).toBe(controller.signal)
  })

  it('deletes the encoded record within its workspace, never by email', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)
    await api.deleteIdentityBreachCheck('workspace-a', 'check/a')
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('http://localhost/api/workspaces/workspace-a/identity-breach-checks/check%2Fa')
    expect(options.method).toBe('DELETE')
    expect(options.body).toBeUndefined()
  })
})
