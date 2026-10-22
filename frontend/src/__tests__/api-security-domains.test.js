import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'

afterEach(() => { vi.unstubAllGlobals(); localStorage.clear() })

describe('canonical security-domain request', () => {
  it('returns the existing endpoint response', async () => {
    const data = { security_domains: [] }
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(data), {
      status: 200, headers: { 'content-type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetch)

    expect(await api.getSecurityCheckDomains('ws-1')).toEqual(data)
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch).toHaveBeenCalledWith('http://localhost/api/workspaces/ws-1/security-domains',
      expect.objectContaining({ cache: 'no-store' }))
  })

  it('surfaces a missing endpoint without making a second request', async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ code: 'not_found' }), {
      status: 404, headers: { 'content-type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetch)

    await expect(api.getSecurityCheckDomains('ws-1')).rejects.toMatchObject({ status: 404, code: 'not_found' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})
