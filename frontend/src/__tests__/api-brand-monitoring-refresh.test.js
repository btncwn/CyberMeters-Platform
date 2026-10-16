import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { TOKEN_KEY } from '../context/authKeys'

afterEach(() => { vi.unstubAllGlobals(); localStorage.clear() })

describe('Brand DNS refresh transport', () => {
  it('posts to the existing workspace endpoint with an authenticated session', async () => {
    localStorage.setItem(TOKEN_KEY, 'synthetic-session')
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ updated: 1 }), {
      status: 200, headers: { 'content-type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetch)

    expect(await api.refreshBrandMonitoring('ws-1')).toEqual({ updated: 1 })
    expect(fetch).toHaveBeenCalledWith('http://localhost/api/workspaces/ws-1/brand-monitoring/refresh',
      expect.objectContaining({ method: 'POST', cache: 'no-store', headers: expect.objectContaining({ Authorization: 'Bearer synthetic-session' }) }))
  })
})
