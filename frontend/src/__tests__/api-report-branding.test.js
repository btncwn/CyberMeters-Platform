import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { TOKEN_KEY } from '../context/authKeys'
beforeEach(() => localStorage.setItem(TOKEN_KEY, 'synthetic-session'))
afterEach(() => { vi.unstubAllGlobals(); localStorage.clear() })
const response = () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } })
describe('Agency/client branding transport', () => {
  it('keeps authenticated cancellation and encoded account/workspace paths for reads', async () => {
    const fetch = vi.fn().mockImplementation(async () => response()); vi.stubGlobal('fetch', fetch); const signal = new AbortController().signal
    await api.getBrandingProfiles({ signal }); await api.getBrandingProfile('profile/a', { signal }); await api.getWorkspaceBranding('ws/a', { signal }); await api.getWorkspaceBrandingLogo('ws/a', { signal })
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(['http://localhost/api/account/branding/profiles', 'http://localhost/api/account/branding/profiles/profile%2Fa', 'http://localhost/api/workspaces/ws%2Fa/branding', 'http://localhost/api/workspaces/ws%2Fa/branding/logo'])
    for (const [, init] of fetch.mock.calls) { expect(init.signal).toBe(signal); expect(init.cache).toBe('no-store'); expect(init.headers.Authorization).toBe('Bearer synthetic-session') }
  })
  it('keeps create/update/name/logo/delete distinct without adding permissions or logo into a URL', async () => {
    const fetch = vi.fn().mockImplementation(async () => response()); vi.stubGlobal('fetch', fetch); const body = { name: 'Agency', logo: 'data:image/png;base64,aGVsbG8=' }
    await api.createBrandingProfile(body); await api.updateBrandingProfile('profile/a', { is_default: true }); await api.deleteBrandingProfile('profile/a')
    await api.updateWorkspaceBranding('ws/a', { display_name: 'Client' }); await api.updateWorkspaceBrandingLogo('ws/a', { logo: body.logo }); await api.deleteWorkspaceBrandingLogo('ws/a')
    expect(fetch.mock.calls.map(([, init]) => init.method)).toEqual(['POST', 'PUT', 'DELETE', 'PUT', 'PUT', 'DELETE'])
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual(body); expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ is_default: true }); expect(JSON.parse(fetch.mock.calls[3][1].body)).toEqual({ display_name: 'Client' })
    for (const [url, init] of fetch.mock.calls) { expect(url).not.toContain(body.logo); if (init.method === 'DELETE') expect(init.body).toBeUndefined() }
  })
})
