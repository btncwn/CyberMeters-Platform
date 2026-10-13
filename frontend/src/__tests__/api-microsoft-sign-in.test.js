import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { TOKEN_KEY, USER_KEY } from '../context/authKeys'

beforeEach(() => {
  localStorage.setItem(TOKEN_KEY, 'existing-session')
  localStorage.setItem(USER_KEY, JSON.stringify({ id: 'u1' }))
})
afterEach(() => { vi.unstubAllGlobals(); localStorage.clear() })
const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('Microsoft sign-in transport', () => {
  it('sends the code and verifiers without the existing session token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(reply(200, { token: 't' }))
    vi.stubGlobal('fetch', fetchMock)
    await api.exchangeOAuthCode('otc', ['verifier'])
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('http://localhost/api/auth/exchange')
    expect(options.method).toBe('POST')
    expect(options.headers.Authorization).toBeUndefined()
    expect(JSON.parse(options.body)).toEqual({ code: 'otc', verifiers: ['verifier'] })
    expect(url).not.toContain('verifier')
  })

  it('a refused exchange leaves the existing session in place', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply(401, { error: 'Sign-in could not be completed in this browser. Please sign in again.' })))
    await expect(api.exchangeOAuthCode('otc', ['verifier'])).rejects.toMatchObject({ status: 401 })
    expect(localStorage.getItem(TOKEN_KEY)).toBe('existing-session')
    expect(localStorage.getItem(USER_KEY)).not.toBeNull()
  })

  it('starts sign-in with a JSON POST carrying only the challenge', async () => {
    const fetchMock = vi.fn().mockResolvedValue(reply(200, { authorize_url: 'https://login.microsoftonline.com/t/oauth2/v2.0/authorize' }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await api.startMicrosoftSignIn('challenge-value')
    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('http://localhost/api/auth/microsoft/start')
    expect(options.headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(options.body)).toEqual({ binding: 'challenge-value' })
    expect(result.authorize_url).toMatch(/^https:\/\/login\.microsoftonline\.com\//)
  })
})
