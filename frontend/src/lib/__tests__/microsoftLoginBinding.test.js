import { createHash, webcrypto } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  clearMicrosoftLoginBindings,
  createMicrosoftLoginBinding,
  microsoftLoginUrl,
  microsoftLoginVerifiers,
  startMicrosoftSignIn,
} from '../microsoftLoginBinding'

function memoryStorage() {
  const map = new Map()
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)) },
    removeItem: (key) => { map.delete(key) },
  }
}
const cryptoImpl = webcrypto

describe('Microsoft sign-in browser binding', () => {
  it('stores a verifier and returns only its SHA-256 challenge', async () => {
    const storage = memoryStorage()
    const challenge = await createMicrosoftLoginBinding({ storage, cryptoImpl })
    const [verifier] = microsoftLoginVerifiers({ storage })
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(challenge).toBe(createHash('sha256').update(verifier).digest('base64url'))
    expect(challenge).not.toBe(verifier)
  })

  it('keeps sign-ins from several tabs, newest first, at most five', async () => {
    const storage = memoryStorage()
    for (let i = 0; i < 7; i++) await createMicrosoftLoginBinding({ storage, cryptoImpl, now: 1_000 + i })
    expect(microsoftLoginVerifiers({ storage, now: 2_000 })).toHaveLength(5)
  })

  it('forgets verifiers older than fifteen minutes', async () => {
    const storage = memoryStorage()
    await createMicrosoftLoginBinding({ storage, cryptoImpl, now: 0 })
    expect(microsoftLoginVerifiers({ storage, now: 15 * 60 * 1000 + 1 })).toEqual([])
  })

  it('treats unreadable storage as no verifier, and clears on request', async () => {
    const storage = memoryStorage()
    storage.setItem('cm_ms_login_bindings', '{not json')
    expect(microsoftLoginVerifiers({ storage })).toEqual([])
    await createMicrosoftLoginBinding({ storage, cryptoImpl })
    clearMicrosoftLoginBindings({ storage })
    expect(microsoftLoginVerifiers({ storage })).toEqual([])
  })

  it('fails when the browser refuses storage, so an unbound sign-in never starts', async () => {
    const storage = { getItem: () => null, setItem: () => { throw new Error('blocked') }, removeItem: () => {} }
    let assigned = null
    await expect(startMicrosoftSignIn('https://api.test/api', { storage, cryptoImpl, assign: (url) => { assigned = url } }))
      .rejects.toThrow()
    expect(assigned).toBeNull()
  })

  it('puts the challenge, never the verifier, in the sign-in URL', async () => {
    const storage = memoryStorage()
    let assigned = null
    await startMicrosoftSignIn('https://api.test/api', { storage, cryptoImpl, assign: (url) => { assigned = url } })
    const [verifier] = microsoftLoginVerifiers({ storage })
    const url = new URL(assigned)
    expect(`${url.origin}${url.pathname}`).toBe('https://api.test/api/auth/microsoft/login')
    expect(url.searchParams.get('binding')).toBe(createHash('sha256').update(verifier).digest('base64url'))
    expect(assigned).not.toContain(verifier)
    expect(microsoftLoginUrl('https://x', 'c-d_e')).toBe('https://x/auth/microsoft/login?binding=c-d_e')
  })
})
