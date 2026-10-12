import { createHash, webcrypto } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  clearMicrosoftLoginBindings,
  createMicrosoftLoginBinding,
  forgetMicrosoftLoginVerifier,
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
    let started = false, assigned = null
    await expect(startMicrosoftSignIn({ storage, cryptoImpl, start: async () => { started = true }, assign: (url) => { assigned = url } }))
      .rejects.toThrow()
    expect(started).toBe(false)
    expect(assigned).toBeNull()
  })

  it('posts only the challenge, then follows the Microsoft authorize URL', async () => {
    const storage = memoryStorage()
    let posted = null, assigned = null
    const authorize = 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=s'
    await startMicrosoftSignIn({ storage, cryptoImpl, start: async (challenge) => { posted = challenge; return { authorize_url: authorize } }, assign: (url) => { assigned = url } })
    const [verifier] = microsoftLoginVerifiers({ storage })
    expect(posted).toBe(createHash('sha256').update(verifier).digest('base64url'))
    expect(assigned).toBe(authorize)
    expect(assigned).not.toContain(verifier)
  })

  it('refuses to follow anything but the Microsoft authorize endpoint', async () => {
    let assigned = null
    await expect(startMicrosoftSignIn({ storage: memoryStorage(), cryptoImpl, start: async () => ({ authorize_url: 'https://evil.example/login' }), assign: (url) => { assigned = url } }))
      .rejects.toThrow()
    expect(assigned).toBeNull()
  })

  it('forgets only the verifier of the finished sign-in', async () => {
    const storage = memoryStorage()
    const first = await createMicrosoftLoginBinding({ storage, cryptoImpl, now: 1_000 })
    await createMicrosoftLoginBinding({ storage, cryptoImpl, now: 2_000 })
    await forgetMicrosoftLoginVerifier(first, { storage, cryptoImpl, now: 3_000 })
    const left = microsoftLoginVerifiers({ storage, now: 3_000 })
    expect(left).toHaveLength(1)
    expect(createHash('sha256').update(left[0]).digest('base64url')).not.toBe(first)
    await forgetMicrosoftLoginVerifier(undefined, { storage, cryptoImpl, now: 3_000 })
    expect(microsoftLoginVerifiers({ storage, now: 3_000 })).toHaveLength(1)
  })
})
