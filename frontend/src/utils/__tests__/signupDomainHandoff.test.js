import { describe, expect, it } from 'vitest'
import {
  PENDING_SIGNUP_DOMAIN_KEY,
  persistSignupDomainParam,
  sanitizeDomainParam,
} from '../signupDomainHandoff'

function memoryStorage() {
  const data = new Map()
  return {
    getItem: key => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: key => data.delete(key),
  }
}

describe('signup domain handoff', () => {
  it('sanitizes a dirty Cyber MOT domain before signup persistence', () => {
    expect(sanitizeDomainParam('HTTPS://www.BlackBullBarbers.co.uk/path?q=1')).toBe('blackbullbarbers.co.uk')
  })

  it('rejects script-like input and does not persist it', () => {
    const storage = memoryStorage()

    expect(persistSignupDomainParam('<script>alert(1)</script>', storage)).toBeNull()
    expect(storage.getItem(PENDING_SIGNUP_DOMAIN_KEY)).toBeNull()
  })

  it('preserves a valid sanitized domain using the onboarding handoff key', () => {
    const storage = memoryStorage()

    expect(persistSignupDomainParam('HTTPS://www.BlackBullBarbers.co.uk/path?q=1', storage)).toBe('blackbullbarbers.co.uk')
    expect(storage.getItem(PENDING_SIGNUP_DOMAIN_KEY)).toBe('blackbullbarbers.co.uk')
  })
})
