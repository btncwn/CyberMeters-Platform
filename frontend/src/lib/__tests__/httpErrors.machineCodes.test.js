import { describe, expect, it } from 'vitest'
import { friendlyHttpError } from '../httpErrors'
import { CUSTOMER_CODE_COPY } from '../customerReasonText'

// Executive 24 Oct 2026: a snake_case machine code from the server never becomes
// err.message (65 screens render err.message directly). It stays on e.error /
// e.code for callers to switch on.
const res = (status) => ({ status })

describe('friendlyHttpError and machine codes', () => {
  it.each(['invalid_json_body', 'unsupported_consent_field', 'invalid_active_checks', 'invalid_customer_state', 'email_verification_required'])(
    '%s never becomes the message; it stays on error and code', (code) => {
      const e = friendlyHttpError(res(400), { error: code })
      expect(e.message).not.toBe(code)
      expect(e.message).not.toMatch(/^[a-z0-9]+(_[a-z0-9]+)+$/)
      expect(e.error).toBe(code)
      expect(e.code).toBe(code)
      expect(e.status).toBe(400)
    })
  it('a code with customer copy reads as that copy', () => {
    const [code, copy] = Object.entries(CUSTOMER_CODE_COPY).find(([k]) => /^[a-z0-9]+(_[a-z0-9]+)+$/.test(k))
    expect(friendlyHttpError(res(400), { error: code }).message).toBe(copy)
  })
  it('a code without copy uses the server\'s human detail, else the status text', () => {
    expect(friendlyHttpError(res(400), { error: 'invalid_json_body', message: 'The request could not be read.' }).message).toBe('The request could not be read.')
    expect(friendlyHttpError(res(400), { error: 'invalid_json_body', message: 'another_code' }).message).toBe('Something went wrong. Please try again.')
    expect(friendlyHttpError(res(500), { error: 'internal_error' }).message).toBe('Something went wrong on our end. Please try again in a moment.')
    expect(friendlyHttpError(res(403), { error: 'forbidden_scope' }).message).toBe('You don’t have access to this. Try switching workspace or contact your admin.')
  })
  it('a human-readable server string is unchanged; bare HTTP words and empty bodies still map', () => {
    expect(friendlyHttpError(res(401), { error: 'Invalid email or password' }).message).toBe('Invalid email or password')
    expect(friendlyHttpError(res(403), { error: 'Forbidden' }).message).toBe('You don’t have access to this. Try switching workspace or contact your admin.')
    expect(friendlyHttpError(res(500), {}).message).toBe('Something went wrong on our end. Please try again in a moment.')
  })
})
