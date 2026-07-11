import { describe, expect, it } from 'vitest'
import { friendlyHttpError } from '../httpErrors'

const res = (status) => ({ status })

describe('friendlyHttpError', () => {
  it('preserves descriptive server messages and attaches status', () => {
    const err = friendlyHttpError(res(403), { error: 'Forbidden — admin role required' })

    expect(err.message).toBe('Forbidden — admin role required')
    expect(err.status).toBe(403)
  })

  it('replaces bare protocol words with safer fallback copy', () => {
    expect(friendlyHttpError(res(403), { error: 'Forbidden' }).message)
      .toBe('You don’t have access to this. Try switching workspace or contact your admin.')
    expect(friendlyHttpError(res(404), { error: 'Not Found' }).message)
      .toBe('We couldn’t find what you were looking for.')
    expect(friendlyHttpError(res(429), { error: 'Too Many Requests' }).message)
      .toBe('Too many requests right now. Please wait a moment and try again.')
  })

  it('uses a human detail field when the server error is only a status word', () => {
    const err = friendlyHttpError(res(403), {
      error: 'Forbidden',
      message: 'Only workspace owners can manage billing.',
    })

    expect(err.message).toBe('Only workspace owners can manage billing.')
  })

  it('maps server failures to customer-safe copy', () => {
    const err = friendlyHttpError(res(500), { error: 'Internal Server Error' })

    expect(err.message).toBe('Something went wrong on our end. Please try again in a moment.')
    expect(err.message).not.toMatch(/internal|sql|stack/i)
  })

  it('falls back to generic copy for other client errors', () => {
    expect(friendlyHttpError(res(409), {}).message).toBe('Something went wrong. Please try again.')
  })
})
