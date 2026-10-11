import { describe, it, expect } from 'vitest'
import { SIGN_IN_OUTCOME_META, sessionFacts, signInErrorText, signInOutcomeMeta } from '../websiteSignInDisplay'

describe('websiteSignInDisplay', () => {
  it('only a confirmed sign-in reads as success', () => {
    const ok = Object.entries(SIGN_IN_OUTCOME_META).filter(([, m]) => m.tone === 'ok').map(([k]) => k)
    expect(ok).toEqual(['signed_in'])
    expect(signInOutcomeMeta('start_page_public').label).toBe('Could not confirm sign-in')
    expect(signInOutcomeMeta('something_new')).toEqual({ label: 'Unknown', tone: 'muted', help: null })
  })

  it('every outcome tells the customer what to do, without verdict words', () => {
    for (const [code, meta] of Object.entries(SIGN_IN_OUTCOME_META)) {
      expect(meta.help, code).toBeTruthy()
      expect(`${meta.label} ${meta.help}`, code).not.toMatch(/vulnerab|hack|attack|compromis|critical|secure site/i)
    }
  })

  it('session facts are neutral and never carry values', () => {
    const facts = sessionFacts({
      cookies_at_sign_in: [
        { name: 'sid', secure: false, httponly: false, samesite: 'none', persistent: true, lifetime_days: 365 },
        { name: 'ok', secure: true, httponly: true, samesite: 'lax', persistent: false, lifetime_days: null },
      ],
      session_cookie_renewed: 'not_renewed',
    })
    expect(facts).toEqual([
      'Cookie sid set at sign-in without Secure',
      'Cookie sid set at sign-in without HttpOnly',
      'Cookie sid set at sign-in with SameSite=None',
      'Cookie sid set at sign-in lasts 365 days',
      'The session cookie kept the same value through sign-in',
    ])
    expect(sessionFacts({ cookies_at_sign_in: [], session_cookie_renewed: 'renewed' })).toEqual([])
  })

  it('maps write errors to plain words, rate limits included', () => {
    expect(signInErrorText({ status: 400, body: { code: 'login_url_not_on_domain' } })).toMatch(/this domain/)
    expect(signInErrorText({ status: 429, body: {} })).toMatch(/Try again in an hour/)
    expect(signInErrorText({ status: 503, body: { error: 'x' } })).toBe('x')
  })
})
