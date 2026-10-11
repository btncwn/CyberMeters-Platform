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

describe('signed-in pages', () => {
  it('summarises the last scan honestly', async () => {
    const { signedInCoverageText } = await import('../websiteSignInDisplay')
    expect(signedInCoverageText(null)).toMatch(/queued and scheduled scans/)
    expect(signedInCoverageText({ outcome: 'credentials_rejected' })).toBe('The last scan could not sign in: sign-in refused.')
    expect(signedInCoverageText({ outcome: 'plan_required' })).toMatch(/paid plan or trial/)
    expect(signedInCoverageText({ outcome: 'signed_in', coverage: 'partial', summary: { counts: { pages_observed: 3 }, limits: { max_pages: 10 }, partial_reasons: ['session_ended'] } }))
      .toBe('3 signed-in pages checked on the last scan (up to 10). Partial: the session ended during the scan.')
  })

  it('lists the anonymous contrast first and never a verdict', async () => {
    const { signedInPageFacts } = await import('../websiteSignInDisplay')
    const facts = signedInPageFacts({
      outcome: 'observed', anonymous_access: 'served_with_signed_in_text',
      cache_control: { kind: 'storable', directives: ['public', 'max-age=600'] }, frame_protection: false,
      missing_headers: ['strict-transport-security'], cookies: [{ name: 'pref', secure: true, httponly: false }],
      forms: [{ action_kind: 'same_origin', action_scheme: 'http' }], mixed_content: { count: 0 }, third_party_scripts: ['cdn.example'],
    })
    expect(facts).toEqual([
      'Without signing in, this page still showed your signed-in text',
      'Cache-Control lets caches keep a copy (public, max-age=600)',
      'Can be shown inside another site’s frame (no X-Frame-Options or frame-ancestors)',
      'HSTS header not sent',
      'Cookie pref without HttpOnly',
      'Form sends over plain HTTP',
      '1 third-party script host on a signed-in page',
    ])
    expect(facts.join(' ')).not.toMatch(/vulnerab|attack|compromis|critical|leak/i)
    expect(signedInPageFacts({ outcome: 'refused' })).toEqual([])
  })
})
