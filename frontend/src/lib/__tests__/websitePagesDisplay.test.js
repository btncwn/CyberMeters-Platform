import { describe, it, expect } from 'vitest'
import { coverageSummary, pageFacts, pageStatusMeta, sensitiveLabel } from '../websitePagesDisplay'

describe('websitePagesDisplay', () => {
  it('states page status without claiming more than the evidence', () => {
    expect(pageStatusMeta('observed').label).toBe('Seen')
    expect(pageStatusMeta('not_found').help).toMatch(/requested and answered 404 or 410/)
    expect(pageStatusMeta('unconfirmed').label).toBe('Could not confirm')
    expect(pageStatusMeta('weird').label).toBe('Unknown')
  })

  it('summarises coverage honestly, including partial and not run', () => {
    expect(coverageSummary(null)).toMatch(/queued and scheduled scans of a verified domain/)
    expect(coverageSummary({ coverage: 'complete', counts: { observed: 4, max_pages: 15 } })).toBe('4 pages seen on the last scan (checks up to 15).')
    expect(coverageSummary({ coverage: 'partial', counts: { observed: 15, max_pages: 15 }, partial_reasons: ['page_limit'] })).toMatch(/Partial: the page limit was reached/)
    expect(coverageSummary({ coverage: 'not_run', partial_reasons: ['not_durable_execution'] })).toMatch(/not checked on the last scan because this scan type/)
    expect(coverageSummary({ coverage: 'complete', counts: { observed: 6, max_pages: 15, js_paths_found: 12, js_paths_checked: 4, js_api_paths_found: 3 } }))
      .toBe("6 pages seen on the last scan (checks up to 15). 12 paths found in the site's JavaScript, 4 checked; 3 API paths noted but not requested.")
  })

  it('lists observed facts neutrally and never includes cookie values', () => {
    const facts = pageFacts({ observation: {
      https: true,
      security_headers: { missing: ['strict-transport-security', 'content-security-policy'], present: [] },
      forms: [{ action_kind: 'other_origin', action_host: 'collector.example', has_password: true }, { action_kind: 'same_origin', action_scheme: 'http', has_password: false }],
      cookies: [{ name: 'session', secure: false }, { name: 'pref', secure: true }],
      mixed_content: { count: 2 },
      third_party_scripts: ['a.example'],
    } })
    expect(facts).toEqual([
      'HSTS header not sent',
      'No Content-Security-Policy',
      'Password form sends to collector.example',
      'Form sends over plain HTTP',
      'Cookie without Secure: session',
      '2 insecure (http://) resources on an HTTPS page',
      '1 third-party script host',
    ])
    expect(facts.join(' ')).not.toMatch(/critical|high|vulnerab|attack|phishing|compromis|secure site|safe/i)
  })

  it('a Set-Cookie that only removes a cookie is not listed as a cookie without Secure', () => {
    const facts = pageFacts({ observation: { https: true, cookies: [{ name: 'old_sid', secure: false, deletes: true }, { name: 'sid', secure: false }] } })
    expect(facts).toEqual(['Cookie without Secure: sid'])
    expect(pageFacts({ observation: { https: true, cookies: [{ name: 'old_sid', secure: false, deletes: true }] } })).toEqual([])
  })

  it('a page with no observation has no facts', () => {
    expect(pageFacts({ observation: null })).toEqual([])
  })

  it('never states an address-inferred page type as fact', () => {
    expect(sensitiveLabel({ sensitive_kind: 'admin', observation: { sensitive_basis: 'path' } })).toBe('Possibly an admin page · from its address')
    expect(sensitiveLabel({ sensitive_kind: 'login', observation: { sensitive_basis: 'password_field' } })).toBe('Sign-in page · has a password field')
    expect(sensitiveLabel({ sensitive_kind: null })).toBe(null)
  })
})
