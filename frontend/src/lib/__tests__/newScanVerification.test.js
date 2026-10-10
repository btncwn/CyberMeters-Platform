import { describe, it, expect } from 'vitest'
import {
  canStartScan, isValidDomainSyntax, domainHintFor, safeErrorMessage,
  isVerificationRequired, dnsInstructionFrom, checkFailureMessage,
  shouldKeepInstructions, SCAN_STATES, DNS_TTL_GUIDANCE,
  requiresVerificationCta, isDeadEnd, canonicalDomainInput, matchWorkspaceDomain } from '../newScanVerification'

// ── The production deadlock (P1) ────────────────────────────────────────────
// Observed live: a valid domain showed "Valid domain format…", Start Scan was
// disabled, the helper said "Verify domain ownership to enable scanning" — and NO
// verification CTA existed. The panel was only reachable from the createScan error
// path, which a disabled button can never trigger. The customer had no way forward.
describe('REGRESSION: no state may require verification without offering a way to do it', () => {
  it('no state is a dead end', () => {
    const deadEnds = SCAN_STATES.filter(isDeadEnd)
    expect(deadEnds).toEqual([])
  })

  it('the exact production screenshot state offers a CTA', () => {
    // valid syntax + unverified + no instructions yet — precisely what was live.
    const state = 'valid_unverified'
    expect(canStartScan(state)).toBe(false)              // Start Scan disabled, correctly
    expect(requiresVerificationCta(state)).toBe(true)    // ...but a CTA MUST be offered
    expect(isDeadEnd(state)).toBe(false)
  })

  it('every unverified-but-actionable state offers a CTA', () => {
    for (const s of ['valid_unverified', 'initiating_verification', 'instructions', 'checking', 'check_failed']) {
      expect(requiresVerificationCta(s)).toBe(true)
    }
  })

  it('verified and scanning states do not nag for verification', () => {
    expect(requiresVerificationCta('verified')).toBe(false)
    expect(requiresVerificationCta('scanning')).toBe(false)
  })

  it('the unverified hint tells the customer what to do', () => {
    expect(domainHintFor('valid_unverified', 'cybermeters.com').text).toMatch(/verify ownership/i)
  })
})

describe('Start Scan is gated on proven ownership, not syntax', () => {
  it('is disabled in every state except verified', () => {
    const enabled = SCAN_STATES.filter(canStartScan)
    expect(enabled).toEqual(['verified'])
  })

  it('is disabled for a syntactically valid but unverified domain', () => {
    expect(isValidDomainSyntax('cybermeters.com')).toBe(true)
    expect(canStartScan('valid_unverified')).toBe(false)   // the old bug: valid syntax => scan
    expect(canStartScan('instructions')).toBe(false)
    expect(canStartScan('check_failed')).toBe(false)
  })
})

describe('never claims "ready to scan" for an unverified domain', () => {
  it('describes the FORMAT only, until ownership is proven', () => {
    const hint = domainHintFor('valid_unverified', 'cybermeters.com')
    expect(hint.text).not.toMatch(/ready to scan/i)
    expect(hint.text).toMatch(/format/i)
    expect(hint.text).toMatch(/verify ownership/i)   // never a dead end, even in copy
    expect(hint.tone).toBe('neutral')          // not a green tick
  })

  it('no unverified state ever says "ready to scan"', () => {
    for (const s of SCAN_STATES.filter((s) => s !== 'verified' && s !== 'scanning')) {
      const hint = domainHintFor(s, 'cybermeters.com')
      expect(hint?.text ?? '').not.toMatch(/ready to scan/i)
    }
  })

  it('says ready to scan ONLY once verified', () => {
    expect(domainHintFor('verified', 'cybermeters.com')).toEqual({
      tone: 'success', text: 'Domain ownership verified — ready to scan',
    })
  })

  it('rejects malformed input without implying ownership', () => {
    expect(domainHintFor('idle', 'not a domain').tone).toBe('error')
    expect(domainHintFor('idle', '')).toBeNull()
  })
})

describe('never exposes a raw machine code', () => {
  it('maps domain_verification_required to customer-safe copy', () => {
    const err = Object.assign(new Error('domain_verification_required'), { code: 'domain_verification_required' })
    const msg = safeErrorMessage(err)
    expect(msg).toBe('Verify ownership of this domain before scanning.')
    expect(msg).not.toContain('domain_verification_required')
  })

  it('never renders a snake_case identifier that leaked into message', () => {
    // The API client preserves the server's `error` string verbatim as the Error
    // message, so this is exactly what New Scan used to print on screen.
    const err = new Error('domain_verification_required')
    expect(safeErrorMessage(err)).not.toMatch(/_/)
    expect(safeErrorMessage(new Error('some_new_backend_code'))).toBe(
      'We could not start this scan. Please try again or contact support.')
  })

  it('keeps genuine human-readable server messages', () => {
    expect(safeErrorMessage(new Error('Invalid email or password'))).toBe('Invalid email or password')
  })

  it('degrades safely on an empty error', () => {
    expect(safeErrorMessage(undefined)).toMatch(/could not start this scan/i)
  })

  it('detects the verification gate from either code or error', () => {
    expect(isVerificationRequired({ code: 'domain_verification_required' })).toBe(true)
    expect(isVerificationRequired({ error: 'domain_verification_required' })).toBe(true)
    expect(isVerificationRequired({ code: 'rate_limit_exceeded' })).toBe(false)
  })
})

describe('DNS instruction comes only from the backend', () => {
  const response = {
    domain: 'cybermeters.com',
    dns: {
      record_type: 'TXT',
      host: '_cybermeters.cybermeters.com',
      value: 'cybermeters-verification=abc123',
    },
  }

  it('surfaces the exact type, host and value the server minted', () => {
    const i = dnsInstructionFrom(response)
    expect(i.record_type).toBe('TXT')
    expect(i.host).toBe('_cybermeters.cybermeters.com')
    expect(i.value).toBe('cybermeters-verification=abc123')
  })

  it('includes TTL guidance and the Cloudflare path', () => {
    const i = dnsInstructionFrom(response)
    expect(i.ttl).toBe(DNS_TTL_GUIDANCE)
    expect(i.provider_path).toBe('Cloudflare: DNS → Records → Add record → TXT')
  })

  it('never invents a token when the server did not return one', () => {
    expect(dnsInstructionFrom({})).toBeNull()
    expect(dnsInstructionFrom({ dns: { host: '_cybermeters.x.com' } })).toBeNull()   // no value
    expect(dnsInstructionFrom(null)).toBeNull()
  })
})

describe('a failed DNS check keeps the instructions actionable', () => {
  it('explains propagation rather than blaming the customer', () => {
    const msg = checkFailureMessage({ code: 'verification_failed' })
    expect(msg).toMatch(/propagate/i)
    expect(msg).not.toMatch(/verification_failed/)
  })

  it('a lookup failure still points at the record below', () => {
    expect(checkFailureMessage({ code: 'network_error' })).toMatch(/still valid/i)
  })

  it('instructions persist through checking and failure', () => {
    expect(shouldKeepInstructions('instructions')).toBe(true)
    expect(shouldKeepInstructions('checking')).toBe(true)
    expect(shouldKeepInstructions('check_failed')).toBe(true)   // must not strand the customer
  })
})

describe('canonicalDomainInput: what people paste becomes the monitored domain', () => {
  it('reduces www to the apex so a one-domain trial is not spent on the wrong name', () => {
    expect(canonicalDomainInput('www.sheshire.co.uk')).toBe('sheshire.co.uk')
    expect(canonicalDomainInput('WWW.Example.com')).toBe('example.com')
  })
  it('strips scheme, path, query, port and trailing dots', () => {
    expect(canonicalDomainInput('https://sheshire.co.uk/')).toBe('sheshire.co.uk')
    expect(canonicalDomainInput('https://www.example.com/shop?x=1#top')).toBe('example.com')
    expect(canonicalDomainInput('example.com:443')).toBe('example.com')
    expect(canonicalDomainInput('example.com.')).toBe('example.com')
  })
  it('never collapses onto a public suffix', () => {
    expect(canonicalDomainInput('www.co.uk')).toBe('www.co.uk')
    expect(canonicalDomainInput('www.com.au')).toBe('www.com.au')
  })
  it('keeps other subdomains as typed', () => {
    expect(canonicalDomainInput('shop.example.com')).toBe('shop.example.com')
    expect(canonicalDomainInput('wwwexample.com')).toBe('wwwexample.com')
  })
  it('a pasted URL is valid syntax after canonicalisation and the hint names the apex', () => {
    expect(domainHintFor('valid_unverified', 'https://www.example.com/')).toEqual({
      tone: 'neutral', text: "We'll monitor example.com — www and other subdomains are covered from there.",
    })
    expect(domainHintFor('idle', 'not a domain').tone).toBe('error')
  })
})

describe('matchWorkspaceDomain: an existing exact record wins, otherwise the apex', () => {
  const both = [{ domain_id: 'apex', domain: 'x.com' }, { domain_id: 'www', domain: 'www.x.com' }]
  it('an older workspace that already monitors www keeps that record', () => {
    expect(matchWorkspaceDomain(both, 'www.x.com').domain_id).toBe('www')
  })
  it('www resolves to the apex when only the apex exists', () => {
    expect(matchWorkspaceDomain([{ domain_id: 'apex', domain: 'x.com' }], 'www.x.com').domain_id).toBe('apex')
  })
  it('a pasted URL resolves to its record and an unknown domain to nothing', () => {
    expect(matchWorkspaceDomain(both, 'https://x.com/').domain_id).toBe('apex')
    expect(matchWorkspaceDomain(both, 'y.com')).toBeNull()
  })
  it('the hint names the record that will actually be scanned', () => {
    expect(domainHintFor('verified', 'www.x.com', 'x.com').text).toMatch(/verified for x\.com/)
  })
})
