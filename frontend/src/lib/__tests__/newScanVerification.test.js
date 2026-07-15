import { describe, it, expect } from 'vitest'
import {
  canStartScan, isValidDomainSyntax, domainHintFor, safeErrorMessage,
  isVerificationRequired, dnsInstructionFrom, checkFailureMessage,
  shouldKeepInstructions, SCAN_STATES, DNS_TTL_GUIDANCE,
} from '../newScanVerification'

describe('Start Scan is gated on proven ownership, not syntax', () => {
  it('is disabled in every state except verified', () => {
    const enabled = SCAN_STATES.filter(canStartScan)
    expect(enabled).toEqual(['verified'])
  })

  it('is disabled for a syntactically valid but unverified domain', () => {
    expect(isValidDomainSyntax('cybermeters.com')).toBe(true)
    expect(canStartScan('ready')).toBe(false)      // the old bug: valid syntax => scan
    expect(canStartScan('needs_setup')).toBe(false)
    expect(canStartScan('instructions')).toBe(false)
    expect(canStartScan('check_failed')).toBe(false)
  })
})

describe('never claims "ready to scan" for an unverified domain', () => {
  it('describes the FORMAT only, until ownership is proven', () => {
    const hint = domainHintFor('ready', 'cybermeters.com')
    expect(hint.text).not.toMatch(/ready to scan/i)
    expect(hint.text).toMatch(/format/i)
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
