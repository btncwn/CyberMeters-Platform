import { describe, expect, it } from 'vitest'
import { assertCustomerCodesMapped, customerReasonText } from '../customerReasonText'

const API_CODES_SHOWN_TO_CUSTOMERS = [
  'external_exposure: checks inconclusive',
  'tls_assessment',
  'not_externally_assessable',
  'Feature requires upgrade: audit_logs',
]

describe('customer reason vocabulary', () => {
  it('requires an explicit customer sentence for each known exposed code', () => {
    expect(() => assertCustomerCodesMapped(API_CODES_SHOWN_TO_CUSTOMERS)).not.toThrow()
    expect(() => assertCustomerCodesMapped(['new_unmapped_reason'])).toThrow('Unmapped customer code')
  })

  it.each(API_CODES_SHOWN_TO_CUSTOMERS)('removes the internal key %s', code => {
    const text = customerReasonText(code)
    expect(text).not.toContain(code)
    expect(text).not.toMatch(/(?:external_exposure|tls_assessment|not_externally_assessable|audit_logs)/)
    expect(text.length).toBeGreaterThan(12)
  })

  it('retains evidence context while translating embedded reason codes', () => {
    expect(customerReasonText('Required checks (tls_assessment) did not complete')).toBe('Required checks (deep TLS checks) did not complete')
    expect(customerReasonText('external_exposure: checks inconclusive')).toBe('Public content responses did not support a conclusion')
  })
})
