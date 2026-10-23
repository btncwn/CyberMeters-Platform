// Internal keys never reach customer text as snake_case (founder P1, 23 Oct
// 2026; Codex C-45 R01–R26). One place for the fallbacks:
//   keyLabel(value)          a known customer code → its copy; any other enum →
//                            a readable sentence ("awaiting_verification" →
//                            "Awaiting verification"); empty → null.
//   conditionKeyLabel(key)   a condition slug in words, headers by their name
//                            ("header_missing_strict_transport_security" → "HSTS header missing").
//   affectedLabel(caseRow)   the "Affected" line of a case: "example.org — HSTS
//                            header missing" instead of "example.org:header_missing_…".
//   isOpaqueId(value)        an internal id (never used as link text or a name).
import { CUSTOMER_CODE_COPY } from '../../../shared/customer-labels.js'
import { customerReasonText } from './customerReasonText.js'

const sentence = (text) => {
  const s = String(text).replace(/[_]+/g, ' ').replace(/\s+/g, ' ').trim()
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''
}

export function keyLabel(value) {
  if (value == null || value === '') return null
  const key = String(value)
  if (Object.hasOwn(CUSTOMER_CODE_COPY, key)) return sentence(CUSTOMER_CODE_COPY[key])
  // An all-caps code (CERT_HAS_EXPIRED) reads as a sentence, not shouting.
  return sentence(/^[A-Z0-9_]+$/.test(key) ? key.toLowerCase() : key)
}

const HEADER_NAMES = Object.freeze({
  strict_transport_security: 'HSTS', strict: 'HSTS', hsts: 'HSTS',
  content_security_policy: 'Content-Security-Policy', content: 'Content-Security-Policy',
  x_frame_options: 'X-Frame-Options', x_content_type_options: 'X-Content-Type-Options', x: 'X-Frame-Options',
  referrer_policy: 'Referrer-Policy', referrer: 'Referrer-Policy',
  permissions_policy: 'Permissions-Policy', permissions: 'Permissions-Policy',
})
const HEADER_STATE = Object.freeze({ missing: 'header missing', weak: 'header weak', malformed: 'header malformed', invalid: 'header invalid' })

export function conditionKeyLabel(key) {
  if (key == null || key === '') return null
  const k = String(key)
  if (Object.hasOwn(CUSTOMER_CODE_COPY, k)) return sentence(CUSTOMER_CODE_COPY[k])
  const header = k.match(/^header_(missing|weak|malformed|invalid)_([a-z_]+)$/)
  if (header) return `${HEADER_NAMES[header[2]] || sentence(header[2])} ${HEADER_STATE[header[1]]}`
  return sentence(k)
}

const SLUG = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/

export function affectedLabel(c) {
  const value = String(c?.resource || c?.asset_ref || c?.domain || '').trim()
  if (!value) return null
  // host:condition_key (website lifecycle cases store this as the asset reference)
  const pair = value.match(/^([a-z0-9][a-z0-9.-]*\.[a-z]{2,}):([a-z][a-z0-9_]+)$/i)
  if (pair && SLUG.test(pair[2])) return `${pair[1]} — ${conditionKeyLabel(pair[2])}`
  return value
}

export function isOpaqueId(value) {
  const v = String(value || '')
  return /^[a-z]+_[0-9a-f]{8,}/i.test(v) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(v) || /^(usr|user|case|mc|acc|ws|scan)_[a-z0-9-]{6,}$/i.test(v)
}

/**
 * Stored prose (notification titles, messages, recommended actions): known codes
 * become their copy, any other snake_case token becomes words. URLs, e-mail
 * addresses and DNS labels such as _dmarc are left alone.
 */
export function keysInText(text) {
  if (text == null) return text
  const coded = customerReasonText(String(text))
  return coded.replace(/(^|[\s(\[,;:'"])([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?=$|[\s).,;:!?'"\]])/g, (_m, pre, slug) => `${pre}${slug.replace(/_/g, ' ')}`)
}
