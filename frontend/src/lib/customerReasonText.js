import { CUSTOMER_CODE_COPY } from '../../../shared/customer-labels.js'
export { CUSTOMER_CODE_COPY } from '../../../shared/customer-labels.js'

// Backend scan warnings carry a module code in a fixed sentence shape. Read them
// as sentences before the code table runs.
const WARNING_SHAPES = Object.freeze([
  [/^Module incomplete: ([a-z0-9_]+)$/i, (code) => `${capitalise(CUSTOMER_CODE_COPY[code] || words(code))} did not finish.`],
  [/^Module skipped \(subrequest budget\): ([a-z0-9_]+)$/i, (code) => `${capitalise(CUSTOMER_CODE_COPY[code] || words(code))} did not run because the scan request budget was reached.`],
])
const words = (code) => String(code).replace(/_/g, ' ')
const capitalise = (text) => text.charAt(0).toUpperCase() + text.slice(1)

const entries = Object.entries(CUSTOMER_CODE_COPY).sort((a, b) => b[0].length - a[0].length)
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export function assertCustomerCodesMapped(codes) {
  for (const code of codes) {
    if (!Object.hasOwn(CUSTOMER_CODE_COPY, code)) throw new Error(`Unmapped customer code: ${code}`)
  }
}

export function customerCodeLabel(code) {
  return CUSTOMER_CODE_COPY[code] || null
}

export function customerReasonText(value) {
  let text = String(value || '')
  for (const [shape, sentence] of WARNING_SHAPES) {
    const match = text.trim().match(shape)
    if (match) return sentence(match[1])
  }
  for (const [code, label] of entries) {
    const pattern = new RegExp(`(^|[^a-z0-9_])(${escape(code)})(?=$|[^a-z0-9_])`, 'gi')
    text = text.replace(pattern, (_match, prefix) => prefix + label)
  }
  return text
}
