// The API keeps stable machine codes. Customer copy is owned in this one table.
export const CUSTOMER_CODE_COPY = Object.freeze({
  'Feature requires upgrade: audit_logs': 'Upgrade your plan to use audit logs.',
  'external_exposure: checks inconclusive': 'Public content responses did not support a conclusion',
  external_exposure: 'public content checks',
  tls_assessment: 'deep TLS checks',
  not_externally_assessable: 'cannot be assessed from outside your organisation',
  audit_logs: 'audit logs',
  asset_exposure: 'asset exposure checks',
  certificate_intelligence: 'certificate checks',
  identity_discovery: 'identity discovery checks',
  budget_exhausted: 'the scan budget was reached',
  subrequest_budget_exhausted: 'the scan request budget was reached',
  tls_network_budget: 'the TLS connection budget was reached',
  checks_inconclusive: 'responses did not support a conclusion',
  origin_error_no_serviceable_response: 'the website returned no usable response',
  origin_not_observed: 'the website could not be observed',
  origin_access_restricted: 'the website blocked the check (authentication, rate limiting or a challenge)',
  origin_timeout: 'the website did not answer in time',
  https_origin_timeout: 'the website did not answer over HTTPS in time',
  server_error: 'a server error interrupted the check',
})

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
  for (const [code, label] of entries) {
    const pattern = new RegExp(`(^|[^a-z0-9_])(${escape(code)})(?=$|[^a-z0-9_])`, 'gi')
    text = text.replace(pattern, (_match, prefix) => prefix + label)
  }
  return text
}
