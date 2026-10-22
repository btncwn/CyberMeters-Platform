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
  http_redirect_access_restricted: 'the website blocked the HTTP-to-HTTPS redirect check (authentication, rate limiting or a challenge)',
  origin_timeout: 'the website did not answer in time',
  https_origin_timeout: 'the website did not answer over HTTPS in time',
  server_error: 'a server error interrupted the check',
  // Free-scan module reasons (FREE_SCAN_MODULE_REASONS in the scan API).
  https_probe_not_executed: 'the website gave no answer over HTTPS',
  https_origin_not_observed: 'only the hosting network answered over HTTPS, not the website itself',
  https_transport_unavailable: 'no HTTPS connection could be made to the website',
  http_redirect_not_observed: 'the plain-HTTP address gave no answer, so the redirect to HTTPS could not be checked',
  probe_not_executed: 'the website gave no answer to this check',
  validation_uncertain: 'the response showed signs of a bot-protection or caching layer, so it may not reflect the website itself',
  email_dns_lookup_unavailable: 'some email DNS lookups (SPF, DKIM or DMARC) returned no answer',
  free_scan_deadline_exhausted: "the preview's time limit was reached before this check finished",
  check_failed: 'the check stopped unexpectedly',
  check_not_completed: 'this check did not finish',
  // Scan modules, as the check a customer recognises (also used by the executive report).
  technology_detection: 'technology detection',
  cve_intelligence: 'vulnerability (CVE) checks',
  known_exploited_vulnerabilities: 'known exploited vulnerability (KEV) checks',
  risk_intelligence: 'risk summary',
  remediation_plan: 'remediation plan',
  subdomain_takeover: 'subdomain takeover checks',
  email_security_intelligence: 'email security detail',
  dns_bruteforce: 'subdomain name checks',
  cloud_storage_discovery: 'cloud storage checks',
  admin_surface_detection: 'admin page checks',
  // Scan-coverage reasons (scan_quality.modules_incomplete[].incomplete_reason and
  // the TLS coverage reason). The backend owns the code; this table owns the words.
  host_probe_unconfirmed: 'some hosts gave an answer that could not be confirmed',
  host_lookup_failure: 'some host names could not be looked up',
  host_cap_truncation: 'more hosts were found than one scan checks; the rest rotate into later scans',
  candidate_cap_truncation: 'more candidates were found than one scan checks',
  some_hosts_unassessed: 'some hosts were not assessed',
  takeover_probe_failed: 'the takeover check could not complete',
  cloud_storage_probe_failed: 'the cloud storage check could not complete',
  exposure_probe_failed: 'the public content check could not complete',
  dns_not_executed: 'the DNS lookups did not run',
  dns_resolution_unavailable: 'the DNS lookups returned no answer',
  certificate_not_observed: 'no certificate was observed',
  active_tls_evidence_unavailable: 'live TLS evidence was unavailable',
  live_tls_not_fully_observed: 'live TLS was not fully observed',
  optional_probe_budget_exhausted: 'the budget for optional checks was reached',
  scan_deadline_exhausted: "the scan's time limit was reached",
  tls_endpoints_unobserved: 'no TLS endpoint answered the deep TLS checks',
  tls_coverage_unavailable: 'TLS coverage could not be measured',
  tls_checks_outside_scan_budget: "some TLS checks were outside this scan's budget",
  tls_checks_inconclusive: 'some TLS checks did not support a conclusion',
  tls_services_outside_scan_budget: "some TLS services were outside this scan's budget",
  tls_endpoint_coverage_incomplete: 'some TLS endpoints were not fully checked',
  tls_result_unavailable: 'the TLS result is unavailable',
})

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
