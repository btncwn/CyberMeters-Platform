// Presentation for the important-page inventory (GET /website-security/pages).
// The backend owns every state; this maps it to words. Observations are shown
// as neutral FACTS ("HSTS header not sent"), never as a verdict or severity —
// findings, severity and cases come only from the backend resolver.

export const PAGE_STATUS_META = Object.freeze({
  observed:    { label: 'Seen',                tone: 'neutral', help: 'The page answered on the last request.' },
  not_found:   { label: 'Not found',           tone: 'muted',   help: 'The page was requested and answered 404 or 410.' },
  unconfirmed: { label: 'Could not confirm',   tone: 'muted',   help: 'The page was requested but the answer did not establish it (error, redirect or timeout). Its last observation is kept.' },
})

export const SENSITIVE_KIND_LABEL = Object.freeze({
  login: 'Sign-in page',
  admin: 'Admin page',
  account: 'Account page',
  checkout: 'Checkout or payment page',
})

const COVERAGE_REASON_LABEL = {
  page_limit: 'the page limit was reached',
  fetch_limit: 'the request limit was reached',
  time_budget: 'the scan ran out of time for this step',
  fetch_timeout: 'some pages did not answer in time',
  aborted: 'the scan stopped early',
  homepage_unavailable: 'the homepage could not be reached',
  homepage_error_status: 'the homepage returned an error',
  homepage_redirects_offsite: 'the homepage redirects to another site',
  not_durable_execution: 'this scan type does not check extra pages',
  reserved_capacity_mode: 'this scan type does not check extra pages',
  deadline_budget: 'the scan ran out of time before this step',
  module_budget_exhausted: 'this step ran out of time',
  module_failed: 'this step could not complete',
}

export function pageStatusMeta(status) {
  return PAGE_STATUS_META[status] ?? { label: 'Unknown', tone: 'muted', help: null }
}

/** One-line summary of the latest run for a domain. */
export function coverageSummary(run) {
  if (!run) return 'No extra pages have been checked yet. They are checked during queued and scheduled scans of a verified domain.'
  const observed = Number(run.counts?.observed) || 0
  const max = Number(run.counts?.max_pages) || 15
  const reasons = (run.partial_reasons || []).map((r) => COVERAGE_REASON_LABEL[r]).filter(Boolean)
  if (run.coverage === 'not_run') {
    return `Extra pages were not checked on the last scan${reasons.length ? ` because ${reasons[0]}` : ''}.`
  }
  let base = `${observed} page${observed === 1 ? '' : 's'} seen on the last scan (checks up to ${max}).`
  const jsFound = Number(run.counts?.js_paths_found) || 0
  if (jsFound > 0) {
    const checked = Number(run.counts?.js_paths_checked) || 0
    const api = Number(run.counts?.js_api_paths_found) || 0
    base += ` ${jsFound} path${jsFound === 1 ? '' : 's'} found in the site's JavaScript, ${checked} checked${api ? `; ${api} API path${api === 1 ? '' : 's'} noted but not requested` : ''}.`
  }
  if (run.coverage === 'partial' && reasons.length) return `${base} Partial: ${reasons.join(', ')}.`
  return base
}

/** Neutral observed facts for a page, in a stable order. */
export function pageFacts(page) {
  const o = page?.observation
  if (!o) return []
  const facts = []
  if (o.https === false) facts.push('Served without HTTPS')
  const missing = new Set(o.security_headers?.missing || [])
  if (missing.has('strict-transport-security')) facts.push('HSTS header not sent')
  if (missing.has('content-security-policy')) facts.push('No Content-Security-Policy')
  for (const f of o.forms || []) {
    if (f.action_kind === 'other_origin' && f.action_host) facts.push(`${f.has_password ? 'Password form' : 'Form'} sends to ${f.action_host}`)
    else if (f.action_scheme === 'http') facts.push(`${f.has_password ? 'Password form' : 'Form'} sends over plain HTTP`)
  }
  // A Set-Cookie that only removes a cookie (deletes: true) stores nothing, so it is not "a cookie without Secure".
  const insecureCookies = (o.cookies || []).filter((c) => !c.secure && c.deletes !== true).map((c) => c.name)
  if (insecureCookies.length) facts.push(`Cookie without Secure: ${insecureCookies.slice(0, 3).join(', ')}${insecureCookies.length > 3 ? '…' : ''}`)
  if (o.mixed_content?.count > 0) facts.push(`${o.mixed_content.count} insecure (http://) resource${o.mixed_content.count === 1 ? '' : 's'} on an HTTPS page`)
  const scripts = o.third_party_scripts || []
  if (scripts.length) facts.push(`${scripts.length} third-party script host${scripts.length === 1 ? '' : 's'}`)
  return facts
}

/** Sensitive-page label with how it was identified (never stated as fact when inferred from the address). */
export function sensitiveLabel(page) {
  const label = SENSITIVE_KIND_LABEL[page?.sensitive_kind]
  if (!label) return null
  const basis = page?.observation?.sensitive_basis
  if (basis === 'password_field') return `${label} · has a password field`
  const POSSIBLY = { login: 'Possibly a sign-in page', admin: 'Possibly an admin page', account: 'Possibly an account page', checkout: 'Possibly a checkout or payment page' }
  return `${POSSIBLY[page.sensitive_kind]} · from its address`
}

export const SOURCE_LABEL = Object.freeze({
  homepage: 'Homepage',
  homepage_link: 'Linked from the homepage',
  sitemap: 'Listed in the sitemap',
  javascript: "Found in the site's JavaScript",
  well_known: 'Common address checked',
})
