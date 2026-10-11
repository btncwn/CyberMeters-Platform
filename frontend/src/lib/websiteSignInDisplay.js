// Presentation for signed-in scanning (/website-security/sign-in). The backend
// decides every outcome; this file only turns its codes into words and says
// what the customer can do next. Facts are neutral — no severity, no verdict.

export const SIGN_IN_METHOD_LABEL = Object.freeze({
  form: 'Sign-in form (username and password)',
  header: 'Request header (for example an API key or bearer token)',
  cookie: 'Session cookie',
})

export const SIGN_IN_OUTCOME_META = Object.freeze({
  signed_in: { label: 'Signed in', tone: 'ok', help: 'CyberMeters signed in and confirmed it on the start page.' },
  credentials_rejected: { label: 'Sign-in refused', tone: 'warn', help: 'The site did not accept this username and password. Check them, and that the test account is not locked.' },
  session_rejected: { label: 'Header or cookie refused', tone: 'warn', help: 'The start page refused the saved header or cookie. It may have expired — save a fresh one.' },
  mfa_required: { label: 'Needs a one-time code', tone: 'warn', help: 'The site asked for a one-time code. Use a test account without two-step sign-in, or the header or cookie method.' },
  captcha_present: { label: 'CAPTCHA on the sign-in page', tone: 'warn', help: 'CyberMeters does not bypass CAPTCHA. Use the header or cookie method instead.' },
  bot_protection: { label: 'Stopped by bot protection', tone: 'warn', help: 'A bot-protection challenge stopped the sign-in. Use the header or cookie method, or allow the test account through.' },
  rate_limited: { label: 'Site asked us to slow down', tone: 'warn', help: 'The site answered “too many requests”. Try again later.' },
  signed_in_text_not_found: { label: 'Signed-in text not found', tone: 'warn', help: 'The start page did not show your signed-in text. Check the spelling, or pick text that is in the page itself rather than added later by JavaScript.' },
  signed_in_text_not_distinctive: { label: 'Signed-in text also shown when signed out', tone: 'warn', help: 'That text appears without signing in too, so it cannot prove sign-in. Use something only a signed-in user sees, such as the test account’s name.' },
  start_page_public: { label: 'Could not confirm sign-in', tone: 'warn', help: 'The start page is also shown without signing in, so it cannot prove sign-in. Choose a page that needs sign-in (such as /account) or add signed-in text.' },
  start_page_unavailable: { label: 'Start page unavailable', tone: 'warn', help: 'The start page did not answer with a normal page. Check its address.' },
  login_page_unavailable: { label: 'Sign-in page unavailable', tone: 'warn', help: 'The sign-in page did not answer with a normal page. Check its address.' },
  login_form_not_found: { label: 'No sign-in form found', tone: 'warn', help: 'No form with a password field is in the sign-in page’s HTML. If the form is built by JavaScript, use the header or cookie method.' },
  username_field_not_found: { label: 'Username field not found', tone: 'warn', help: 'Enter the username field’s name under “Advanced”.' },
  login_form_uses_get: { label: 'Form would put the password in the address', tone: 'warn', help: 'This form sends the password in the URL (GET). CyberMeters will not submit it.' },
  login_form_posts_offsite: { label: 'Form sends to another site', tone: 'warn', help: 'The sign-in form posts to another site. CyberMeters only sends credentials to this domain.' },
  login_not_https: { label: 'Part of the sign-in is not HTTPS', tone: 'warn', help: 'CyberMeters only sends credentials over HTTPS, so it stopped.' },
  sign_in_redirects_offsite: { label: 'Sign-in continues on another site', tone: 'warn', help: 'This looks like single sign-on. CyberMeters does not send credentials to another site — use the header or cookie method.' },
  sign_in_redirect_not_followed: { label: 'Stopped at a redirect after sign-in', tone: 'warn', help: 'After sign-in the site redirected to an address that could change something, so CyberMeters did not follow it. Add a page that needs sign-in as the start page.' },
  login_error_status: { label: 'Error after sign-in', tone: 'warn', help: 'The site returned an error after the form was sent.' },
  plan_required: { label: 'Needs a paid plan or trial', tone: 'muted', help: 'Signed-in scanning needs an active paid plan or trial, so the scan did not sign in.' },
  vault_unavailable: { label: 'Temporarily unavailable', tone: 'muted', help: 'Signed-in scanning is temporarily unavailable.' },
  budget_exhausted: { label: 'Ran out of time', tone: 'muted', help: 'The sign-in took longer than allowed. Try again.' },
  error: { label: 'Could not complete', tone: 'muted', help: 'The sign-in could not be completed. Try again.' },
})

export function signInOutcomeMeta(code) {
  return SIGN_IN_OUTCOME_META[code] ?? { label: 'Unknown', tone: 'muted', help: null }
}

export const PAUSED_REASON_TEXT = Object.freeze({
  repeated_sign_in_failures: 'Paused after 3 refused sign-ins in a row so the test account is not locked out. Fix the details and test again, or save them again, to resume.',
})

const INPUT_ERROR_TEXT = {
  authorization_required: 'Confirm that you are allowed to let CyberMeters sign in to this site.',
  login_url_invalid: 'Enter the full address of the sign-in page, for example https://example.com/login.',
  login_url_not_https: 'The sign-in page must use https://.',
  login_url_not_on_domain: 'The sign-in page must be on this domain or its www address.',
  login_url_not_a_page: 'That address looks like an action (such as sign-out) or an API, not a page.',
  start_url_invalid: 'Enter the full address of a page that needs sign-in.',
  start_url_not_https: 'The start page must use https://.',
  start_url_not_on_domain: 'The start page must be on this domain or its www address.',
  start_url_not_a_page: 'That address looks like an action (such as sign-out) or an API, not a page.',
  start_url_is_login_page: 'The start page must be a page behind the sign-in, not the sign-in page.',
  start_url_required: 'Enter a page that needs sign-in, so the sign-in can be confirmed.',
  username_and_password_required: 'Enter both the username and the password.',
  username_invalid: 'Check the username.',
  password_invalid: 'Check the password.',
  header_name_invalid: 'That header cannot be used. Use a header such as Authorization or X-API-Key.',
  header_value_invalid: 'Check the header value (one line of plain text).',
  header_name_and_value_required: 'Enter both the header name and its value.',
  cookie_name_invalid: 'Check the cookie name.',
  cookie_value_invalid: 'Check the cookie value (no spaces, commas or semicolons).',
  cookie_name_and_value_required: 'Enter both the cookie name and its value.',
  signed_in_text_invalid: 'Signed-in text must be 3 to 120 characters.',
  username_field_invalid: 'Check the username field name.',
  password_field_invalid: 'Check the password field name.',
  method_invalid: 'Choose how CyberMeters should sign in.',
  plan_required: 'Signed-in scanning needs an active paid plan or trial.',
  vault_unavailable: 'Signed-in scanning is temporarily unavailable.',
  domain_not_verified: 'Verify this domain in this workspace first.',
  session_role_required: 'A workspace owner or admin is required.',
  profile_not_saved: 'Your changes were not saved. Reload and try again.',
  profile_not_found: 'Signed-in scanning is not set up for this domain.',
}

/** Words for a failed write ({ status, body } from the API client). */
export function signInErrorText(result) {
  if (result?.status === 429) return 'Too many changes or tests for now. Try again in an hour.'
  return INPUT_ERROR_TEXT[result?.body?.code] || result?.body?.error || 'That did not work. Try again.'
}

/** Neutral facts about the session the site created (names and flags only). */
export function sessionFacts(detail) {
  const facts = []
  for (const c of detail?.cookies_at_sign_in || []) {
    if (!c.secure) facts.push(`Cookie ${c.name} set at sign-in without Secure`)
    if (!c.httponly) facts.push(`Cookie ${c.name} set at sign-in without HttpOnly`)
    if (c.samesite === 'none') facts.push(`Cookie ${c.name} set at sign-in with SameSite=None`)
    if (c.persistent && c.lifetime_days > 30) facts.push(`Cookie ${c.name} set at sign-in lasts ${Math.round(c.lifetime_days)} days`)
  }
  if (detail?.session_cookie_renewed === 'not_renewed') facts.push('The session cookie kept the same value through sign-in')
  return facts
}

export const PROOF_TEXT = Object.freeze({
  signed_in_text: 'Confirmed by your signed-in text on the start page.',
  anonymous_refused: 'Confirmed because the start page opened with the session but refused a request without it.',
})

// ── Signed-in pages (latest scan) ───────────────────────────────────────────

export const SIGNED_IN_PAGE_STATUS = Object.freeze({
  observed: 'Checked',
  refused: 'Refused for this account',
  redirect_not_followed: 'Redirect not followed',
  not_found: 'Not found',
  error_status: 'Error',
  redirected_offsite: 'Goes to another site',
  not_html: 'Not a page',
  unavailable: 'No answer',
})

const SIGNED_IN_PARTIAL_TEXT = {
  page_limit: 'the page limit was reached',
  fetch_limit: 'the request limit was reached',
  time_budget: 'time ran out',
  scan_budget: 'the scan’s request budget ran out',
  session_ended: 'the session ended during the scan',
  aborted: 'the scan stopped early',
  error: 'part of the check could not complete',
  deadline_budget: 'the scan ran out of time before this step',
  module_budget_exhausted: 'this step ran out of time',
  module_failed: 'this step could not complete',
}

/** One line about the latest scan's signed-in check for a domain. */
export function signedInCoverageText(latest) {
  if (!latest) return 'Signed-in pages are checked during queued and scheduled scans.'
  if (latest.outcome !== 'signed_in') {
    if (latest.outcome === 'plan_required') return 'The last scan did not sign in: signed-in scanning needs an active paid plan or trial.'
    return `The last scan could not sign in: ${signInOutcomeMeta(latest.outcome).label.toLowerCase()}.`
  }
  const s = latest.summary || {}
  const n = Number(s.counts?.pages_observed) || 0
  const max = Number(s.limits?.max_pages) || 10
  const reasons = (s.partial_reasons || []).map((r) => SIGNED_IN_PARTIAL_TEXT[r]).filter(Boolean)
  const base = `${n} signed-in page${n === 1 ? '' : 's'} checked on the last scan (up to ${max}).`
  return latest.coverage === 'partial' && reasons.length ? `${base} Partial: ${reasons.join(', ')}.` : base
}

/** Neutral facts for one signed-in page; the anonymous contrast comes first. */
export function signedInPageFacts(page) {
  if (!page || page.outcome !== 'observed') return []
  const facts = []
  if (page.anonymous_access === 'served_with_signed_in_text') facts.push('Without signing in, this page still showed your signed-in text')
  if (page.anonymous_access === 'served_same_page') facts.push('Also served without signing in (same page)')
  const cc = page.cache_control || {}
  if (cc.kind === 'missing') facts.push('No Cache-Control header')
  if (cc.kind === 'storable') facts.push(`Cache-Control lets caches keep a copy${cc.directives?.length ? ` (${cc.directives.join(', ')})` : ''}`)
  if (page.frame_protection === false) facts.push('Can be shown inside another site’s frame (no X-Frame-Options or frame-ancestors)')
  const missing = new Set(page.missing_headers || [])
  if (missing.has('strict-transport-security')) facts.push('HSTS header not sent')
  if (missing.has('content-security-policy')) facts.push('No Content-Security-Policy')
  for (const c of page.cookies || []) {
    if (!c.secure) facts.push(`Cookie ${c.name} without Secure`)
    if (!c.httponly) facts.push(`Cookie ${c.name} without HttpOnly`)
  }
  for (const f of page.forms || []) {
    if (f.action_kind === 'other_origin' && f.action_host) facts.push(`Form sends to ${f.action_host}`)
    else if (f.action_scheme === 'http') facts.push('Form sends over plain HTTP')
  }
  if (page.mixed_content?.count > 0) facts.push(`${page.mixed_content.count} insecure (http://) resource${page.mixed_content.count === 1 ? '' : 's'}`)
  const scripts = page.third_party_scripts || []
  if (scripts.length) facts.push(`${scripts.length} third-party script host${scripts.length === 1 ? '' : 's'} on a signed-in page`)
  return facts
}
