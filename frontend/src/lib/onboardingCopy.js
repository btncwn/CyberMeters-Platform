// Every sentence onboarding shows after a request fails. Onboarding never
// renders server text: a response's `error`/`message` can name routes or
// internals ("Call POST /api/…"), so each failure is mapped from its machine
// fields (status, code, verification outcome) to plain copy written here.

export const VERIFY_NOT_FOUND_YET =
  'We couldn’t see the record yet. DNS changes can take a few minutes — try again shortly.'
export const VERIFY_VALUE_MISMATCH =
  'We found a CyberMeters record, but its value doesn’t match. Copy the TXT value above exactly, then try again.'
export const VERIFY_LOOKUP_FAILED =
  'We couldn’t check your DNS just now. Try again in a minute.'
export const VERIFY_RECORD_REFRESHED =
  'Your DNS record has been prepared again. Add the TXT value shown above, then select Verify ownership.'
export const VERIFY_NOT_SAVED =
  'We couldn’t finish the check just now. Please try again.'
export const VERIFY_DOMAIN_MISSING =
  'We couldn’t find this domain in your workspace. Reload the page and try again.'
export const RECORD_PREPARE_FAILED =
  'We couldn’t prepare your DNS record just now. Try again in a moment.'

const NETWORK = 'We couldn’t reach CyberMeters. Check your internet connection and try again.'

/**
 * The note shown after Verify ownership did not verify. `result` is either the
 * 200 body of POST /verify or the thrown ApiError (status/code/outcome fields).
 * Returns null for a success. `no_token` is handled by the page (it prepares a
 * fresh record), so its copy here is the one shown after that.
 */
export function verifyOutcomeCopy(result) {
  if (!result || result.success === true) return null
  if (result.code === 'network_error') return NETWORK
  switch (result.outcome) {
    case 'dns_not_found': return VERIFY_NOT_FOUND_YET
    case 'dns_mismatch': return VERIFY_VALUE_MISMATCH
    case 'dns_lookup_error': return VERIFY_LOOKUP_FAILED
    case 'no_token': return VERIFY_RECORD_REFRESHED
    case 'domain_link_not_found':
    case 'workspace_ambiguous': return VERIFY_DOMAIN_MISSING
    case 'persistence_zero_rows':
    case 'persistence_unexpected_rows':
    case 'persistence_confirmation_failed':
    case 'internal_error': return VERIFY_NOT_SAVED
    default: break
  }
  if (result.status === 404) return VERIFY_DOMAIN_MISSING
  if (result.status >= 500) return VERIFY_NOT_SAVED
  // A 200 "not proven" without a recognised outcome reads as not found yet.
  return VERIFY_NOT_FOUND_YET
}

/** Plain copy for a failed onboarding action (workspace, domain, scan, record). */
export function onboardingActionError(action, err) {
  if (err?.code === 'network_error') return NETWORK
  if (err?.code === 'maintenance') return 'CyberMeters is undergoing scheduled maintenance and will be back shortly.'
  if (action === 'domain') {
    if (err?.code === 'trial_domain_limit' || err?.code === 'plan_limit_exceeded' || err?.code === 'additional_domain_billing_unavailable') {
      return 'Your plan’s domain limit has been reached. Choose a plan with more domains to add another.'
    }
    if (err?.status === 400) return 'Enter a domain like example.com — no https:// or www.'
    if (err?.status === 403) return 'Only a workspace owner or admin can add domains.'
    return 'We couldn’t add this domain just now. Try again in a moment.'
  }
  if (action === 'workspace') {
    if (err?.status === 400) return 'Enter a name for your workspace.'
    return 'We couldn’t create your workspace just now. Try again in a moment.'
  }
  if (action === 'scan') {
    if (err?.code === 'domain_verification_required') return 'Verify the domain before starting your first check.'
    if (err?.code === 'rate_limit_exceeded' || err?.code === 'plan_limit_exceeded') return 'Your plan’s scan limit has been reached for now.'
    return 'We couldn’t start the check just now. Try again in a moment.'
  }
  if (action === 'record') return RECORD_PREPARE_FAILED
  if (action === 'load') return 'We couldn’t load your setup just now. Reload the page to try again.'
  return 'Something went wrong. Please try again.'
}
