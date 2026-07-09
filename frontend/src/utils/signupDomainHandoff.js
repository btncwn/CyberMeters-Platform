export const PENDING_SIGNUP_DOMAIN_KEY = 'cm_pending_domain'

// Free Cyber MOT links to /signup?domain=<scanned-domain>. Keep this helper
// strict so script-like or malformed values never enter the onboarding handoff.
export function sanitizeDomainParam(raw) {
  if (!raw) return null
  const domain = String(raw)
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/[/?#].*$/, '')

  return /^[a-z0-9][a-z0-9.-]{1,251}\.[a-z]{2,}$/.test(domain) ? domain : null
}

export function persistSignupDomainParam(raw, storage = localStorage) {
  const domain = sanitizeDomainParam(raw)
  if (!domain) return null
  storage.setItem(PENDING_SIGNUP_DOMAIN_KEY, domain)
  return domain
}
