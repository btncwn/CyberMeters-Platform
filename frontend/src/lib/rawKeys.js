// Raw internal keys must never reach a customer's screen (founder, 18 Oct 2026).
// A raw key is a lowercase snake_case token such as `email_missing_spf`,
// `shadow_it_unmanaged_technology` or `plan_feature_required`: an identifier the
// backend uses that has no customer wording. Shared by the area-page e2e pass
// (PR-C) and the key-to-wording mapping table (PR-D), so both agree on what
// counts as a leak.
export const RAW_KEY_PATTERN = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g

// Tokens that look like keys but are legitimate customer text: DNS record names
// a customer types (`_dmarc`, `_domainkey` never match because they start with
// an underscore) and nothing else today. Add an entry only with a reason.
export const RAW_KEY_ALLOWLIST = Object.freeze(new Map())

/** Every distinct raw key in a piece of visible text, minus the allowlist. */
export function findRawKeys(text) {
  const found = new Set()
  for (const match of String(text || '').matchAll(RAW_KEY_PATTERN)) {
    if (!RAW_KEY_ALLOWLIST.has(match[0])) found.add(match[0])
  }
  return [...found]
}
