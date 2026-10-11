// Customer wording for POST /brand/discovery outcomes. The backend owns what
// was found; this only explains it. Wording stays inside the evidence: this is
// a passive Certificate Transparency lookup for lookalike names, not a scan of
// the internet and not proof that anyone is abusing the brand.

const n = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0)
const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`

export const BRAND_DISCOVERY_BOUNDARY =
  'This checks public certificate logs for names that resemble your brand. A lookalike name is a signal to review, not proof of abuse.'

export function brandDiscoveryOutcome(result) {
  const status = result?.status
  const body = result?.body || {}

  if (status === 200) {
    const added = n(body.inserted)
    const updated = n(body.updated) + n(body.merged)
    const incomplete = body.partial === true || body.incomplete === true
    const headline = added > 0
      ? `${plural(added, 'new lookalike candidate', 'new lookalike candidates')} found.`
      : 'No new lookalike candidates found.'
    const parts = []
    if (updated > 0) parts.push(`${plural(updated, 'existing candidate was', 'existing candidates were')} refreshed.`)
    if (incomplete) parts.push('Some certificate-log lookups did not complete, so this check was partial. The daily check will try again.')
    return { tone: incomplete ? 'warning' : 'success', title: headline, detail: parts.join(' ') || null, refresh: true }
  }
  if (status === 409 && body.error === 'brand_profile_required') {
    return { tone: 'warning', title: 'Save a brand profile first.', detail: 'The check runs for the protected brand and primary domain you configure.', refresh: false }
  }
  if (status === 403 && body.error === 'domain_verification_required') {
    return { tone: 'warning', title: 'Verify your primary domain first.', detail: 'The check only runs for a domain this workspace has proven it controls.', refresh: false }
  }
  if (status === 403) {
    return { tone: 'error', title: 'You do not have permission to run this check.', detail: 'Ask a workspace member who can add domains.', refresh: false }
  }
  if (status === 429) {
    return { tone: 'warning', title: 'This check was run recently.', detail: 'To keep lookups fair, it can run a few times an hour. The daily check also runs automatically.', refresh: false }
  }
  if (status === 502 && body.error === 'brand_discovery_upstream_unavailable') {
    return { tone: 'warning', title: 'Certificate logs could not be reached.', detail: 'No result was recorded from this attempt. Please try again later — the daily check also runs automatically.', refresh: false }
  }
  if (status === 404) {
    return { tone: 'error', title: 'This workspace is no longer available.', detail: null, refresh: false }
  }
  return { tone: 'error', title: 'The check could not be completed.', detail: 'Please try again in a moment.', refresh: false }
}
