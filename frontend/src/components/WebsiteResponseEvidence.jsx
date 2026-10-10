// Render only the stored website probe fields, never raw response headers or
// Set-Cookie values. Unavailable probes remain unavailable, not missing headers.
const HEADERS = [
  'strict-transport-security', 'content-security-policy', 'x-frame-options',
  'x-content-type-options', 'referrer-policy', 'permissions-policy',
]
function displayUrl(value) {
  if (!value) return 'Not recorded'
  try {
    const url = new URL(value)
    if (!['http:', 'https:'].includes(url.protocol)) return 'Not recorded'
    return `${url.origin}${url.pathname}`
  } catch { return 'Not recorded' }
}
export default function WebsiteResponseEvidence({ headers }) {
  const checks = Array.isArray(headers?.checked_paths) ? headers.checked_paths : []
  return (
    <details className="border-t border-gray-100 px-6 py-4 text-sm text-gray-700">
      <summary className="cursor-pointer text-base font-medium">Recorded website responses</summary>
      <p className="mt-3">Evidence from this scan, not a new check. URL credentials and query strings are hidden.</p>
      {!checks.length && <p className="mt-3">Per-request evidence was not recorded in this report.</p>}
      {checks.map((check, index) => (
        <div key={index} className="mt-4 space-y-2 rounded-lg border border-gray-200 p-4">
          <p className="break-all font-medium">{displayUrl(check.requested_url)}</p>
          <p>Result: {String(check.status || 'Not recorded').replace(/_/g, ' ')}{Number.isInteger(check.status_code) ? ` · HTTP ${check.status_code}` : ''}</p>
          {check.final_url && <p className="break-all">Final URL: {displayUrl(check.final_url)}</p>}
          {check.status === 'ok' && <dl className="space-y-2">
            {HEADERS.filter((name) => Object.hasOwn(check.headers_observed || {}, name)).map((name) => <div key={name}>
              <dt className="font-medium">{name}</dt><dd className="break-words">{check.headers_observed[name] || 'No value captured'}</dd>
            </div>)}
          </dl>}
        </div>
      ))}
    </details>
  )
}
