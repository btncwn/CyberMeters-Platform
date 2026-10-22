// Website Security: what signed-in scanning did in this scan (S2-SIGNED-IN-REPORT,
// founder decision 22 Oct 2026). The snapshot owns the sentences; this renders
// them verbatim, plus one fact line. A null "anonymous access refused" reads
// "not observed", never "no". Never a credential, username or session value —
// the API carries none. A report from before the section existed renders nothing.
import { formatDate } from '../utils/dates'

export function signedInFactLine(si) {
  if (!si || si.status !== 'recorded' || si.signed_in !== true) return null
  const refused = si.anonymous_access_refused === true ? 'yes' : si.anonymous_access_refused === false ? 'no' : 'not observed'
  const parts = [`Signed-in pages: ${Number.isInteger(si.pages_checked) ? si.pages_checked : 0} checked`, `anonymous access refused: ${refused}`]
  if (si.last_successful_sign_in_at) parts.push(`last signed in ${formatDate(si.last_successful_sign_in_at, '', { timeZone: 'UTC' })} UTC`)
  return parts.join(' · ')
}

export default function SignedInScanningSummary({ section }) {
  if (!section || typeof section !== 'object') return null
  const fact = signedInFactLine(section)
  return (
    <section className="card p-5 space-y-2" aria-labelledby="signed-in-scanning-title" data-testid="signed-in-scanning">
      <h3 id="signed-in-scanning-title" className="font-semibold text-gray-900">Website Security: signed-in scanning</h3>
      {fact && <p className="text-sm font-medium text-gray-900" data-testid="signed-in-fact">{fact}</p>}
      {section.customer_message && <p className="text-sm text-gray-700">{section.customer_message}</p>}
      {section.limitation && <p className="text-xs text-gray-600">{section.limitation}</p>}
    </section>
  )
}
