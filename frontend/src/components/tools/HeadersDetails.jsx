import { StateBadge } from './ToolResult'

// Presentation of the security headers result: each header the API judged,
// its value as sent, and what it does. All wording comes from the API result.
const STATE_FOR = { valid: 'pass', weak: 'warn', malformed: 'fail', missing: 'fail', unknown: 'unknown' }
const STATUS_LABEL = { valid: 'Set', weak: 'Weak', malformed: 'Invalid value', missing: 'Missing', unknown: 'Could not judge' }

export default function HeadersDetails({ result }) {
  const headers = result.headers || []
  if (headers.length === 0) return null
  return (
    <section aria-labelledby="headers-heading" className="space-y-3">
      <h2 id="headers-heading" className="text-lg font-bold">The six headers</h2>
      {result.response?.final_url && <p className="text-sm text-gray-600">As sent by {result.response.final_url} (HTTP {result.response.status}).</p>}
      <ul className="divide-y divide-gray-100 rounded-2xl border border-gray-100 bg-white">
        {headers.map((header) => (
          <li key={header.key} className="p-4 sm:p-5 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <StateBadge state={STATE_FOR[header.status] || 'unknown'} />
              <span className="font-mono text-sm font-semibold break-all">{header.name}</span>
              <span className="text-xs text-gray-500">{header.label || STATUS_LABEL[header.status] || header.status}</span>
            </div>
            <p className="text-sm text-gray-700">{header.meaning}</p>
            {header.value
              ? <p className="font-mono text-xs text-gray-600 break-all">{header.value}</p>
              : null}
            {((header.status !== 'valid' && header.status !== 'missing') || header.note) && header.details && <p className="text-sm text-gray-600">{header.details}</p>}
          </li>
        ))}
      </ul>
    </section>
  )
}
