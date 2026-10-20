// Presentation of the lookalike result: each registered close variant and
// what DNS shows for it. Facts only, never a judgement of the owner: the API
// result decides what was observed; this file only labels it.
function Chip({ tone, children }) {
  const tones = {
    red: 'bg-red-100 text-red-800',
    amber: 'bg-amber-100 text-amber-900',
    grey: 'bg-gray-200 text-gray-800',
  }
  return <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${tones[tone]}`}>{children}</span>
}

function facts(row) {
  const out = [<Chip key="reg" tone="grey">Registered</Chip>]
  if (row.resolves === true) out.push(<Chip key="web" tone="amber">Points at a server</Chip>)
  if (row.mx === true) out.push(<Chip key="mail" tone="red">Receives email</Chip>)
  if (row.detail_checked === false) out.push(<Chip key="nd" tone="grey">Server and email not checked</Chip>)
  return out
}

export default function LookalikeDetails({ result }) {
  const rows = result.lookalikes || []
  if (result.verdict?.level === 'unknown') return null
  return (
    <section aria-labelledby="lookalike-heading" className="space-y-3">
      <h2 id="lookalike-heading" className="text-lg font-bold">Registered lookalikes</h2>
      <p className="text-sm text-gray-600">{result.candidates_checked} close variants of {result.registrable_domain} were checked in DNS.</p>
      {rows.length === 0
        ? <p className="rounded-xl border border-gray-200 bg-white p-4 text-sm text-gray-700">None of them is registered.</p>
        : (
          <ul className="divide-y divide-gray-100 rounded-2xl border border-gray-100 bg-white">
            {rows.map((row) => (
              <li key={row.domain} className="p-4 sm:p-5 space-y-2">
                <p className="font-mono text-sm font-semibold break-all">{row.domain}</p>
                <p className="text-sm text-gray-600">{row.variant_label}</p>
                <div className="flex flex-wrap gap-2">{facts(row)}</div>
              </li>
            ))}
          </ul>
        )}
    </section>
  )
}
