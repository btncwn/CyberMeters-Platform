import { StateBadge } from './ToolResult'

// Presentation of the DMARC result's record, tags, policy ladder and report
// destinations. All wording comes from the API result.
const DESTINATION_STATE = {
  authorized: 'pass',
  not_required_same_organisational_domain: 'pass',
  not_required_cybermeters_hosted: 'pass',
  unauthorized: 'fail',
  malformed: 'fail',
}

export default function DmarcDetails({ result }) {
  const { record, tags = [], ladder, reporting } = result
  if (!record) return null
  const currentIndex = ladder?.steps?.findIndex((step) => step.policy === ladder.current) ?? -1
  return (
    <div className="space-y-8">
      <section aria-labelledby="dmarc-record-heading" className="space-y-3">
        <h2 id="dmarc-record-heading" className="text-lg font-bold">The record</h2>
        <p className="text-sm text-gray-600">
          {record.inherited
            ? <>No record at this exact name, so the policy published at <span className="font-mono">{record.dns_name}</span> applies.</>
            : <>Published at <span className="font-mono">{record.dns_name}</span>.</>}
        </p>
        {record.values?.length > 0
          ? record.values.map((value) => <pre key={value} className="rounded-xl bg-gray-900 text-gray-100 p-4 text-sm whitespace-pre-wrap break-all">{value}</pre>)
          : <p className="text-sm text-gray-700">No DMARC record was observed.</p>}
      </section>

      {ladder?.steps && (
        <section aria-labelledby="ladder-heading" className="space-y-3">
          <h2 id="ladder-heading" className="text-lg font-bold">Policy ladder</h2>
          <ol className="grid sm:grid-cols-3 gap-3">
            {ladder.steps.map((step, index) => {
              const here = index === currentIndex
              return (
                <li key={step.policy} aria-current={here ? 'step' : undefined}
                  className={`rounded-xl border p-4 text-sm ${here ? 'border-brand-600 bg-brand-50 ring-1 ring-brand-600' : index < currentIndex ? 'border-gray-200 bg-white text-gray-500' : 'border-dashed border-gray-300 bg-white'}`}>
                  <p className="font-semibold">{index + 1}. {step.label}{here ? ' — you are here' : ''}</p>
                  <p className="mt-1 text-gray-600">{step.detail}</p>
                </li>
              )
            })}
          </ol>
          {ladder.declared && ladder.declared !== ladder.current && (
            <p className="text-sm text-gray-600">The record declares p={ladder.declared}; testing mode makes the requested policy one step lower.</p>
          )}
        </section>
      )}

      {tags.length > 0 && (
        <section aria-labelledby="tags-heading" className="space-y-3">
          <h2 id="tags-heading" className="text-lg font-bold">What each part means</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-gray-500"><th className="py-2 pr-4 font-medium">Tag</th><th className="py-2 pr-4 font-medium">Value</th><th className="py-2 font-medium">Meaning</th></tr></thead>
              <tbody className="divide-y divide-gray-100">
                {tags.map((tag) => (
                  <tr key={tag.tag} className="align-top">
                    <td className="py-2 pr-4 font-mono">{tag.tag}</td>
                    <td className="py-2 pr-4 font-mono whitespace-nowrap">{tag.value}{tag.defaulted ? <span className="block font-sans text-xs text-gray-500">default</span> : null}</td>
                    <td className="py-2 text-gray-700">{tag.meaning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {(reporting?.rua?.length > 0 || reporting?.ruf?.length > 0) && (
        <section aria-labelledby="reports-heading" className="space-y-3">
          <h2 id="reports-heading" className="text-lg font-bold">Where reports go</h2>
          <ul className="space-y-3">
            {[...(reporting.rua || []).map((d) => ({ ...d, kind: 'Aggregate (rua)' })), ...(reporting.ruf || []).map((d) => ({ ...d, kind: 'Failure (ruf)' }))].map((destination) => (
              <li key={`${destination.kind}-${destination.uri}`} className="flex gap-3 items-start text-sm">
                <StateBadge state={DESTINATION_STATE[destination.status] || (destination.kind.startsWith('Failure') ? 'info' : 'unknown')} />
                <div>
                  <p className="font-mono break-all">{destination.uri}</p>
                  <p className="text-gray-600">{destination.kind} · {destination.label}{destination.message ? `. ${destination.message}` : ''}</p>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
