import { useId } from 'react'
import { parseServerDate } from '../utils/dates'
import { assetSourceLabel } from '../lib/assetSourceLabel'

// Why a name is in the inventory and what was measured for it. Every sentence
// is the backend's (engines/asset-evidence.js); this component only lays the
// separate facts out — where the name was seen, why it is in scope, what DNS
// said, which service answered, which finding rests on which measurement and
// what was not checked. Nothing here is derived or upgraded.

function fmtDate(value) {
  const d = parseServerDate(value)
  return d && !Number.isNaN(d.getTime())
    ? d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
    : null
}

function fmtDateTime(value) {
  const d = parseServerDate(value)
  return d && !Number.isNaN(d.getTime())
    ? d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : null
}

const SEVERITY_CLASS = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
}

function Section({ title, meta, children }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="space-y-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <h3 id={id} className="label">{title}</h3>
        {meta && <span className="text-xs text-gray-400">{meta}</span>}
      </div>
      {children}
    </section>
  )
}

function SeenIn({ seenIn }) {
  if (!seenIn) return null
  const sources = Array.isArray(seenIn.sources) ? seenIn.sources : []
  return (
    <div className="space-y-1.5">
      {sources.length > 0 && (
        <ul className="space-y-1" aria-label="Where this name was seen">
          {sources.map((item) => {
            const first = fmtDate(item.first_seen_at)
            const last = fmtDate(item.last_seen_at)
            return (
              <li key={item.source} className="text-xs text-gray-700">
                <span className="font-medium">{assetSourceLabel(item.source)}</span>
                {first && (
                  <span className="text-gray-500">
                    {first === last || !last ? `, seen ${first}` : `, first seen ${first}, last seen ${last}`}
                  </span>
                )}
              </li>
            )
          })}
        </ul>
      )}
      {seenIn.status === 'not_recorded' && seenIn.first_source && (
        <p className="text-xs text-gray-700">
          <span className="font-medium">{assetSourceLabel(seenIn.first_source)}</span>
          <span className="text-gray-500"> (the source that first found it)</span>
        </p>
      )}
      {seenIn.note && (
        <p className="text-xs text-gray-500">
          {seenIn.note}
          {seenIn.status === 'recorded_since' && fmtDate(seenIn.recorded_since) ? ` Recorded since ${fmtDate(seenIn.recorded_since)}.` : ''}
        </p>
      )}
    </div>
  )
}

function DnsAnswer({ dns }) {
  if (!dns || dns.status !== 'checked') {
    return <p className="text-xs text-gray-500">DNS was not asked about this name in the recent scans.</p>
  }
  return (
    <div className="space-y-2">
      <dl className="space-y-1.5">
        {(dns.families || []).map((family) => (
          <div key={family.family} className="grid grid-cols-[7rem_1fr] gap-2">
            <dt className="text-xs font-medium text-gray-600">{family.family}</dt>
            <dd className="text-xs text-gray-700 min-w-0">
              <span>{family.label}</span>
              {(family.values || []).length > 0 && (
                <span className="mt-1 flex flex-wrap gap-1">
                  {family.values.map((value) => (
                    <span key={value} className="mono text-xs bg-gray-50 border border-gray-200 rounded-sm px-1.5 py-0.5 break-all">{value}</span>
                  ))}
                  {family.more_values > 0 && <span className="text-xs text-gray-500">and {family.more_values} more</span>}
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>
      {(dns.alias_chain || []).length > 0 && (
        <p className="text-xs text-gray-600">
          Alias of <span className="mono break-all">{dns.alias_chain.join(' then ')}</span>
        </p>
      )}
      {dns.uncertain && <p className="text-xs text-amber-700">{dns.uncertain}</p>}
    </div>
  )
}

function ServiceAnswer({ service }) {
  if (!service || service.status !== 'checked') {
    return <p className="text-xs text-gray-500">No web request was made to this name in the recent scans.</p>
  }
  return (
    <div className="space-y-1.5">
      <ul className="space-y-1">
        {(service.attempts || []).map((attempt, index) => (
          <li key={`${attempt.protocol}-${attempt.port}-${index}`} className="text-xs text-gray-700">
            <span className="font-medium">
              {attempt.protocol ? `${attempt.protocol} on port ${attempt.port}` : 'Web request'}
            </span>
            {`: ${attempt.label}`}
            {attempt.ended_at && <span className="text-gray-500">{`. The answer came from ${attempt.ended_at}.`}</span>}
          </li>
        ))}
      </ul>
      {service.address_family_note && <p className="text-xs text-gray-500">{service.address_family_note}</p>}
    </div>
  )
}

function Findings({ findings }) {
  const items = Array.isArray(findings?.items) ? findings.items : []
  if (items.length === 0) {
    return (
      <p className="text-xs text-gray-500">
        No finding was raised from these measurements. Anything listed under Not checked was not assessed.
      </p>
    )
  }
  return (
    <ul className="space-y-3">
      {items.map((finding, index) => (
        <li key={`${finding.finding_type}-${index}`} className="rounded-xl bg-gray-50 px-3 py-2.5 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            {finding.severity && <span className={SEVERITY_CLASS[finding.severity] || 'badge-unknown'}>{finding.severity}</span>}
            <span className="text-xs font-semibold text-gray-800">{finding.title || finding.finding_type}</span>
          </div>
          <p className="text-xs text-gray-700"><span className="font-medium">Measured: </span>{finding.measured_label}</p>
          {finding.check_id && (
            <p className="text-xs text-gray-500">
              {`Check ${finding.check_id}${finding.check_version ? `, version ${finding.check_version}` : ''}`}
              {finding.rule ? `: ${finding.rule}` : ''}
            </p>
          )}
        </li>
      ))}
      {findings.more > 0 && <li className="text-xs text-gray-500">{`${findings.more} more in the scan report.`}</li>}
    </ul>
  )
}

export default function AssetEvidence({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  if (evidence.status === 'unavailable') {
    return (
      <div className="px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl text-xs text-gray-600">
        {evidence.customer_message || 'Evidence for this name could not be read.'}
      </div>
    )
  }
  const recorded = evidence.status === 'recorded'
  const notChecked = Array.isArray(evidence.not_checked) ? evidence.not_checked : []
  return (
    <div className="space-y-5 border-t border-gray-100 pt-5">
      {evidence.customer_message && (
        <p className="text-xs text-gray-600">{evidence.customer_message}</p>
      )}
      <Section title="Why it is listed">
        {evidence.scope?.label && <p className="text-xs text-gray-700">{evidence.scope.label}</p>}
        <SeenIn seenIn={evidence.seen_in} />
      </Section>
      {recorded && (
        <>
          <Section title="DNS answer" meta={evidence.dns?.checked_at ? `Checked ${fmtDateTime(evidence.dns.checked_at)}` : null}>
            <DnsAnswer dns={evidence.dns} />
          </Section>
          <Section title="Web service" meta={evidence.service?.checked_at ? `Checked ${fmtDateTime(evidence.service.checked_at)}` : null}>
            <ServiceAnswer service={evidence.service} />
          </Section>
          <Section title="Findings" meta={evidence.findings?.measured_at ? `Measured ${fmtDateTime(evidence.findings.measured_at)}` : null}>
            <Findings findings={evidence.findings} />
          </Section>
        </>
      )}
      {notChecked.length > 0 && (
        <Section title="Not checked">
          <ul className="space-y-1 list-disc pl-4">
            {notChecked.map((gap) => (
              <li key={gap.part} className="text-xs text-gray-600">{gap.label}</li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  )
}
