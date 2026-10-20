import { useState } from 'react'

// Presentation only: every verdict, state and sentence comes from the API's
// result. This file maps the backend's level/state codes to labels and colours.
const LEVELS = {
  good: { label: 'Looks good', tone: 'border-emerald-200 bg-emerald-50 text-emerald-900' },
  attention: { label: 'Needs attention', tone: 'border-amber-200 bg-amber-50 text-amber-950' },
  risk: { label: 'At risk', tone: 'border-red-200 bg-red-50 text-red-900' },
  unknown: { label: 'Could not check', tone: 'border-gray-200 bg-gray-50 text-gray-900' },
}

const STATES = {
  pass: { label: 'Passed', tone: 'bg-emerald-100 text-emerald-800' },
  warn: { label: 'Needs attention', tone: 'bg-amber-100 text-amber-900' },
  fail: { label: 'Problem', tone: 'bg-red-100 text-red-800' },
  unknown: { label: 'Could not check', tone: 'bg-gray-200 text-gray-800' },
  info: { label: 'Note', tone: 'bg-sky-100 text-sky-900' },
}

export function StateBadge({ state }) {
  const s = STATES[state] || STATES.info
  return <span className={`inline-block shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold ${s.tone}`}>{s.label}</span>
}

// Every time on the page is the viewer's local time, with its zone named: a
// link that expires after a clock change must not look an hour off.
export const LOCAL_TIME = Object.freeze({ year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })

function formatTime(iso) {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? null : date.toLocaleString(undefined, LOCAL_TIME)
}

export function CopyButton({ value, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="btn-secondary text-sm px-3 py-1.5"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        } catch { /* the value stays selectable on the page */ }
      }}
    >
      {copied ? 'Copied' : label}
    </button>
  )
}

export function DnsRecord({ record, heading }) {
  if (!record) return null
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4 space-y-3">
      {heading && <p className="text-sm font-semibold text-gray-900">{heading}</p>}
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
        <dt className="text-gray-500">Type</dt><dd className="font-mono">{record.type}</dd>
        <dt className="text-gray-500">Name</dt><dd className="font-mono break-all">{record.name}</dd>
        <dt className="text-gray-500">Value</dt><dd className="font-mono break-all">{record.value}</dd>
      </dl>
      <div className="flex flex-wrap gap-2">
        <CopyButton value={record.value} label="Copy value" />
        <CopyButton value={record.name} label="Copy name" />
      </div>
    </div>
  )
}

function NextStep({ step }) {
  if (!step) return null
  return (
    <section aria-labelledby="next-step-heading" className="space-y-3">
      <h2 id="next-step-heading" className="text-lg font-bold">Next step: {step.title}</h2>
      {step.explanation && <p className="text-sm text-gray-700 leading-relaxed">{step.explanation}</p>}
      {step.replaces?.length > 0 && (
        <div className="text-sm text-gray-600">
          <p>Current record{step.replaces.length > 1 ? 's' : ''}:</p>
          <ul className="mt-1 space-y-1">{step.replaces.map((value) => <li key={value} className="font-mono break-all">{value}</li>)}</ul>
        </div>
      )}
      <DnsRecord record={step.record} heading={step.replaces?.length ? 'Replace it with' : null} />
      {step.options?.map((option) => (
        <div key={option.label} className="space-y-2">
          <p className="text-sm font-semibold">{option.label}</p>
          <p className="text-sm text-gray-600">{option.explanation}</p>
          <DnsRecord record={option.record} />
        </div>
      ))}
      {step.cautions?.length > 0 && (
        <ul className="list-disc pl-5 space-y-1 text-sm text-gray-700">{step.cautions.map((c) => <li key={c}>{c}</li>)}</ul>
      )}
    </section>
  )
}

export default function ToolResult({ result, cached = false, share = null, sharedUntil = null, children }) {
  const level = LEVELS[result.verdict?.level] || LEVELS.unknown
  const checkedAt = formatTime(result.checked_at)
  return (
    <div className="space-y-8" data-testid="tool-result">
      <section className={`rounded-2xl border p-5 sm:p-6 ${level.tone}`} aria-live="polite">
        <p className="text-sm font-semibold uppercase tracking-wide">{level.label}</p>
        <h2 className="text-2xl font-bold mt-1">{result.verdict?.headline}</h2>
        <p className="mt-2 leading-relaxed">{result.verdict?.summary}</p>
        <p className="mt-3 text-sm opacity-80">
          {result.domain}{checkedAt ? ` · checked ${checkedAt}` : ''}{cached ? ' (a recent check of the same domain, reused for up to 10 minutes)' : ''}
          {sharedUntil ? ` · shared link valid until ${formatTime(sharedUntil)}` : ''}
        </p>
      </section>

      {children}

      <NextStep step={result.next_step} />

      <section aria-labelledby="checked-heading" className="space-y-3">
        <h2 id="checked-heading" className="text-lg font-bold">What we checked</h2>
        <ul className="space-y-3">
          {(result.checked || []).map((item) => (
            <li key={item.label} className="flex gap-3 items-start">
              <StateBadge state={item.state} />
              <div className="text-sm"><p className="font-semibold">{item.label}</p>{item.detail && <p className="text-gray-600">{item.detail}</p>}</div>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="not-checked-heading" className="space-y-3">
        <h2 id="not-checked-heading" className="text-lg font-bold">What we could not check</h2>
        <ul className="space-y-2 text-sm">
          {(result.not_checked || []).map((item) => (
            <li key={item.label}><span className="font-semibold">{item.label}.</span> <span className="text-gray-600">{item.reason}</span></li>
          ))}
        </ul>
      </section>

      {result.why_it_matters && (
        <section aria-labelledby="why-heading" className="space-y-2">
          <h2 id="why-heading" className="text-lg font-bold">Why it matters for a small business</h2>
          <p className="text-sm text-gray-700 leading-relaxed">{result.why_it_matters}</p>
        </section>
      )}

      {share?.url && (
        <section className="rounded-xl border border-gray-200 bg-white p-4 flex flex-wrap items-center gap-3 justify-between">
          <p className="text-sm text-gray-600">Share this result. The link shows this check only and stops working on {formatTime(share.expires_at)}.</p>
          <CopyButton value={share.url} label="Copy share link" />
        </section>
      )}
    </div>
  )
}
