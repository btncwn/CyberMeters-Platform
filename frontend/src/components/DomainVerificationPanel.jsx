import { useState } from 'react'
import Spinner from './Spinner'
import { shouldKeepInstructions } from '../lib/newScanVerification'
import OneClickDnsButton from './OneClickDnsButton'

// ── Domain-ownership setup, shown inline in New Scan ─────────────────────────
// Presentational only. Every value on screen comes from the backend's verification
// response — this component never builds a host or a token, because a client-built
// value could disagree with what the server stored and send the customer to publish
// a record that can never verify.
//
// It is deliberately framed as a next step, not an error: the customer has done
// nothing wrong, they simply have not proven ownership yet.

function CopyButton({ value, label }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1800)
        } catch { /* clipboard unavailable — the value is on screen to copy by hand */ }
      }}
      className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 hover:text-brand-800 transition-colors shrink-0"
      aria-label={`Copy ${label}`}
    >
      {copied ? 'Copied' : <>Copy {label}</>}
    </button>
  )
}

function Field({ label, value, copyLabel }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5 border-b border-gray-100 last:border-0">
      <div className="min-w-0">
        <p className="text-xs uppercase tracking-wide text-gray-400 font-semibold mb-0.5">{label}</p>
        <p className="font-mono text-xs text-gray-900 break-all">{value}</p>
      </div>
      {copyLabel && <CopyButton value={value} label={copyLabel} />}
    </div>
  )
}

export default function DomainVerificationPanel({ domain, dns, state, note, onVerify, oneClick = null }) {
  const checking = state === 'checking'

  if (state === 'verified') {
    return (
      <div className="rounded-lg border border-brand-200 bg-brand-50 p-4 flex items-start gap-2.5">
        <div>
          <p className="text-sm font-semibold text-brand-900">Domain ownership verified</p>
          <p className="text-xs text-brand-700 mt-0.5">You can now scan {domain}.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 space-y-3">
      <div className="flex items-start gap-2.5">
        <div>
          <p className="text-sm font-semibold text-gray-900">Verify ownership of {domain}</p>
          <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
            Before scanning, prove you control this domain by adding a DNS record. This is a
            one-time step for this workspace.
          </p>
        </div>
      </div>

      {/* The instruction persists through checking and a failed check — clearing it
          would leave the customer with no route back to the record. */}
      {dns && shouldKeepInstructions(state) && (
        <>
          <OneClickDnsButton offer={oneClick} />
          <div className="rounded-md border border-gray-200 bg-white px-3.5">
            <Field label="Type" value={dns.record_type} />
            <Field label="Name / Host" value={dns.host} copyLabel="host" />
            <Field label="Value" value={dns.value} copyLabel="value" />
            <Field label="TTL" value={dns.ttl} />
          </div>

          <p className="text-xs text-gray-500 flex items-start gap-1.5">
            <span className="font-medium text-gray-600">{dns.provider_path}</span>
          </p>
        </>
      )}

      {!dns && (
        <p className="text-xs text-gray-500 flex items-center gap-1.5">
          <Spinner size="sm" /> Preparing your verification record…
        </p>
      )}

      {/* A failed check is a waiting state, not a dead end. */}
      {note && (
        <p className="text-xs text-brand-700 bg-transparent border border-[1.5px] border-brand-700 rounded-md px-3 py-2 leading-relaxed">
          {note}
        </p>
      )}

      {dns && (
        <button
          type="button"
          onClick={onVerify}
          disabled={checking}
          className="btn-secondary w-full justify-center py-2.5 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {checking
            ? <><Spinner size="sm" /><span>Checking DNS…</span></>
            : <span>I&rsquo;ve added the DNS record — Verify domain</span>}
        </button>
      )}
    </div>
  )
}
