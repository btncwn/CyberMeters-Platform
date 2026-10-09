import { parseServerDate } from '../utils/dates'

const text = value => typeof value === 'string' && value.trim() ? value : 'Not recorded'
const time = value => {
  if (typeof value !== 'string') return 'Not recorded'
  const parsed = parseServerDate(value)
  return Number.isFinite(parsed?.getTime()) ? `${parsed.toLocaleString('en-GB', { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short' })} UTC` : 'Not recorded'
}
const stateLabels = { open: 'Open', closed: 'Closed', timeout: 'Timed out', error: 'Measurement failed', not_run: 'Not run' }
const endpoint = value => value?.address ? `${value.address.includes(':') ? `[${value.address}]` : value.address}:${value.port ?? '?'}` : 'Not recorded'

function Field({ label, children }) {
  return <div className="min-w-0"><dt className="text-xs text-gray-500">{label}</dt><dd className="mt-0.5 text-sm text-gray-800 break-words [overflow-wrap:anywhere]">{children}</dd></div>
}

// This is an evidence view, not a second certificate verdict. A received leaf,
// name match and validation against the named trust store are separate facts.
export default function LiveTlsEvidence({ evidence, showEndpoints = true }) {
  if (!evidence || typeof evidence !== 'object') return null
  const leaf = evidence.leaf_certificate || {}
  const collected = evidence.leaf_collected === true && leaf.collection_performed === true && leaf.collection_complete === true && typeof leaf.certificate_identity === 'string' && !!leaf.certificate_identity
  const match = evidence.hostname_match || {}
  const trust = evidence.trust_store_validation || {}
  const matchResult = collected && match.assessment_performed === true && match.certificate_identity === leaf.certificate_identity ? match.result : 'unknown'
  const store = trust.trust_store_context || evidence.trust_store_context || {}
  const trustResult = collected && trust.validation_performed === true && trust.certificate_identity === leaf.certificate_identity && typeof store.name === 'string' && !!store.name && typeof store.sha256 === 'string' && !!store.sha256 ? trust.validation_result : 'unknown'
  const runtimeChain = evidence.runtime_chain?.collection_performed === true && Array.isArray(evidence.runtime_chain.certificates) ? evidence.runtime_chain.certificates : []
  const endpoints = showEndpoints && Array.isArray(evidence.endpoint_observations) ? evidence.endpoint_observations : []
  const names = Array.isArray(leaf.dns_names) ? leaf.dns_names.filter(value => typeof value === 'string') : []

  return <details className="rounded-lg border border-gray-200 bg-white p-3" data-testid="live-tls-evidence">
    <summary className="cursor-pointer text-sm font-semibold text-gray-800">Live TLS evidence — {collected ? 'certificate observed' : 'not fully observed'}</summary>
    <div className="mt-3 space-y-4">
      <p className="text-xs text-gray-500">These observations describe the recorded connection. They do not establish that every endpoint or the whole service is secure.</p>
      {evidence.all_planned_endpoints_observed === false && <p className="text-sm text-amber-800">Endpoint coverage is incomplete. Unmeasured endpoints remain unknown.</p>}
      {evidence.all_planned_endpoints_observed === true && endpoints.length > 0 && <p className="text-sm text-gray-600">All planned endpoints were observed in this run.</p>}
      {!collected ? <p className="text-sm text-gray-600">A complete live certificate was not recorded. Existing certificate-log evidence is separate; it does not confirm the certificate currently served.</p> : <>
        <dl className="grid gap-3 sm:grid-cols-2">
          <Field label="Endpoint">{endpoint(evidence.endpoint)}</Field>
          <Field label="Reference hostname or address">{text(match.reference_hostname || evidence.endpoint?.hostname)}</Field>
          <Field label="Observed at">{time(evidence.observed_at)}</Field>
          <Field label="Protocol / cipher">{text(evidence.protocol)} / {text(evidence.cipher)}</Field>
          <Field label="Subject">{text(leaf.subject)}</Field>
          <Field label="Issuer">{text(leaf.issuer)}</Field>
          <Field label="Valid from">{time(leaf.not_before)}</Field>
          <Field label="Valid until">{time(leaf.not_after)}</Field>
          <Field label="Hostname or address match"><span className={matchResult === 'mismatched' ? 'text-red-700 font-medium' : ''}>{matchResult === 'matched' ? 'Matched the recorded identity' : matchResult === 'mismatched' ? 'Did not match the recorded identity' : 'Not established'}</span></Field>
          <Field label="Named trust-store validation"><span className={trustResult === 'invalid' ? 'text-red-700 font-medium' : ''}>{trustResult === 'valid' ? 'Valid against the recorded trust store' : trustResult === 'invalid' ? 'Invalid against the recorded trust store' : 'Not established'}</span></Field>
          <Field label="Trust store">{text(store.name)}{store.version ? ` · ${text(store.version)}` : ''}</Field>
          <Field label="Trust-store fingerprint">{text(store.sha256)}</Field>
        </dl>
        <dl className="space-y-3">
          <Field label="Leaf certificate fingerprint">{leaf.certificate_identity}</Field>
          <Field label="DNS names (SAN)">{names.length ? names.join(', ') : 'Not recorded'}</Field>
        </dl>
        {trustResult === 'invalid' && trust.reason && <p className="text-xs text-red-700">Validation detail: {text(trust.reason)}</p>}
        <details className="rounded border border-gray-100 p-3">
          <summary className="cursor-pointer text-sm font-medium">Runtime-observed issuer chain ({runtimeChain.length} recorded)</summary>
          <p className="mt-2 text-xs text-gray-500">This is the runtime’s issuer chain, which may include a root from its trust store. It is not the exact chain sent over the connection, and its completeness is not established.</p>
          {runtimeChain.length ? <ol className="mt-3 space-y-3">{runtimeChain.map((certificate, index) => <li key={`${certificate.certificate_identity || 'unknown'}-${index}`} className="border-t border-gray-100 pt-2"><dl className="space-y-1"><Field label={`Certificate ${index + 1}`}>{text(certificate.certificate_identity)}</Field><Field label="Subject">{text(certificate.subject)}</Field><Field label="Issuer">{text(certificate.issuer)}</Field><Field label="Valid until">{time(certificate.not_after)}</Field></dl></li>)}</ol> : <p className="mt-2 text-xs text-gray-500">No runtime issuer certificates recorded.</p>}
        </details>
      </>}
      <p className="text-xs text-gray-500">Exact presented chain: unknown. Revocation / OCSP status: not assessed.</p>
      {endpoints.length > 0 && <div className="space-y-2"><h4 className="text-sm font-semibold">Endpoint observations ({endpoints.length})</h4>{endpoints.map((row, index) => <div key={`${row.address}:${row.port}:${index}`} className="rounded border border-gray-100 p-3 space-y-2"><p className="text-sm break-all">{endpoint(row)} — {stateLabels[row.state] || 'Not assessed'}</p>{row.tls ? <LiveTlsEvidence evidence={row.tls} showEndpoints={false} /> : <p className="text-xs text-gray-500">Live TLS was not observed for this endpoint.</p>}</div>)}</div>}
    </div>
  </details>
}
