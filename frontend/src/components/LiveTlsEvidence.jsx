import { useEvidenceTime } from '../lib/reportTime'
import { keyLabel } from '../lib/keyLabel'

const text = value => typeof value === 'string' && value.trim() ? value : 'Not recorded'
const stateLabels = { open: 'Open', closed: 'Closed', timeout: 'Timed out', error: 'Measurement failed', not_run: 'Not run' }
const endpoint = value => value?.address ? `${value.address.includes(':') ? `[${value.address}]` : value.address}:${value.port ?? '?'}` : 'Not recorded'
const keyText = leaf => typeof leaf?.public_key_algorithm === 'string' && leaf.public_key_algorithm
  ? `${leaf.public_key_algorithm.toUpperCase()}${Number.isInteger(leaf.public_key_size_bits) ? ` ${leaf.public_key_size_bits}-bit` : ''}`
  : 'Not recorded'

function Field({ label, children }) {
  return <div className="min-w-0"><dt className="text-xs text-gray-500">{label}</dt><dd className="mt-0.5 text-sm text-gray-800 wrap-break-word wrap-anywhere">{children}</dd></div>
}

const controlStates = { accepted: 'Accepted', rejected: 'Rejected', uncertain: 'Uncertain', not_applicable: 'Not applicable', not_authorized: 'Not authorized', unexecutable: 'Could not execute' }
// S3-B: an intrusive check the customer has not authorised is stated plainly.
// Seat 3's held reasons (TLS specials go-live, 23 Oct 2026), in plain words.
const CONTROL_REASONS = Object.freeze({
  requires_customer_authorisation: 'Not tested — requires your authorisation',
  authorised_engine_not_released: 'Authorised — not yet available',
  address_not_verified_not_tested: 'Not tested — this address is not verified as yours',
  // The producer's reason (shared/tls/catalog.js TLS_AUTHORISED_ON_DEMAND_REASON);
  // the older key stays as an alias.
  scheduled_or_unknown_origin: 'Not tested — authorised checks run only on scans you start yourself, never on scheduled scans.',
  authorised_runs_on_started_check: 'Not tested — authorised checks run only on scans you start yourself, never on scheduled scans.',
  // The TLS engine's reason when the server offers no heartbeat extension
  // (network-probe tls-engine; a server-feature limit, not a failed check).
  heartbeat_unavailable: 'Not applicable — this server did not offer the TLS heartbeat extension that Heartbleed relies on.',
})
// Where a customer adds their OWN servers so the TLS checks can test them.
export const ADDITIONAL_TLS_SERVICES_HREF = '/ws/certificates?tab=settings#additional-tls-services'
const controlState = (row, item = null) => {
  // Founder, 23 Oct 2026: a provider-infrastructure refusal names the host and,
  // when known, the provider, and says what to do — never just "not tested".
  if (row?.reason === 'provider_infrastructure_not_tested') {
    const host = typeof item?.hostname === 'string' && item.hostname ? item.hostname : 'This host'
    const provider = row.provider_name || item?.provider_name || item?.provider || null
    return `Not tested — ${host} is served by shared provider infrastructure${provider ? ` (${provider})` : ''}. Add your own servers to test them.`
  }
  return (row?.reason && CONTROL_REASONS[row.reason]) || controlStates[row?.state] || 'Unknown'
}
// Why an endpoint has no checks, from the planner's own scope deferrals
// (assessment.scope_deferrals, founder live run 24 Oct 2026): plain words,
// never "Not recorded". Not tested is never counted as passed.
const DEFERRAL_REASONS = Object.freeze({
  representative_address_scope: (h, p) => `Not tested in this scan — CyberMeters tests one address per host and port, and another address for ${h}:${p} was tested.`,
  tls_plan_budget: () => 'Not tested in this scan — the scan\u2019s TLS check limit was reached before this service. It is not counted as passed.',
  https_service_not_observed: () => 'Not tested in this scan — no HTTPS service was observed on this host in this scan.',
  non_https_service: () => 'Not tested in this scan — these checks test HTTPS services, and this service is not HTTPS.',
})
export function endpointNotTestedReason(item, deferrals) {
  const host = typeof item?.hostname === 'string' ? item.hostname : null
  const port = item?.port
  const byEndpoint = (Array.isArray(deferrals?.endpoints) ? deferrals.endpoints : [])
    .find((row) => row?.hostname === host && row?.port === port && (!row.address || row.address === item?.address))
  const byHost = (Array.isArray(deferrals?.hosts) ? deferrals.hosts : []).find((row) => row?.hostname === host && row?.port === port)
  const reason = (byEndpoint || byHost)?.reason
  const say = DEFERRAL_REASONS[reason]
  if (say) return say(host || 'this host', port ?? '?')
  return 'Not tested in this scan — no TLS checks were planned for this address. Its TLS status remains unknown.'
}
// When the endpoint was assessed: its own checks' latest observation time.
const endpointAssessedAt = (item) => {
  const times = (Array.isArray(item?.checks) ? item.checks : []).map((row) => row?.observed_at).filter((v) => typeof v === 'string' && v)
  return item?.observed_at || (times.length ? times.sort().at(-1) : null)
}
const number = value => Number.isSafeInteger(value) && value >= 0 ? String(value) : 'Not recorded'
const yesNo = value => value === true ? 'Yes' : value === false ? 'No' : 'Unknown'
const controlName = value => typeof value === 'string' ? value.replaceAll('_', ' ').replaceAll('-', ' ') : 'Unnamed check'
function StapledOcsp({ value }) {
  const time = useEvidenceTime()
  if (!value || typeof value !== 'object') return <p className="text-xs text-gray-500">Stapled OCSP: not recorded.</p>
  const verified = value.signature_valid === true && value.cert_id_match === true && value.fresh === true
  const label = value.state === 'absent' ? 'No stapled response observed'
    : verified && value.state === 'good' ? 'Good status in the verified staple'
    : verified && value.state === 'revoked' ? 'Revoked status in the verified staple'
    : value.state === 'invalid' ? 'Invalid or unverifiable staple' : 'Status not verified'
  return <div className="space-y-1 text-xs"><p className="font-medium">Stapled OCSP: {label}</p><p>Signature valid: {yesNo(value.signature_valid)} · Certificate matches: {yesNo(value.cert_id_match)} · Fresh: {yesNo(value.fresh)}</p><p>This update: {time(value.this_update)} · Next update: {time(value.next_update)}</p><p className="text-gray-500">A missing or unverified staple does not establish revocation status.</p></div>
}
function TlsControlDetail({ row }) {
  const time = useEvidenceTime()
  const evidence = row.evidence && typeof row.evidence === 'object' ? row.evidence : {}
  const negotiated = evidence.negotiated
  const certificates = evidence.certificates
  const extensions = evidence.extensions
  const vulnerability = evidence.vulnerability
  const offered = Array.isArray(certificates?.offered_chain) ? certificates.offered_chain : null
  const trusted = Array.isArray(certificates?.trusted_chain) ? certificates.trusted_chain : null
  return <div className="mt-2 space-y-3">
    <p className="text-xs text-gray-500">Observed {time(row.observed_at)} · Engine {text(row.engine?.family)} {text(row.engine?.version)} · Build {text(row.engine?.build_id)} · Sandboxed: {yesNo(row.engine?.sandboxed)}</p>
    {row.reason && <p className="text-xs text-gray-600">Reason: {controlName(row.reason)}</p>}
    {negotiated && <dl className="grid gap-2 sm:grid-cols-2"><Field label="Negotiated protocol / cipher">{text(negotiated.version)} / {text(negotiated.cipher)}</Field><Field label="Cipher bits">{number(negotiated.cipher_bits)}</Field><Field label="Key exchange group / bits">{text(negotiated.group)} / {number(negotiated.group_bits)}</Field><Field label="Forward secrecy observed">{yesNo(negotiated.pfs)}</Field><Field label="ALPN">{text(negotiated.alpn)}</Field><Field label="SNI sent">{typeof negotiated.sni_sent === 'boolean' ? yesNo(negotiated.sni_sent) : text(negotiated.sni_sent)}</Field></dl>}
    {certificates && <div className="space-y-2"><dl className="grid gap-2 sm:grid-cols-3"><Field label="Certificate trust result">{{valid:'Valid',invalid:'Invalid',unknown:'Unknown'}[certificates.trust] || 'Unknown'}</Field><Field label="Hostname matched">{yesNo(certificates.hostname)}</Field><Field label="Certificate dates valid">{yesNo(certificates.dates)}</Field><Field label="Trust bundle fingerprint">{text(certificates.trust_bundle_sha256)}</Field><Field label="Certificate evaluated at">{time(certificates.evaluation_at)}</Field></dl>
      {certificates.reason && <p className="text-xs text-gray-600">Certificate validation detail: {controlName(certificates.reason)}</p>}
      <details className="text-xs"><summary className="cursor-pointer font-medium">Server-offered chain ({offered ? `${offered.length} recorded` : 'not recorded'})</summary>{offered && <ol className="mt-2 space-y-2">{offered.map((certificate, index) => <li key={`${certificate.sha256}-${index}`} className="break-all">{index + 1}. {text(certificate.sha256)}<span className="block">Public-key fingerprint: {text(certificate.spki_sha256)}</span><span className="block">{text(certificate.key_type)} · {number(certificate.key_bits)} bits · {text(certificate.signature_algorithm)}</span><span className="block">Valid {time(certificate.not_before)} – {time(certificate.not_after)}</span><span className="block">Self-signed: {yesNo(certificate.self_signed)} · CA: {yesNo(certificate.ca)}</span></li>)}</ol>}</details>
      <details className="text-xs"><summary className="cursor-pointer font-medium">Built trust path ({trusted ? `${trusted.length} recorded` : 'not recorded'})</summary>{trusted && <ol className="mt-2 space-y-1">{trusted.map((fingerprint, index) => <li key={`${fingerprint}-${index}`} className="break-all">{index + 1}. {text(fingerprint)}</li>)}</ol>}<p className="mt-1 text-gray-500">This path can include certificates from the scanner’s trust store. The server-offered chain is listed separately.</p></details>
    </div>}
    {evidence.ocsp && <StapledOcsp value={evidence.ocsp} />}
    {extensions && <dl className="grid gap-2 sm:grid-cols-2">{[['ems','Extended master secret'],['compression','Compression'],['secure_renegotiation','Secure renegotiation'],['fallback_scsv','Fallback protection'],['session_reused','Session resumed'],['renegotiation_completed','Bounded renegotiation completed']].filter(([key]) => Object.hasOwn(extensions,key)).map(([key,label]) => <Field key={key} label={label}>{yesNo(extensions[key])}</Field>)}{Number.isSafeInteger(extensions.early_data_max) && <Field label="Advertised early-data limit">{number(extensions.early_data_max)} bytes</Field>}</dl>}
    {vulnerability && <div className="text-xs space-y-1"><p className="font-medium">Vulnerability test: {{confirmed:'Confirmed by the recorded test',not_observed:'Not observed in this test',unknown:'Unknown'}[vulnerability.status] || 'Unknown'}</p><p>Profile: {text(vulnerability.profile)} · Vectors completed: {number(vulnerability.completed_vectors)} / {number(vulnerability.planned_vectors)}</p></div>}
  </div>
}

export function TlsAssessmentEvidence({ assessment }) {
  const time = useEvidenceTime()
  if (!assessment || typeof assessment !== 'object') return <p className="text-xs text-gray-500">Deep TLS checks: not recorded.</p>
  const endpoints = Array.isArray(assessment.endpoints) ? assessment.endpoints : []
  const coverage = assessment.coverage || {}
  const store = assessment.trust_store_context
  const costs = assessment.costs
  return <section className="space-y-3 border-t border-gray-100 pt-3" aria-label="TLS security assessment">
    <h4 className="text-sm font-semibold">TLS security assessment</h4>
    <p className="text-xs text-gray-600">Coverage: {{complete:'Complete for the recorded scope',partial:'Partial — some checks remain unresolved or outside this scan budget',not_run:'Not run'}[assessment.quality] || 'Not established'}. Results apply to the recorded endpoints and time.</p>
    <p className="text-xs text-gray-500">Profile: {text(assessment.version)} · Policy: {text(assessment.policy_version)}</p>
    <ul className="flex flex-wrap gap-2 text-xs" aria-label="TLS check coverage">{[['planned','Planned'],['completed','Completed'],['uncertain','Uncertain'],['unexecutable','Could not execute'],['not_authorized','Not authorized'],['not_applicable','Not applicable'],['omitted_checks','Outside scan budget'],['endpoint_gaps','Endpoint gaps']].map(([key,label]) => <li key={key}>{label}: {number(coverage[key])}</li>)}</ul>
    <p className="text-xs text-gray-500">Trust store: {store ? `${text(store.name)} · ${text(store.version)} · ${text(store.sha256)}` : 'Not recorded for this assessment'}{store?.observed_at ? ` · ${time(store.observed_at)}` : ''}</p>
    {costs && <p className="text-xs text-gray-500">Recorded cost: {number(costs.connections)} connections · {number(costs.bytes_sent)} bytes sent · {number(costs.bytes_received)} bytes received · {number(costs.duration_ms)} ms · {number(costs.unknown_attempts)} attempts with unknown cost. Budget charged: {number(costs.charged_connections)} connections / {number(costs.charged_bytes)} bytes.</p>}
    {!endpoints.length && <p className="text-sm text-gray-600">No endpoint checks recorded. Their TLS status remains unknown.</p>}
    {endpoints.map((item,index) => <details key={`${item.hostname}:${item.address}:${item.port}:${index}`} className="rounded-sm border border-gray-200 p-3"><summary className="cursor-pointer text-sm font-medium break-all">{text(item.hostname)} · {endpoint(item)} · {text(item.application_protocol)}</summary><div className="mt-2 space-y-3"><p className="text-xs text-gray-500">SNI: {text(item.sni)} · Transport: {text(item.transport)} · DNS observed {time(item.dns_observed_at)} · Assessed {endpointAssessedAt(item) ? time(endpointAssessedAt(item)) : 'Not tested in this scan'}</p>{Array.isArray(item.checks) && item.checks.length ? item.checks.map((row,checkIndex) => <details key={`${row.control}:${row.protocol}:${row.cipher_id}:${checkIndex}`} className="border-t border-gray-100 pt-2"><summary className="cursor-pointer text-sm">{controlName(row.control)}{row.protocol ? ` · ${text(row.protocol)}` : ''}{row.cipher_id ? ` · ${text(row.cipher_id)}` : ''} — {controlState(row, item)}{row.reason === 'provider_infrastructure_not_tested' && <> <a href={ADDITIONAL_TLS_SERVICES_HREF} className="underline text-brand-700">Add your own servers</a></>}</summary><TlsControlDetail row={row} /></details>) : <p className="text-sm text-gray-600" data-testid="tls-endpoint-not-tested">{endpointNotTestedReason(item, assessment.scope_deferrals)}</p>}</div></details>)}
    <p className="text-xs text-gray-500">Protocol, cipher, resumption and early-data support alone do not establish a vulnerability. QUIC is not measured by these TCP checks.</p>
    {Array.isArray(assessment.limitations) && assessment.limitations.length > 0 && <ul className="list-disc pl-4 text-xs text-gray-500" aria-label="TLS assessment limitations">{assessment.limitations.filter(value => typeof value === 'string').map((value,index) => <li key={index}>{controlName(value)}</li>)}</ul>}
  </section>
}

// This is an evidence view, not a second certificate verdict. A received leaf,
// name match and validation against the named trust store are separate facts.
export default function LiveTlsEvidence({ evidence, assessment, showEndpoints = true }) {
  const time = useEvidenceTime()
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
  const deepAssessment = assessment || evidence.tls_assessment

  return <details className="rounded-lg border border-gray-200 bg-white p-3" data-testid="live-tls-evidence">
    <summary className="cursor-pointer text-sm font-semibold text-gray-800">Live TLS evidence — {collected ? 'certificate observed' : 'not fully observed'}</summary>
    <div className="mt-3 space-y-4">
      <p className="text-xs text-gray-500">These observations describe the recorded connection. They do not establish that every endpoint or the whole service is secure.</p>
      {evidence.all_planned_endpoints_observed === false && <p className="text-sm text-brand-700">Endpoint coverage is incomplete. Unmeasured endpoints remain unknown.</p>}
      {evidence.all_planned_endpoints_observed === true && endpoints.length > 0 && <p className="text-sm text-gray-600">All planned endpoints were observed in this run.</p>}
      {!collected ? <p className="text-sm text-gray-600">A complete live certificate was not recorded, so the certificate currently served is unknown.</p> : <>
        <dl className="grid gap-3 sm:grid-cols-2">
          <Field label="Endpoint (address and port)">{endpoint(evidence.endpoint)}</Field>
          <Field label="Name sent (SNI)">{typeof evidence.endpoint?.hostname === 'string' && evidence.endpoint.hostname ? evidence.endpoint.hostname : 'None sent'}</Field>
          <Field label="Name checked against">{text(match.reference_hostname || evidence.endpoint?.hostname)}</Field>
          <Field label="Observed at">{time(evidence.observed_at)}</Field>
          <Field label="Protocol / cipher">{text(evidence.protocol)} / {text(evidence.cipher)}</Field>
          <Field label="Subject">{text(leaf.subject)}</Field>
          <Field label="Issuer">{text(leaf.issuer)}</Field>
          <Field label="Serial number">{text(leaf.serial_number)}</Field>
          <Field label="Key">{keyText(leaf)}</Field>
          <Field label="Valid from">{time(leaf.not_before)}</Field>
          <Field label="Valid until">{time(leaf.not_after)}</Field>
          <Field label="Hostname or address match"><span className={matchResult === 'mismatched' ? 'text-red-700 font-medium' : ''}>{matchResult === 'matched' ? 'Matched the recorded identity' : matchResult === 'mismatched' ? 'Did not match the recorded identity' : 'Not established'}</span></Field>
          <Field label="Named trust-store validation"><span className={trustResult === 'invalid' ? 'text-red-700 font-medium' : ''}>{trustResult === 'valid' ? 'Valid against the recorded trust store' : trustResult === 'invalid' ? 'Invalid against the recorded trust store' : 'Not established'}</span></Field>
          <Field label="Trust store">{/mozilla ca roots/i.test(String(store.name || '')) ? `Mozilla CA root store${store.version ? ` (scanner bundle ${text(store.version)})` : ''}` : `${text(store.name)}${store.version ? ` · ${text(store.version)}` : ''}`}</Field>
          <Field label="Trust-store fingerprint">{text(store.sha256)}</Field>
        </dl>
        <dl className="space-y-3">
          <Field label="Leaf certificate fingerprint">{leaf.certificate_identity}</Field>
          <Field label="DNS names (SAN)">{names.length ? names.join(', ') : 'Not recorded'}</Field>
        </dl>
        {trustResult === 'invalid' && trust.reason && <p className="text-xs text-red-700">Validation detail: {keyLabel(trust.reason)}</p>}
        <details className="rounded-sm border border-gray-100 p-3">
          <summary className="cursor-pointer text-sm font-medium">Runtime-observed issuer chain ({runtimeChain.length} recorded)</summary>
          <p className="mt-2 text-xs text-gray-500">This is the runtime’s issuer chain, which may include a root from its trust store. It is not the exact chain sent over the connection, and its completeness is not established.</p>
          {runtimeChain.length ? <ol className="mt-3 space-y-3">{runtimeChain.map((certificate, index) => <li key={`${certificate.certificate_identity || 'unknown'}-${index}`} className="border-t border-gray-100 pt-2"><dl className="space-y-1"><Field label={`Certificate ${index + 1}`}>{text(certificate.certificate_identity)}</Field><Field label="Subject">{text(certificate.subject)}</Field><Field label="Issuer">{text(certificate.issuer)}</Field><Field label="Valid until">{time(certificate.not_after)}</Field></dl></li>)}</ol> : <p className="mt-2 text-xs text-gray-500">No runtime issuer certificates recorded.</p>}
        </details>
      </>}
      {showEndpoints && <>
        <p className="text-xs text-gray-500">{deepAssessment ? 'The live-leaf capture above does not establish the exact presented chain or revocation status. Additional measurements are shown below.' : 'Exact presented chain: unknown. Revocation / OCSP status: not assessed.'}</p>
        <TlsAssessmentEvidence assessment={deepAssessment} />
      </>}
      {endpoints.length > 0 && <div className="space-y-2"><h4 className="text-sm font-semibold">Endpoint observations ({endpoints.length})</h4>{endpoints.map((row, index) => <div key={`${row.address}:${row.port}:${index}`} className="rounded-sm border border-gray-100 p-3 space-y-2"><p className="text-sm break-all">{endpoint(row)} — {stateLabels[row.state] || 'Not assessed'}</p>{row.tls ? <LiveTlsEvidence evidence={row.tls} showEndpoints={false} /> : <p className="text-xs text-gray-500">Live TLS was not observed for this endpoint.</p>}</div>)}</div>}
    </div>
  </details>
}
