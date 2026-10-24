import { TLS_AUTHORISATION_REQUIRED_REASON } from '../../../../shared/tls/catalog.js';
// The deep TLS profile includes static states for controls the engine cannot
// execute (notably the unreleased special checks). Those states remain visible
// in the TLS receipt, but do not make every supported-profile scan incomplete.
// A pending supported check omitted by the cap, or an inconclusive attempted
// check, DOES prevent an unqualified whole-scan completion claim.
// A server that has dropped a legacy protocol, a cipher or client renegotiation
// often refuses the probe without the TLS version alert the engine needs to
// call it "rejected": it closes the connection (transport_eof), fails the
// handshake with no alert, or sends a different alert. When the same endpoint
// completed at least one handshake in the same run, the server was reachable
// and that refusal means "not accepted". It is recorded as rejected with its
// own basis and the engine's original state, so "rejected with an alert" and
// "refused without a version alert" never collapse into one. Timeouts,
// budget cuts, mid-run aborts and unreachable endpoints stay inconclusive.
// An unexecutable check whose reason is an engine-capability or server-feature
// limit (the server offers no heartbeat extension, the engine build cannot
// offer that cipher, group or vector) is a bounded part of the profile, not a
// check this run failed to perform. Once at least one check completed, it does
// not keep the TLS module partial. Anything CyberMeters did not run on its own
// side (feature_disabled, lost authority, ...) still does.
export const TLS_CAPABILITY_UNEXECUTABLE_REASONS = Object.freeze([
  'heartbeat_unavailable', 'cipher_unavailable', 'protocol_unavailable',
  'group_unavailable', 'control_unavailable', 'requires_credentials',
  // Authorised by the customer, engine not released (S3-B follow-up): stated.
  'authorised_engine_not_released',
  // Authorised, held to a started check or refused on a provider edge (F1): stated.
  'scheduled_or_unknown_origin', 'provider_infrastructure_not_tested', 'address_not_verified_not_tested',
]);
export function blockingTlsUnexecutable(checks) {
  return (Array.isArray(checks) ? checks : []).filter(row => row?.state === 'unexecutable'
    && !TLS_CAPABILITY_UNEXECUTABLE_REASONS.includes(row.reason)).length;
}

// An intrusive control the customer has not authorised (S3-B) is stated, not
// missing: it never keeps the assessment partial. Losing an authority that did
// exist (scope changed mid-run) still does.
export function blockingTlsNotAuthorized(checks) {
  return (Array.isArray(checks) ? checks : []).filter(row => row?.state === 'not_authorized'
    && row.reason !== TLS_AUTHORISATION_REQUIRED_REASON).length;
}

export const TLS_REFUSAL_REASONS = Object.freeze(['transport_eof', 'handshake_failed', 'peer_alert']);
const LEGACY_PROTOCOLS = new Set(['ssl2', 'ssl3', 'tls1', 'tls1_1']);

export function isTlsRefusalProbe(check) {
  return (check?.control === 'protocol' && LEGACY_PROTOCOLS.has(check.protocol))
    || check?.control === 'cipher' || check?.control === 'secure_renegotiation';
}

// The customer outcome of a TLS control, from its stored evidence (F1 rerun,
// 24 Oct 2026). The engine 'state' names the CONNECTION outcome ('accepted'
// means the handshake for that control completed), not the feature: showing
// 'Accepted' for compression, early data or OCSP read as the opposite of the
// truth. The raw state stays in the receipt; the UI reads this. Anything not
// settled by evidence is 'unknown' - never a guessed yes or no.
const unknownOutcome = { value: 'unknown', summary: 'Not determined in this run.' };
// endpointChecks: the same endpoint's other rows (downgrade needs to know
// whether the endpoint serves TLS 1.3 at all).
export function tlsControlOutcome(row, endpointChecks = []) {
  const ext = row?.evidence?.extensions || null, ocsp = row?.evidence?.ocsp || null;
  const done = row?.state === 'accepted' || row?.state === 'rejected';
  switch (row?.control) {
    case 'compression':
      if (!done || typeof ext?.compression !== 'boolean') return unknownOutcome;
      return ext.compression
        ? { value: 'yes', summary: 'TLS compression is used.' }
        : { value: 'no', summary: 'TLS compression is not used.' };
    case 'early_data':
      if (row.protocol !== 'tls1_3' || !done || !Number.isSafeInteger(ext?.early_data_max)) return unknownOutcome;
      // An advertised ticket limit: CyberMeters does not send 0-RTT data.
      return ext.early_data_max > 0
        ? { value: 'yes', summary: '0-RTT early data is enabled (advertised by the server).' }
        : { value: 'no', summary: '0-RTT early data is not advertised.' };
    case 'ocsp': {
      if (!done || !ocsp?.state) return unknownOutcome;
      const verified = ocsp.signature_valid === true && ocsp.cert_id_match === true && ocsp.fresh === true;
      if (ocsp.state === 'absent') return { value: 'no', summary: 'No OCSP response is stapled.' };
      if (ocsp.state === 'good' && verified) return { value: 'yes', summary: 'A valid OCSP response is stapled.' };
      if (ocsp.state === 'revoked' && verified) return { value: 'revoked', summary: 'The stapled OCSP response says the certificate is revoked.' };
      if (ocsp.state === 'unknown' && verified)
        return { value: 'status_unknown', summary: 'A verified OCSP response is stapled, but it reports the certificate status as unknown.' };
      return { value: 'invalid', summary: 'An OCSP response is stapled but could not be verified.' };
    }
    case 'secure_renegotiation':
      if (ext?.renegotiation_completed === true) return { value: 'allowed', summary: 'Client-initiated renegotiation is allowed.' };
      // 'handshake_failed' is also set for local/non-alert errors (engine.c
      // do_handshake): it means refused only when the server supports secure
      // renegotiation; a peer alert is a refusal on its own.
      if (ext?.renegotiation_completed === false && (row.state === 'uncertain' || row.state === 'rejected')
          && (row.reason === 'peer_alert' || (row.reason === 'handshake_failed' && ext?.secure_renegotiation === true)))
        return { value: 'refused', summary: 'Client-initiated renegotiation is refused.' };
      return unknownOutcome;
    case 'fallback_scsv':
      if (row.state === 'rejected' && row.reason === 'fallback_rejected' && ext?.fallback_scsv !== false)
        return { value: 'blocked', summary: 'Protocol downgrade is blocked (TLS_FALLBACK_SCSV).' };
      // The fallback probe runs at TLS 1.2. A server whose highest version IS
      // TLS 1.2 correctly accepts it (RFC 7507), so 'not blocked' is a claim only
      // when this endpoint was seen serving TLS 1.3.
      if (row.state === 'accepted' && ext?.fallback_scsv === false
          && (Array.isArray(endpointChecks) ? endpointChecks : []).some(r => r?.control === 'protocol' && r.protocol === 'tls1_3' && r.state === 'accepted'))
        return { value: 'not_blocked', summary: 'Protocol downgrade is not blocked.' };
      return unknownOutcome;
    default:
      return null;
  }
}

export function classifyTlsRefusals(checks) {
  const rows = Array.isArray(checks) ? checks : [];
  const reachable = new Set(rows.filter(row => row?.state === 'accepted').map(row => row.endpoint_index));
  return rows.map(row => {
    if (row?.state === 'rejected') return { ...row, rejection_basis: 'engine_alert' };
    // Heartbleed needs the TLS heartbeat extension. A server that does not offer
    // it is not a check CyberMeters failed to run: it is "Not applicable — this
    // server did not offer the TLS heartbeat extension that Heartbleed relies
    // on" (Executive, 24 Oct 2026). A stated state, not a pass verdict: no
    // finding, no case, no alert, and a retest of an open case stays
    // inconclusive. The producer's reason is kept.
    if (row?.control === 'heartbleed' && row.state === 'unexecutable' && row.reason === 'heartbeat_unavailable') {
      return { ...row, state: 'not_applicable', engine_state: 'unexecutable' };
    }
    if (row?.state === 'uncertain' && reachable.has(row.endpoint_index)
        && TLS_REFUSAL_REASONS.includes(row.reason) && isTlsRefusalProbe(row)) {
      return { ...row, state: 'rejected', engine_state: 'uncertain', rejection_basis: 'refused_without_version_alert' };
    }
    return row;
  });
}

const count = (coverage, key) => Number.isSafeInteger(coverage?.[key]) && coverage[key] >= 0
  ? coverage[key]
  : null;

export function tlsSupportedCoverageGapReason(assessment) {
  if (assessment?.source !== 'tls_assessment') return null;
  if (!assessment.coverage || typeof assessment.coverage !== 'object') return 'tls_coverage_unavailable';
  const omitted = count(assessment.coverage, 'omitted_checks');
  const uncertain = count(assessment.coverage, 'uncertain');
  if (omitted === null || uncertain === null) return 'tls_coverage_unavailable';
  if (omitted > 0) return 'tls_checks_outside_scan_budget';
  if (uncertain > 0) return 'tls_checks_inconclusive';
  if (count(assessment.coverage, 'omitted_services') > 0) return 'tls_services_outside_scan_budget';
  if (count(assessment.coverage, 'endpoint_gaps') > 0) return 'tls_endpoint_coverage_incomplete';
  if (!Array.isArray(assessment.endpoints) || !assessment.endpoints.some(endpoint => Array.isArray(endpoint?.checks) && endpoint.checks.length > 0)) return 'tls_endpoints_unobserved';
  if (assessment.quality === 'unavailable') return 'tls_result_unavailable';
  return null;
}

export function projectTlsScanQualityForCustomer(quality, assessment) {
  const reason = tlsSupportedCoverageGapReason(assessment);
  if (!reason) return quality;
  const original = quality && typeof quality === 'object' ? quality : { status: quality ?? null };
  const incomplete = Array.isArray(original.modules_incomplete) ? original.modules_incomplete : [];
  const warnings = Array.isArray(original.warnings) ? original.warnings : [];
  return {
    ...original,
    status: original.status === 'degraded' ? 'degraded' : 'partial',
    modules_incomplete: [
      ...incomplete.filter(item => item?.module !== 'tls_assessment'),
      { module: 'tls_assessment', incomplete_reason: reason },
    ],
    warnings: warnings.includes('Module incomplete: tls_assessment')
      ? warnings : [...warnings, 'Module incomplete: tls_assessment'],
  };
}
