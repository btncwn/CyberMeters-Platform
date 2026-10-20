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
]);
export function blockingTlsUnexecutable(checks) {
  return (Array.isArray(checks) ? checks : []).filter(row => row?.state === 'unexecutable'
    && !TLS_CAPABILITY_UNEXECUTABLE_REASONS.includes(row.reason)).length;
}

export const TLS_REFUSAL_REASONS = Object.freeze(['transport_eof', 'handshake_failed', 'peer_alert']);
const LEGACY_PROTOCOLS = new Set(['ssl2', 'ssl3', 'tls1', 'tls1_1']);

export function isTlsRefusalProbe(check) {
  return (check?.control === 'protocol' && LEGACY_PROTOCOLS.has(check.protocol))
    || check?.control === 'cipher' || check?.control === 'secure_renegotiation';
}

export function classifyTlsRefusals(checks) {
  const rows = Array.isArray(checks) ? checks : [];
  const reachable = new Set(rows.filter(row => row?.state === 'accepted').map(row => row.endpoint_index));
  return rows.map(row => {
    if (row?.state === 'rejected') return { ...row, rejection_basis: 'engine_alert' };
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
