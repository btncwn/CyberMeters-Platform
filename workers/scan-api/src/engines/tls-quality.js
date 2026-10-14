// The deep TLS profile includes static states for controls the engine cannot
// execute (notably the unreleased special checks). Those states remain visible
// in the TLS receipt, but do not make every supported-profile scan incomplete.
// A pending supported check omitted by the cap, or an inconclusive attempted
// check, DOES prevent an unqualified whole-scan completion claim.
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
  if (!Array.isArray(assessment.endpoints) || assessment.endpoints.length === 0) return 'tls_endpoints_unobserved';
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
