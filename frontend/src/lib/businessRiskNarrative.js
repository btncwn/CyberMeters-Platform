// The Business Risk Indicator sentence is frozen when the scan finishes and says
// "No major gaps detected" without regard to coverage. The PDF bounds it by the
// snapshot's own coverage facts (engines/pdf.js); the scan page says the same.
const COVERAGE_LIMIT = 'Coverage is incomplete: some checks did not run or still need customer input, so this provisional indicator is not confirmation that no other material gaps exist.'

// A report that could not be read has not confirmed coverage, so it is incomplete.
export function coverageIsIncomplete(report) {
  const coverage = report?.evidence_completeness
  if (!coverage) return true
  return (coverage.scan_quality && coverage.scan_quality !== 'complete')
    || (coverage.assessment_quality && coverage.assessment_quality !== 'complete')
    || (coverage.monitoring_state && coverage.monitoring_state !== 'monitoring_healthy')
    || (Array.isArray(coverage.modules_skipped) && coverage.modules_skipped.length > 0)
    || (Array.isArray(report.executive_summary?.not_fully_assessed) && report.executive_summary.not_fully_assessed.length > 0)
}

export function businessRiskNarrative(explanation, report) {
  if (!explanation || !coverageIsIncomplete(report)) return explanation
  if (/No major gaps detected/.test(explanation)) {
    return `No major gaps were identified in the evidence available. ${COVERAGE_LIMIT}`
  }
  return `${explanation} ${COVERAGE_LIMIT}`
}
