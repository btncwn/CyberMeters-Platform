// Presentation adapter for the backend-owned anonymous preview contract.
// It never derives health from findings or score. Unknown/legacy contracts fail
// closed as incomplete until the backend supplies explicit evidence coverage.

export const FREE_SCAN_EXECUTION_STATES = Object.freeze([
  'attempted',
  'completed',
  'failed',
  'partial',
  'incomplete',
  'unavailable',
])

const EXECUTION_STATE_SET = new Set(FREE_SCAN_EXECUTION_STATES)
const EXPECTED_MODULES = Object.freeze([
  Object.freeze({ module: 'dns', label: 'DNS' }),
  Object.freeze({ module: 'ssl', label: 'TLS' }),
  Object.freeze({ module: 'headers', label: 'Headers' }),
  Object.freeze({ module: 'email_security', label: 'Email' }),
])

export const FREE_SCAN_STATE_LABELS = Object.freeze({
  attempted: 'Attempted',
  completed: 'Completed',
  failed: 'Failed',
  partial: 'Partial',
  incomplete: 'Incomplete',
  unavailable: 'Unavailable',
})

function normalizedModuleEvidence(result) {
  const supplied = new Map(
    (Array.isArray(result?.module_evidence) ? result.module_evidence : [])
      .map((entry) => [entry?.module, entry]),
  )
  return EXPECTED_MODULES.map((expected) => {
    const entry = supplied.get(expected.module)
    const state = EXECUTION_STATE_SET.has(entry?.state)
      ? entry.state
      : 'incomplete'
    return {
      module: expected.module,
      label: entry?.label || expected.label,
      attempted: entry?.attempted === true,
      state,
    }
  })
}

function normalizedSignal(result, signal) {
  const entry = result?.monitoring_states?.signals?.[signal]
  const state = [
    'monitoring_healthy',
    'monitoring_degraded',
    'signal_unavailable',
    'evidence_incomplete',
  ].includes(entry?.state)
    ? entry.state
    : 'evidence_incomplete'
  return {
    state,
    complete: state === 'monitoring_healthy',
    message: entry?.message || 'Monitoring evidence was incomplete in this run.',
  }
}

export function deriveFreeScanPresentation(result) {
  const moduleEvidence = normalizedModuleEvidence(result)
  const coverageComplete = result?.evidence_coverage?.complete === true
  const previewState = result?.preview_state
  const previewStateRecognized = [
    'issues_observed',
    'no_issues_observed',
    'evidence_incomplete',
  ].includes(previewState)
  const noIssuesObserved =
    coverageComplete && previewState === 'no_issues_observed'
  const issuesObserved = previewState === 'issues_observed'
  const evidenceIncomplete = !coverageComplete || !previewStateRecognized

  let headline = 'Evidence incomplete'
  let summary = (
    result?.evidence_coverage?.messages?.filter(Boolean).join(' ') ||
    'Some preview checks did not complete, so CyberMeters cannot draw a clean conclusion from this run.'
  )
  if (noIssuesObserved) {
    headline = 'No issues observed in the completed preview checks'
    summary = 'The four preview modules completed and produced no findings. This is a limited preview, not an assessment across all eight Cyber MOT domains.'
  } else if (issuesObserved) {
    headline = 'Issues observed in the preview checks'
    summary = evidenceIncomplete
      ? 'The findings shown are supported by completed evidence, but other preview checks were incomplete.'
      : 'The completed preview checks produced the findings shown below.'
  }

  return {
    coverageComplete,
    evidenceIncomplete,
    noIssuesObserved,
    issuesObserved,
    showScore:
      coverageComplete &&
      previewStateRecognized &&
      Number.isFinite(Number(result?.score)),
    headline,
    summary,
    moduleEvidence,
    signals: {
      dns: normalizedSignal(result, 'dns'),
      website_security: normalizedSignal(result, 'website_security'),
      email_protection: normalizedSignal(result, 'email_protection'),
    },
  }
}
