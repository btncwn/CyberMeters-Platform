// Presentation adapter for the backend-owned anonymous preview contract.
// It never derives health, severity or domain verdicts. Missing/legacy fields
// fail closed so the public page cannot turn absent evidence into reassurance.

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
  Object.freeze({ module: 'subdomains', label: 'Certificate Transparency' }),
  Object.freeze({ module: 'technology_detection', label: 'Technology' }),
])

export const EXPECTED_CYBER_MOT_DOMAINS = Object.freeze([
  Object.freeze({ domain_key: 'email_protection', display_name: 'Email Protection' }),
  Object.freeze({ domain_key: 'brand_protection', display_name: 'Brand Protection' }),
  Object.freeze({ domain_key: 'attack_surface', display_name: 'Attack Surface' }),
  Object.freeze({ domain_key: 'certificates_trust', display_name: 'Certificates & Trust' }),
  Object.freeze({ domain_key: 'cyber_essentials_readiness', display_name: 'Cyber Essentials Readiness' }),
  Object.freeze({ domain_key: 'website_security', display_name: 'Website Security' }),
  Object.freeze({ domain_key: 'identity_exposure', display_name: 'Identity Exposure' }),
  Object.freeze({ domain_key: 'shadow_it_unmanaged_technology', display_name: 'Shadow IT & Unmanaged Technology' }),
])

const DOMAIN_STATES = new Set([
  'assessed_healthy',
  'issue_detected',
  'provisional',
  'degraded',
  'unavailable',
  'not_configured',
  'customer_input_required',
  'monitoring_only',
  'not_yet_assessed',
  'evidence_insufficient',
])

export const FREE_SCAN_STATE_LABELS = Object.freeze({
  attempted: 'Attempted',
  completed: 'Completed',
  failed: 'Failed',
  partial: 'Partial',
  incomplete: 'Incomplete',
  unavailable: 'Unavailable',
})

export const DOMAIN_STATE_LABELS = Object.freeze({
  assessed_healthy: 'Assessed — no issue observed',
  issue_detected: 'Issue observed',
  provisional: 'Provisional',
  degraded: 'Evidence degraded',
  unavailable: 'Unavailable',
  not_configured: 'Not configured',
  customer_input_required: 'Unlock to assess',
  input_required: 'Unlock to assess',
  monitoring_only: 'Observation only',
  not_yet_assessed: 'Not yet assessed',
  evidence_insufficient: 'Evidence incomplete',
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

function normalizedDomains(result) {
  const supplied = new Map(
    (Array.isArray(result?.cyber_mot_domains) ? result.cyber_mot_domains : [])
      .map((entry) => [entry?.domain_key, entry]),
  )
  return EXPECTED_CYBER_MOT_DOMAINS.map((expected) => {
    const entry = supplied.get(expected.domain_key)
    const state = DOMAIN_STATES.has(entry?.state)
      ? entry.state
      : 'evidence_insufficient'
    const displayState = entry?.display_state === 'input_required'
      ? 'input_required'
      : state
    return {
      domain_key: expected.domain_key,
      display_name: entry?.display_name || expected.display_name,
      state,
      display_state: displayState,
      coverage: entry?.coverage || 'partial',
      severity: entry?.severity || null,
      headline_count: Number.isFinite(entry?.headline_count)
        ? entry.headline_count
        : null,
      count_kind: entry?.count_kind || 'input_required',
      samples: Array.isArray(entry?.samples) ? entry.samples.slice(0, 2) : [],
      locked_count: Number.isFinite(entry?.locked_count)
        ? Math.max(0, entry.locked_count)
        : 0,
      unlock_required: entry?.unlock_required === true,
      summary: entry?.summary || 'Evidence was incomplete for this preview domain.',
      limitation: entry?.limitation || 'Evidence scope is limited to this bounded public preview.',
    }
  })
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
  const noIssuesObserved = coverageComplete && previewState === 'no_issues_observed'
  const issuesObserved = previewState === 'issues_observed'
  const evidenceIncomplete = !coverageComplete || !previewStateRecognized || previewState === 'evidence_incomplete'

  let headline = 'Evidence incomplete'
  let summary = (
    result?.evidence_coverage?.messages?.filter(Boolean).join(' ') ||
    'This bounded snapshot observed useful public signals, but deep checks were not run anonymously.'
  )
  if (noIssuesObserved) {
    headline = 'No issues observed in the completed preview checks'
    summary = 'The bounded preview checks completed and produced no findings. This is not a full eight-domain assessment.'
  } else if (issuesObserved) {
    headline = 'Issues observed in the preview checks'
    summary = evidenceIncomplete
      ? 'The findings shown are supported by completed evidence, while other checks remain incomplete or gated.'
      : 'The completed preview checks produced the findings shown below.'
  }

  return {
    coverageComplete,
    evidenceIncomplete,
    noIssuesObserved,
    issuesObserved,
    showScore:
      coverageComplete &&
      previewState === 'no_issues_observed' &&
      Number.isFinite(Number(result?.score)),
    headline,
    summary,
    moduleEvidence,
    domains: normalizedDomains(result),
    signals: {
      dns: normalizedSignal(result, 'dns'),
      website_security: normalizedSignal(result, 'website_security'),
      email_protection: normalizedSignal(result, 'email_protection'),
      certificate_transparency: normalizedSignal(result, 'certificate_transparency'),
    },
  }
}
