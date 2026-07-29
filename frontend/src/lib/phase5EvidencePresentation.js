// Customer presentation consumes the canonical backend decision. It does not
// reproduce the executed/incomplete/deadline/skipped/error vocabulary.
export function isPhase5EvidenceAvailable(moduleResult) {
  return moduleResult?.evidence_publishable === true
}

export function phase5KnownCount(moduleResult, value) {
  if (!isPhase5EvidenceAvailable(moduleResult)) return null
  return Number.isFinite(value) ? value : null
}
