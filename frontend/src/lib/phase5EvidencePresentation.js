// Customer presentation consumes the canonical backend decision. It does not
// reproduce the executed/incomplete/deadline/skipped/error vocabulary.
export function isPhase5EvidenceAvailable(moduleResult) {
  return moduleResult?.evidence_publishable === true
}

export function phase5KnownCount(moduleResult, value) {
  if (!isPhase5EvidenceAvailable(moduleResult)) return null
  return Number.isFinite(value) ? value : null
}

// A module the scan's check pack does not include (outside vulnerability data).
// The backend states it; it is neither missing evidence nor a measured zero.
export function isNotInCheckPack(moduleResult) {
  return moduleResult?.outcome === 'not_in_check_pack'
}
