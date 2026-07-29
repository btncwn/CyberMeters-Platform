import { isPublishableModuleEvidence } from "./scan-budget.js";

export const PHASE5_EVIDENCE_MODULES = Object.freeze({
  cve: "cve_intelligence",
  kev: "known_exploited_vulnerabilities",
  email: "email_security_intelligence",
});

export const PHASE5_INCOMPLETE_REASON = "phase5_evidence_incomplete";

/**
 * One producer-to-consumer contract for Phase-5 evidence.
 *
 * This composes the canonical module-level decision; it does not restate the
 * deferral/skip/error vocabulary. Every Phase-5 consumer must use this result
 * rather than interpreting fallback zeroes as measured evidence.
 */
export function resolvePhase5EvidenceContract(modules = {}) {
  const publishable = Object.fromEntries(
    Object.entries(PHASE5_EVIDENCE_MODULES).map(([name, moduleKey]) => [
      name,
      isPublishableModuleEvidence(modules?.[moduleKey]),
    ]),
  );
  const incompleteModules = Object.entries(PHASE5_EVIDENCE_MODULES)
    .filter(([name]) => !publishable[name])
    .map(([, moduleKey]) => moduleKey);
  return {
    complete: incompleteModules.length === 0,
    publishable,
    incomplete_modules: incompleteModules,
  };
}

/**
 * A score/band is a customer conclusion over the completed assessment.
 * Phase-5 evidence gaps therefore remove the conclusion; they do not turn
 * unassessed CVE/KEV/email evidence into a provisional healthy number.
 */
export function resolvePhase5CustomerAssessment({
  score = null,
  riskLevel = null,
  modules = {},
} = {}) {
  const evidence = resolvePhase5EvidenceContract(modules);
  return {
    score: evidence.complete && Number.isFinite(score) ? score : null,
    risk_level: evidence.complete && riskLevel != null ? riskLevel : null,
    evidence,
  };
}

/**
 * Add the canonical backend decision to the three customer-visible module
 * objects. The frontend consumes this boolean and never reimplements the
 * executable-evidence vocabulary.
 */
export function projectPhase5EvidenceForCustomer(modules = {}) {
  const evidence = resolvePhase5EvidenceContract(modules);
  const projected = { ...modules };
  for (const [name, moduleKey] of Object.entries(PHASE5_EVIDENCE_MODULES)) {
    const value = modules?.[moduleKey];
    if (value && typeof value === "object") {
      projected[moduleKey] = {
        ...value,
        evidence_publishable: evidence.publishable[name],
      };
    }
  }
  return projected;
}
